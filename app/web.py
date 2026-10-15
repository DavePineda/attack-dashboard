"""Aplicación web: API de ingesta, API de estadísticas y el dashboard estático."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .config import Settings
from .geo import CountryLookup
from .ingest import BadRequest, parse_batch
from .store import Store

log = logging.getLogger("web")
STATIC_DIR = Path(__file__).parent / "static"
MAX_BODY = 1_048_576  # 1 MiB por lote
RANGES = {"24h": (timedelta(hours=24), "hour"),
          "7d": (timedelta(days=7), "day"),
          "30d": (timedelta(days=30), "day")}
MESES = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"]

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
]


class SecurityHeaders:
    """Middleware ASGI puro: añade cabeceras de seguridad y oculta el banner del servidor."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        is_api = scope["path"].startswith("/api/")

        async def wrapped(message):
            if message["type"] == "http.response.start":
                drop = {b"server", b"cache-control"} if is_api else {b"server"}
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in drop]
                headers.extend(SECURITY_HEADERS)
                if is_api:
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, wrapped)


def peer_ip(scope) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """IP de quien abrió la conexión TCP: no se puede falsificar con cabeceras."""
    client = scope.get("client")
    try:
        ip = ipaddress.ip_address(client[0]) if client else None
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


class ProxyOnly:
    """Middleware ASGI puro: solo acepta conexiones de los proxies de TRUSTED_PROXIES.

    Cierra el puerto directo del nodo de Botkeep, por donde se podría falsificar
    X-Forwarded-For para saltarse el limitador y el bloqueo por fallos.
    """

    def __init__(self, app, trusted: tuple) -> None:
        self.app, self.trusted = app, trusted

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            ip = peer_ip(scope)
            if ip is None or not any(ip in net for net in self.trusted):
                response = JSONResponse({"error": "Acceso directo no permitido"}, status_code=403)
                return await response(scope, receive, send)
        await self.app(scope, receive, send)


class TokenBucket:
    """Limitador de tasa en memoria (suficiente para una sola instancia)."""

    def __init__(self, rate: float, burst: int) -> None:
        self.rate, self.burst = rate, burst
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (float(self.burst), now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        ok = tokens >= cost
        self._buckets[key] = (tokens - cost if ok else tokens, now)
        if len(self._buckets) > 50_000:  # evita crecer sin límite ante un escaneo
            cutoff = now - self.burst / self.rate
            self._buckets = {k: v for k, v in self._buckets.items() if v[1] > cutoff}
        return ok

    def peek(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (float(self.burst), now))
        return min(self.burst, tokens + (now - last) * self.rate) >= cost


def _valid_ip(value: str) -> str | None:
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return None


def error(status: int, message: str, **headers: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers=headers or None)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


def build_timeline(rows: list[dict], *, since: datetime, now: datetime, unit: str,
                   tz) -> list[dict[str, Any]]:
    """Rellena los huecos para que el gráfico muestre también las horas/días sin eventos."""
    def floor(dt: datetime) -> datetime:
        local = dt.astimezone(tz)
        local = local.replace(minute=0, second=0, microsecond=0)
        if unit == "day":
            local = local.replace(hour=0)
        return local.replace(tzinfo=None)

    counts: dict[datetime, dict[str, int]] = {}
    for row in rows:
        key = floor(row["bucket"])
        counts.setdefault(key, {})[row["source"]] = int(row["n"])

    step = timedelta(hours=1) if unit == "hour" else timedelta(days=1)
    out, cursor, end = [], floor(since), floor(now)
    while cursor <= end:
        aware = cursor.replace(tzinfo=tz)
        label = (f"{cursor:%H}:00" if unit == "hour"
                 else f"{cursor.day} {MESES[cursor.month - 1]}")
        found = counts.get(cursor, {})
        out.append({"t": _iso(aware), "label": label,
                    "fail2ban": found.get("fail2ban", 0), "ufw": found.get("ufw", 0)})
        cursor += step
    return out


def create_app(settings: Settings, store: Store, geo: CountryLookup | None = None,
               *, run_background: bool = True) -> Starlette:
    geo = geo or CountryLookup("")
    stats_limiter = TokenBucket(rate=0.5, burst=30)      # ~30 req/min por IP
    ingest_limiter = TokenBucket(rate=2.0, burst=60)
    auth_fail_limiter = TokenBucket(rate=1 / 60, burst=10)  # 10 fallos, luego 1/min
    sensor_cache: dict[bytes, tuple[float, tuple[int, str] | None]] = {}
    stats_cache: dict[str, tuple[float, dict]] = {}
    stats_lock = asyncio.Lock()

    def client_ip(request: Request) -> str:
        if settings.client_ip_header:
            ip = _valid_ip(request.headers.get(settings.client_ip_header, ""))
            if ip:
                return ip
        if settings.trust_proxy:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded:
                ip = _valid_ip(forwarded.split(",")[-1])
                if ip:
                    return ip
        return request.client.host if request.client else "desconocido"

    async def read_body(request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared and (not declared.isdigit() or int(declared) > MAX_BODY):
            raise BadRequest("Lote demasiado grande")
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BODY:
                raise BadRequest("Lote demasiado grande")
            chunks.append(chunk)
        return b"".join(chunks)

    async def ingest(request: Request) -> Response:
        ip = client_ip(request)
        if not ingest_limiter.allow(ip):
            return error(429, "Demasiadas solicitudes", **{"Retry-After": "30"})
        if not auth_fail_limiter.peek(ip):
            return error(429, "Demasiados intentos fallidos", **{"Retry-After": "60"})

        auth = request.headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        token = token.strip()
        sensor = None
        if scheme.lower() == "bearer" and 32 <= len(token) <= 128:
            sha = hashlib.sha256(token.encode()).digest()
            cached = sensor_cache.get(sha)
            if cached and cached[0] > time.monotonic():
                sensor = cached[1]
            else:
                sensor = await store.sensor_for_token(sha)
                sensor_cache[sha] = (time.monotonic() + 60, sensor)
        if sensor is None:
            auth_fail_limiter.allow(ip)
            # La IP de conexión sirve para descubrir qué valor poner en TRUSTED_PROXIES.
            log.warning("Ingesta rechazada: token inválido desde %s (conexión de %s)",
                        ip, peer_ip(request.scope) or "desconocida")
            return error(401, "No autorizado", **{"WWW-Authenticate": "Bearer"})

        if "application/json" not in request.headers.get("content-type", ""):
            return error(415, "Se esperaba application/json")
        try:
            body = await read_body(request)
            payload = json.loads(body)
            events, rejected = parse_batch(
                payload, now=datetime.now(timezone.utc),
                retention_days=settings.retention_days, max_events=settings.max_batch)
        except BadRequest as exc:
            return error(413 if "grande" in str(exc) else 400, str(exc))
        except (ValueError, UnicodeDecodeError):
            return error(400, "JSON inválido")

        countries = [geo.country(e.ip) for e in events]
        inserted = await store.insert_events(sensor[0], events, countries)
        stats_cache.clear()
        log.info("Sensor %s: %d recibidos, %d nuevos, %d rechazados",
                 sensor[1], len(events), inserted, rejected)
        return JSONResponse({"accepted": len(events), "inserted": inserted,
                             "duplicates": len(events) - inserted, "rejected": rejected})

    async def stats(request: Request) -> Response:
        if not stats_limiter.allow(client_ip(request)):
            return error(429, "Demasiadas solicitudes", **{"Retry-After": "30"})
        key = request.query_params.get("range", "7d")
        if key not in RANGES:
            return error(400, "range debe ser 24h, 7d o 30d")

        cached = stats_cache.get(key)
        if cached and cached[0] > time.monotonic():
            return JSONResponse(cached[1])
        async with stats_lock:  # una sola consulta pesada a la vez
            cached = stats_cache.get(key)
            if cached and cached[0] > time.monotonic():
                return JSONResponse(cached[1])
            payload = await compute_stats(key)
            stats_cache[key] = (time.monotonic() + settings.stats_cache_seconds, payload)
        return JSONResponse(payload)

    async def compute_stats(key: str) -> dict[str, Any]:
        span, unit = RANGES[key]
        now = datetime.now(timezone.utc)
        since = now - span
        raw = await store.stats(since=since, unit=unit, tz=settings.display_tz.key,
                                mask=settings.mask_ips)
        summary = raw["summary"]
        return {
            "range": key,
            "generated_at": _iso(now),
            "title": settings.site_title,
            "masked": settings.mask_ips,
            "geoip": geo.enabled,
            "geoip_attribution": settings.geoip_attribution if geo.enabled else "",
            "source_url": settings.source_url,
            "retention_days": settings.retention_days,
            "timezone": settings.display_tz.key,
            "summary": {
                "bans": int(summary["bans"]), "blocked": int(summary["blocked"]),
                "unique_ips": int(summary["unique_ips"]), "countries": int(summary["countries"]),
                "last_event": _iso(summary["last_event"]),
            },
            "timeline": {"unit": unit, "buckets": build_timeline(
                raw["timeline"], since=since, now=now, unit=unit, tz=settings.display_tz)},
            "countries": [{"country": r["country"], "ips": int(r["ips"]), "hits": int(r["hits"])}
                          for r in raw["countries"]],
            "ports": [{"proto": r["proto"], "port": int(r["dport"]), "hits": int(r["hits"]),
                       "ips": int(r["ips"])} for r in raw["ports"]],
            "jails": [{"jail": r["jail"], "bans": int(r["bans"]), "ips": int(r["ips"])}
                      for r in raw["jails"]],
            "top": [{"addr": r["addr"], "country": r["country"], "bans": int(r["bans"]),
                     "blocked": int(r["blocked"]), "hosts": int(r["hosts"]),
                     "first_seen": _iso(r["first_seen"]), "last_seen": _iso(r["last_seen"])}
                    for r in raw["top"]],
            "sensors": {"count": int(raw["sensors"]["count"] or 0),
                        "last_seen": _iso(raw["sensors"]["last_seen"])},
        }

    async def retention_loop() -> None:
        while True:
            try:
                deleted = await store.purge(settings.retention_days)
                if deleted:
                    log.info("Retención: %d eventos con más de %d días eliminados",
                             deleted, settings.retention_days)
            except Exception:
                log.exception("Fallo en la tarea de retención")
            await asyncio.sleep(6 * 3600)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        await store.open()
        task = asyncio.create_task(retention_loop()) if run_background else None
        log.info("Dashboard listo (máscara de IPs: %s, retención: %d días)",
                 settings.mask_ips, settings.retention_days)
        if settings.trusted_proxies:
            log.info("Solo se aceptan conexiones de: %s",
                     ", ".join(str(net) for net in settings.trusted_proxies))
        else:
            log.warning("TRUSTED_PROXIES vacío: se acepta acceso directo al puerto y "
                        "X-Forwarded-For podría ser falso")
        try:
            yield
        finally:
            if task:
                task.cancel()
            await store.close()
            geo.close()

    routes = [
        Route("/api/v1/ingest", ingest, methods=["POST"]),
        Route("/api/v1/stats", stats, methods=["GET"]),
        Mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static"),
    ]
    app = Starlette(routes=routes, lifespan=lifespan)
    if settings.trusted_proxies:
        app.add_middleware(ProxyOnly, trusted=settings.trusted_proxies)
    app.add_middleware(SecurityHeaders)  # la última añadida es la más externa
    return app
