"""Validación de los lotes que envía el agente. Funciones puras, sin red ni base de datos."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

SOURCES = {"fail2ban", "ufw"}
JAIL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
PROTO_RE = re.compile(r"^[A-Z0-9]{1,10}$")
MAX_HITS = 10_000_000
FUTURE_SKEW = timedelta(minutes=10)
MAX_BYTES = 1 << 50          # 1 PiB: cualquier valor mayor es un error del agente
MAX_LOAD = 10_000.0
HOST_TEXT_RE = re.compile(r"^[\w .,:()+/-]{1,80}$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


class BadRequest(ValueError):
    """El cuerpo completo es inválido (estructura, tamaño)."""


@dataclass(frozen=True)
class Event:
    ts: datetime
    source: str
    jail: str | None
    ip: str
    proto: str | None
    dport: int | None
    hits: int


@dataclass(frozen=True)
class Metrics:
    ts: datetime
    cpu_pct: float | None
    load: tuple[float, float, float] | None
    mem_total: int
    mem_used: int
    swap_total: int
    swap_used: int
    disk_total: int
    disk_used: int
    disk_avail: int


def _parse_ts(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("ts")
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        raise ValueError("ts sin zona horaria")
    return ts.astimezone(timezone.utc)


def _parse_event(item: object, oldest: datetime, newest: datetime) -> Event:
    if not isinstance(item, dict):
        raise ValueError("evento")
    ts = _parse_ts(item.get("ts"))
    if not oldest <= ts <= newest:
        raise ValueError("ts fuera de rango")

    source = item.get("source")
    if source not in SOURCES:
        raise ValueError("source")

    ip_raw = item.get("ip")
    if not isinstance(ip_raw, str) or len(ip_raw) > 45:
        raise ValueError("ip")
    ip = ipaddress.ip_address(ip_raw)
    if not ip.is_global:  # privadas, loopback, link-local, documentación…
        raise ValueError("ip no pública")

    jail = item.get("jail")
    if jail is not None and (not isinstance(jail, str) or not JAIL_RE.match(jail)):
        raise ValueError("jail")

    proto = item.get("proto")
    if proto is not None:
        if not isinstance(proto, str) or not PROTO_RE.match(proto.upper()):
            raise ValueError("proto")
        proto = proto.upper()

    dport = item.get("dport")
    if dport is not None and (type(dport) is not int or not 0 <= dport <= 65535):
        raise ValueError("dport")

    hits = item.get("hits", 1)
    if type(hits) is not int or not 1 <= hits <= MAX_HITS:
        raise ValueError("hits")
    if source == "fail2ban":
        hits = 1

    return Event(ts, source, jail, ip.compressed, proto, dport, hits)


def parse_batch(payload: object, *, now: datetime, retention_days: int,
                max_events: int) -> tuple[list[Event], int]:
    """Devuelve (eventos válidos, cantidad rechazada). Lanza BadRequest si el lote no sirve."""
    if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
        raise BadRequest('Se esperaba {"events": [...]}')
    items = payload["events"]
    if len(items) > max_events:
        raise BadRequest(f"Máximo {max_events} eventos por lote")

    oldest = now - timedelta(days=retention_days)
    newest = now + FUTURE_SKEW
    events: list[Event] = []
    rejected = 0
    for item in items:
        try:
            events.append(_parse_event(item, oldest, newest))
        except ValueError:
            rejected += 1
    return events, rejected


def _number(value: object, low: float, high: float, name: str) -> float:
    # bool es subclase de int; NaN e infinito no pasan la comparación de rango.
    if type(value) not in (int, float) or not low <= value <= high:
        raise ValueError(name)
    return float(value)


def _bytes(item: dict, name: str, *, positive: bool = False) -> int:
    value = item.get(name)
    if type(value) is not int or not (1 if positive else 0) <= value <= MAX_BYTES:
        raise ValueError(name)
    return value


def parse_metrics(item: object, *, now: datetime) -> Metrics:
    """Estado del servidor que manda el agente en cada ejecución. Lanza ValueError si no sirve.

    Cubre todas las restricciones CHECK de la tabla metrics: una fila inválida haría fallar
    también la transacción de los eventos del mismo lote.
    """
    if not isinstance(item, dict):
        raise ValueError("metrics")
    ts = _parse_ts(item.get("ts"))
    if abs(ts - now) > FUTURE_SKEW:
        raise ValueError("ts fuera de rango")

    cpu = item.get("cpu_pct")
    cpu = None if cpu is None else _number(cpu, 0, 100, "cpu_pct")

    load = item.get("load")
    if load is not None:
        if not isinstance(load, list) or len(load) != 3:
            raise ValueError("load")
        load = tuple(_number(v, 0, MAX_LOAD, "load") for v in load)

    m = Metrics(ts, cpu, load,
                _bytes(item, "mem_total", positive=True), _bytes(item, "mem_used"),
                _bytes(item, "swap_total"), _bytes(item, "swap_used"),
                _bytes(item, "disk_total", positive=True), _bytes(item, "disk_used"),
                _bytes(item, "disk_avail"))
    if (m.mem_used > m.mem_total or m.swap_used > m.swap_total
            or m.disk_used > m.disk_total or m.disk_avail > m.disk_total):
        raise ValueError("usado mayor que total")
    return m


def parse_host(item: object) -> dict[str, str | None]:
    """Datos de la cabecera de la tarjeta del servidor. Un campo inválido queda en None."""
    item = item if isinstance(item, dict) else {}

    def text(key: str, pattern: re.Pattern) -> str | None:
        value = item.get(key)
        return value if isinstance(value, str) and pattern.match(value) else None

    def ip(key: str, version: int) -> str | None:
        value = item.get(key)
        try:
            addr = ipaddress.ip_address(value) if isinstance(value, str) and len(value) <= 45 else None
        except ValueError:
            return None
        return addr.compressed if addr and addr.version == version and addr.is_global else None

    return {"label": text("label", HOST_TEXT_RE), "service": text("service", HOST_TEXT_RE),
            "hostname": text("hostname", HOSTNAME_RE), "os": text("os", HOST_TEXT_RE),
            "kernel": text("kernel", HOST_TEXT_RE), "ipv4": ip("ipv4", 4), "ipv6": ip("ipv6", 6)}


def mask_network(ip: str) -> str:
    """IPv4 → /24, IPv6 → /48. Para mostrar públicamente sin exponer hosts concretos."""
    addr = ipaddress.ip_address(ip)
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
