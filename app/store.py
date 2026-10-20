"""Acceso a PostgreSQL con psycopg 3 (pool asíncrono). Todo el SQL vive aquí."""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from .ingest import Event, Metrics

log = logging.getLogger("store")
SCHEMA = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")

SQL_SENSOR_BY_HASH = """
SELECT id, name FROM sensors WHERE token_sha256 = %(sha)s AND enabled
"""

SQL_TOUCH_SENSOR = "UPDATE sensors SET last_seen = now() WHERE id = %(id)s"

# Un solo parámetro JSON por lote: un viaje a la base y sin inferencia de tipos de arrays.
SQL_INSERT_EVENTS = """
INSERT INTO events (sensor_id, ts, source, jail, ip, proto, dport, hits, country)
SELECT %(sensor_id)s, u.ts, u.source, u.jail, u.ip, u.proto, u.dport, u.hits, u.country
FROM jsonb_to_recordset(%(rows)s::jsonb)
     AS u(ts timestamptz, source text, jail text, ip inet, proto text,
          dport int, hits int, country text)
ON CONFLICT DO NOTHING
"""

SQL_SUMMARY = """
SELECT count(*) FILTER (WHERE source = 'fail2ban')                AS bans,
       COALESCE(sum(hits) FILTER (WHERE source = 'ufw'), 0)::bigint AS blocked,
       count(DISTINCT ip)                                          AS unique_ips,
       count(DISTINCT country)                                     AS countries,
       max(ts)                                                     AS last_event
FROM events
WHERE ts >= %(since)s
"""

SQL_TIMELINE = """
SELECT date_trunc(%(unit)s, ts, %(tz)s) AS bucket, source, sum(hits)::bigint AS n
FROM events
WHERE ts >= %(since)s
GROUP BY 1, 2
ORDER BY 1
"""

SQL_COUNTRIES = """
SELECT COALESCE(country, '??') AS country, count(DISTINCT ip) AS ips, sum(hits)::bigint AS hits
FROM events
WHERE ts >= %(since)s
GROUP BY 1
ORDER BY ips DESC, hits DESC
LIMIT 10
"""

SQL_PORTS = """
SELECT proto, dport, sum(hits)::bigint AS hits, count(DISTINCT ip) AS ips
FROM events
WHERE ts >= %(since)s AND source = 'ufw' AND dport IS NOT NULL
GROUP BY 1, 2
ORDER BY hits DESC
LIMIT 10
"""

SQL_JAILS = """
SELECT COALESCE(jail, 'desconocido') AS jail, count(*) AS bans, count(DISTINCT ip) AS ips
FROM events
WHERE ts >= %(since)s AND source = 'fail2ban'
GROUP BY 1
ORDER BY bans DESC
LIMIT 10
"""

# Con %(mask)s = true se agrupa por red (/24 en IPv4, /48 en IPv6) para no publicar hosts.
SQL_TOP_SOURCES = """
WITH x AS (
    SELECT CASE WHEN %(mask)s
                THEN set_masklen(ip::cidr, CASE family(ip) WHEN 4 THEN 24 ELSE 48 END)
                ELSE ip::cidr END AS net,
           ip, country, source, hits, ts
    FROM events
    WHERE ts >= %(since)s
)
SELECT CASE WHEN %(mask)s THEN text(net) ELSE host(net) END   AS addr,
       mode() WITHIN GROUP (ORDER BY country)                AS country,
       count(*) FILTER (WHERE source = 'fail2ban')           AS bans,
       COALESCE(sum(hits) FILTER (WHERE source = 'ufw'), 0)::bigint AS blocked,
       count(DISTINCT ip)                                    AS hosts,
       min(ts)                                               AS first_seen,
       max(ts)                                               AS last_seen
FROM x
GROUP BY net
ORDER BY bans DESC, blocked DESC
LIMIT 15
"""

SQL_SENSORS = """
SELECT count(*) FILTER (WHERE enabled) AS count, max(last_seen) AS last_seen FROM sensors
"""

SQL_PURGE = "DELETE FROM events WHERE ts < now() - make_interval(days => %(days)s)"
SQL_PURGE_METRICS = "DELETE FROM metrics WHERE ts < now() - make_interval(days => %(days)s)"

SQL_INSERT_METRICS = """
INSERT INTO metrics (sensor_id, ts, cpu_pct, load1, load5, load15, mem_total, mem_used,
                     swap_total, swap_used, disk_total, disk_used, disk_avail)
VALUES (%(sensor_id)s, %(ts)s, %(cpu_pct)s, %(load1)s, %(load5)s, %(load15)s, %(mem_total)s,
        %(mem_used)s, %(swap_total)s, %(swap_used)s, %(disk_total)s, %(disk_used)s, %(disk_avail)s)
ON CONFLICT DO NOTHING
"""

SQL_SET_HOST = "UPDATE sensors SET host_info = %(host)s::jsonb WHERE id = %(id)s"

# Estado del servidor: el sensor que envió las métricas más recientes (hoy solo hay uno).
SQL_SERVER_LATEST = """
SELECT s.id AS sensor_id, s.name, s.last_seen, s.host_info, m.ts, m.cpu_pct,
       m.load1, m.load5, m.load15, m.mem_total, m.mem_used, m.swap_total, m.swap_used,
       m.disk_total, m.disk_used, m.disk_avail
FROM metrics m JOIN sensors s ON s.id = m.sensor_id
ORDER BY m.ts DESC
LIMIT 1
"""

# Disco en % como `df`: usado / (usado + libre para usuarios); el reservado para root no cuenta.
SQL_SERVER_SERIES_RAW = """
SELECT ts AS t, cpu_pct AS cpu,
       100 * mem_used::float8 / mem_total AS mem,
       100 * disk_used::float8 / NULLIF(disk_used + disk_avail, 0) AS disk
FROM metrics
WHERE sensor_id = %(sid)s AND ts >= %(since)s
ORDER BY ts
"""

SQL_SERVER_SERIES_HOURLY = """
SELECT date_trunc('hour', ts, %(tz)s) AS t, avg(cpu_pct) AS cpu,
       avg(100 * mem_used::float8 / mem_total) AS mem,
       avg(100 * disk_used::float8 / NULLIF(disk_used + disk_avail, 0)) AS disk
FROM metrics
WHERE sensor_id = %(sid)s AND ts >= %(since)s
GROUP BY 1
ORDER BY 1
"""

SQL_SERVER_SUMMARY = """
SELECT max(cpu_pct) AS cpu_max, avg(cpu_pct) AS cpu_avg,
       max(100 * mem_used::float8 / mem_total) AS mem_max,
       avg(100 * mem_used::float8 / mem_total) AS mem_avg,
       (array_agg(disk_used ORDER BY ts))[1]      AS disk_first,
       (array_agg(disk_used ORDER BY ts DESC))[1] AS disk_last
FROM metrics
WHERE sensor_id = %(sid)s AND ts >= %(since)s
"""

# Si la red entre el nodo de la API y el de la base se corta, una conexión muerta solo se
# detecta con los temporizadores TCP del sistema (pueden ser horas) y la consulta que la usa
# se queda colgada. Con esto falla en menos de un minuto. DATABASE_URL tiene prioridad.
TCP_DEFAULTS = {
    "connect_timeout": 10,       # s para abrir una conexión
    "keepalives": 1,             # sondear las conexiones sin tráfico...
    "keepalives_idle": 30,       # ...tras 30 s de inactividad,
    "keepalives_interval": 10,   # cada 10 s,
    "keepalives_count": 3,       # y darla por muerta tras 3 sondeos sin respuesta
    "tcp_user_timeout": 30_000,  # ms con datos enviados sin confirmar antes de cortarla
}


def tcp_options(dsn: str) -> dict[str, int]:
    """Las opciones de TCP_DEFAULTS que DATABASE_URL no fija ya."""
    from psycopg.conninfo import conninfo_to_dict

    given = conninfo_to_dict(dsn)
    return {k: v for k, v in TCP_DEFAULTS.items() if k not in given}


# Prueba de red en cada arranque: separa un problema de red entre nodos (como el del 16/10,
# con la base sana desde fuera) de uno de credenciales o TLS. Solo informa, no frena el arranque.
PROBE_TIMEOUT = 5.0
CONTROL_ADDR = ("1.1.1.1", 443)


def db_address(dsn: str) -> tuple[str, int] | None:
    """Host (o hostaddr) y puerto de DATABASE_URL; None si es un socket local."""
    from psycopg.conninfo import conninfo_to_dict

    info = conninfo_to_dict(dsn)
    host = (info.get("hostaddr") or info.get("host") or "localhost").split(",")[0]
    if host.startswith("/"):
        return None
    return host, int(str(info.get("port") or 5432).split(",")[0])


async def tcp_probe(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> tuple[bool, str]:
    """Abre y cierra una conexión TCP. Devuelve (éxito, detalle para el log)."""
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except TimeoutError:  # antes que OSError: es una subclase
        return False, (f"sin respuesta en {timeout:g} s (los paquetes se pierden por el camino: "
                       "red entre nodos o cortafuegos)")
    except ConnectionRefusedError:
        return False, "conexión rechazada (nadie escucha en ese puerto: ¿base parada?)"
    except socket.gaierror as exc:
        return False, f"no se pudo resolver el nombre ({exc})"
    except OSError as exc:
        return False, f"error de red ({exc})"
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True, f"OK ({time.monotonic() - start:.1f} s)"


async def check_network(dsn: str) -> None:
    addr = db_address(dsn)
    if addr is None:
        return
    ok, detail = await tcp_probe(*addr)
    if ok:
        log.info("Red hacia PostgreSQL %s:%d: %s", *addr, detail)
        return
    log.warning("Red hacia PostgreSQL %s:%d: %s", *addr, detail)
    # ¿Falla solo la base o toda la salida a internet?
    ok, detail = await tcp_probe(*CONTROL_ADDR)
    log.warning("Control de salida a internet %s:%d: %s", *CONTROL_ADDR, detail)


class Store(Protocol):
    async def open(self) -> None: ...
    async def close(self) -> None: ...
    async def sensor_for_token(self, sha256: bytes) -> tuple[int, str] | None: ...
    async def insert_events(self, sensor_id: int, events: list[Event],
                            countries: list[str | None], *, metrics: Metrics | None = None,
                            host: dict | None = None) -> int: ...
    async def stats(self, *, since: datetime, unit: str, tz: str, mask: bool) -> dict[str, Any]: ...
    async def purge(self, retention_days: int) -> int: ...


def events_to_json(events: list[Event], countries: list[str | None]) -> str:
    return json.dumps([
        {"ts": e.ts.isoformat(), "source": e.source, "jail": e.jail, "ip": e.ip,
         "proto": e.proto, "dport": e.dport, "hits": e.hits, "country": c}
        for e, c in zip(events, countries, strict=True)
    ])


class PgStore:
    def __init__(self, dsn: str, work_mem: str = "32MB") -> None:
        if not dsn:
            raise RuntimeError("Falta DATABASE_URL")
        self._dsn = dsn
        self._work_mem = work_mem
        self._pool = None

    async def _configure(self, conn) -> None:
        # Solo para las sesiones de la API: no toca la configuración global de la base.
        await conn.execute("SELECT set_config('work_mem', %s, false)", (self._work_mem,))

    async def open(self) -> None:
        from psycopg.rows import dict_row
        from psycopg_pool import AsyncConnectionPool

        await check_network(self._dsn)
        tcp = tcp_options(self._dsn)
        for attempt in range(1, 11):
            # Un pool que no logró abrir queda cerrado y no se puede reutilizar:
            # cada intento necesita uno nuevo.
            pool = AsyncConnectionPool(
                self._dsn, min_size=1, max_size=4, open=False, timeout=10,
                kwargs={"autocommit": True, "row_factory": dict_row, **tcp},
                configure=self._configure,
                # Prueba cada conexión al sacarla del pool: si está rota, la descarta y
                # entrega otra en vez de dejar que falle la consulta.
                check=AsyncConnectionPool.check_connection,
            )
            try:
                await pool.open(wait=True, timeout=10)
                break
            except Exception as exc:  # la base puede tardar en arrancar
                await pool.close()
                log.warning("PostgreSQL no disponible (intento %d/10): %s", attempt, exc)
                if attempt == 10:
                    raise
                await asyncio.sleep(3)
        self._pool = pool
        async with self._pool.connection() as conn:
            await conn.execute(SCHEMA)
        log.info("Esquema aplicado")

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()

    async def sensor_for_token(self, sha256: bytes) -> tuple[int, str] | None:
        async with self._pool.connection() as conn:
            cur = await conn.execute(SQL_SENSOR_BY_HASH, {"sha": sha256})
            row = await cur.fetchone()
        return (row["id"], row["name"]) if row else None

    async def insert_events(self, sensor_id: int, events: list[Event],
                            countries: list[str | None], *, metrics: Metrics | None = None,
                            host: dict | None = None) -> int:
        async with self._pool.connection() as conn:
            async with conn.transaction():
                inserted = 0
                if events:
                    cur = await conn.execute(SQL_INSERT_EVENTS, {
                        "sensor_id": sensor_id, "rows": events_to_json(events, countries)})
                    inserted = cur.rowcount
                if metrics:
                    load = metrics.load or (None, None, None)
                    await conn.execute(SQL_INSERT_METRICS, {
                        "sensor_id": sensor_id, "ts": metrics.ts, "cpu_pct": metrics.cpu_pct,
                        "load1": load[0], "load5": load[1], "load15": load[2],
                        "mem_total": metrics.mem_total, "mem_used": metrics.mem_used,
                        "swap_total": metrics.swap_total, "swap_used": metrics.swap_used,
                        "disk_total": metrics.disk_total, "disk_used": metrics.disk_used,
                        "disk_avail": metrics.disk_avail})
                if host:
                    await conn.execute(SQL_SET_HOST, {"id": sensor_id, "host": json.dumps(host)})
                await conn.execute(SQL_TOUCH_SENSOR, {"id": sensor_id})
        return inserted

    async def stats(self, *, since: datetime, unit: str, tz: str, mask: bool) -> dict[str, Any]:
        params = {"since": since, "unit": unit, "tz": tz, "mask": mask}
        out: dict[str, Any] = {}
        async with self._pool.connection() as conn:
            for key, sql, one in (
                ("summary", SQL_SUMMARY, True),
                ("timeline", SQL_TIMELINE, False),
                ("countries", SQL_COUNTRIES, False),
                ("ports", SQL_PORTS, False),
                ("jails", SQL_JAILS, False),
                ("top", SQL_TOP_SOURCES, False),
                ("sensors", SQL_SENSORS, True),
            ):
                cur = await conn.execute(sql, params)
                out[key] = await cur.fetchone() if one else await cur.fetchall()

            out["server"] = None
            cur = await conn.execute(SQL_SERVER_LATEST)
            latest = await cur.fetchone()
            if latest:
                # 24 h: un punto por ejecución del agente; 7 y 30 días: medias por hora.
                params["sid"] = latest["sensor_id"]
                series_sql = SQL_SERVER_SERIES_RAW if unit == "hour" else SQL_SERVER_SERIES_HOURLY
                cur = await conn.execute(series_sql, params)
                series = await cur.fetchall()
                cur = await conn.execute(SQL_SERVER_SUMMARY, params)
                out["server"] = {"latest": latest, "series": series,
                                 "series_unit": "raw" if unit == "hour" else "hour",
                                 "summary": await cur.fetchone()}
        return out

    async def purge(self, retention_days: int) -> int:
        async with self._pool.connection() as conn:
            await conn.execute(SQL_PURGE_METRICS, {"days": retention_days})
            cur = await conn.execute(SQL_PURGE, {"days": retention_days})
            return cur.rowcount
