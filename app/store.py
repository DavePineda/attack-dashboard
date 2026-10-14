"""Acceso a PostgreSQL con psycopg 3 (pool asíncrono). Todo el SQL vive aquí."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from .ingest import Event

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


class Store(Protocol):
    async def open(self) -> None: ...
    async def close(self) -> None: ...
    async def sensor_for_token(self, sha256: bytes) -> tuple[int, str] | None: ...
    async def insert_events(self, sensor_id: int, events: list[Event],
                            countries: list[str | None]) -> int: ...
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

        self._pool = AsyncConnectionPool(
            self._dsn, min_size=1, max_size=4, open=False, timeout=10,
            kwargs={"autocommit": True, "row_factory": dict_row},
            configure=self._configure,
        )
        for attempt in range(1, 11):
            try:
                await self._pool.open(wait=True, timeout=10)
                break
            except Exception as exc:  # la base puede tardar en arrancar
                log.warning("PostgreSQL no disponible (intento %d/10): %s", attempt, exc)
                if attempt == 10:
                    raise
                await asyncio.sleep(3)
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
                            countries: list[str | None]) -> int:
        async with self._pool.connection() as conn:
            async with conn.transaction():
                inserted = 0
                if events:
                    cur = await conn.execute(SQL_INSERT_EVENTS, {
                        "sensor_id": sensor_id, "rows": events_to_json(events, countries)})
                    inserted = cur.rowcount
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
        return out

    async def purge(self, retention_days: int) -> int:
        async with self._pool.connection() as conn:
            cur = await conn.execute(SQL_PURGE, {"days": retention_days})
            return cur.rowcount
