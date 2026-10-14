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


def mask_network(ip: str) -> str:
    """IPv4 → /24, IPv6 → /48. Para mostrar públicamente sin exponer hosts concretos."""
    addr = ipaddress.ip_address(ip)
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
