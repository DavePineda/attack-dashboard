"""Configuración leída del entorno (Botkeep → pestaña Environment, o un archivo .env)."""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Carga un .env sencillo (CLAVE=valor). No pisa variables ya definidas."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            os.environ.setdefault(key, value)


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "si", "sí", "on"}


def _int(name: str, default: int, lo: int, hi: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    number = int(value)
    if not lo <= number <= hi:
        raise ValueError(f"{name} debe estar entre {lo} y {hi}")
    return number


def _pg_size(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip() or default
    if not re.fullmatch(r"\d{1,6}(kB|MB|GB)", value):
        raise ValueError(f"{name} debe ser un tamaño como 32MB (unidades: kB, MB, GB)")
    return value


def _networks(name: str) -> tuple:
    nets = []
    for part in os.environ.get(name, "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise ValueError(f"{name}: '{part}' no es una IP ni una red válida") from None
    return tuple(nets)


def _https_url(value: str) -> str:
    value = value.strip()
    return value if re.fullmatch(r"https://[^\s\"'<>]{1,300}", value) else ""


@dataclass(frozen=True)
class Settings:
    database_url: str
    # PG_WORK_MEM: memoria por ordenamiento en las conexiones de la API (las estadísticas
    # de 30 días agrupan y ordenan mucho; con el valor por defecto de 4MB irían a disco).
    pg_work_mem: str
    port: int
    mask_ips: bool
    retention_days: int
    geoip_db: str
    # TRUST_PROXY: usar la última IP de X-Forwarded-For (la que añadió el proxy de Botkeep).
    trust_proxy: bool
    # CLIENT_IP_HEADER: p. ej. "cf-connecting-ip", solo si el dominio pasa por Cloudflare.
    client_ip_header: str
    # TRUSTED_PROXIES: IPs o redes del proxy de Botkeep. Si se define, se rechaza (403) toda
    # conexión que no venga de ellas, p. ej. el puerto directo del nodo, donde nadie añade la
    # IP real y X-Forwarded-For lo escribiría el propio cliente.
    trusted_proxies: tuple
    display_tz: ZoneInfo
    site_title: str
    source_url: str
    geoip_attribution: str
    max_batch: int
    stats_cache_seconds: int

    @classmethod
    def from_env(cls) -> "Settings":
        port = os.environ.get("SERVER_PORT") or os.environ.get("PORT") or "8000"
        return cls(
            database_url=os.environ.get("DATABASE_URL", "").strip(),
            pg_work_mem=_pg_size("PG_WORK_MEM", "32MB"),
            port=int(port),
            mask_ips=_bool("PUBLIC_MASK_IPS", True),
            retention_days=_int("RETENTION_DAYS", 30, 1, 3650),
            geoip_db=os.environ.get("GEOIP_DB", "").strip(),
            trust_proxy=_bool("TRUST_PROXY", True),
            client_ip_header=os.environ.get("CLIENT_IP_HEADER", "").strip().lower(),
            trusted_proxies=_networks("TRUSTED_PROXIES"),
            display_tz=ZoneInfo(os.environ.get("DISPLAY_TZ", "America/Bogota")),
            site_title=os.environ.get("SITE_TITLE", "Ataques a 0r1sk.xyz").strip()[:80],
            source_url=_https_url(os.environ.get("SOURCE_URL", "")),
            geoip_attribution=os.environ.get(
                "GEOIP_ATTRIBUTION", "Geolocalización por país: DB-IP.com (CC BY 4.0)").strip()[:200],
            max_batch=_int("INGEST_MAX_EVENTS", 2000, 1, 10000),
            stats_cache_seconds=_int("STATS_CACHE_SECONDS", 60, 0, 3600),
        )
