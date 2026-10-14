"""Geolocalización por país con una base .mmdb local (DB-IP Lite o MaxMind GeoLite2).

Opcional: si GEOIP_DB no está definido o el archivo no existe, el país queda vacío.
No se consulta ningún servicio externo: las IPs atacantes nunca salen del servidor.
"""
from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("geo")


class CountryLookup:
    def __init__(self, path: str) -> None:
        self._reader = None
        if not path:
            log.info("GEOIP_DB no definido: sin geolocalización")
            return
        if not Path(path).is_file():
            log.warning("GEOIP_DB=%s no existe: sin geolocalización", path)
            return
        try:
            import maxminddb
            self._reader = maxminddb.open_database(path)
            log.info("Base GeoIP cargada: %s", path)
        except Exception as exc:
            log.warning("No se pudo abrir la base GeoIP: %s", exc)

    @property
    def enabled(self) -> bool:
        return self._reader is not None

    def country(self, ip: str) -> str | None:
        if self._reader is None:
            return None
        try:
            record = self._reader.get(ip)
        except ValueError:
            return None
        if not isinstance(record, dict):
            return None
        for key in ("country", "registered_country"):
            code = (record.get(key) or {}).get("iso_code")
            if isinstance(code, str) and len(code) == 2:
                return code.upper()
        return None

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
