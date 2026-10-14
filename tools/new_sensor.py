#!/usr/bin/env python3
"""Genera el token de un sensor (un VPS) y el SQL para registrarlo.

Uso, en tu propio equipo:
    python3 tools/new_sensor.py vps-correo

El token se muestra UNA vez: va al archivo de configuración del agente en el VPS.
En la base solo se guarda su SHA-256 (pégalo en la pestaña Data de PostgreSQL en Botkeep).
"""
import hashlib
import re
import secrets
import sys


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", sys.argv[1]):
        print("Uso: new_sensor.py <nombre>  (minúsculas, números, - y _)", file=sys.stderr)
        return 2
    name = sys.argv[1]
    token = secrets.token_urlsafe(32)  # 256 bits
    digest = hashlib.sha256(token.encode()).hexdigest()
    print(f"\nToken para el agente (guárdalo en /etc/attack-shipper/shipper.env):\n\n"
          f"  SHIPPER_TOKEN={token}\n")
    print("SQL para ejecutar en la base del dashboard:\n")
    print(f"  INSERT INTO sensors (name, token_sha256)\n"
          f"  VALUES ('{name}', decode('{digest}', 'hex'));\n")
    print("Para revocarlo:  UPDATE sensors SET enabled = false WHERE name = "
          f"'{name}';\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
