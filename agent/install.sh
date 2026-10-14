#!/usr/bin/env bash
# Instala attack-shipper en un VPS Debian/Ubuntu. Ejecutar como root desde la carpeta agent/.
# Es idempotente: se puede volver a correr para actualizar el script sin tocar la configuración.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta como root: sudo ./install.sh" >&2
  exit 1
fi
command -v python3 >/dev/null || { echo "Falta python3" >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || { echo "Se requiere Python 3.9+" >&2; exit 1; }

cd "$(dirname "$0")"

id attack-shipper &>/dev/null || \
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin attack-shipper

install -d -m 0755 -o root -g root /opt/attack-shipper
install -m 0644 -o root -g root shipper.py /opt/attack-shipper/shipper.py

install -d -m 0750 -o root -g attack-shipper /etc/attack-shipper
if [[ ! -f /etc/attack-shipper/shipper.env ]]; then
  install -m 0640 -o root -g attack-shipper shipper.env.example /etc/attack-shipper/shipper.env
  echo ">> Edita /etc/attack-shipper/shipper.env (SHIPPER_ENDPOINT y SHIPPER_TOKEN)."
fi

install -m 0644 attack-shipper.service /etc/systemd/system/attack-shipper.service
install -m 0644 attack-shipper.timer   /etc/systemd/system/attack-shipper.timer
systemctl daemon-reload

# Comprobar que el grupo adm realmente puede leer los logs configurados.
set -a; . /etc/attack-shipper/shipper.env; set +a
for f in "${SHIPPER_FAIL2BAN_LOG:-}" "${SHIPPER_UFW_LOG:-}"; do
  [[ -z "$f" ]] && continue
  if [[ ! -e "$f" ]]; then
    echo "!! $f no existe (¿UFW tiene logging activado? ufw logging low)"
  elif ! runuser -u attack-shipper -g attack-shipper -G adm -- test -r "$f"; then
    echo "!! attack-shipper no puede leer $f; revisa grupo/permisos (ls -l $f)"
  fi
done

if [[ -n "${SHIPPER_TOKEN:-}" ]]; then
  systemctl enable --now attack-shipper.timer
  echo ">> Timer activo. Prueba manual: systemctl start attack-shipper && journalctl -u attack-shipper -n 20"
else
  echo ">> Cuando completes el token: systemctl enable --now attack-shipper.timer"
fi
