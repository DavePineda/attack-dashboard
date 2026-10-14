#!/usr/bin/env bash
# Comprobaciones locales en el VPS que avisan a Uptime Kuma por monitores tipo "Push".
#
# Sirve para servicios que NO se exponen a Internet (Unbound, Pi-hole, WireGuard):
# Uptime Kuma en Botkeep no puede alcanzarlos, así que es el VPS quien informa que están bien.
# Si un servicio falla, simplemente no se envía el push y Kuma lo marca como caído.
#
# Configuración: /etc/kuma-healthchecks.env (0600 root:root), con las URLs de push de Kuma:
#   KUMA_PUSH_UNBOUND=https://estado.0r1sk.xyz/api/push/XXXXXXXX
#   KUMA_PUSH_PIHOLE=https://estado.0r1sk.xyz/api/push/YYYYYYYY
#   KUMA_PUSH_WIREGUARD=https://estado.0r1sk.xyz/api/push/ZZZZZZZZ
#   UNBOUND_ADDR=127.0.0.1   UNBOUND_PORT=5335
#   PIHOLE_ADDR=127.0.0.1    PIHOLE_PORT=53
#   WG_IFACE=wg0
# Deja vacía la URL de lo que no tengas en ese VPS.
set -uo pipefail

ENV_FILE=/etc/kuma-healthchecks.env
[[ -r $ENV_FILE ]] && . "$ENV_FILE"

push() {  # push <url> <mensaje> <ping_ms>
  local url=$1 msg=$2 ping=${3:-}
  [[ -z $url ]] && return 0
  curl -fsS --max-time 10 -G "$url" \
    --data-urlencode "status=up" --data-urlencode "msg=$msg" --data-urlencode "ping=$ping" \
    -o /dev/null || echo "No se pudo contactar a Uptime Kuma ($msg)" >&2
}

dns_ms() {  # dns_ms <servidor> <puerto> -> imprime el tiempo de consulta si responde
  local out
  out=$(dig @"$1" -p "$2" cloudflare.com A +tries=1 +time=3 2>/dev/null) || return 1
  grep -q "status: NOERROR" <<<"$out" || return 1
  grep -oP 'Query time: \K[0-9]+' <<<"$out"
}

# Unbound (resolución recursiva real, con DNSSEC)
if [[ -n ${KUMA_PUSH_UNBOUND:-} ]] && ms=$(dns_ms "${UNBOUND_ADDR:-127.0.0.1}" "${UNBOUND_PORT:-5335}"); then
  push "$KUMA_PUSH_UNBOUND" "Unbound resuelve" "$ms"
fi

# Pi-hole (el DNS que usan los clientes de la VPN)
if [[ -n ${KUMA_PUSH_PIHOLE:-} ]] && ms=$(dns_ms "${PIHOLE_ADDR:-127.0.0.1}" "${PIHOLE_PORT:-53}"); then
  push "$KUMA_PUSH_PIHOLE" "Pi-hole responde" "$ms"
fi

# WireGuard: interfaz arriba y escuchando
if [[ -n ${KUMA_PUSH_WIREGUARD:-} ]]; then
  iface=${WG_IFACE:-wg0}
  if [[ -d /sys/class/net/$iface ]] && port=$(wg show "$iface" listen-port 2>/dev/null) && [[ -n $port ]]; then
    peers=$(wg show "$iface" latest-handshakes 2>/dev/null \
      | awk -v now="$(date +%s)" '$2 > 0 && now - $2 < 180 {n++} END {print n+0}')
    push "$KUMA_PUSH_WIREGUARD" "$iface en UDP $port, $peers peers activos" ""
  fi
fi
