# Uptime Kuma para 0r1sk.xyz

Uptime Kuma responde a **"¿mis servicios están arriba?"**; el dashboard de ataques responde a
**"¿quién intenta tumbarlos?"**. Juntos forman el mini-SOC del laboratorio.

## 1. Crear el servicio en Botkeep

1. **Create → Websites & services → Uptime Kuma.** Asignación sugerida: 384 MB de RAM,
   0,3 vCPU y 400 MB de disco (Kuma guarda el historial en su base local; con ~15 monitores
   cada 60 s eso alcanza de sobra).
2. **Domains:** conecta `estado.0r1sk.xyz`. En Cloudflare crea el registro que indique el panel
   (normalmente un CNAME) con el proxy activado.
3. Abre la URL y crea la cuenta de administrador **de inmediato**: hasta que lo hagas, cualquiera
   que llegue primero puede reclamar la instancia.
4. **Settings → Security:** activa 2FA (TOTP) y usa una contraseña larga y única.
5. **Settings → Backup:** exporta la configuración después de crear los monitores y guárdala
   fuera de Botkeep.

## 2. Monitores

Intervalo general: 60 s, con 3 reintentos antes de marcar caído (evita falsos positivos por
un paquete perdido). Usa nombres neutros: la página de estado es pública.

### Desde Internet (Kuma consulta directamente)

| Nombre | Tipo | Destino | Notas |
|---|---|---|---|
| Sitio web | HTTP(s) – Keyword | `https://0r1sk.xyz` | Palabra clave: algo fijo de tu página. Activa **Certificate Expiry Notification**. |
| Dashboard de ataques | HTTP(s) – JSON Query | `https://ataques.0r1sk.xyz/health` | Consulta `database` igual a `true`. |
| Correo – IMAPS | TCP Port | `mail.0r1sk.xyz:993` | |
| Correo – Submission | TCP Port | `mail.0r1sk.xyz:587` | |
| Correo – SMTPS | TCP Port | `mail.0r1sk.xyz:465` | |
| Correo – SMTP (MX) | TCP Port | `mail.0r1sk.xyz:25` | Muchos proveedores bloquean el puerto 25 **saliente**; si siempre falla desde Botkeep, elimínalo y confía en 465/587/993. |
| Webmail / panel | HTTP(s) | la URL que uses | Solo si existe. Certificado incluido. |
| DNS – registro MX | DNS | `0r1sk.xyz`, tipo MX, resolver `1.1.1.1` | Detecta si alguien rompe la zona en Cloudflare. |
| DNS – mail A | DNS | `mail.0r1sk.xyz`, tipo A, resolver `1.1.1.1` | Comprueba que apunta a la IP de InterServer. |

> **Ping (ICMP)** probablemente no funcione: los procesos en Botkeep corren sin root. Usa TCP Port.

### Desde dentro de los VPS (monitores tipo Push)

Unbound, Pi-hole y WireGuard **no deben** estar expuestos a Internet, así que Kuma no puede
consultarlos. Se invierte el flujo: el VPS hace la prueba localmente y, si todo está bien,
avisa a Kuma. Si el aviso deja de llegar, Kuma marca el servicio como caído.

| Nombre | Tipo | Intervalo | Quién avisa |
|---|---|---|---|
| DNS recursivo (Unbound) | Push | 120 s | `vps/kuma-healthchecks.sh` |
| Bloqueo de anuncios (Pi-hole) | Push | 120 s | `vps/kuma-healthchecks.sh` |
| VPN (WireGuard) | Push | 120 s | `vps/kuma-healthchecks.sh` |
| Agente de ataques – VPS correo | Push | 600 s | `attack-shipper` (variable `SHIPPER_KUMA_PUSH_URL`) |
| Agente de ataques – VPS VPN | Push | 600 s | `attack-shipper` |

Al crear cada monitor Push, Kuma muestra su URL (`https://estado.0r1sk.xyz/api/push/<token>`).
Ese token es un secreto: quien lo tenga puede marcar el servicio como "arriba".

Instalación en el VPS (como root):

```bash
install -m 0750 vps/kuma-healthchecks.sh /usr/local/sbin/kuma-healthchecks.sh
install -m 0644 vps/kuma-healthchecks.service vps/kuma-healthchecks.timer /etc/systemd/system/
install -m 0600 /dev/null /etc/kuma-healthchecks.env   # y pega aquí las URLs de push
systemctl daemon-reload && systemctl enable --now kuma-healthchecks.timer
systemctl start kuma-healthchecks && journalctl -u kuma-healthchecks -n 20
```

Requiere `dig` (`apt install dnsutils`) y `wg` (`wireguard-tools`). Ajusta `UNBOUND_PORT`
(5335 es el puerto habitual cuando Unbound va detrás de Pi-hole).

## 3. Notificaciones

**Settings → Notifications → Telegram** (o correo, Discord…). Aplícala por defecto a todos los
monitores. Activa también la notificación de certificado próximo a vencer (14 y 7 días).

## 4. Página de estado pública

**Status Pages → New:** slug `estado`, título "Estado de 0r1sk.xyz". Grupos sugeridos:

- **Web**: Sitio web, Dashboard de ataques
- **Correo**: IMAPS, Submission, SMTPS, MX
- **Red privada**: DNS recursivo, Bloqueo de anuncios, VPN
- **Telemetría**: Agentes de ataques

Desactiva mostrar la URL/host de cada monitor y no incluyas IPs. Enlaza la página desde tu
portafolio y desde el pie del dashboard de ataques.

## 5. Qué contar en el portafolio

- Monitoreo **externo** (caja negra) e **interno** (push) sin abrir puertos nuevos.
- Alertas de expiración de certificados y de cambios en DNS.
- El agente de ataques reporta su propio latido: si deja de enviar datos, te enteras.
- 2FA y copia de seguridad de la configuración fuera de la plataforma.
