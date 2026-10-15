# Dashboard de ataques · 0r1sk.xyz

Telemetría en vivo de lo que **Fail2ban** y **UFW** bloquean en mis servidores: baneos por
servicio, puertos escaneados, países de origen y las redes más insistentes.

Un agente sin dependencias en cada VPS lee los logs y los envía por HTTPS a una API en Python
con PostgreSQL, alojada en Botkeep. El dashboard es una página estática sin librerías de
terceros, servida con una CSP estricta.

![Dashboard con datos de ejemplo](docs/captura.png)

```mermaid
flowchart LR
  subgraph VPS1[VPS correo]
    F1[fail2ban.log] --> A1[attack-shipper]
    U1[ufw.log] --> A1
  end
  subgraph VPS2[VPS VPN]
    F2[fail2ban.log] --> A2[attack-shipper]
    U2[ufw.log] --> A2
  end
  A1 -- HTTPS + token --> API
  A2 -- HTTPS + token --> API
  subgraph Botkeep
    API[API Starlette] --> DB[(PostgreSQL)]
    API --> WEB[Dashboard estático]
  end
  CF[Cloudflare] --> WEB
```

## Decisiones de seguridad

| Riesgo | Mitigación |
|---|---|
| Token del agente robado de la base | Solo se guarda su **SHA-256**; el token en claro vive únicamente en el VPS (`0640 root:attack-shipper`). Un token por servidor, revocable con un `UPDATE`. |
| Fuerza bruta contra la ingesta | Tokens de 256 bits, limitador por IP y bloqueo progresivo tras 10 intentos fallidos. |
| IP falsificada por el puerto directo del nodo | Con `TRUSTED_PROXIES` solo se aceptan conexiones del proxy de Botkeep (la IP de la conexión TCP no se puede falsificar); el resto recibe 403. |
| Datos maliciosos en el lote | Validación estricta (tipos, rangos, regex), solo IPs públicas, máximo 2000 eventos y 1 MiB por lote; además `CHECK` en la base. Consultas siempre parametrizadas. |
| Reenvíos y conteos duplicados | Índice único de deduplicación + `ON CONFLICT DO NOTHING`. El agente solo envía ventanas de UFW **cerradas**, así un reintento nunca produce conteos parciales. |
| XSS / clickjacking en el dashboard | CSP `default-src 'none'` con solo `'self'`, sin `innerHTML` con datos, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, sin CDNs. |
| Exponer a terceros | Las IPs se publican agrupadas en **/24 (IPv4) y /48 (IPv6)**. La geolocalización es una base local: las IPs nunca salen del servidor. |
| Agente comprometido en el VPS | Usuario de sistema sin shell, `ProtectSystem=strict`, sin capabilities, filtro de syscalls, `/var/log` de solo lectura, límites de memoria y CPU. |
| Crecimiento de la base (1,5 GB de disco para PostgreSQL) | UFW se agrega por ventanas de 10 min y una tarea borra lo que supera `RETENTION_DAYS` (30 días por defecto, el rango máximo del dashboard). |
| Servidor sobrecargado | Caché de estadísticas de 60 s, una sola consulta pesada a la vez y límite de solicitudes públicas. |

## Estructura

```
app/
  web.py          API (ingesta + estadísticas), cabeceras de seguridad, limitador
  ingest.py       validación de lotes (funciones puras)
  store.py        PostgreSQL con psycopg 3; todo el SQL está aquí
  schema.sql      tablas, restricciones e índices (se aplica al arrancar)
  geo.py          país por IP con una base .mmdb local (opcional)
  static/         dashboard: HTML + CSS + JS sin dependencias, gráficos SVG propios
agent/
  shipper.py      agente para los VPS (solo biblioteca estándar)
  attack-shipper.service / .timer, install.sh, shipper.env.example
tools/new_sensor.py   genera el token de un VPS y el SQL para registrarlo
tests/            pruebas del agente y de la API
```

## Despliegue en Botkeep

Todo el plan (2 GB RAM · 1,5 vCPU · 2 GB disco) se reparte entre los dos servicios del
dashboard, sin dejar nada libre:

| Servicio | RAM | CPU | Disco |
|---|---|---|---|
| PostgreSQL | 1536 MB | 1,0 | 1536 MB |
| API del dashboard | 512 MB | 0,5 | 512 MB |
| **Total** | **2048 MB** | **1,5** | **2048 MB** |

La API es un solo proceso Python que en la práctica usa 100–200 MB de RAM y no puede ocupar más
de un núcleo; las consultas pesadas, la caché de datos y el almacenamiento están en PostgreSQL,
así que ahí rinde cada recurso extra.

Antes de empezar:

- Botkeep revisa el fondo compartido al crear o cambiar recursos y no garantiza que una
  asignación se pueda **aumentar** después. Crea **primero PostgreSQL** con su asignación exacta
  y **luego la API** con el resto.
- Los servicios detenidos también cuentan: si ya tienes otro servicio creado, elimínalo antes
  para liberar sus recursos.

### 1. Base de datos

**Create → Databases → PostgreSQL** con **1536 MB de RAM, 1,0 vCPU y 1536 MB de disco**. En la
pestaña **Database** copia los datos de conexión y arma la URL. Botkeep exige TLS con
verificación del certificado: el CA del panel (**CA certificate**) está en
`certs/botkeep-ca.pem` y la API lo usa con `sslmode=verify-full`, que comprueba el certificado y
la IP del servidor:

```
postgresql://USUARIO:CLAVE@HOST:PUERTO/BASE?sslmode=verify-full&sslrootcert=/home/container/certs/botkeep-ca.pem
```

Si la clave tiene caracteres especiales (`@ : / ? # % & +` o espacios), codifícalos en la URL
(por ejemplo `@` → `%40`). Nunca uses `sslmode=require` ni `disable` para "arreglar" un error
de conexión: se perdería la protección contra suplantación del servidor.

### 2. API

1. **Create → Applications → Python** con **512 MB de RAM, 0,5 vCPU y 512 MB de disco**,
   desde el repositorio [DavePineda/attack-dashboard](https://github.com/DavePineda/attack-dashboard)
   (o un ZIP).
2. Comando de inicio: `python main.py`. Las dependencias están en `requirements.txt`.
3. En **Environment** define (ver `.env.example`):
   - `DATABASE_URL` (secreto)
   - `SOURCE_URL=https://github.com/DavePineda/attack-dashboard`
   - opcionales: `RETENTION_DAYS` (30 por defecto), `PG_WORK_MEM` (32MB por defecto),
     `PUBLIC_MASK_IPS`, `SITE_TITLE`, `GEOIP_DB`
4. **Domains:** pulsa **Enable HTTPS** (activa el acceso web) y en **Custom domain** adjunta
   `dash.0r1sk.xyz`. En Cloudflare crea los dos registros que muestra Botkeep (`A dash` y
   `TXT _botkeep-challenge.dash`) en **Solo DNS** (nube gris, como exige Botkeep) y pulsa
   **Verify DNS**: Botkeep emite y renueva el certificado de Let's Encrypt.
   La app escucha en `0.0.0.0:$SERVER_PORT`, como pide Botkeep.
5. Arranca y revisa **Console**: debe decir `Esquema aplicado` y `Dashboard listo` (solo
   aparecen si la API se conectó a PostgreSQL). Luego abre `https://dash.0r1sk.xyz`: el
   dashboard debe cargar, aunque todavía no tenga eventos.
6. **Cerrar el puerto directo.** El puerto directo del nodo de Botkeep sigue abierto aunque se
   use el dominio, y ahí `X-Forwarded-For` lo escribe el propio cliente.
   Envía una ingesta con un token falso a `https://dash.0r1sk.xyz/api/v1/ingest`; en
   **Console** aparece `Ingesta rechazada: ... (conexión de X.X.X.X)`. Esa `X.X.X.X` es el
   proxy de Botkeep: defínela en `TRUSTED_PROXIES` y reinicia. Desde entonces el puerto
   directo responde 403 y el dominio sigue funcionando.

`CLIENT_IP_HEADER=cf-connecting-ip` solo sirve si el dominio pasa por el proxy de Cloudflare
(Botkeep pide nube gris, así que no se usa). Defínela **solo** en ese caso: si no, cualquiera
podría falsificar esa cabecera.

### 3. Geolocalización (opcional)

Descarga **DB-IP IP to Country Lite** en formato MMDB (licencia CC BY 4.0, gratuita, sin
registro), súbela a la app como `data/country.mmdb` y define `GEOIP_DB=data/country.mmdb`.
El pie del dashboard muestra la atribución que exige la licencia. MaxMind GeoLite2-Country
también funciona; en ese caso ajusta `GEOIP_ATTRIBUTION`.

### 4. Registrar cada VPS

En tu equipo:

```bash
python3 tools/new_sensor.py vps-correo
```

Ejecuta el `INSERT` que imprime en la pestaña **Data** de PostgreSQL y guarda el token.

### 5. Instalar el agente en el VPS

```bash
scp -r agent/ usuario@vps:/tmp/attack-shipper
ssh usuario@vps
sudo /tmp/attack-shipper/install.sh
sudo nano /etc/attack-shipper/shipper.env    # SHIPPER_ENDPOINT, SHIPPER_TOKEN, SHIPPER_IGNORE_NETS
sudo systemctl enable --now attack-shipper.timer
sudo systemctl start attack-shipper && journalctl -u attack-shipper -n 20
```

Requisitos: Python 3.9+, `ufw logging low` (o superior) y logs legibles por el grupo `adm`
(lo normal en Debian/Ubuntu; el instalador lo comprueba). En `SHIPPER_IGNORE_NETS` pon tus
propias IPs y la red de la VPN. La primera ejecución empieza desde el final de los logs; usa
`SHIPPER_BACKFILL=1` una sola vez si quieres enviar el historial existente.

## API

| Método | Ruta | Descripción |
|---|---|---|
| `POST` | `/api/v1/ingest` | `Authorization: Bearer <token>`, cuerpo `{"events": [...]}`. Responde `accepted`, `inserted`, `duplicates`, `rejected`. |
| `GET` | `/api/v1/stats?range=24h\|7d\|30d` | Resumen, serie temporal, países, puertos, jails y orígenes. |

Evento:

```json
{"ts": "2026-10-14T15:23:45Z", "source": "fail2ban", "jail": "sshd", "ip": "203.0.113.7"}
{"ts": "2026-10-14T15:20:00Z", "source": "ufw", "ip": "203.0.113.7", "proto": "TCP", "dport": 23, "hits": 14}
```

## Pruebas

```bash
python3 -m unittest discover tests -v
```

`test_shipper.py` usa solo la biblioteca estándar (parsers, agregación, ventanas cerradas,
reintentos, rotación de logs). `test_web.py` levanta la API con un almacén falso y prueba
autenticación, validación, deduplicación, límites, cabeceras y bloqueo por intentos fallidos.

## Ideas para seguir

- Reportar automáticamente las IPs más agresivas a AbuseIPDB.
- Correlacionar con el catálogo KEV de CISA para alertar sobre CVEs de los servicios atacados.
- Exportar los eventos en formato STIX/CSV para practicar análisis en un SIEM.
