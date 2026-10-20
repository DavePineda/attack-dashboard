#!/usr/bin/env python3
"""attack-shipper: lee Fail2ban y UFW en el VPS y envía los eventos al dashboard.

- Solo biblioteca estándar de Python 3.9+: nada que instalar en el servidor.
- Se ejecuta como oneshot desde un timer de systemd, con un usuario sin privilegios.
- Guarda el desplazamiento (offset) de cada log y solo lo avanza cuando el envío fue
  exitoso. Si algo falla, la siguiente ejecución reenvía y la API descarta duplicados.
- UFW se agrega por (ventana, IP, protocolo, puerto) para no inundar la base: solo se
  envían ventanas ya cerradas, así un reenvío nunca produce conteos parciales.
- Soporta rotación de logs (lee el resto de <log>.1 antes de empezar el archivo nuevo).
- Envía también el estado del servidor (CPU, carga, RAM, swap y disco /) y sus datos
  básicos (hostname, sistema, kernel, IPs) para la tarjeta del servidor del dashboard.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import re
import socket
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.1.0"
MAX_READ_BYTES = 64 * 1024 * 1024  # por archivo y ejecución

log = logging.getLogger("attack-shipper")

# 2026-10-14 10:23:45,123 fail2ban.actions [811]: NOTICE  [sshd] Ban 203.0.113.7
# ("Restore Ban" se ignora: es un baneo previo restaurado al reiniciar fail2ban.)
F2B_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)?\s+fail2ban\.actions\s*"
    r"\[\d+\]:\s+NOTICE\s+\[(?P<jail>[A-Za-z0-9_.-]{1,64})\]\s+Ban\s+(?P<ip>\S+)\s*$")
# Syslog clásico ("Oct 14 10:23:45 host ...") o RFC 3339 ("2026-10-14T10:23:45.12-05:00 host ...")
SYSLOG_TS_RE = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
    r"|(?P<bsd>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}))\s")
# Tras la fecha: "<host> kernel: ". Cualquier usuario puede escribir "[UFW BLOCK]" en syslog
# con `logger`; esas líneas llevan otra etiqueta y se descartan.
KERNEL_TAG_RE = re.compile(r"\S+\s+kernel:\s")
KV_RE = re.compile(r"\b([A-Z]+)=(\S*)")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


# ---------------------------------------------------------------- configuración
@dataclass
class Config:
    endpoint: str
    token: str
    fail2ban_log: str = "/var/log/fail2ban.log"
    ufw_log: str = "/var/log/ufw.log"
    bucket_seconds: int = 600
    state_dir: Path = Path("/var/lib/attack-shipper")
    max_batch: int = 1000
    timeout: int = 20
    ignore_nets: list = field(default_factory=list)
    metrics: bool = True
    host_label: str = ""
    host_service: str = ""
    proc_dir: Path = Path("/proc")
    disk_path: str = "/"
    os_release: Path = Path("/etc/os-release")

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ
        endpoint = env.get("SHIPPER_ENDPOINT", "").strip()
        token = env.get("SHIPPER_TOKEN", "").strip()
        if not endpoint.startswith("https://") and not env.get("SHIPPER_ALLOW_HTTP"):
            raise SystemExit("SHIPPER_ENDPOINT debe usar https://")
        if len(token) < 32:
            raise SystemExit("SHIPPER_TOKEN falta o es demasiado corto")
        state = env.get("STATE_DIRECTORY") or env.get("SHIPPER_STATE_DIR") or "/var/lib/attack-shipper"
        nets = [ipaddress.ip_network(n.strip(), strict=False)
                for n in env.get("SHIPPER_IGNORE_NETS", "").split(",") if n.strip()]
        bucket = int(env.get("SHIPPER_BUCKET_SECONDS", "600"))
        if bucket < 60 or 86400 % bucket:
            raise SystemExit("SHIPPER_BUCKET_SECONDS debe ser >= 60 y dividir 86400")
        return cls(
            endpoint=endpoint, token=token,
            fail2ban_log=env.get("SHIPPER_FAIL2BAN_LOG", cls.fail2ban_log).strip(),
            ufw_log=env.get("SHIPPER_UFW_LOG", cls.ufw_log).strip(),
            bucket_seconds=bucket,
            state_dir=Path(state.split(":")[0]),
            max_batch=min(int(env.get("SHIPPER_MAX_BATCH", "1000")), 2000),
            timeout=int(env.get("SHIPPER_TIMEOUT", "20")),
            ignore_nets=nets,
            metrics=env.get("SHIPPER_METRICS", "1") != "0",
            host_label=env.get("SHIPPER_HOST_LABEL", "").strip()[:60],
            host_service=env.get("SHIPPER_HOST_SERVICE", "").strip()[:60],
        )


# ---------------------------------------------------------------- parsers
def public_ip(raw: str, ignore: list) -> str | None:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if not ip.is_global or any(ip in net for net in ignore):
        return None
    return ip.compressed


def parse_fail2ban(line: str, ignore: list) -> dict | None:
    m = F2B_RE.match(line)
    if not m:
        return None
    ip = public_ip(m["ip"], ignore)
    if not ip:
        return None
    # fail2ban escribe en hora local sin zona: astimezone() le asigna la del sistema.
    ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S").astimezone(timezone.utc)
    return {"ts": ts, "source": "fail2ban", "jail": m["jail"], "ip": ip, "hits": 1}


def parse_syslog_ts(line: str, now: datetime) -> datetime | None:
    m = SYSLOG_TS_RE.match(line)
    if not m:
        return None
    if m["iso"]:
        return datetime.fromisoformat(m["iso"].replace("Z", "+00:00")).astimezone(timezone.utc)
    mon, day, hms = m["bsd"].split()
    local_now = now.astimezone()
    try:
        ts = datetime.strptime(f"{local_now.year} {MONTHS[mon]} {day} {hms}", "%Y %m %d %H:%M:%S")
    except (KeyError, ValueError):
        return None
    ts = ts.astimezone()  # hora local del sistema
    if ts - now > timedelta(days=1):  # línea de diciembre leída en enero
        ts = ts.replace(year=ts.year - 1)
    return ts.astimezone(timezone.utc)


def parse_ufw(line: str, now: datetime, ignore: list) -> dict | None:
    if "[UFW BLOCK]" not in line:
        return None
    m = SYSLOG_TS_RE.match(line)
    if not m or not KERNEL_TAG_RE.match(line, m.end()):
        return None
    ts = parse_syslog_ts(line, now)
    if ts is None:
        return None
    kv = dict(KV_RE.findall(line))
    if not kv.get("IN"):  # solo tráfico entrante
        return None
    ip = public_ip(kv.get("SRC", ""), ignore)
    if not ip:
        return None
    proto = kv.get("PROTO", "").upper() or None
    if proto and not re.fullmatch(r"[A-Z0-9]{1,10}", proto):
        proto = None
    dport = int(kv["DPT"]) if kv.get("DPT", "").isdigit() and int(kv["DPT"]) <= 65535 else None
    return {"ts": ts, "source": "ufw", "ip": ip, "proto": proto, "dport": dport}


def bucket_start(ts: datetime, seconds: int) -> datetime:
    epoch = int(ts.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, timezone.utc)


# ---------------------------------------------------------------- lectura incremental
@dataclass
class Cursor:
    inode: int = 0
    offset: int = 0


def read_lines(path: Path, start: int, stop_before=None) -> tuple[list[str], int, str]:
    """Lee líneas completas desde `start`. Devuelve (líneas, offset_final, motivo).

    motivo: "eof" (fin o línea incompleta), "stop" (stop_before fue True: la línea queda
    para la próxima ejecución) o "cap" (se alcanzó MAX_READ_BYTES en esta ejecución).
    """
    lines: list[str] = []
    with path.open("rb") as fh:
        fh.seek(start)
        pos = start
        while True:
            if pos - start >= MAX_READ_BYTES:
                return lines, pos, "cap"
            raw = fh.readline()
            if not raw or not raw.endswith(b"\n"):
                return lines, pos, "eof"
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if stop_before is not None and stop_before(line):
                return lines, pos, "stop"
            pos += len(raw)
            lines.append(line)


class LogSource:
    """Un archivo de log con rotación. Devuelve líneas nuevas y el cursor propuesto."""

    def __init__(self, name: str, path: str, cursor: Cursor) -> None:
        self.name, self.path, self.cursor = name, Path(path), cursor

    def lines(self, stop_before=None):
        new = Cursor(self.cursor.inode, self.cursor.offset)
        try:
            st = self.path.stat()
        except FileNotFoundError:
            log.warning("%s: %s no existe", self.name, self.path)
            return [], new
        out: list[str] = []
        if new.inode and st.st_ino != new.inode:
            rotated = self.path.with_name(self.path.name + ".1")
            try:
                if rotated.stat().st_ino == new.inode:
                    out, last, reason = read_lines(rotated, new.offset, stop_before)
                    if reason in ("stop", "cap"):  # seguir en el archivo viejo la próxima vez
                        new.offset = last
                        return out, new
            except FileNotFoundError:
                pass
            log.info("%s: rotación detectada", self.name)
            new = Cursor(st.st_ino, 0)
        elif not new.inode:
            # Primera ejecución: empezar desde el final para no reenviar todo el historial,
            # salvo que se pida explícitamente SHIPPER_BACKFILL=1.
            start = 0 if os.environ.get("SHIPPER_BACKFILL") == "1" else st.st_size
            new = Cursor(st.st_ino, start)
        elif st.st_size < new.offset:  # copytruncate
            new.offset = 0
        lines, new.offset, _ = read_lines(self.path, new.offset, stop_before)
        return out + lines, new


# ---------------------------------------------------------------- estado del servidor
def read_cpu(proc: Path) -> tuple[int, int] | None:
    """(total, inactivo) acumulados desde el arranque, de la primera línea de /proc/stat."""
    try:
        fields = (proc / "stat").read_text().splitlines()[0].split()
        # user nice system idle iowait irq softirq steal (guest ya va dentro de user/nice)
        values = [int(v) for v in fields[1:9]]
    except (OSError, IndexError, ValueError):
        return None
    if fields[0] != "cpu" or len(values) < 5:
        return None
    return sum(values), values[3] + values[4]


def cpu_percent(prev, cur) -> float | None:
    """Uso medio entre dos lecturas: el agente corre cada 2 min, así que es la media de 2 min."""
    if not prev or not cur:
        return None
    total, idle = cur[0] - prev[0], cur[1] - prev[1]
    if total <= 0 or idle < 0:  # el servidor se reinició entre lecturas
        return None
    return round(100 * (total - idle) / total, 1)


def read_load(proc: Path) -> list[float] | None:
    try:
        return [float(v) for v in (proc / "loadavg").read_text().split()[:3]]
    except (OSError, ValueError):
        return None


def read_memory(proc: Path) -> dict | None:
    """RAM usada = total - disponible: la caché que Linux libera cuando hace falta no cuenta."""
    try:
        kib = {}
        for line in (proc / "meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            if rest.split():
                kib[key] = int(rest.split()[0])
        total, avail = kib["MemTotal"] * 1024, kib["MemAvailable"] * 1024
        swap_total, swap_free = kib.get("SwapTotal", 0) * 1024, kib.get("SwapFree", 0) * 1024
    except (OSError, KeyError, ValueError):
        return None
    return {"mem_total": total, "mem_used": total - avail,
            "swap_total": swap_total, "swap_used": swap_total - swap_free}


def read_disk(path: str) -> dict | None:
    """Mismo criterio que `df`: tamaño, usado y libre para usuarios normales."""
    try:
        st = os.statvfs(path)
    except (OSError, AttributeError):  # AttributeError: statvfs no existe fuera de Unix
        return None
    return {"disk_total": st.f_blocks * st.f_frsize,
            "disk_used": (st.f_blocks - st.f_bfree) * st.f_frsize,
            "disk_avail": st.f_bavail * st.f_frsize}


def os_name(path: Path) -> str | None:
    try:
        for line in path.read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        pass
    return None


def source_ip(family: int, target: str) -> str | None:
    """IP pública con la que este servidor sale a internet. Un socket UDP "conectado" solo
    elige la ruta: no envía ningún paquete."""
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.connect((target, 53))
            return public_ip(s.getsockname()[0], [])
    except OSError:
        return None


def collect_metrics(cfg: Config, state: dict, now: datetime) -> tuple[dict | None, tuple | None]:
    """Devuelve (métricas o None si no se pudieron leer, contadores de CPU para la próxima vez)."""
    cpu = read_cpu(cfg.proc_dir)
    memory, disk = read_memory(cfg.proc_dir), read_disk(cfg.disk_path)
    if not memory or not disk:
        return None, cpu
    return {"ts": now.isoformat().replace("+00:00", "Z"),
            "cpu_pct": cpu_percent(state.get("cpu"), cpu),
            "load": read_load(cfg.proc_dir), **memory, **disk}, cpu


def host_info(cfg: Config) -> dict:
    return {"label": cfg.host_label or None, "service": cfg.host_service or None,
            "hostname": socket.getfqdn() or None, "os": os_name(cfg.os_release),
            "kernel": f"{platform.system()} {platform.release()}".strip() or None,
            "ipv4": source_ip(socket.AF_INET, "1.1.1.1"),
            "ipv6": source_ip(socket.AF_INET6, "2606:4700:4700::1111")}


# ---------------------------------------------------------------- envío
class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Un 3xx es un error: seguirlo reenviaría el token a la URL que diga la respuesta."""

    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def post_json(cfg: Config, payload: dict) -> dict:
    data = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(cfg.endpoint, data=data, method="POST", headers={
        "Authorization": f"Bearer {cfg.token}",
        "Content-Type": "application/json",
        "User-Agent": f"attack-shipper/{VERSION}",
    })
    with OPENER.open(req, timeout=cfg.timeout) as resp:
        return json.loads(resp.read() or b"{}")


def collect(cfg: Config, state: dict, now: datetime):
    """Devuelve (eventos, nuevo_estado)."""
    events: list[dict] = []
    new_state = dict(state)

    if cfg.fail2ban_log:
        src = LogSource("fail2ban", cfg.fail2ban_log, Cursor(**state.get("fail2ban", {})))
        lines, cur = src.lines()
        for line in lines:
            ev = parse_fail2ban(line, cfg.ignore_nets)
            if ev:
                events.append(ev)
        new_state["fail2ban"] = cur.__dict__

    if cfg.ufw_log:
        open_window = bucket_start(now, cfg.bucket_seconds)

        def window_still_open(line: str) -> bool:
            ts = parse_syslog_ts(line, now)
            return ts is not None and ts >= open_window

        src = LogSource("ufw", cfg.ufw_log, Cursor(**state.get("ufw", {})))
        lines, cur = src.lines(stop_before=window_still_open)
        agg: dict[tuple, int] = {}
        for line in lines:
            ev = parse_ufw(line, now, cfg.ignore_nets)
            if ev:
                key = (bucket_start(ev["ts"], cfg.bucket_seconds), ev["ip"], ev["proto"], ev["dport"])
                agg[key] = agg.get(key, 0) + 1
        for (ts, ip, proto, dport), hits in agg.items():
            events.append({"ts": ts, "source": "ufw", "ip": ip, "proto": proto,
                           "dport": dport, "hits": hits})
        new_state["ufw"] = cur.__dict__

    for ev in events:
        ev["ts"] = ev["ts"].isoformat().replace("+00:00", "Z")
    return events, new_state


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path: Path, state: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    os.replace(tmp, path)  # escritura atómica


def run(cfg: Config, now: datetime | None = None, sender=post_json) -> int:
    now = now or datetime.now(timezone.utc)
    state_file = cfg.state_dir / "state.json"
    state = load_state(state_file)
    events, new_state = collect(cfg, state, now)
    extra: dict = {}
    if cfg.metrics:
        metrics, cpu = collect_metrics(cfg, state, now)
        if cpu:
            new_state["cpu"] = list(cpu)
        extra["host"] = host_info(cfg)
        if metrics:
            extra["metrics"] = metrics

    totals = {"accepted": 0, "inserted": 0, "rejected": 0}
    # Siempre al menos un envío (aunque vacío): valida el token y actualiza last_seen,
    # así el dashboard sabe que el agente sigue vivo aunque no haya ataques nuevos.
    # El estado del servidor viaja una sola vez por ejecución, en el primer lote.
    for i in range(0, max(len(events), 1), cfg.max_batch):
        payload = {"events": events[i:i + cfg.max_batch], **(extra if i == 0 else {})}
        try:
            result = sender(cfg, payload)
        except urllib.error.HTTPError as exc:
            log.error("La API respondió %s: %s", exc.code, exc.read()[:300].decode("utf-8", "replace"))
            return 1
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.error("No se pudo enviar el lote: %s", exc)
            return 1
        for key in totals:
            totals[key] += int(result.get(key, 0))

    save_state(state_file, new_state)
    log.info("%d eventos, %d nuevos, %d rechazados",
             len(events), totals["inserted"], totals["rejected"])
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = Config.from_env()
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    return run(cfg)


if __name__ == "__main__":
    sys.exit(main())
