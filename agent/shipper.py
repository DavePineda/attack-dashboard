#!/usr/bin/env python3
"""attack-shipper: lee Fail2ban y UFW en el VPS y envía los eventos al dashboard.

- Solo biblioteca estándar de Python 3.9+: nada que instalar en el servidor.
- Se ejecuta como oneshot desde un timer de systemd, con un usuario sin privilegios.
- Guarda el desplazamiento (offset) de cada log y solo lo avanza cuando el envío fue
  exitoso. Si algo falla, la siguiente ejecución reenvía y la API descarta duplicados.
- UFW se agrega por (ventana, IP, protocolo, puerto) para no inundar la base: solo se
  envían ventanas ya cerradas, así un reenvío nunca produce conteos parciales.
- Soporta rotación de logs (lee el resto de <log>.1 antes de empezar el archivo nuevo).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.0.0"
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
    kuma_push_url: str = ""
    max_batch: int = 1000
    timeout: int = 20
    ignore_nets: list = field(default_factory=list)

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
            kuma_push_url=env.get("SHIPPER_KUMA_PUSH_URL", "").strip(),
            max_batch=min(int(env.get("SHIPPER_MAX_BATCH", "1000")), 2000),
            timeout=int(env.get("SHIPPER_TIMEOUT", "20")),
            ignore_nets=nets,
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


# ---------------------------------------------------------------- envío
def post_json(cfg: Config, payload: dict) -> dict:
    data = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(cfg.endpoint, data=data, method="POST", headers={
        "Authorization": f"Bearer {cfg.token}",
        "Content-Type": "application/json",
        "User-Agent": f"attack-shipper/{VERSION}",
    })
    with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
        return json.loads(resp.read() or b"{}")


def kuma_push(cfg: Config, message: str) -> None:
    if not cfg.kuma_push_url:
        return
    parts = urllib.parse.urlsplit(cfg.kuma_push_url)
    query = urllib.parse.urlencode({"status": "up", "msg": message[:100], "ping": ""})
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    try:
        urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": f"attack-shipper/{VERSION}"}), timeout=10).read()
    except (urllib.error.URLError, OSError) as exc:
        log.warning("No se pudo notificar a Uptime Kuma: %s", exc)


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

    totals = {"accepted": 0, "inserted": 0, "rejected": 0}
    # Siempre al menos un envío (aunque vacío): valida el token y actualiza last_seen,
    # así el latido a Uptime Kuma solo llega si la API realmente acepta al agente.
    for i in range(0, max(len(events), 1), cfg.max_batch):
        try:
            result = sender(cfg, {"events": events[i:i + cfg.max_batch]})
        except urllib.error.HTTPError as exc:
            log.error("La API respondió %s: %s", exc.code, exc.read()[:300].decode("utf-8", "replace"))
            return 1
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.error("No se pudo enviar el lote: %s", exc)
            return 1
        for key in totals:
            totals[key] += int(result.get(key, 0))

    save_state(state_file, new_state)
    msg = (f"{len(events)} eventos, {totals['inserted']} nuevos, "
           f"{totals['rejected']} rechazados")
    log.info(msg)
    kuma_push(cfg, msg)
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = Config.from_env()
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    return run(cfg)


if __name__ == "__main__":
    sys.exit(main())
