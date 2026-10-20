"""Pruebas del agente. Solo biblioteca estándar: python3 -m unittest discover tests"""
import http.server
import ipaddress
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))
import shipper  # noqa: E402

os.environ["TZ"] = "America/Bogota"
if hasattr(__import__("time"), "tzset"):
    __import__("time").tzset()

F2B = ("2026-10-14 10:23:45,123 fail2ban.actions        [811]: NOTICE  [sshd] Ban 45.33.32.10\n"
       "2026-10-14 10:24:00,001 fail2ban.actions        [811]: NOTICE  [postfix-sasl] Ban 2a01:4f8:1c1c::7\n"
       "2026-10-14 10:25:00,001 fail2ban.actions        [811]: NOTICE  [sshd] Restore Ban 45.33.32.11\n"
       "2026-10-14 10:26:00,001 fail2ban.actions        [811]: NOTICE  [sshd] Unban 45.33.32.10\n"
       "2026-10-14 10:27:00,001 fail2ban.actions        [811]: NOTICE  [sshd] Ban 192.168.1.20\n"
       "2026-10-14 10:28:00,001 fail2ban.filter         [811]: INFO    [sshd] Found 45.33.32.12\n")


def ufw_line(ts: str, src: str, dpt="22", proto="TCP", inbound=True, action="BLOCK") -> str:
    iface = "IN=eth0 OUT=" if inbound else "IN= OUT=eth0"
    return (f"{ts} vps kernel: [123.456] [UFW {action}] {iface} MAC=aa:bb SRC={src} "
            f"DST=198.51.100.5 LEN=40 TTL=240 PROTO={proto} SPT=50000 DPT={dpt} WINDOW=1024 SYN URGP=0\n")


class ParserTests(unittest.TestCase):
    def test_fail2ban_only_real_public_bans(self):
        events = [shipper.parse_fail2ban(l, []) for l in F2B.splitlines()]
        got = [(e["jail"], e["ip"]) for e in events if e]
        self.assertEqual(got, [("sshd", "45.33.32.10"), ("postfix-sasl", "2a01:4f8:1c1c::7")])

    def test_fail2ban_local_time_to_utc(self):
        ev = shipper.parse_fail2ban(F2B.splitlines()[0], [])
        self.assertEqual(ev["ts"], datetime(2026, 10, 14, 15, 23, 45, tzinfo=timezone.utc))

    def test_ufw_bsd_and_iso_timestamps(self):
        now = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
        a = shipper.parse_ufw(ufw_line("Oct 14 10:23:45", "45.33.32.10"), now, [])
        b = shipper.parse_ufw(ufw_line("2026-10-14T10:23:45.123456-05:00", "45.33.32.10"), now, [])
        self.assertEqual(a["ts"], b["ts"].replace(microsecond=0))
        self.assertEqual((a["proto"], a["dport"]), ("TCP", 22))

    def test_ufw_december_line_read_in_january(self):
        now = datetime(2027, 1, 1, 6, 0, tzinfo=timezone.utc)
        ev = shipper.parse_ufw(ufw_line("Dec 31 23:59:00", "45.33.32.10"), now, [])
        self.assertEqual(ev["ts"].year, 2027)  # 23:59 Bogotá = 04:59 UTC del 1 de enero
        ev = shipper.parse_ufw(ufw_line("Dec 30 10:00:00", "45.33.32.10"), now, [])
        self.assertEqual(ev["ts"].year, 2026)

    def test_ufw_filters(self):
        now = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
        nets = [ipaddress.ip_network("45.33.32.0/24")]
        self.assertIsNone(shipper.parse_ufw(ufw_line("Oct 14 10:00:00", "45.33.32.1", inbound=False), now, []))
        self.assertIsNone(shipper.parse_ufw(ufw_line("Oct 14 10:00:00", "10.0.0.5"), now, []))
        self.assertIsNone(shipper.parse_ufw(ufw_line("Oct 14 10:00:00", "45.33.32.1"), now, nets))
        self.assertIsNone(shipper.parse_ufw(ufw_line("Oct 14 10:00:00", "45.33.32.1", action="ALLOW"), now, []))
        icmp = ufw_line("Oct 14 10:00:00", "45.33.32.1", proto="ICMP").replace(" DPT=22", "")
        self.assertIsNone(shipper.parse_ufw(icmp, now, [])["dport"])

    def test_ufw_only_kernel_lines(self):
        # `logger "[UFW BLOCK] …"` deja la etiqueta del usuario o la que elija, no "kernel:".
        now = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
        real = ufw_line("Oct 14 10:00:00", "45.33.32.1")
        self.assertIsNotNone(shipper.parse_ufw(real, now, []))
        for tag in ("root:", "logger:", "kernel[123]:", "evil: kernel:"):
            forged = real.replace("vps kernel:", f"vps {tag}")
            self.assertIsNone(shipper.parse_ufw(forged, now, []), tag)


class RunTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.f2b = self.dir / "fail2ban.log"
        self.ufw = self.dir / "ufw.log"
        self.f2b.write_text("")
        self.ufw.write_text("")
        self.cfg = shipper.Config(endpoint="https://x/api", token="t" * 40,
                                  fail2ban_log=str(self.f2b), ufw_log=str(self.ufw),
                                  bucket_seconds=600, state_dir=self.dir, metrics=False)
        self.sent = []

    def sender(self, cfg, payload):
        self.sent.extend(payload["events"])
        return {"accepted": len(payload["events"]), "inserted": len(payload["events"]), "rejected": 0}

    def failing_sender(self, cfg, payload):
        raise OSError("red caída")

    def test_first_run_starts_at_end_then_ships_new_lines(self):
        self.f2b.write_text(F2B)  # historial previo: no se envía
        now = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
        self.assertEqual(shipper.run(self.cfg, now, self.sender), 0)
        self.assertEqual(self.sent, [])
        with self.f2b.open("a") as fh:
            fh.write(F2B.splitlines(True)[0])
        shipper.run(self.cfg, now, self.sender)
        self.assertEqual(len(self.sent), 1)

    def test_ufw_aggregates_and_waits_for_closed_window(self):
        shipper.run(self.cfg, datetime(2026, 10, 14, 15, 0, tzinfo=timezone.utc), self.sender)
        lines = [ufw_line("Oct 14 10:01:00", "45.33.32.1"), ufw_line("Oct 14 10:05:00", "45.33.32.1"),
                 ufw_line("Oct 14 10:06:00", "45.33.32.1", dpt="23"),
                 ufw_line("Oct 14 10:12:00", "45.33.32.1")]  # ventana 10:10 aún abierta
        self.ufw.write_text("".join(lines))
        now = datetime(2026, 10, 14, 15, 14, tzinfo=timezone.utc)  # 10:14 en Bogotá
        shipper.run(self.cfg, now, self.sender)
        got = sorted((e["dport"], e["hits"], e["ts"]) for e in self.sent)
        self.assertEqual(got, [(22, 2, "2026-10-14T15:00:00Z"), (23, 1, "2026-10-14T15:00:00Z")])
        self.sent.clear()
        shipper.run(self.cfg, datetime(2026, 10, 14, 15, 21, tzinfo=timezone.utc), self.sender)
        self.assertEqual([(e["hits"], e["ts"]) for e in self.sent], [(1, "2026-10-14T15:10:00Z")])

    def test_failure_does_not_advance_offset(self):
        now = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
        shipper.run(self.cfg, now, self.sender)
        self.f2b.write_text(F2B)
        self.assertEqual(shipper.run(self.cfg, now, self.failing_sender), 1)
        shipper.run(self.cfg, now, self.sender)
        self.assertEqual(len(self.sent), 2)

    def test_rotation_reads_rest_of_old_file(self):
        now = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
        shipper.run(self.cfg, now, self.sender)
        lines = F2B.splitlines(True)
        self.f2b.write_text(lines[0])
        shipper.run(self.cfg, now, self.sender)
        with self.f2b.open("a") as fh:
            fh.write(lines[1])  # escrito justo antes de rotar
        self.f2b.rename(self.dir / "fail2ban.log.1")
        self.f2b.write_text(lines[0].replace("45.33.32.10", "45.33.32.99"))
        shipper.run(self.cfg, now, self.sender)
        self.assertEqual([e["ip"] for e in self.sent], ["45.33.32.10", "2a01:4f8:1c1c::7", "45.33.32.99"])

    def test_state_is_json(self):
        shipper.run(self.cfg, datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc), self.sender)
        state = json.loads((self.dir / "state.json").read_text())
        self.assertEqual(set(state), {"fail2ban", "ufw"})


MEMINFO = ("MemTotal:        2000000 kB\nMemFree:          100000 kB\n"
           "MemAvailable:     700000 kB\nSwapTotal:       1000000 kB\nSwapFree:         900000 kB\n")
DISK = {"disk_total": 40_000, "disk_used": 14_000, "disk_avail": 24_000}


def proc_stat(user, idle, iowait=0):
    return f"cpu  {user} 0 0 {idle} {iowait} 0 0 0 0 0\ncpu0 {user} 0 0 {idle} {iowait} 0 0 0 0 0\n"


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.proc = Path(tempfile.mkdtemp())
        (self.proc / "meminfo").write_text(MEMINFO)
        (self.proc / "loadavg").write_text("0.42 0.38 0.35 1/234 5678\n")
        (self.proc / "stat").write_text(proc_stat(1000, 9000))

    def test_cpu_is_the_average_between_two_readings(self):
        first = shipper.read_cpu(self.proc)
        self.assertEqual(first, (10000, 9000))
        (self.proc / "stat").write_text(proc_stat(1250, 9700, iowait=50))
        # 1000 ticks nuevos: 750 inactivos (700 idle + 50 iowait) → 25 % de uso.
        self.assertEqual(shipper.cpu_percent(first, shipper.read_cpu(self.proc)), 25.0)
        self.assertIsNone(shipper.cpu_percent(None, first))          # primera lectura
        self.assertIsNone(shipper.cpu_percent((99999, 1), first))    # reinicio del servidor

    def test_memory_excludes_cache_and_load(self):
        self.assertEqual(shipper.read_memory(self.proc), {
            "mem_total": 2_048_000_000, "mem_used": 1_331_200_000,
            "swap_total": 1_024_000_000, "swap_used": 102_400_000})
        self.assertEqual(shipper.read_load(self.proc), [0.42, 0.38, 0.35])

    def test_unreadable_proc_gives_none(self):
        empty = Path(tempfile.mkdtemp())
        self.assertIsNone(shipper.read_cpu(empty))
        self.assertIsNone(shipper.read_memory(empty))
        self.assertIsNone(shipper.read_load(empty))

    @unittest.skipUnless(hasattr(os, "statvfs"), "statvfs solo existe en Unix")
    def test_disk_like_df(self):
        disk = shipper.read_disk("/")
        self.assertGreater(disk["disk_total"], 0)
        self.assertLessEqual(disk["disk_used"] + disk["disk_avail"], disk["disk_total"])

    def test_os_name(self):
        path = self.proc / "os-release"
        path.write_text('NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04.5 LTS"\n')
        self.assertEqual(shipper.os_name(path), "Ubuntu 24.04.5 LTS")
        self.assertIsNone(shipper.os_name(self.proc / "no-existe"))

    def test_run_sends_metrics_once_and_keeps_cpu_counters(self):
        state_dir = Path(tempfile.mkdtemp())
        f2b = state_dir / "fail2ban.log"
        f2b.write_text("")
        cfg = shipper.Config(endpoint="https://x/api", token="t" * 40, fail2ban_log=str(f2b),
                             ufw_log="", state_dir=state_dir, proc_dir=self.proc, max_batch=1)
        payloads = []

        def sender(cfg, payload):
            payloads.append(payload)
            return {"accepted": len(payload["events"]), "inserted": 0, "rejected": 0}

        now = datetime(2026, 10, 14, 16, 0, tzinfo=timezone.utc)
        with mock.patch.object(shipper, "read_disk", return_value=DISK), \
             mock.patch.object(shipper, "host_info", return_value={"hostname": "mail.example"}):
            shipper.run(cfg, now, sender)
            self.assertIsNone(payloads[0]["metrics"]["cpu_pct"])  # aún no hay lectura previa
            (self.proc / "stat").write_text(proc_stat(1500, 9500))
            with f2b.open("a") as fh:  # dos eventos con max_batch=1 → dos lotes
                fh.write(F2B.splitlines(True)[0] + F2B.splitlines(True)[1])
            payloads.clear()
            shipper.run(cfg, now, sender)

        self.assertEqual(len(payloads), 2)
        first, second = payloads
        self.assertEqual(first["metrics"]["cpu_pct"], 50.0)
        self.assertEqual(first["metrics"]["load"], [0.42, 0.38, 0.35])
        self.assertEqual(first["metrics"]["disk_used"], 14_000)
        self.assertEqual(first["host"], {"hostname": "mail.example"})
        self.assertNotIn("metrics", second)
        self.assertNotIn("host", second)
        state = json.loads((state_dir / "state.json").read_text())
        self.assertEqual(state["cpu"], [11000, 9500])


class RedirectTests(unittest.TestCase):
    def test_post_does_not_follow_redirects(self):
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/robado")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        cfg = shipper.Config(endpoint=f"http://127.0.0.1:{server.server_port}/api",
                             token="t" * 40, state_dir=Path(tempfile.mkdtemp()))
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            shipper.post_json(cfg, {"events": []})
        ctx.exception.close()
        self.assertEqual(ctx.exception.code, 302)
        self.assertEqual(hits, ["/api"])  # nunca se llamó a /robado con el token


if __name__ == "__main__":
    unittest.main()
