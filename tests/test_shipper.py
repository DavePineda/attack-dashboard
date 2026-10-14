"""Pruebas del agente. Solo biblioteca estándar: python3 -m unittest discover tests"""
import ipaddress
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

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


class RunTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.f2b = self.dir / "fail2ban.log"
        self.ufw = self.dir / "ufw.log"
        self.f2b.write_text("")
        self.ufw.write_text("")
        self.cfg = shipper.Config(endpoint="https://x/api", token="t" * 40,
                                  fail2ban_log=str(self.f2b), ufw_log=str(self.ufw),
                                  bucket_seconds=600, state_dir=self.dir)
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


if __name__ == "__main__":
    unittest.main()
