"""Pruebas de la validación del estado del servidor (funciones puras, sin red ni base).

python3 -m unittest discover tests
"""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ingest import parse_host, parse_metrics  # noqa: E402

NOW = datetime(2026, 10, 20, 15, 0, tzinfo=timezone.utc)


def metrics(**kw):
    base = {"ts": "2026-10-20T14:59:30Z", "cpu_pct": 18.5, "load": [0.42, 0.38, 0.35],
            "mem_total": 2_000, "mem_used": 1_300, "swap_total": 1_000, "swap_used": 0,
            "disk_total": 40_000, "disk_used": 14_000, "disk_avail": 24_000}
    base.update(kw)
    return base


class ParseMetricsTests(unittest.TestCase):
    def test_valid(self):
        m = parse_metrics(metrics(), now=NOW)
        self.assertEqual((m.cpu_pct, m.load, m.disk_avail), (18.5, (0.42, 0.38, 0.35), 24_000))
        self.assertEqual(m.ts, NOW - timedelta(seconds=30))

    def test_first_reading_without_cpu_or_load(self):
        m = parse_metrics(metrics(cpu_pct=None, load=None), now=NOW)
        self.assertIsNone(m.cpu_pct)
        self.assertIsNone(m.load)

    def test_rejects_out_of_range(self):
        bad = [
            {"cpu_pct": 150}, {"cpu_pct": -1}, {"cpu_pct": float("nan")}, {"cpu_pct": True},
            {"cpu_pct": "18"}, {"load": [1, 2]}, {"load": [1, 2, -3]}, {"load": "1 2 3"},
            {"mem_total": 0}, {"mem_used": 2_001}, {"swap_used": 1_001}, {"mem_used": 1.5},
            {"disk_used": 40_001}, {"disk_avail": -1}, {"disk_total": 1 << 60},
            {"ts": "2026-10-20T14:00:00Z"},   # una hora atrás
            {"ts": "2026-10-20T15:30:00Z"},   # futuro
            {"ts": "2026-10-20T14:59:30"},    # sin zona horaria
        ]
        for change in bad:
            with self.subTest(change=change), self.assertRaises(ValueError):
                parse_metrics(metrics(**change), now=NOW)
        with self.assertRaises(ValueError):
            parse_metrics("no-es-un-objeto", now=NOW)
        with self.assertRaises(ValueError):
            parse_metrics({k: v for k, v in metrics().items() if k != "disk_avail"}, now=NOW)


class ParseHostTests(unittest.TestCase):
    def test_valid_fields(self):
        host = parse_host({"label": "Servidor de correo", "service": "Mox v0.0.17",
                           "hostname": "mail.0r1sk.xyz", "os": "Ubuntu 24.04.5 LTS",
                           "kernel": "Linux 6.8.0-146-generic", "ipv4": "69.10.53.55",
                           "ipv6": "2604:a00:50:1fc:216:3eff:fe2e:772b"})
        self.assertEqual(host["ipv6"], "2604:a00:50:1fc:216:3eff:fe2e:772b")
        self.assertEqual(host["service"], "Mox v0.0.17")
        self.assertNotIn(None, host.values())

    def test_invalid_fields_become_none(self):
        host = parse_host({"label": "<script>alert(1)</script>", "hostname": "mail;rm -rf",
                           "os": "x" * 81, "kernel": 42, "ipv4": "10.0.0.5",
                           "ipv6": "69.10.53.55", "extra": "ignorado"})
        self.assertEqual(set(host.values()), {None})
        self.assertNotIn("extra", host)
        self.assertEqual(set(parse_host("nada").values()), {None})


if __name__ == "__main__":
    unittest.main()
