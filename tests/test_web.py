"""Pruebas de la capa HTTP con un almacén falso (sin PostgreSQL).

Requiere starlette y uvicorn: python3 -m unittest discover tests
"""
import hashlib
import json
import os
import socket
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn  # noqa: E402

from app.config import Settings  # noqa: E402
from app.web import create_app  # noqa: E402

TOKEN = "k" * 43


class FakeStore:
    def __init__(self):
        self.events = []
        self.keys = set()

    async def open(self): ...
    async def close(self): ...
    async def purge(self, days): return 0

    async def sensor_for_token(self, sha):
        return (1, "vps-prueba") if sha == hashlib.sha256(TOKEN.encode()).digest() else None

    async def insert_events(self, sensor_id, events, countries):
        new = 0
        for e in events:
            key = (sensor_id, e.source, e.ts, e.ip, e.jail, e.proto, e.dport)
            if key not in self.keys:
                self.keys.add(key)
                self.events.append(e)
                new += 1
        return new

    async def stats(self, *, since, unit, tz, mask):
        evs = [e for e in self.events if e.ts >= since]
        return {
            "summary": {"bans": sum(e.source == "fail2ban" for e in evs),
                        "blocked": sum(e.hits for e in evs if e.source == "ufw"),
                        "unique_ips": len({e.ip for e in evs}), "countries": 0,
                        "last_event": max((e.ts for e in evs), default=None)},
            "timeline": [], "countries": [], "ports": [], "jails": [], "top": [],
            "sensors": {"count": 1, "last_seen": None},
        }


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(app):
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, port=port, log_level="error",
                                           server_header=False, date_header=False))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return server, port


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update({"DATABASE_URL": "x", "STATS_CACHE_SECONDS": "0", "TRUST_PROXY": "true"})
        cls.store = FakeStore()
        app = create_app(Settings.from_env(), cls.store, run_background=False)
        cls.server, cls.port = start_server(app)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True

    def req(self, path, body=None, token=TOKEN, ctype="application/json", raw=None, xff=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        headers = {"Content-Type": ctype}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if xff:
            headers["X-Forwarded-For"] = xff
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, headers=headers,
                                   method="POST" if data is not None else "GET")
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, dict(resp.headers), json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), json.loads(exc.read() or b"null")

    def ev(self, **kw):
        base = {"ts": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
                "source": "fail2ban", "jail": "sshd", "ip": "45.33.32.10"}
        base.update(kw)
        return base

    def test_rejects_bad_token(self):
        status, headers, _ = self.req("/api/v1/ingest", {"events": []}, token="z" * 43)
        self.assertEqual(status, 401)
        self.assertEqual(headers.get("www-authenticate"), "Bearer")

    def test_ingest_validates_and_dedups(self):
        batch = {"events": [
            self.ev(),
            self.ev(ip="10.0.0.1"),                       # privada
            self.ev(ts="2020-01-01T00:00:00Z"),           # fuera de retención
            self.ev(ts="2026-10-14T10:00:00"),            # sin zona horaria
            self.ev(source="ufw", jail=None, proto="tcp", dport=22, hits=7),
            self.ev(jail="sshd; DROP TABLE"),
            self.ev(source="ufw", dport=70000),
            "no-es-un-objeto",
        ]}
        status, _, body = self.req("/api/v1/ingest", batch)
        self.assertEqual(status, 200)
        self.assertEqual((body["accepted"], body["rejected"]), (2, 6))
        status, _, body = self.req("/api/v1/ingest", batch)
        self.assertEqual((body["inserted"], body["duplicates"]), (0, 2))

    def test_rejects_malformed_bodies(self):
        self.assertEqual(self.req("/api/v1/ingest", raw=b"{nope")[0], 400)
        self.assertEqual(self.req("/api/v1/ingest", raw=b"[]")[0], 400)
        self.assertEqual(self.req("/api/v1/ingest", {"events": []}, ctype="text/plain")[0], 415)
        big = {"events": [self.ev()] * 2001}
        self.assertIn(self.req("/api/v1/ingest", big)[0], (400, 413))

    def test_stats_and_security_headers(self):
        status, headers, body = self.req("/api/v1/stats?range=24h", token=None)
        self.assertEqual(status, 200)
        self.assertIn("default-src 'none'", headers["content-security-policy"])
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn("server", {k.lower() for k in headers})
        self.assertEqual(len(body["timeline"]["buckets"]), 25)
        self.assertEqual(self.req("/api/v1/stats?range=1y", token=None)[0], 400)

    def test_static_index(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/") as resp:
            html = resp.read().decode()
            self.assertIn("app.js", html)
            self.assertEqual(resp.headers["x-frame-options"], "DENY")

    def test_failed_auth_is_rate_limited(self):
        ip = "198.51.100.1, 203.0.113.50"  # cuenta la última IP (la que añade el proxy)
        codes = [self.req("/api/v1/ingest", {"events": []}, token="y" * 43, xff=ip)[0]
                 for _ in range(12)]
        self.assertEqual(codes[:10], [401] * 10)
        self.assertEqual(codes[-1], 429)
        # Otra IP no se ve afectada, y un token válido desde la IP bloqueada también espera.
        self.assertEqual(self.req("/api/v1/ingest", {"events": []}, xff="203.0.113.51")[0], 200)
        self.assertEqual(self.req("/api/v1/ingest", {"events": []}, xff="1.1.1.1, 203.0.113.50")[0], 429)


class ProxyOnlyTests(unittest.TestCase):
    """Con TRUSTED_PROXIES solo pasan las conexiones del proxy (en la prueba, 127.0.0.1)."""

    def start(self, trusted):
        os.environ["TRUSTED_PROXIES"] = trusted
        try:
            settings = Settings.from_env()
        finally:
            del os.environ["TRUSTED_PROXIES"]
        server, port = start_server(create_app(settings, FakeStore(), run_background=False))
        self.addCleanup(setattr, server, "should_exit", True)
        return port

    def get(self, port):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
                return resp.status, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers)

    def test_direct_connection_is_rejected(self):
        status, headers = self.get(self.start("10.9.8.0/24"))
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("x-frame-options"), "DENY")  # cabeceras de seguridad igual

    def test_trusted_proxy_is_accepted(self):
        self.assertEqual(self.get(self.start("127.0.0.1"))[0], 200)

    def test_invalid_value_fails_at_startup(self):
        os.environ["TRUSTED_PROXIES"] = "no-es-una-ip"
        try:
            with self.assertRaises(ValueError):
                Settings.from_env()
        finally:
            del os.environ["TRUSTED_PROXIES"]


if __name__ == "__main__":
    unittest.main()
