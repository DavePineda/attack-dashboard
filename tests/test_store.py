"""Pruebas de las opciones de conexión a PostgreSQL (sin servidor).

Requiere psycopg: python3 -m unittest discover tests
"""
import asyncio
import importlib.util
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import store  # noqa: E402
from app.store import TCP_DEFAULTS, check_network, db_address, tcp_options, tcp_probe  # noqa: E402

DSN = ("postgresql://u:p@db.example:5432/dash"
       "?sslmode=verify-full&sslrootcert=/home/container/certs/botkeep-ca.pem")


@unittest.skipUnless(importlib.util.find_spec("psycopg"), "requiere psycopg")
class TcpOptionsTests(unittest.TestCase):
    def test_defaults_apply(self):
        self.assertEqual(tcp_options(DSN), TCP_DEFAULTS)

    def test_database_url_wins(self):
        options = tcp_options(DSN + "&keepalives_idle=60&connect_timeout=5")
        self.assertNotIn("keepalives_idle", options)
        self.assertNotIn("connect_timeout", options)
        self.assertEqual(options["tcp_user_timeout"], 30_000)

    def test_libpq_accepts_the_options(self):
        from psycopg.conninfo import conninfo_to_dict, make_conninfo

        # make_conninfo valida los nombres con libpq: uno desconocido lanza un error.
        merged = conninfo_to_dict(make_conninfo(DSN, **tcp_options(DSN)))
        self.assertEqual(merged["tcp_user_timeout"], "30000")
        self.assertEqual(merged["sslmode"], "verify-full")


@unittest.skipUnless(importlib.util.find_spec("psycopg"), "requiere psycopg")
class DbAddressTests(unittest.TestCase):
    def test_host_and_port(self):
        self.assertEqual(db_address(DSN), ("db.example", 5432))

    def test_default_port_and_hostaddr(self):
        self.assertEqual(db_address("host=db.example hostaddr=10.0.0.5 dbname=x"),
                         ("10.0.0.5", 5432))

    def test_first_of_several_hosts(self):
        self.assertEqual(db_address("postgresql://u@a.example:6000,b.example:6001/x"),
                         ("a.example", 6000))

    def test_unix_socket_is_skipped(self):
        self.assertIsNone(db_address("host=/var/run/postgresql dbname=x"))


class TcpProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_port(self):
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            ok, detail = await tcp_probe("127.0.0.1", port)
        self.assertTrue(ok)
        self.assertTrue(detail.startswith("OK ("))

    async def test_closed_port(self):
        with socket.socket() as s:  # un puerto libre que nadie escucha
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        ok, detail = await tcp_probe("127.0.0.1", port)
        self.assertFalse(ok)
        self.assertIn("rechazada", detail)

    async def test_timeout(self):
        async def hang(*args):
            await asyncio.sleep(10)

        with mock.patch("asyncio.open_connection", hang):
            ok, detail = await tcp_probe("192.0.2.1", 5432, timeout=0.05)
        self.assertFalse(ok)
        self.assertIn("sin respuesta en 0.05 s", detail)


@unittest.skipUnless(importlib.util.find_spec("psycopg"), "requiere psycopg")
class CheckNetworkTests(unittest.IsolatedAsyncioTestCase):
    async def test_ok_logs_once(self):
        probe = mock.AsyncMock(return_value=(True, "OK (0.0 s)"))
        with mock.patch.object(store, "tcp_probe", probe), \
             self.assertLogs("store", "INFO") as logs:
            await check_network(DSN)
        probe.assert_awaited_once_with("db.example", 5432)
        self.assertEqual(logs.output,
                         ["INFO:store:Red hacia PostgreSQL db.example:5432: OK (0.0 s)"])

    async def test_failure_adds_control(self):
        probe = mock.AsyncMock(side_effect=[(False, "sin respuesta"), (True, "OK (0.1 s)")])
        with mock.patch.object(store, "tcp_probe", probe), \
             self.assertLogs("store", "WARNING") as logs:
            await check_network(DSN)
        self.assertEqual(probe.await_args_list[1].args, store.CONTROL_ADDR)
        self.assertEqual(len(logs.output), 2)
        self.assertIn("Control de salida a internet 1.1.1.1:443: OK", logs.output[1])


if __name__ == "__main__":
    unittest.main()
