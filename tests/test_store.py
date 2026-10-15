"""Pruebas de las opciones de conexión a PostgreSQL (sin servidor).

Requiere psycopg: python3 -m unittest discover tests
"""
import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.store import TCP_DEFAULTS, tcp_options  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
