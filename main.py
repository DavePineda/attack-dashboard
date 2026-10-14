"""Punto de entrada para Botkeep: `python main.py`.

Escucha en 0.0.0.0 y en el puerto que asigna Botkeep (SERVER_PORT).
"""
import logging
import sys

from app.config import Settings, load_dotenv

load_dotenv()

import uvicorn  # noqa: E402

from app.geo import CountryLookup  # noqa: E402
from app.store import PgStore  # noqa: E402
from app.web import create_app  # noqa: E402

logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

settings = Settings.from_env()
app = create_app(settings, PgStore(settings.database_url), CountryLookup(settings.geoip_db))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=settings.port, workers=1,
                proxy_headers=False, server_header=False, date_header=False,
                access_log=False, log_level="info")
