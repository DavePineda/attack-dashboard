-- Esquema del dashboard de ataques. Idempotente: se aplica en cada arranque.

CREATE TABLE IF NOT EXISTS sensors (
    id            SERIAL PRIMARY KEY,
    name          TEXT        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,47}$'),
    -- Solo se guarda el SHA-256 del token; el token en claro nunca toca la base.
    token_sha256  BYTEA       NOT NULL UNIQUE CHECK (length(token_sha256) = 32),
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS events (
    id           BIGSERIAL   PRIMARY KEY,
    sensor_id    INT         NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    ts           TIMESTAMPTZ NOT NULL,
    source       TEXT        NOT NULL CHECK (source IN ('fail2ban', 'ufw')),
    jail         TEXT        CHECK (jail ~ '^[A-Za-z0-9_.-]{1,64}$'),
    ip           INET        NOT NULL,
    proto        TEXT        CHECK (proto ~ '^[A-Z0-9]{1,10}$'),
    dport        INT         CHECK (dport BETWEEN 0 AND 65535),
    -- Fail2ban: 1 por baneo. UFW: paquetes bloqueados agregados por ventana de tiempo.
    hits         INT         NOT NULL DEFAULT 1 CHECK (hits > 0),
    country      CHAR(2),
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Deduplicación: el agente puede reenviar un lote sin duplicar datos.
CREATE UNIQUE INDEX IF NOT EXISTS events_dedup_idx ON events (
    sensor_id, source, ts, ip,
    (COALESCE(jail, '')), (COALESCE(proto, '')), (COALESCE(dport, -1))
);
CREATE INDEX IF NOT EXISTS events_ts_idx        ON events (ts);
CREATE INDEX IF NOT EXISTS events_source_ts_idx ON events (source, ts);
