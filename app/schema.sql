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

-- Cabecera de la tarjeta del servidor (hostname, sistema, kernel, IPs): la última que envió.
ALTER TABLE sensors ADD COLUMN IF NOT EXISTS host_info JSONB;

-- Estado del servidor: una fila por ejecución del agente (cada 2 min). Bytes en BIGINT.
CREATE TABLE IF NOT EXISTS metrics (
    sensor_id   INT         NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    ts          TIMESTAMPTZ NOT NULL,
    cpu_pct     REAL        CHECK (cpu_pct BETWEEN 0 AND 100),  -- NULL en la 1.ª lectura
    load1       REAL        CHECK (load1 >= 0),
    load5       REAL        CHECK (load5 >= 0),
    load15      REAL        CHECK (load15 >= 0),
    mem_total   BIGINT      NOT NULL CHECK (mem_total > 0),
    mem_used    BIGINT      NOT NULL CHECK (mem_used >= 0),
    swap_total  BIGINT      NOT NULL CHECK (swap_total >= 0),
    swap_used   BIGINT      NOT NULL CHECK (swap_used >= 0),
    disk_total  BIGINT      NOT NULL CHECK (disk_total > 0),
    disk_used   BIGINT      NOT NULL CHECK (disk_used >= 0),
    disk_avail  BIGINT      NOT NULL CHECK (disk_avail >= 0),
    PRIMARY KEY (sensor_id, ts),
    CHECK (mem_used <= mem_total AND swap_used <= swap_total
           AND disk_used <= disk_total AND disk_avail <= disk_total)
);
CREATE INDEX IF NOT EXISTS metrics_ts_idx ON metrics (ts);
