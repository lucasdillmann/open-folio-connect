CREATE TABLE IF NOT EXISTS backup_policy (
    user_id               UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enabled               BOOLEAN     NOT NULL DEFAULT false,
    source_id             TEXT,
    revision              INTEGER     NOT NULL DEFAULT 0,
    upload_entitled       BOOLEAN     NOT NULL DEFAULT true,
    next_due_at           TIMESTAMPTZ,
    last_backup_at        TIMESTAMPTZ,
    read_grace_expires_at TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS backup_keys (
    user_id           UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    key_id            UUID        NOT NULL,
    recovery_envelope TEXT        NOT NULL,
    recovery_revision INTEGER     NOT NULL DEFAULT 1,
    trusted_revision  INTEGER     NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS backup_trusted_envelopes (
    key_id     UUID        NOT NULL,
    device_id  UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    envelope   TEXT        NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (key_id, device_id)
);

CREATE TABLE IF NOT EXISTS backup_points (
    backup_id          UUID PRIMARY KEY,
    user_id            UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id             UUID        NOT NULL,
    source_id          TEXT        NOT NULL,
    size_bytes         BIGINT      NOT NULL,
    checksum           TEXT        NOT NULL,
    format             INTEGER     NOT NULL,
    trigger_source     TEXT        NOT NULL DEFAULT 'scheduled',
    published_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    encrypted_metadata TEXT        NOT NULL,
    storage_path       TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS backup_points_user_published_idx
    ON backup_points (user_id, published_at DESC);
