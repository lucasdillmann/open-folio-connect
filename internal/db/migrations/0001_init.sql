CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY,
    email       TEXT        NOT NULL UNIQUE,
    password    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS teams (
    id                      UUID PRIMARY KEY,
    name                    TEXT        NOT NULL,
    plan                    TEXT        NOT NULL DEFAULT 'basic',
    subscription_status     TEXT        NOT NULL DEFAULT 'active',
    subscription_period_end TIMESTAMPTZ,
    cancel_at_period_end    BOOLEAN     NOT NULL DEFAULT false,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS team_members (
    team_id   UUID        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role      TEXT        NOT NULL DEFAULT 'owner',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS devices (
    id                  UUID PRIMARY KEY,
    team_id             UUID        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_nonce        UUID        NOT NULL,
    display_name        TEXT        NOT NULL,
    platform            TEXT        NOT NULL,
    os_version          TEXT,
    app_version         TEXT,
    device_public_key   TEXT,
    trust_state         TEXT        NOT NULL DEFAULT 'untrusted',
    trusted_key_version INTEGER,
    device_key_envelope TEXT,
    last_seen_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (team_id, device_nonce)
);

CREATE INDEX IF NOT EXISTS devices_team_idx ON devices (team_id);

CREATE TABLE IF NOT EXISTS team_keys (
    team_id              UUID PRIMARY KEY REFERENCES teams(id) ON DELETE CASCADE,
    key_version          INTEGER     NOT NULL,
    state                TEXT        NOT NULL DEFAULT 'ACTIVE',
    device_id            UUID        REFERENCES devices(id) ON DELETE SET NULL,
    device_key_envelope  TEXT,
    signature            TEXT,
    challenge_response   TEXT,
    recovery_envelope    TEXT,
    committed_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS key_challenges (
    id          UUID PRIMARY KEY,
    team_id     UUID        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    device_id   UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    challenge   TEXT        NOT NULL,
    nonce       TEXT        NOT NULL,
    key_version INTEGER     NOT NULL,
    consumed_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS key_challenges_team_idx ON key_challenges (team_id, device_id);

CREATE TABLE IF NOT EXISTS oplog_events (
    seq                 BIGSERIAL PRIMARY KEY,
    team_id             UUID        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    event_id            TEXT        NOT NULL,
    device_id           UUID        NOT NULL,
    user_id             UUID        NOT NULL,
    event_type          TEXT        NOT NULL,
    entity              TEXT        NOT NULL,
    entity_id           TEXT        NOT NULL,
    client_timestamp    TEXT        NOT NULL,
    payload             TEXT        NOT NULL,
    payload_key_version INTEGER     NOT NULL,
    server_timestamp    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (team_id, event_id)
);

CREATE INDEX IF NOT EXISTS oplog_events_team_seq_idx ON oplog_events (team_id, seq);

CREATE TABLE IF NOT EXISTS pairings (
    id                     UUID PRIMARY KEY,
    team_id                UUID        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    code_hash              TEXT        NOT NULL,
    issuer_device_id       UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    issuer_ephemeral_pub   TEXT        NOT NULL,
    claimer_device_id      UUID        REFERENCES devices(id) ON DELETE CASCADE,
    claimer_ephemeral_pub  TEXT,
    status                 TEXT        NOT NULL DEFAULT 'open',
    key_version            INTEGER     NOT NULL,
    require_sas            BOOLEAN     NOT NULL DEFAULT true,
    expires_at             TIMESTAMPTZ NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS pairings_code_hash_idx ON pairings (code_hash);

CREATE TABLE IF NOT EXISTS pairing_messages (
    id           UUID PRIMARY KEY,
    pairing_id   UUID        NOT NULL REFERENCES pairings(id) ON DELETE CASCADE,
    payload_type TEXT        NOT NULL,
    payload      TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pairing_messages_pairing_idx ON pairing_messages (pairing_id, created_at);

CREATE TABLE IF NOT EXISTS snapshots (
    id                   UUID PRIMARY KEY,
    team_id              UUID        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    device_id            UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_id             UUID        NOT NULL,
    schema_version       INTEGER     NOT NULL,
    covers_tables        TEXT[]      NOT NULL DEFAULT '{}',
    size_bytes           BIGINT      NOT NULL,
    checksum             TEXT        NOT NULL,
    storage_path         TEXT        NOT NULL,
    payload_key_version  INTEGER     NOT NULL,
    oplog_seq            BIGINT      NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (team_id, event_id)
);

CREATE INDEX IF NOT EXISTS snapshots_team_created_idx ON snapshots (team_id, created_at DESC);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL UNIQUE,
    rotated_to  UUID        REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    revoked_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx ON refresh_tokens (user_id);

CREATE TABLE IF NOT EXISTS auth_codes (
    id            UUID PRIMARY KEY,
    code          TEXT        NOT NULL UNIQUE,
    code_challenge TEXT,
    redirect_to   TEXT,
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consumed_at   TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS login_otps (
    id          UUID PRIMARY KEY,
    email       TEXT        NOT NULL,
    code_hash   TEXT        NOT NULL,
    code_challenge TEXT,
    consumed_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS login_otps_email_idx ON login_otps (email, created_at DESC);
