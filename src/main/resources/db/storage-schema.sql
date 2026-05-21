CREATE TABLE IF NOT EXISTS vault_storage (
    key_path      VARCHAR(1024) NOT NULL PRIMARY KEY,
    encrypted_data JSONB         NOT NULL,
    updated_at    TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vault_storage_key_path_prefix
    ON vault_storage (key_path varchar_pattern_ops);

CREATE TABLE IF NOT EXISTS approle_credentials (
    secret_id  VARCHAR(36)  NOT NULL PRIMARY KEY,
    role_name  VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    used       BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_approle_credentials_expires_at
    ON approle_credentials (expires_at);
