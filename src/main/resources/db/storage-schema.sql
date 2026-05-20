CREATE TABLE IF NOT EXISTS vault_storage (
    key_path      VARCHAR(1024) NOT NULL PRIMARY KEY,
    encrypted_data JSONB         NOT NULL,
    updated_at    TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vault_storage_key_path_prefix
    ON vault_storage (key_path varchar_pattern_ops);
