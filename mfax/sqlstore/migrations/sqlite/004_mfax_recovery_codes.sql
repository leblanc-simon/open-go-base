-- Codes de secours (mfax.WithRecoveryCodes) : empreintes SHA-256 seulement, jamais les
-- codes en clair. used_at en secondes Unix (0 : non utilisé), comme mfa_lockouts.
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    user_id   INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used_at   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, code_hash)
);
