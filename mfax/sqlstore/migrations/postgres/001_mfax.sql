-- Schéma mfax, dialecte PostgreSQL. Tables dédiées ; user_id référence
-- l'utilisateur authx sans contrainte FK dure (mfax reste indépendant de l'ordre
-- de migration de la table users). Booléen enabled en SMALLINT (0/1) pour un
-- scan Go identique entre dialectes.
CREATE TABLE IF NOT EXISTS mfa_totp (
    user_id    BIGINT PRIMARY KEY,
    secret     TEXT NOT NULL,
    enabled    SMALLINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mfa_challenges (
    token      TEXT PRIMARY KEY,
    user_id    BIGINT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
