-- Schéma dédié à mfax. user_id référence l'utilisateur authx, mais sans
-- contrainte FK dure : mfax reste indépendant du nom/ordre de migration de la
-- table users. La suppression d'un utilisateur doit purger ces lignes côté
-- projet (ou via TOTPStore.Delete).
CREATE TABLE IF NOT EXISTS mfa_totp (
    user_id    INTEGER PRIMARY KEY,
    secret     TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mfa_challenges (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user ON mfa_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
