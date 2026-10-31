-- Verrouillage par compte (mfax.WithLockout) : codes faux comptés hors des défis,
-- pour qu'un nouveau défi (mot de passe rejoué) ne remette pas le compteur à zéro.
-- Instants en secondes Unix : comparaisons identiques entre dialectes.
CREATE TABLE IF NOT EXISTS mfa_lockouts (
    user_id      BIGINT PRIMARY KEY,
    failures     INTEGER NOT NULL DEFAULT 0,
    window_start BIGINT NOT NULL,
    lockouts     INTEGER NOT NULL DEFAULT 0,
    locked_until BIGINT NOT NULL DEFAULT 0
);
