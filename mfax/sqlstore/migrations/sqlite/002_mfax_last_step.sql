-- Anti-rejeu TOTP : dernier pas de temps consommé avec succès. Un code n'est
-- accepté que pour un pas strictement supérieur (cf. mfax.consumeCode).
ALTER TABLE mfa_totp ADD COLUMN last_step INTEGER NOT NULL DEFAULT 0;
