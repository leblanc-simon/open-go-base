// Package sqlstore fournit une implémentation database/sql des stores de mfax
// (TOTPStore, ChallengeStore, LockoutStore) et les migrations du schéma associé
// (tables dédiées mfa_totp, mfa_challenges et mfa_lockouts).
//
// Plusieurs dialectes sont gérés (SQLite, PostgreSQL) ; le dialecte est passé à
// Migrate et aux constructeurs via appconf.Dialect (typiquement
// cfg.Database.Dialect()). Le driver n'est pas importé ici : le projet ouvre son
// *sql.DB et le passe à New / Migrate.
package sqlstore

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/internal/sqldialect"
	"leblanc.io/open-go-base/internal/sqlmigrate"
	"leblanc.io/open-go-base/mfax"
)

//go:embed migrations
var migrationsFS embed.FS

// ErrUnsupportedDialect signale un dialecte sans migrations fournies (p. ex.
// MySQL, prévu mais pas encore livré).
var ErrUnsupportedDialect = errors.New("mfax/sqlstore: unsupported SQL dialect")

func supported(d appconf.Dialect) bool {
	return d == appconf.DialectSQLite || d == appconf.DialectPostgres
}

// Migrate applique les migrations du schéma mfax pour le dialecte d. Idempotent.
// À appeler après les migrations de authx (la table users doit exister par
// ailleurs).
func Migrate(db *sql.DB, d appconf.Dialect) error {
	if !supported(d) {
		return fmt.Errorf("%w: %q", ErrUnsupportedDialect, d)
	}
	return sqlmigrate.Run(db, migrationsFS, "migrations/"+d.String(), d)
}

// TOTPStore implémente mfax.TOTPStore sur une base SQL.
type TOTPStore struct {
	db      *sql.DB
	dialect appconf.Dialect
}

// NewTOTPStore construit un TOTPStore sur db pour le dialecte d.
func NewTOTPStore(db *sql.DB, d appconf.Dialect) *TOTPStore { return &TOTPStore{db: db, dialect: d} }

func (s *TOTPStore) rb(q string) string { return sqldialect.Rebind(s.dialect, q) }

// Get renvoie mfax.ErrTOTPNotFound si l'utilisateur n'a pas de secret.
func (s *TOTPStore) Get(userID int64) (*mfax.TOTP, error) {
	row := s.db.QueryRow(s.rb(`SELECT user_id, secret, enabled, last_step FROM mfa_totp WHERE user_id = ?`), userID)
	t := &mfax.TOTP{}
	var enabled int
	if err := row.Scan(&t.UserID, &t.Secret, &enabled, &t.LastStep); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, mfax.ErrTOTPNotFound
		}
		return nil, err
	}
	t.Enabled = enabled == 1
	return t, nil
}

// SetLastStep avance atomiquement le dernier pas TOTP consommé. La condition
// last_step < ? rend l'opération monotone et atomique : deux requêtes
// concurrentes portant le même pas ne peuvent pas réussir toutes les deux.
func (s *TOTPStore) SetLastStep(userID int64, step int64) (bool, error) {
	res, err := s.db.Exec(
		s.rb(`UPDATE mfa_totp SET last_step = ? WHERE user_id = ? AND last_step < ?`),
		step, userID, step,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Set crée ou remplace le secret TOTP de l'utilisateur (upsert). La syntaxe
// ON CONFLICT ... DO UPDATE est commune à SQLite et PostgreSQL.
func (s *TOTPStore) Set(userID int64, secret string, enabled bool) error {
	_, err := s.db.Exec(
		s.rb(`INSERT INTO mfa_totp (user_id, secret, enabled) VALUES (?, ?, ?)
		 ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, enabled = excluded.enabled`),
		userID, secret, boolToInt(enabled),
	)
	return err
}

// Delete supprime le secret TOTP de l'utilisateur.
func (s *TOTPStore) Delete(userID int64) error {
	_, err := s.db.Exec(s.rb(`DELETE FROM mfa_totp WHERE user_id = ?`), userID)
	return err
}

// ChallengeStore implémente mfax.ChallengeStore sur une base SQL.
type ChallengeStore struct {
	db      *sql.DB
	dialect appconf.Dialect
}

// NewChallengeStore construit un ChallengeStore sur db pour le dialecte d.
func NewChallengeStore(db *sql.DB, d appconf.Dialect) *ChallengeStore {
	return &ChallengeStore{db: db, dialect: d}
}

func (s *ChallengeStore) rb(q string) string { return sqldialect.Rebind(s.dialect, q) }

// Create persiste un challenge.
func (s *ChallengeStore) Create(c *mfax.Challenge) error {
	_, err := s.db.Exec(
		s.rb(`INSERT INTO mfa_challenges (token, user_id, attempts, expires_at) VALUES (?, ?, ?, ?)`),
		c.Token, c.UserID, c.Attempts, c.ExpiresAt.UTC(),
	)
	return err
}

// Get renvoie mfax.ErrChallengeNotFound si le token est inconnu.
func (s *ChallengeStore) Get(token string) (*mfax.Challenge, error) {
	row := s.db.QueryRow(
		s.rb(`SELECT token, user_id, attempts, expires_at, created_at FROM mfa_challenges WHERE token = ?`), token,
	)
	c := &mfax.Challenge{}
	if err := row.Scan(&c.Token, &c.UserID, &c.Attempts, &c.ExpiresAt, &c.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, mfax.ErrChallengeNotFound
		}
		return nil, err
	}
	return c, nil
}

// IncrAttempts incrémente atomiquement le compteur de tentatives et renvoie
// true si l'incrément a eu lieu (la ligne existait et attempts < limit), false
// sinon. La condition attempts < limit dans l'UPDATE rend le test-et-incrément
// atomique : des requêtes concurrentes ne peuvent pas dépasser le plafond.
func (s *ChallengeStore) IncrAttempts(token string, limit int) (bool, error) {
	res, err := s.db.Exec(
		s.rb(`UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token = ? AND attempts < ?`),
		token, limit,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Delete supprime un challenge par son token.
func (s *ChallengeStore) Delete(token string) error {
	_, err := s.db.Exec(s.rb(`DELETE FROM mfa_challenges WHERE token = ?`), token)
	return err
}

// PurgeExpired supprime les challenges expirés et renvoie le nombre effacé.
func (s *ChallengeStore) PurgeExpired() (int64, error) {
	res, err := s.db.Exec(s.rb(`DELETE FROM mfa_challenges WHERE expires_at < ?`), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Vérifications de conformité aux interfaces de mfax.
var (
	_ mfax.TOTPStore      = (*TOTPStore)(nil)
	_ mfax.ChallengeStore = (*ChallengeStore)(nil)
	_ mfax.LockoutStore   = (*LockoutStore)(nil)
)

// LockoutStore implémente mfax.LockoutStore sur une base SQL (table mfa_lockouts).
type LockoutStore struct {
	db      *sql.DB
	dialect appconf.Dialect
}

// NewLockoutStore construit un LockoutStore sur db pour le dialecte d.
func NewLockoutStore(db *sql.DB, d appconf.Dialect) *LockoutStore {
	return &LockoutStore{db: db, dialect: d}
}

func (s *LockoutStore) rb(q string) string { return sqldialect.Rebind(s.dialect, q) }

// LockedUntil renvoie la fin du verrouillage en cours, ou l'instant zéro.
func (s *LockoutStore) LockedUntil(userID int64, now time.Time) (time.Time, error) {
	var until int64
	err := s.db.QueryRow(s.rb(`SELECT locked_until FROM mfa_lockouts WHERE user_id = ?`), userID).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	if until <= now.Unix() {
		return time.Time{}, nil
	}
	return time.Unix(until, 0), nil
}

// Fail compte un échec. L'upsert repart d'une nouvelle fenêtre si la précédente est
// close ; le verrouillage n'est posé que par l'UPDATE conditionnel (seuil atteint,
// palier inchangé) : deux échecs concurrents ne verrouillent qu'une fois.
func (s *LockoutStore) Fail(userID int64, now time.Time, p mfax.LockoutPolicy) (time.Time, error) {
	at := now.Unix()
	cutoff := now.Add(-p.Window).Unix()
	if _, err := s.db.Exec(s.rb(`INSERT INTO mfa_lockouts (user_id, failures, window_start) VALUES (?, 1, ?)
		ON CONFLICT(user_id) DO UPDATE SET
		    failures = CASE WHEN mfa_lockouts.window_start <= ? THEN 1 ELSE mfa_lockouts.failures + 1 END,
		    window_start = CASE WHEN mfa_lockouts.window_start <= ? THEN excluded.window_start ELSE mfa_lockouts.window_start END`),
		userID, at, cutoff, cutoff); err != nil {
		return time.Time{}, err
	}
	var failures, lockouts int
	if err := s.db.QueryRow(s.rb(`SELECT failures, lockouts FROM mfa_lockouts WHERE user_id = ?`), userID).
		Scan(&failures, &lockouts); err != nil {
		return time.Time{}, err
	}
	if failures < p.Threshold {
		return time.Time{}, nil
	}
	until := now.Add(p.LockDuration(lockouts)).Unix()
	res, err := s.db.Exec(s.rb(`UPDATE mfa_lockouts
		   SET failures = 0, window_start = ?, lockouts = lockouts + 1, locked_until = ?
		 WHERE user_id = ? AND failures >= ? AND lockouts = ?`),
		at, until, userID, p.Threshold, lockouts)
	if err != nil {
		return time.Time{}, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return time.Time{}, err
	}
	return time.Unix(until, 0), nil
}

// Reset efface les échecs et le palier de verrouillage de l'utilisateur.
func (s *LockoutStore) Reset(userID int64) error {
	_, err := s.db.Exec(s.rb(`DELETE FROM mfa_lockouts WHERE user_id = ?`), userID)
	return err
}
