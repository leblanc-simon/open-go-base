// Package sqlstore fournit une implémentation database/sql des stores de authx
// (UserStore, SessionStore) et les migrations du schéma associé.
//
// Plusieurs dialectes sont gérés (SQLite, PostgreSQL) ; le dialecte est passé à
// Migrate et aux constructeurs via appconf.Dialect (typiquement
// cfg.Database.Dialect()). Les migrations vivent dans un sous-dossier par
// dialecte (migrations/<dialecte>/). Le driver n'est pas importé ici : le projet
// ouvre son *sql.DB et le passe à New / Migrate.
package sqlstore

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/internal/sqldialect"
	"leblanc.io/open-go-base/internal/sqlmigrate"
)

//go:embed migrations
var migrationsFS embed.FS

// ErrUnsupportedDialect signale un dialecte sans migrations fournies (p. ex.
// MySQL, prévu mais pas encore livré).
var ErrUnsupportedDialect = errors.New("authx/sqlstore: unsupported SQL dialect")

func supported(d appconf.Dialect) bool {
	return d == appconf.DialectSQLite || d == appconf.DialectPostgres
}

// Migrate applique les migrations du schéma authx (tables users, sessions) pour
// le dialecte d. Idempotent : sûr à appeler à chaque démarrage.
func Migrate(db *sql.DB, d appconf.Dialect) error {
	if !supported(d) {
		return fmt.Errorf("%w: %q", ErrUnsupportedDialect, d)
	}
	return sqlmigrate.Run(db, migrationsFS, "migrations/"+d.String(), d)
}

// UserStore implémente authx.UserStore sur une base SQL. Il n'expose que la
// lecture et la mise à jour de last_login dont authx a besoin ; la
// création/édition d'utilisateurs relève du projet.
type UserStore struct {
	db      *sql.DB
	dialect appconf.Dialect
}

// NewUserStore construit un UserStore sur db pour le dialecte d.
func NewUserStore(db *sql.DB, d appconf.Dialect) *UserStore { return &UserStore{db: db, dialect: d} }

func (s *UserStore) rb(q string) string { return sqldialect.Rebind(s.dialect, q) }

const userColumns = `id, email, password_hash, role, is_active, must_change_pwd, created_at, last_login`

func scanUser(row interface{ Scan(...any) error }) (*authx.User, error) {
	u := &authx.User{}
	var isActive, mustChange int
	var role string
	var lastLogin sql.NullTime
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &role, &isActive, &mustChange, &u.CreatedAt, &lastLogin); err != nil {
		return nil, err
	}
	u.Role = authx.Role(role)
	u.IsActive = isActive == 1
	u.MustChangePwd = mustChange == 1
	if lastLogin.Valid {
		t := lastLogin.Time
		u.LastLogin = &t
	}
	return u, nil
}

// GetByEmail renvoie authx.ErrUserNotFound si l'email est inconnu.
func (s *UserStore) GetByEmail(email string) (*authx.User, error) {
	row := s.db.QueryRow(s.rb(`SELECT `+userColumns+` FROM users WHERE email = ?`), email)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authx.ErrUserNotFound
	}
	return u, err
}

// GetByID renvoie authx.ErrUserNotFound si l'identifiant est inconnu.
func (s *UserStore) GetByID(id int64) (*authx.User, error) {
	row := s.db.QueryRow(s.rb(`SELECT `+userColumns+` FROM users WHERE id = ?`), id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, authx.ErrUserNotFound
	}
	return u, err
}

// UpdateLastLogin horodate la dernière connexion réussie.
func (s *UserStore) UpdateLastLogin(id int64) error {
	_, err := s.db.Exec(s.rb(`UPDATE users SET last_login = ? WHERE id = ?`), time.Now().UTC(), id)
	return err
}

// Create insère un utilisateur (confort pour le bootstrap et les tests du
// projet ; hors interface authx.UserStore). passwordHash doit déjà être un hash
// authx.HashPassword. La récupération de l'ID généré diffère selon le dialecte
// (RETURNING en PostgreSQL, LastInsertId ailleurs).
func (s *UserStore) Create(email, passwordHash string, role authx.Role, mustChangePwd bool) (*authx.User, error) {
	const insert = `INSERT INTO users (email, password_hash, role, must_change_pwd) VALUES (?, ?, ?, ?)`
	if s.dialect == appconf.DialectPostgres {
		var id int64
		err := s.db.QueryRow(s.rb(insert+` RETURNING id`), email, passwordHash, string(role), boolToInt(mustChangePwd)).Scan(&id)
		if err != nil {
			return nil, err
		}
		return s.GetByID(id)
	}
	res, err := s.db.Exec(s.rb(insert), email, passwordHash, string(role), boolToInt(mustChangePwd))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetByID(id)
}

// SessionStore implémente authx.SessionStore sur une base SQL.
type SessionStore struct {
	db      *sql.DB
	dialect appconf.Dialect
}

// NewSessionStore construit un SessionStore sur db pour le dialecte d.
func NewSessionStore(db *sql.DB, d appconf.Dialect) *SessionStore {
	return &SessionStore{db: db, dialect: d}
}

func (s *SessionStore) rb(q string) string { return sqldialect.Rebind(s.dialect, q) }

// Create persiste une session.
func (s *SessionStore) Create(sess *authx.Session) error {
	_, err := s.db.Exec(
		s.rb(`INSERT INTO sessions (token, user_id, purpose, expires_at, user_agent, ip) VALUES (?, ?, ?, ?, ?, ?)`),
		sess.Token, sess.UserID, string(sess.Purpose), sess.ExpiresAt.UTC(), sess.UserAgent, sess.IP,
	)
	return err
}

// Get renvoie authx.ErrSessionNotFound si le token est inconnu.
func (s *SessionStore) Get(token string) (*authx.Session, error) {
	row := s.db.QueryRow(
		s.rb(`SELECT token, user_id, purpose, expires_at, user_agent, ip FROM sessions WHERE token = ?`), token,
	)
	var sess authx.Session
	var purpose string
	var ua, ip sql.NullString
	if err := row.Scan(&sess.Token, &sess.UserID, &purpose, &sess.ExpiresAt, &ua, &ip); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, authx.ErrSessionNotFound
		}
		return nil, err
	}
	sess.Purpose = authx.Purpose(purpose)
	sess.UserAgent = ua.String
	sess.IP = ip.String
	return &sess, nil
}

// Touch repousse l'expiration d'une session existante.
func (s *SessionStore) Touch(token string, expiresAt time.Time) error {
	_, err := s.db.Exec(s.rb(`UPDATE sessions SET expires_at = ? WHERE token = ?`), expiresAt.UTC(), token)
	return err
}

// Delete supprime une session par son token.
func (s *SessionStore) Delete(token string) error {
	_, err := s.db.Exec(s.rb(`DELETE FROM sessions WHERE token = ?`), token)
	return err
}

// DeleteByUser supprime toutes les sessions d'un utilisateur.
func (s *SessionStore) DeleteByUser(userID int64) error {
	_, err := s.db.Exec(s.rb(`DELETE FROM sessions WHERE user_id = ?`), userID)
	return err
}

// PurgeExpired supprime les sessions expirées et renvoie le nombre effacé.
func (s *SessionStore) PurgeExpired() (int64, error) {
	res, err := s.db.Exec(s.rb(`DELETE FROM sessions WHERE expires_at < ?`), time.Now().UTC())
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

// Vérifications de conformité aux interfaces de authx.
var (
	_ authx.UserStore    = (*UserStore)(nil)
	_ authx.SessionStore = (*SessionStore)(nil)
)
