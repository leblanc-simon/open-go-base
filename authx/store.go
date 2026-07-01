package authx

import "time"

// UserStore donne accès aux utilisateurs. authx ne fournit que les opérations
// dont il a besoin pour le login ; la création/édition d'utilisateurs reste à
// la charge du projet (ou d'un autre composant). Une implémentation
// database/sql prête à l'emploi est fournie dans authx/sqlstore.
type UserStore interface {
	// GetByEmail renvoie ErrUserNotFound si l'email est inconnu.
	GetByEmail(email string) (*User, error)
	// GetByID renvoie ErrUserNotFound si l'identifiant est inconnu.
	GetByID(id int64) (*User, error)
	// UpdateLastLogin horodate la dernière connexion réussie.
	UpdateLastLogin(id int64) error
}

// SessionStore persiste les sessions. Get renvoie ErrSessionNotFound si le
// token est inconnu ; une session expirée peut être renvoyée (c'est l'appelant
// qui tranche via Session.Expired). Une implémentation database/sql est fournie
// dans authx/sqlstore.
type SessionStore interface {
	Create(s *Session) error
	Get(token string) (*Session, error)
	// Touch repousse l'expiration d'une session existante (sessions glissantes).
	Touch(token string, expiresAt time.Time) error
	Delete(token string) error
	// DeleteByUser supprime toutes les sessions d'un utilisateur (déconnexion
	// globale, désactivation de compte).
	DeleteByUser(userID int64) error
	// PurgeExpired supprime les sessions expirées et renvoie le nombre effacé.
	PurgeExpired() (int64, error)
}
