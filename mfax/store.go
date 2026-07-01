package mfax

import (
	"errors"
	"time"
)

var (
	// ErrTOTPNotFound est renvoyée par TOTPStore quand l'utilisateur n'a aucun
	// secret TOTP enregistré.
	ErrTOTPNotFound = errors.New("mfax: totp not found")
	// ErrChallengeNotFound est renvoyée par ChallengeStore quand le token est
	// inconnu.
	ErrChallengeNotFound = errors.New("mfax: challenge not found")
)

// TOTP est le secret TOTP d'un utilisateur. Enabled distingue un secret
// provisoire (en cours de configuration, non confirmé) d'un secret actif.
// LastStep est le dernier pas de temps TOTP consommé avec succès : il sert à
// rejeter le rejeu d'un code déjà utilisé (un code n'est accepté que pour un pas
// strictement supérieur). Comme le pas dérive du temps, il croît toujours.
type TOTP struct {
	UserID   int64
	Secret   string
	Enabled  bool
	LastStep int64
}

// Challenge est un ticket « mot de passe vérifié, en attente du code TOTP », lié
// à un utilisateur et borné dans le temps et en nombre de tentatives.
type Challenge struct {
	Token     string
	UserID    int64
	Attempts  int
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Expired indique si le challenge est expiré à l'instant now.
func (c *Challenge) Expired(now time.Time) bool { return !c.ExpiresAt.After(now) }

// TOTPStore persiste le secret TOTP par utilisateur (table dédiée : mfax ne
// touche pas au schéma de authx). Une implémentation database/sql est fournie
// dans mfax/sqlstore.
type TOTPStore interface {
	// Get renvoie ErrTOTPNotFound si l'utilisateur n'a pas de secret.
	Get(userID int64) (*TOTP, error)
	// Set crée ou remplace le secret de l'utilisateur, avec son état
	// d'activation. LastStep n'est pas réinitialisé (le pas étant temporel, un
	// ancien pas ne peut pas bloquer un code futur).
	Set(userID int64, secret string, enabled bool) error
	// SetLastStep avance atomiquement le dernier pas consommé et renvoie true si
	// l'avancée a eu lieu (step strictement supérieur au pas enregistré). Un
	// false signale un rejeu ou une consommation concurrente du même pas.
	SetLastStep(userID int64, step int64) (bool, error)
	// Delete supprime le secret de l'utilisateur.
	Delete(userID int64) error
}

// ChallengeStore persiste les challenges TOTP en attente.
type ChallengeStore interface {
	Create(c *Challenge) error
	// Get renvoie ErrChallengeNotFound si le token est inconnu.
	Get(token string) (*Challenge, error)
	// IncrAttempts incrémente atomiquement le compteur de tentatives du
	// challenge et renvoie true si l'incrément a eu lieu (tentative autorisée),
	// false si le plafond limit était déjà atteint (ou token inconnu).
	// L'atomicité protège contre les requêtes concurrentes : un test-puis-
	// incrément non atomique laisserait dépasser le plafond.
	IncrAttempts(token string, limit int) (bool, error)
	Delete(token string) error
	// PurgeExpired supprime les challenges expirés et renvoie le nombre effacé.
	PurgeExpired() (int64, error)
}
