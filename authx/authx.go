package authx

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role est le rôle applicatif d'un utilisateur. authx ne fige aucune liste de
// rôles : un projet définit les valeurs qui lui conviennent et les passe à
// RequireAuth.
type Role string

// Purpose distingue une session pleinement authentifiée d'une session
// intermédiaire de configuration (p. ex. forcer un premier changement de mot de
// passe ou la configuration de la 2FA avant tout accès).
type Purpose string

const (
	PurposeAuth  Purpose = "auth"  // session normale, pleinement authentifiée
	PurposeSetup Purpose = "setup" // session restreinte aux pages de configuration
)

// User est l'utilisateur tel que vu par authx. PasswordHash n'est jamais
// sérialisé. Les champs propres à la 2FA ne vivent pas ici : mfax possède son
// propre schéma (table dédiée).
type User struct {
	ID            int64      `json:"id"`
	Email         string     `json:"email"`
	PasswordHash  string     `json:"-"`
	Role          Role       `json:"role"`
	IsActive      bool       `json:"is_active"`
	MustChangePwd bool       `json:"must_change_pwd"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLogin     *time.Time `json:"last_login,omitempty"`
}

// Session est une session persistée. Token est un secret aléatoire de 256 bits
// (clé opaque), jamais dérivé d'une donnée utilisateur.
type Session struct {
	Token     string
	UserID    int64
	Purpose   Purpose
	ExpiresAt time.Time
	UserAgent string
	IP        string
}

// Expired indique si la session est expirée à l'instant now.
func (s *Session) Expired(now time.Time) bool { return !s.ExpiresAt.After(now) }

var (
	// ErrUserNotFound est renvoyée par UserStore quand aucun utilisateur ne
	// correspond. Les handlers la traitent comme un échec d'authentification
	// générique (jamais distingué d'un mot de passe invalide côté réponse).
	ErrUserNotFound = errors.New("authx: user not found")
	// ErrSessionNotFound est renvoyée par SessionStore quand le token est inconnu.
	ErrSessionNotFound = errors.New("authx: session not found")
	// ErrInvalidCredentials signale un couple email/mot de passe invalide.
	ErrInvalidCredentials = errors.New("authx: invalid credentials")
)

// prehash réduit un mot de passe de longueur arbitraire à 44 octets (base64 de
// son SHA-256) avant de le passer à bcrypt. bcrypt ignore silencieusement tout
// octet au-delà du 72e (et s'arrête au premier octet NUL) : sans pré-hachage,
// deux mots de passe partageant leurs 72 premiers octets seraient équivalents.
// Schéma « bcrypt(base64(sha256(pwd))) », identique à Django/Dropbox ; le base64
// garantit l'absence d'octet NUL dans l'entrée bcrypt.
//
// IMPORTANT : ce format diffère d'un bcrypt direct. Des hash produits avant son
// introduction ne valident plus — les mots de passe concernés doivent être
// re-hachés (re-saisie ou réinitialisation).
func prehash(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	enc := base64.StdEncoding.EncodeToString(sum[:])
	return []byte(enc)
}

// HashPassword renvoie le hash bcrypt d'un mot de passe en clair (pré-haché en
// SHA-256, cf. prehash). cost <= 0 retombe sur bcrypt.DefaultCost.
func HashPassword(plain string, cost int) (string, error) {
	if cost <= 0 {
		cost = bcrypt.DefaultCost
	}
	h, err := bcrypt.GenerateFromPassword(prehash(plain), cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// CheckPassword renvoie nil si le mot de passe correspond au hash, ou
// ErrInvalidCredentials sinon. Toute autre erreur bcrypt (hash corrompu) est
// remontée telle quelle.
func CheckPassword(hash, plain string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), prehash(plain))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrInvalidCredentials
	}
	return err
}

// dummyPassword est comparé à un hash factice dans le chemin d'échec du login
// (email inconnu / compte inactif) pour égaliser le temps de réponse : sans ça,
// l'absence de calcul bcrypt révélerait par timing qu'un compte n'existe pas.
const dummyPassword = "anti-enumeration-dummy"

// newDummyHash précalcule un hash bcrypt factice au coût cost (clampé dans la
// plage bcrypt valide, défaut sinon), pour servir d'égaliseur de timing.
func newDummyHash(cost int) string {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	h, err := bcrypt.GenerateFromPassword([]byte(dummyPassword), cost)
	if err != nil {
		return ""
	}
	return string(h)
}

// RandomToken génère un token aléatoire de 32 octets (256 bits) en hexadécimal,
// adapté aux clés de session et de challenge.
func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
