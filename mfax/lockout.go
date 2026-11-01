package mfax

import (
	"errors"
	"net/http"
	"time"

	"leblanc.io/open-go-base/authx"
)

const (
	defaultLockoutThreshold   = 10
	defaultLockoutWindow      = 15 * time.Minute
	defaultLockoutDuration    = 15 * time.Minute
	defaultLockoutMaxDuration = 24 * time.Hour
)

// ErrLocked est renvoyée par Confirm quand le compte est verrouillé : trop de codes
// faux récents. Le code soumis n'est alors pas examiné.
var ErrLocked = errors.New("mfax: account locked")

// LockoutPolicy borne les codes faux d'un compte, tous défis confondus : au-delà de
// Threshold échecs dans une fenêtre de Window ouverte au premier échec, le compte est
// verrouillé pendant Duration, durée doublée à chaque verrouillage suivant (plafond
// MaxDuration). Un code juste efface le compteur et le palier.
type LockoutPolicy struct {
	Threshold   int
	Window      time.Duration
	Duration    time.Duration
	MaxDuration time.Duration
}

// LockDuration renvoie la durée du verrouillage numéro n+1 (n verrouillages déjà subis
// depuis le dernier code juste).
func (p LockoutPolicy) LockDuration(n int) time.Duration {
	d := p.Duration
	for i := 0; i < n && d < p.MaxDuration; i++ {
		d *= 2
	}
	return min(d, p.MaxDuration)
}

// LockoutStore persiste les échecs de code par utilisateur. Le compteur vit hors des
// défis : en ouvrir un nouveau (en rejouant le mot de passe) ne le remet pas à zéro.
// Une implémentation database/sql est fournie dans mfax/sqlstore.
type LockoutStore interface {
	// LockedUntil renvoie la fin du verrouillage en cours à l'instant now, ou l'instant
	// zéro si le compte n'est pas verrouillé.
	LockedUntil(userID int64, now time.Time) (time.Time, error)
	// Fail enregistre un échec à now selon p, atomiquement. S'il atteint le seuil, il
	// verrouille le compte et renvoie la fin du verrouillage ; sinon l'instant zéro.
	Fail(userID int64, now time.Time, p LockoutPolicy) (time.Time, error)
	// Reset efface les échecs et le palier de verrouillage (code juste, ou levée du
	// verrouillage par un administrateur).
	Reset(userID int64) error
}

// LockoutHook est appelé quand un échec verrouille un compte, jusqu'à until (journal
// d'audit, alerte). Il ne doit pas écrire de réponse.
type LockoutHook func(r *http.Request, user *authx.User, until time.Time)

// WithLockout active le verrouillage par compte, réglé par les champs Lockout* de
// appconf.MFA (valeurs nulles : 10 échecs en 15 min, verrouillage de 15 min doublé à
// chaque récidive, 24 h au plus). Sans cette option, seul le plafond de tentatives par
// défi s'applique, qu'un nouveau défi remet à zéro.
func WithLockout(store LockoutStore) Option { return func(s *Service) { s.lockout = store } }

// WithLockoutHook fournit le crochet appelé à chaque verrouillage.
func WithLockoutHook(h LockoutHook) Option { return func(s *Service) { s.onLock = h } }

// LockedUntil renvoie la fin du verrouillage en cours de userID (instant zéro sans
// verrouillage, ou sans WithLockout).
func (s *Service) LockedUntil(userID int64) (time.Time, error) {
	if s.lockout == nil {
		return time.Time{}, nil
	}
	return s.lockout.LockedUntil(userID, time.Now())
}

// Confirm vérifie et consomme un code TOTP de user hors du parcours de connexion :
// réauthentification avant une action sensible (step-up). Il applique l'anti-rejeu et
// le verrouillage par compte : un compte verrouillé reçoit ErrLocked sans que le code
// soit examiné, un code faux compte comme un échec, un code juste efface le compteur.
func (s *Service) Confirm(r *http.Request, user *authx.User, code string) (bool, error) {
	return s.confirm(r, user, func() (bool, error) { return s.consumeCode(user.ID, code) })
}

// confirm applique le verrouillage par compte autour de check, qui vérifie et consomme un
// code (TOTP ou de secours).
func (s *Service) confirm(r *http.Request, user *authx.User, check func() (bool, error)) (bool, error) {
	if until, err := s.LockedUntil(user.ID); err != nil {
		return false, err
	} else if !until.IsZero() {
		return false, ErrLocked
	}
	valid, err := check()
	if err != nil {
		return false, err
	}
	if !valid {
		locked, err := s.recordFailure(r, user)
		if err != nil {
			return false, err
		}
		if locked {
			return false, ErrLocked
		}
		return false, nil
	}
	if s.lockout != nil {
		if err := s.lockout.Reset(user.ID); err != nil {
			return false, err
		}
	}
	return true, nil
}

// recordFailure compte un code faux ; il renvoie true si cet échec verrouille le compte.
func (s *Service) recordFailure(r *http.Request, user *authx.User) (bool, error) {
	if s.lockout == nil {
		return false, nil
	}
	until, err := s.lockout.Fail(user.ID, time.Now(), s.policy)
	if err != nil || until.IsZero() {
		return false, err
	}
	if s.onLock != nil {
		s.onLock(r, user, until)
	}
	return true, nil
}

func lockoutPolicy(t int, window, d, maxD time.Duration) LockoutPolicy {
	p := LockoutPolicy{Threshold: t, Window: window, Duration: d, MaxDuration: maxD}
	if p.Threshold <= 0 {
		p.Threshold = defaultLockoutThreshold
	}
	if p.Window <= 0 {
		p.Window = defaultLockoutWindow
	}
	if p.Duration <= 0 {
		p.Duration = defaultLockoutDuration
	}
	if p.MaxDuration <= 0 {
		p.MaxDuration = defaultLockoutMaxDuration
	}
	p.MaxDuration = max(p.MaxDuration, p.Duration)
	return p
}
