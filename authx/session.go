package authx

import (
	"context"
	"net/http"
	"strings"
	"time"

	"leblanc.io/open-go-base/appconf"
)

const (
	defaultCookieName = "session"
	defaultSessionTTL = 12 * time.Hour
)

type ctxKey int

const (
	ctxKeyUser ctxKey = iota
	ctxKeySession
)

// Manager câble les stores et la configuration de session. Il fournit le
// middleware de chargement de session, le garde RequireAuth, et les opérations
// d'ouverture/fermeture de session utilisées par les handlers (et par mfax pour
// finaliser une session après vérification du second facteur).
type Manager struct {
	cfg       appconf.Auth
	users     UserStore
	sessions  SessionStore
	dummyHash string // hash bcrypt factice, égaliseur de timing au login
}

// New construit un Manager à partir d'un fragment appconf.Auth et des stores du
// projet. Les valeurs nulles de cfg retombent sur des défauts sûrs.
func New(cfg appconf.Auth, users UserStore, sessions SessionStore) *Manager {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.CookieName == "" {
		cfg.CookieName = defaultCookieName
	}
	if cfg.CookieSecure == "" {
		cfg.CookieSecure = "auto"
	}
	return &Manager{
		cfg: cfg, users: users, sessions: sessions,
		dummyHash: newDummyHash(cfg.BcryptCost),
	}
}

// Users expose le UserStore sous-jacent (pratique pour les composants qui
// partagent le même store, p. ex. mfax).
func (m *Manager) Users() UserStore { return m.users }

// UserFrom renvoie l'utilisateur attaché à la requête par LoadSession, ou nil.
func UserFrom(r *http.Request) *User {
	if v, ok := r.Context().Value(ctxKeyUser).(*User); ok {
		return v
	}
	return nil
}

// SessionFrom renvoie la session attachée à la requête par LoadSession, ou nil.
func SessionFrom(r *http.Request) *Session {
	if v, ok := r.Context().Value(ctxKeySession).(*Session); ok {
		return v
	}
	return nil
}

// LoadSession lit le cookie de session, charge l'utilisateur, l'attache au
// contexte et fait glisser l'expiration des sessions auth. Il ne refuse jamais
// une requête : c'est RequireAuth qui le fait. Une session invalide/expirée ou
// pointant vers un compte inactif est purgée silencieusement.
func (m *Manager) LoadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(m.cfg.CookieName)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		sess, err := m.sessions.Get(c.Value)
		if err != nil || sess.Expired(time.Now()) {
			m.clearCookie(w, r)
			if err == nil {
				_ = m.sessions.Delete(sess.Token)
			}
			next.ServeHTTP(w, r)
			return
		}
		user, err := m.users.GetByID(sess.UserID)
		if err != nil || !user.IsActive {
			_ = m.sessions.Delete(sess.Token)
			m.clearCookie(w, r)
			next.ServeHTTP(w, r)
			return
		}
		// Glisse l'expiration à chaque accès, sauf pour les sessions de setup.
		if sess.Purpose == PurposeAuth {
			newExp := time.Now().Add(m.cfg.SessionTTL)
			_ = m.sessions.Touch(sess.Token, newExp)
			sess.ExpiresAt = newExp
			m.setCookie(w, r, sess.Token, newExp)
		}
		ctx := context.WithValue(r.Context(), ctxKeyUser, user)
		ctx = context.WithValue(ctx, ctxKeySession, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAuth redirige vers /login si la requête n'est pas authentifiée. Si des
// rôles sont fournis, l'utilisateur doit en posséder un (sinon 403). Une session
// de purpose=setup est rejetée ici : seul le projet décide quelles routes de
// configuration l'acceptent (en n'y plaçant pas RequireAuth, ou via SetupOnly).
func (m *Manager) RequireAuth(roles ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFrom(r)
			if user == nil {
				RedirectToLogin(w, r)
				return
			}
			if sess := SessionFrom(r); sess != nil && sess.Purpose != PurposeAuth {
				RedirectToLogin(w, r)
				return
			}
			if len(roles) > 0 && !hasRole(user.Role, roles) {
				http.Error(w, "Accès interdit", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hasRole(have Role, allowed []Role) bool {
	for _, r := range allowed {
		if have == r {
			return true
		}
	}
	return false
}

// OpenSession crée une session persistée pour user, pose le cookie et, pour une
// session auth, horodate la dernière connexion. mfax l'appelle pour finaliser
// une session après vérification du second facteur.
func (m *Manager) OpenSession(w http.ResponseWriter, r *http.Request, user *User, purpose Purpose) (*Session, error) {
	token, err := RandomToken()
	if err != nil {
		return nil, err
	}
	exp := time.Now().Add(m.cfg.SessionTTL)
	sess := &Session{
		Token: token, UserID: user.ID, Purpose: purpose,
		ExpiresAt: exp, UserAgent: r.UserAgent(), IP: ClientIP(r),
	}
	if err := m.sessions.Create(sess); err != nil {
		return nil, err
	}
	m.setCookie(w, r, token, exp)
	if purpose == PurposeAuth {
		_ = m.users.UpdateLastLogin(user.ID)
	}
	return sess, nil
}

// Elevate remplace la session courante (typiquement de purpose=setup) par une
// session pleinement authentifiée. mfax l'utilise pour finaliser l'enrôlement
// 2FA : configurer son second facteur depuis une session de setup donne accès
// au reste de l'application sans repasser par le formulaire de connexion.
func (m *Manager) Elevate(w http.ResponseWriter, r *http.Request, user *User) (*Session, error) {
	if sess := SessionFrom(r); sess != nil {
		_ = m.sessions.Delete(sess.Token)
	}
	return m.OpenSession(w, r, user, PurposeAuth)
}

// Logout supprime la session courante et efface le cookie. Sans session active,
// il se contente d'effacer le cookie.
func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) {
	if sess := SessionFrom(r); sess != nil {
		_ = m.sessions.Delete(sess.Token)
	} else if c, err := r.Cookie(m.cfg.CookieName); err == nil && c.Value != "" {
		_ = m.sessions.Delete(c.Value)
	}
	m.clearCookie(w, r)
}

func (m *Manager) setCookie(w http.ResponseWriter, r *http.Request, token string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cfg.CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   m.CookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (m *Manager) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.CookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// CookieSecure décide de l'attribut Secure selon cfg.CookieSecure. En mode
// "auto", true ssi la connexion est TLS directe ou terminée en https par un
// reverse-proxy (X-Forwarded-Proto). Exporté pour que les composants qui posent
// leurs propres cookies (p. ex. mfax) appliquent la même politique.
func (m *Manager) CookieSecure(r *http.Request) bool {
	switch m.cfg.CookieSecure {
	case "on":
		return true
	case "off":
		return false
	}
	if r != nil && r.TLS != nil {
		return true
	}
	if r != nil && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}
