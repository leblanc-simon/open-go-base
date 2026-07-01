package authx

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Renderer rend les pages dont authx a besoin. Le projet l'implémente avec son
// moteur de templates : authx fournit les données, le projet le HTML.
type Renderer interface {
	// RenderLogin affiche le formulaire de connexion. Il est appelé sur GET
	// /login et après un échec d'authentification (View.Error renseigné).
	RenderLogin(w http.ResponseWriter, r *http.Request, view LoginView)
}

// LoginView porte les données du formulaire de connexion.
type LoginView struct {
	Next  string // destination post-login à préserver dans le formulaire
	Email string // email pré-rempli après un échec
	Error string // message d'erreur à afficher (vide = formulaire vierge)
}

// SecondFactor intercale une étape de vérification après la validation du mot de
// passe. mfax l'implémente ; un projet sans 2FA laisse ce hook nil.
type SecondFactor interface {
	// Begin est appelé après un mot de passe valide. S'il renvoie required=true,
	// le login s'interrompt et redirige vers redirectURL (le second facteur prend
	// la main, typiquement après avoir posé son propre cookie de challenge ou
	// ouvert une session de configuration). S'il renvoie required=false, le login
	// ouvre immédiatement une session pleinement authentifiée.
	Begin(w http.ResponseWriter, r *http.Request, user *User) (required bool, redirectURL string, err error)
}

// Handlers regroupe les handlers HTTP de connexion. Construire via NewHandlers.
type Handlers struct {
	mgr      *Manager
	renderer Renderer
	sf       SecondFactor
	homePath string
}

// HandlerOption configure les Handlers.
type HandlerOption func(*Handlers)

// WithSecondFactor branche une étape de second facteur (p. ex. mfax).
func WithSecondFactor(sf SecondFactor) HandlerOption {
	return func(h *Handlers) { h.sf = sf }
}

// WithHomePath définit la destination par défaut après connexion (défaut "/").
func WithHomePath(p string) HandlerOption {
	return func(h *Handlers) {
		if p != "" {
			h.homePath = p
		}
	}
}

// NewHandlers construit les handlers de connexion sur un Manager et un Renderer.
func NewHandlers(mgr *Manager, renderer Renderer, opts ...HandlerOption) *Handlers {
	h := &Handlers{mgr: mgr, renderer: renderer, homePath: "/"}
	for _, o := range opts {
		o(h)
	}
	return h
}

// LoginGET affiche le formulaire de connexion ; redirige vers l'accueil si une
// session auth est déjà active.
func (h *Handlers) LoginGET(w http.ResponseWriter, r *http.Request) {
	if sess := SessionFrom(r); sess != nil && sess.Purpose == PurposeAuth {
		http.Redirect(w, r, h.homePath, http.StatusSeeOther)
		return
	}
	h.renderer.RenderLogin(w, r, LoginView{Next: r.URL.Query().Get("next")})
}

// LoginPOST traite la soumission du formulaire : vérifie le mot de passe, puis
// délègue au second facteur s'il est configuré, sinon ouvre la session.
//
// Réponse volontairement générique en cas d'échec (jamais distinguer email
// inconnu de mot de passe erroné), pour ne pas faciliter l'énumération.
func (h *Handlers) LoginPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.PostForm.Get("email")))
	password := r.PostForm.Get("password")
	next := r.PostForm.Get("next")

	fail := func() {
		h.renderer.RenderLogin(w, r, LoginView{Next: next, Email: email, Error: "Identifiants invalides"})
	}

	user, err := h.mgr.users.GetByEmail(email)
	if err != nil || !user.IsActive {
		// Égalise le temps de réponse : on exécute une comparaison bcrypt même
		// en l'absence de compte valide, pour ne pas révéler son existence par
		// canal temporel (le message d'erreur, lui, est déjà générique).
		_ = CheckPassword(h.mgr.dummyHash, password)
		fail()
		return
	}
	if err := CheckPassword(user.PasswordHash, password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			fail()
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if h.sf != nil {
		required, redirectURL, err := h.sf.Begin(w, r, user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if required {
			http.Redirect(w, r, withNext(redirectURL, next), http.StatusSeeOther)
			return
		}
	}

	if _, err := h.mgr.OpenSession(w, r, user, PurposeAuth); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, SafeRedirectPath(next, h.homePath), http.StatusSeeOther)
}

// Logout supprime la session et redirige vers /login.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	h.mgr.Logout(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// RedirectToLogin redirige vers /login en conservant la cible courante dans
// ?next= (utilisé par RequireAuth).
func RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Path
	if r.URL.RawQuery != "" {
		next += "?" + r.URL.RawQuery
	}
	target := "/login"
	if next != "/" && next != "/login" {
		target += "?next=" + url.QueryEscape(next)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// ClientIP renvoie l'IP du client (sans port). X-Forwarded-For (premier saut)
// prime s'il est présent, sinon RemoteAddr est nettoyé de son port. Pour une
// résolution sûre derrière des proxys non fiables, composer avec le composant
// ratelimit côté projet.
func ClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		return strings.TrimSpace(v)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// isLocalPath indique si p est un chemin local sûr pour une redirection : il
// commence par "/", n'est pas protocol-relative ("//", ni "/\" que les
// navigateurs normalisent en "//" → open redirect), et ne contient aucun
// caractère de contrôle (anti-injection CRLF dans l'en-tête Location).
func isLocalPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	if len(p) > 1 && (p[1] == '/' || p[1] == '\\') {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return false
		}
	}
	return true
}

// SafeRedirectPath n'accepte qu'un chemin local (cf. isLocalPath), sinon retombe
// sur fallback. Empêche les redirections ouvertes via ?next=//evil.example ou
// ?next=/\evil.example. Exporté pour être réutilisé par les autres composants
// (p. ex. mfax après vérification du second facteur).
func SafeRedirectPath(next, fallback string) string {
	if isLocalPath(next) {
		return next
	}
	return fallback
}

// withNext ajoute ?next= à une URL si next est un chemin local non vide.
func withNext(base, next string) string {
	if !isLocalPath(next) {
		return base
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "next=" + url.QueryEscape(next)
}
