package csrfx

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"html"
	"html/template"
	"net/http"
	"strings"
)

const (
	defaultCookieName = "csrf_token"
	defaultFieldName  = "csrf_token"
	defaultHeaderName = "X-CSRF-Token"
	tokenBytes        = 32 // 256 bits
)

type ctxKey int

const ctxKeyToken ctxKey = 0

// Protector applique une protection CSRF par double soumission (double-submit
// cookie) : un cookie de jeton aléatoire est posé sur les requêtes sûres, et les
// requêtes mutantes (POST/PUT/PATCH/DELETE) doivent présenter le même jeton dans
// l'en-tête X-CSRF-Token ou le champ de formulaire csrf_token. C'est une défense
// en profondeur, à combiner avec des cookies SameSite (cf. authx).
//
// Le cookie est HttpOnly : le jeton est injecté côté serveur dans les
// formulaires via FuncMap (csrfField/csrfToken), pas lu en JavaScript.
type Protector struct {
	cookieName string
	fieldName  string
	headerName string
	secure     string // "auto" | "on" | "off"
	onFailure  http.Handler
	session    func(*http.Request) string
}

// Option configure le Protector.
type Option func(*Protector)

// WithCookieName change le nom du cookie de jeton (défaut "csrf_token").
func WithCookieName(n string) Option {
	return func(p *Protector) {
		if n != "" {
			p.cookieName = n
		}
	}
}

// WithFieldName change le nom du champ de formulaire attendu (défaut "csrf_token").
func WithFieldName(n string) Option {
	return func(p *Protector) {
		if n != "" {
			p.fieldName = n
		}
	}
}

// WithHeaderName change le nom de l'en-tête accepté (défaut "X-CSRF-Token").
func WithHeaderName(n string) Option {
	return func(p *Protector) {
		if n != "" {
			p.headerName = n
		}
	}
}

// WithSecure pilote l'attribut Secure du cookie : "auto" (Secure si TLS direct
// ou X-Forwarded-Proto=https), "on" (toujours), "off" (jamais). Défaut "auto".
func WithSecure(mode string) Option {
	return func(p *Protector) {
		switch mode {
		case "auto", "on", "off":
			p.secure = mode
		}
	}
}

// WithFailureHandler remplace la réponse d'une requête mutante refusée (jeton
// absent ou incorrect) : le projet rend ainsi une page traduite à son format. Le
// handler doit répondre 403 (Forbidden) ; il reçoit la requête avec le jeton
// courant dans le contexte (Token), ce qui permet de réafficher un formulaire.
// Un handler nil est ignoré (réponse par défaut : 403 en texte brut).
func WithFailureHandler(h http.Handler) Option {
	return func(p *Protector) {
		if h != nil {
			p.onFailure = h
		}
	}
}

// WithSessionBinding lie le jeton à la session : le jeton attendu dans le champ ou
// l'en-tête devient HMAC-SHA256(clé = valeur du cookie, message = session(r)), et non
// plus la valeur du cookie elle-même. Un attaquant qui sait écrire le cookie (depuis un
// sous-domaine, ou par une réponse HTTP en clair) ne peut plus forger un couple
// cookie-champ valable : il lui faudrait le secret de session de la victime. session
// renvoie un secret propre à la session de la requête (son jeton), ou "" sans session.
// Une session qui change (connexion, déconnexion) change le jeton attendu : un
// formulaire affiché avant est alors refusé. Une fonction nil est ignorée.
func WithSessionBinding(session func(*http.Request) string) Option {
	return func(p *Protector) {
		if session != nil {
			p.session = session
		}
	}
}

// New construit un Protector. Sans option, valeurs par défaut sûres.
func New(opts ...Option) *Protector {
	p := &Protector{
		cookieName: defaultCookieName,
		fieldName:  defaultFieldName,
		headerName: defaultHeaderName,
		secure:     "auto",
		onFailure:  http.HandlerFunc(defaultFailure),
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Middleware retourne le middleware net/http appliquant la protection. Il pose
// le cookie de jeton si absent, expose le jeton dans le contexte (cf. Token /
// FuncMap), et rejette en 403 toute requête mutante au jeton manquant ou
// incorrect. Les méthodes sûres (GET/HEAD/OPTIONS/TRACE) passent toujours.
func (p *Protector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := p.cookieToken(r)
		if token == "" {
			var err error
			if token, err = randomToken(); err != nil {
				http.Error(w, "csrf: token generation failed", http.StatusInternalServerError)
				return
			}
			p.setCookie(w, r, token)
		}
		expected := p.expectedToken(r, token)
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyToken, expected))

		if isMutating(r.Method) && !p.validToken(r, expected) {
			p.onFailure.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Token renvoie le jeton CSRF de la requête courante (posé par le middleware),
// ou "" si le middleware n'est pas monté.
func Token(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyToken).(string); ok {
		return v
	}
	return ""
}

// FuncMap fournit des helpers de template liés à la requête r : "csrfToken"
// renvoie le jeton brut, "csrfField" renvoie un <input type="hidden"> prêt à
// insérer dans un formulaire. À fusionner dans le FuncMap des templates du
// projet, par requête.
func (p *Protector) FuncMap(r *http.Request) template.FuncMap {
	tok := Token(r)
	field := template.HTML(`<input type="hidden" name="` +
		html.EscapeString(p.fieldName) + `" value="` + html.EscapeString(tok) + `">`)
	return template.FuncMap{
		"csrfToken": func() string { return tok },
		"csrfField": func() template.HTML { return field },
	}
}

func (p *Protector) cookieToken(r *http.Request) string {
	c, err := r.Cookie(p.cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// expectedToken renvoie le jeton à présenter : la valeur du cookie, ou son HMAC lié à
// la session (WithSessionBinding).
func (p *Protector) expectedToken(r *http.Request, cookieToken string) string {
	if p.session == nil {
		return cookieToken
	}
	mac := hmac.New(sha256.New, []byte(cookieToken))
	mac.Write([]byte("csrfx-session\x00"))
	mac.Write([]byte(p.session(r)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (p *Protector) validToken(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}
	sent := r.Header.Get(p.headerName)
	if sent == "" {
		sent = r.PostFormValue(p.fieldName) // déclenche ParseForm (mis en cache pour le handler)
	}
	if sent == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sent), []byte(expected)) == 1
}

func (p *Protector) setCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     p.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   p.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (p *Protector) cookieSecure(r *http.Request) bool {
	switch p.secure {
	case "on":
		return true
	case "off":
		return false
	}
	if r != nil && r.TLS != nil {
		return true
	}
	return r != nil && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func defaultFailure(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "Forbidden - CSRF token invalide", http.StatusForbidden)
}

func isMutating(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

func randomToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
