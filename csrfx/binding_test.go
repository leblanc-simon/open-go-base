package csrfx_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"leblanc.io/open-go-base/csrfx"
)

// sessionOf lit un secret de session factice dans le cookie "session".
func sessionOf(r *http.Request) string {
	if c, err := r.Cookie("session"); err == nil {
		return c.Value
	}
	return ""
}

func boundHandler(name string) (http.Handler, *string) {
	seen := new(string)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = csrfx.Token(r)
		w.WriteHeader(http.StatusOK)
	})
	opts := []csrfx.Option{csrfx.WithSecure("on"), csrfx.WithSessionBinding(sessionOf)}
	if name != "" {
		opts = append(opts, csrfx.WithCookieName(name))
	}
	return csrfx.New(opts...).Middleware(next), seen
}

func post(h http.Handler, cookies map[string]string, field string) int {
	form := url.Values{"csrf_token": {field}}
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for n, v := range cookies {
		req.AddCookie(&http.Cookie{Name: n, Value: v})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestSessionBindingDefeatsCookieTossing : un attaquant qui pose lui-même le cookie
// CSRF (sous-domaine, HTTP en clair) et soumet la même valeur dans le champ est refusé
// dès que le jeton est lié à la session.
func TestSessionBindingDefeatsCookieTossing(t *testing.T) {
	h, _ := boundHandler("")
	if code := post(h, map[string]string{"csrf_token": "posé-par-l-attaquant", "session": "secret-de-la-victime"},
		"posé-par-l-attaquant"); code != http.StatusForbidden {
		t.Fatalf("double soumission naïve acceptée malgré la liaison : %d", code)
	}
}

// TestSessionBindingAcceptsRenderedToken : le jeton rendu dans le formulaire (Token)
// passe pour la même session, et seulement pour elle.
func TestSessionBindingAcceptsRenderedToken(t *testing.T) {
	h, seen := boundHandler("")
	req := httptest.NewRequest(http.MethodGet, "/form", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "valeur-du-cookie"})
	req.AddCookie(&http.Cookie{Name: "session", Value: "s1"})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if *seen == "" || *seen == "valeur-du-cookie" {
		t.Fatalf("jeton rendu %q : attendu un HMAC distinct du cookie", *seen)
	}
	rendered := *seen
	if code := post(h, map[string]string{"csrf_token": "valeur-du-cookie", "session": "s1"}, rendered); code != http.StatusOK {
		t.Fatalf("jeton rendu refusé : %d", code)
	}
	if code := post(h, map[string]string{"csrf_token": "valeur-du-cookie", "session": "s2"}, rendered); code != http.StatusForbidden {
		t.Fatalf("jeton d'une autre session accepté : %d", code)
	}
	if code := post(h, map[string]string{"csrf_token": "autre-cookie", "session": "s1"}, rendered); code != http.StatusForbidden {
		t.Fatalf("jeton d'un autre cookie accepté : %d", code)
	}
}

// TestHostPrefixedCookie : le préfixe __Host- passe par WithCookieName ; le cookie posé
// en respecte les règles (Secure, Path=/, sans Domain).
func TestHostPrefixedCookie(t *testing.T) {
	h, _ := boundHandler("__Host-csrf_token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-csrf_token" {
			found = true
			if !c.Secure || c.Path != "/" || c.Domain != "" {
				t.Errorf("cookie __Host- invalide : Secure=%v Path=%q Domain=%q", c.Secure, c.Path, c.Domain)
			}
		}
	}
	if !found {
		t.Fatal("cookie __Host-csrf_token absent")
	}
}
