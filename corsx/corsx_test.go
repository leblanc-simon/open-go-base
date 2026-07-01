package corsx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"leblanc.io/open-go-base/appconf"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestPreflightAllowsConfiguredOrigin(t *testing.T) {
	cfg := appconf.CORS{
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type"},
		MaxAge:         300,
	}
	h := Middleware(cfg)(okHandler())

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q, want https://app.example.com", got)
	}
}

func TestDisallowedOriginNotReflected(t *testing.T) {
	cfg := appconf.CORS{AllowedOrigins: []string{"https://app.example.com"}}
	h := Middleware(cfg)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("origine non autorisée reflétée: %q", got)
	}
}

// Sécurité : "*" + credentials ne doit jamais produire un wildcard permissif.
func TestWildcardWithCredentialsIsNotPermissive(t *testing.T) {
	cfg := appconf.CORS{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	}
	h := Middleware(cfg)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	origin := rec.Header().Get("Access-Control-Allow-Origin")
	creds := rec.Header().Get("Access-Control-Allow-Credentials")
	if origin == "*" && creds == "true" {
		t.Errorf("combinaison interdite servie: origin=* + credentials=true")
	}
}
