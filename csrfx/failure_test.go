package csrfx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"leblanc.io/open-go-base/csrfx"
)

func TestFailureHandlerReplacesDefaultResponse(t *testing.T) {
	var seenToken string
	failure := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenToken = csrfx.Token(r)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("page traduite"))
	})
	reached := false
	h := csrfx.New(csrfx.WithSecure("off"), csrfx.WithFailureHandler(failure)).Middleware(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "abc"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if reached {
		t.Fatal("le handler protégé ne doit pas être atteint")
	}
	if rec.Code != http.StatusForbidden || rec.Body.String() != "page traduite" {
		t.Fatalf("code %d, corps %q", rec.Code, rec.Body.String())
	}
	if seenToken != "abc" {
		t.Fatalf("jeton vu par le gestionnaire d'échec : %q", seenToken)
	}
}

func TestNilFailureHandlerKeepsDefault(t *testing.T) {
	h := csrfx.New(csrfx.WithFailureHandler(nil)).Middleware(http.NotFoundHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/action", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d, want 403", rec.Code)
	}
}
