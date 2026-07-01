package csrfx_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"leblanc.io/open-go-base/csrfx"
)

func newHandler() (http.Handler, *bool) {
	reached := new(bool)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
	return csrfx.New(csrfx.WithSecure("off")).Middleware(next), reached
}

func TestSafeMethodSetsCookieAndPasses(t *testing.T) {
	h, reached := newHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !*reached {
		t.Fatal("la requête GET aurait dû passer")
	}
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" && c.Value != "" {
			found = true
			if !c.HttpOnly {
				t.Error("le cookie CSRF doit être HttpOnly")
			}
		}
	}
	if !found {
		t.Error("aucun cookie csrf_token posé sur la requête sûre")
	}
}

func TestMutatingWithoutTokenRejected(t *testing.T) {
	h, reached := newHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "abc"})
	h.ServeHTTP(rec, req)

	if *reached {
		t.Fatal("POST sans jeton soumis ne doit pas atteindre le handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d, want 403", rec.Code)
	}
}

func TestMutatingWithMismatchRejected(t *testing.T) {
	h, reached := newHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-token"})
	req.Header.Set("X-CSRF-Token", "autre-token")
	h.ServeHTTP(rec, req)

	if *reached || rec.Code != http.StatusForbidden {
		t.Fatalf("jeton non concordant accepté: reached=%v code=%d", *reached, rec.Code)
	}
}

func TestMutatingWithMatchingHeaderPasses(t *testing.T) {
	h, reached := newHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "match"})
	req.Header.Set("X-CSRF-Token", "match")
	h.ServeHTTP(rec, req)

	if !*reached || rec.Code != http.StatusOK {
		t.Fatalf("jeton concordant (header) rejeté: reached=%v code=%d", *reached, rec.Code)
	}
}

func TestMutatingWithMatchingFormFieldPasses(t *testing.T) {
	h, reached := newHandler()
	rec := httptest.NewRecorder()
	form := url.Values{"csrf_token": {"match"}}
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "match"})
	h.ServeHTTP(rec, req)

	if !*reached || rec.Code != http.StatusOK {
		t.Fatalf("jeton concordant (champ de formulaire) rejeté: reached=%v code=%d", *reached, rec.Code)
	}
}
