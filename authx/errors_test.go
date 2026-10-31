package authx_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
)

type recordedError struct {
	status int
	code   authx.ErrorCode
	err    error
}

func recordErrors(into *[]recordedError) authx.ErrorHandler {
	return func(w http.ResponseWriter, r *http.Request, status int, code authx.ErrorCode, err error) {
		*into = append(*into, recordedError{status, code, err})
		w.WriteHeader(status)
	}
}

func loginRequest(email, password string) *http.Request {
	form := url.Values{"email": {email}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestLoginFailureCarriesStableCode(t *testing.T) {
	u := newUser(t, 1, "alice@example.org", "bon")
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, newFakeUsers(u), newFakeSessions())
	rend := &captureRenderer{}
	h := authx.NewHandlers(mgr, rend)

	for _, email := range []string{"alice@example.org", "inconnu@example.org"} {
		h.LoginPOST(httptest.NewRecorder(), loginRequest(email, "mauvais"))
		if rend.last.Code != authx.CodeInvalidCredentials {
			t.Errorf("%s : code %q, want %q", email, rend.last.Code, authx.CodeInvalidCredentials)
		}
		if rend.last.Error != authx.DefaultMessage(authx.CodeInvalidCredentials) {
			t.Errorf("%s : texte par défaut %q", email, rend.last.Error)
		}
	}
}

func TestLoginInvalidFormUsesErrorHandler(t *testing.T) {
	mgr := authx.New(appconf.Auth{}, newFakeUsers(), newFakeSessions())
	var got []recordedError
	h := authx.NewHandlers(mgr, &captureRenderer{}, authx.WithErrorHandler(recordErrors(&got)))

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.LoginPOST(rec, req)

	if rec.Code != http.StatusBadRequest || len(got) != 1 || got[0].code != authx.CodeInvalidForm {
		t.Fatalf("code %d, erreurs %+v", rec.Code, got)
	}
}

type failingSessions struct{ *fakeSessions }

func (failingSessions) Create(*authx.Session) error { return errors.New("pq: détail interne") }

func TestInternalErrorNeverLeaksCause(t *testing.T) {
	u := newUser(t, 1, "alice@example.org", "bon")
	sessions := failingSessions{newFakeSessions()}

	// Réponse par défaut : texte générique, sans la cause.
	h := authx.NewHandlers(authx.New(appconf.Auth{}, newFakeUsers(u), sessions), &captureRenderer{})
	rec := httptest.NewRecorder()
	h.LoginPOST(rec, loginRequest("alice@example.org", "bon"))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "détail") {
		t.Fatalf("code %d, corps %q", rec.Code, rec.Body.String())
	}

	// Gestionnaire du projet : il reçoit la cause pour la journaliser.
	var got []recordedError
	h = authx.NewHandlers(authx.New(appconf.Auth{}, newFakeUsers(u), sessions), &captureRenderer{},
		authx.WithErrorHandler(recordErrors(&got)))
	h.LoginPOST(httptest.NewRecorder(), loginRequest("alice@example.org", "bon"))
	if len(got) != 1 || got[0].code != authx.CodeInternal || got[0].err == nil {
		t.Fatalf("erreurs %+v", got)
	}
}

func forbiddenRequest(t *testing.T, opts ...authx.ManagerOption) *httptest.ResponseRecorder {
	t.Helper()
	u := newUser(t, 1, "alice@example.org", "bon")
	u.Role = "viewer"
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, newFakeUsers(u), newFakeSessions(), opts...)
	sess, err := mgr.OpenSession(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/login", nil), u, authx.PurposeAuth)
	if err != nil {
		t.Fatal(err)
	}
	handler := mgr.LoadSession(mgr.RequireAuth("admin")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("le handler protégé ne doit pas être atteint")
	})))
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sess.Token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestRequireAuthForbiddenUsesManagerErrorHandler(t *testing.T) {
	var got []recordedError
	rec := forbiddenRequest(t, authx.WithManagerErrorHandler(recordErrors(&got)))
	if rec.Code != http.StatusForbidden || len(got) != 1 || got[0].code != authx.CodeForbidden {
		t.Fatalf("code %d, erreurs %+v", rec.Code, got)
	}
}

func TestRequireAuthForbiddenDefaultResponse(t *testing.T) {
	rec := forbiddenRequest(t, authx.WithManagerErrorHandler(nil))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), authx.DefaultMessage(authx.CodeForbidden)) {
		t.Fatalf("code %d, corps %q", rec.Code, rec.Body.String())
	}
}

func TestDefaultMessageUnknownCode(t *testing.T) {
	if authx.DefaultMessage("nope") != "" {
		t.Fatal("un code inconnu n'a pas de texte")
	}
}
