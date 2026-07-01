package authx_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
)

// === Fakes en mémoire ===

type fakeUsers struct {
	byID    map[int64]*authx.User
	byEmail map[string]*authx.User
}

func newFakeUsers(us ...*authx.User) *fakeUsers {
	f := &fakeUsers{byID: map[int64]*authx.User{}, byEmail: map[string]*authx.User{}}
	for _, u := range us {
		f.byID[u.ID] = u
		f.byEmail[u.Email] = u
	}
	return f
}

func (f *fakeUsers) GetByEmail(email string) (*authx.User, error) {
	if u, ok := f.byEmail[email]; ok {
		return u, nil
	}
	return nil, authx.ErrUserNotFound
}

func (f *fakeUsers) GetByID(id int64) (*authx.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return nil, authx.ErrUserNotFound
}

func (f *fakeUsers) UpdateLastLogin(id int64) error {
	if u, ok := f.byID[id]; ok {
		now := time.Now()
		u.LastLogin = &now
	}
	return nil
}

type fakeSessions struct{ m map[string]*authx.Session }

func newFakeSessions() *fakeSessions { return &fakeSessions{m: map[string]*authx.Session{}} }

func (f *fakeSessions) Create(s *authx.Session) error { f.m[s.Token] = s; return nil }
func (f *fakeSessions) Get(token string) (*authx.Session, error) {
	if s, ok := f.m[token]; ok {
		return s, nil
	}
	return nil, authx.ErrSessionNotFound
}
func (f *fakeSessions) Touch(token string, exp time.Time) error {
	if s, ok := f.m[token]; ok {
		s.ExpiresAt = exp
	}
	return nil
}
func (f *fakeSessions) Delete(token string) error { delete(f.m, token); return nil }
func (f *fakeSessions) DeleteByUser(uid int64) error {
	for t, s := range f.m {
		if s.UserID == uid {
			delete(f.m, t)
		}
	}
	return nil
}
func (f *fakeSessions) PurgeExpired() (int64, error) {
	var n int64
	for t, s := range f.m {
		if s.Expired(time.Now()) {
			delete(f.m, t)
			n++
		}
	}
	return n, nil
}

type captureRenderer struct{ last authx.LoginView }

func (c *captureRenderer) RenderLogin(w http.ResponseWriter, r *http.Request, v authx.LoginView) {
	c.last = v
	w.WriteHeader(http.StatusOK)
}

func newUser(t *testing.T, id int64, email, pwd string) *authx.User {
	t.Helper()
	hash, err := authx.HashPassword(pwd, 4) // coût bas pour des tests rapides
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return &authx.User{ID: id, Email: email, PasswordHash: hash, IsActive: true}
}

// === Tests ===

func TestPasswordRoundTrip(t *testing.T) {
	h, err := authx.HashPassword("s3cret-passphrase", 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := authx.CheckPassword(h, "s3cret-passphrase"); err != nil {
		t.Errorf("mot de passe correct rejeté: %v", err)
	}
	if err := authx.CheckPassword(h, "mauvais"); err != authx.ErrInvalidCredentials {
		t.Errorf("attendu ErrInvalidCredentials, obtenu %v", err)
	}
}

func TestSafeRedirectPath(t *testing.T) {
	cases := map[string]string{
		"/dashboard":          "/dashboard",
		"//evil.example":      "/",
		"/\\evil.example":     "/", // backslash normalisé en // par les navigateurs
		"https://evil":        "/",
		"":                    "/",
		"relative":            "/",
		"/a?b=c":              "/a?b=c",
		"/a\r\nSet-Cookie: x": "/", // caractères de contrôle (anti-CRLF)
	}
	for in, want := range cases {
		if got := authx.SafeRedirectPath(in, "/"); got != want {
			t.Errorf("SafeRedirectPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoginSuccessThenAuthenticatedRequest(t *testing.T) {
	u := newUser(t, 1, "alice@example.org", "correct horse battery")
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, newFakeUsers(u), newFakeSessions())
	rend := &captureRenderer{}
	h := authx.NewHandlers(mgr, rend)

	// Login.
	form := url.Values{"email": {"alice@example.org"}, "password": {"correct horse battery"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.LoginPOST(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: code %d, want 303", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("aucun cookie de session posé")
	}
	sessionCookie := cookies[0]
	if !sessionCookie.HttpOnly {
		t.Error("cookie de session non HttpOnly")
	}

	// Requête authentifiée derrière LoadSession + RequireAuth.
	var seen *authx.User
	protected := mgr.LoadSession(mgr.RequireAuth()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = authx.UserFrom(r)
		w.WriteHeader(http.StatusNoContent)
	})))
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	protected.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNoContent {
		t.Fatalf("requête protégée: code %d, want 204", rec2.Code)
	}
	if seen == nil || seen.Email != "alice@example.org" {
		t.Fatalf("utilisateur non attaché au contexte: %+v", seen)
	}
}

func TestLoginWrongPasswordRendersGenericError(t *testing.T) {
	u := newUser(t, 1, "alice@example.org", "bon")
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, newFakeUsers(u), newFakeSessions())
	rend := &captureRenderer{}
	h := authx.NewHandlers(mgr, rend)

	form := url.Values{"email": {"alice@example.org"}, "password": {"mauvais"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.LoginPOST(rec, req)

	if rend.last.Error == "" {
		t.Error("attendu un message d'erreur affiché")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("aucun cookie ne doit être posé sur un échec")
	}
}

func TestRequireAuthRedirectsAnonymous(t *testing.T) {
	mgr := authx.New(appconf.Auth{}, newFakeUsers(), newFakeSessions())
	handler := mgr.LoadSession(mgr.RequireAuth()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("le handler protégé ne doit pas être atteint")
	})))
	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code %d, want 303", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?next=") {
		t.Errorf("redirection inattendue: %q", loc)
	}
}

func TestSecondFactorInterceptsLogin(t *testing.T) {
	u := newUser(t, 1, "bob@example.org", "pw")
	sessions := newFakeSessions()
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, newFakeUsers(u), sessions)
	sf := &fakeSecondFactor{redirect: "/login/2fa"}
	h := authx.NewHandlers(mgr, &captureRenderer{}, authx.WithSecondFactor(sf))

	form := url.Values{"email": {"bob@example.org"}, "password": {"pw"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.LoginPOST(rec, req)

	if !sf.called {
		t.Fatal("le second facteur n'a pas été consulté")
	}
	if loc := rec.Header().Get("Location"); loc != "/login/2fa" {
		t.Errorf("redirection = %q, want /login/2fa", loc)
	}
	// Aucune session auth ne doit être ouverte tant que le 2e facteur n'a pas réussi.
	if len(sessions.m) != 0 {
		t.Errorf("session ouverte prématurément: %d", len(sessions.m))
	}
}

type fakeSecondFactor struct {
	redirect string
	called   bool
}

func (f *fakeSecondFactor) Begin(w http.ResponseWriter, r *http.Request, u *authx.User) (bool, string, error) {
	f.called = true
	return true, f.redirect, nil
}
