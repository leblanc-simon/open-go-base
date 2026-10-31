package mfax_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/mfax"
)

type setupRenderer struct {
	verifyRenderer
	setup mfax.SetupView
}

func (r *setupRenderer) RenderSetup(w http.ResponseWriter, req *http.Request, v mfax.SetupView) {
	r.setup = v
}

func formRequest(target string, form url.Values, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

// beginChallenge active le TOTP de user et renvoie le cookie de challenge et le secret.
func beginChallenge(t *testing.T, svc *mfax.Service, store *fakeTOTP, user *authx.User) (*http.Cookie, string) {
	t.Helper()
	secret, _, err := svc.Provision(user)
	if err != nil {
		t.Fatal(err)
	}
	store.m[user.ID].Enabled = true
	rec := httptest.NewRecorder()
	if _, _, err := svc.Begin(rec, httptest.NewRequest(http.MethodPost, "/login", nil), user); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0], secret
}

func TestVerifyBadCodeCarriesStableCode(t *testing.T) {
	rend := &verifyRenderer{}
	svc, store, _, _, user := newService(t, mfax.WithRenderer(rend))
	ch, _ := beginChallenge(t, svc, store, user)
	if ch.Name != mfax.ChallengeCookieName {
		t.Fatalf("cookie %q, want %q", ch.Name, mfax.ChallengeCookieName)
	}
	svc.VerifyPOST(httptest.NewRecorder(), formRequest("/login/2fa", url.Values{"code": {"000000"}}, ch))
	if rend.last.Code != mfax.CodeInvalidCode || rend.last.Error != mfax.DefaultMessage(mfax.CodeInvalidCode) {
		t.Fatalf("vue %+v", rend.last)
	}
}

func TestValidCodeCarriesNoErrorCode(t *testing.T) {
	rend := &verifyRenderer{}
	svc, store, _, _, user := newService(t, mfax.WithRenderer(rend))
	ch, secret := beginChallenge(t, svc, store, user)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	svc.VerifyPOST(rec, formRequest("/login/2fa", url.Values{"code": {code}}, ch))
	if rec.Code != http.StatusSeeOther || rend.last.Code != "" {
		t.Fatalf("code %d, vue %+v", rec.Code, rend.last)
	}
}

func TestVerifyExhaustedRedirectsWithCode(t *testing.T) {
	svc, store, _, _, user := newService(t, mfax.WithRenderer(&verifyRenderer{}))
	ch, _ := beginChallenge(t, svc, store, user)
	var last *httptest.ResponseRecorder
	for range 4 { // MaxAttempts vaut 3 dans newService
		last = httptest.NewRecorder()
		svc.VerifyPOST(last, formRequest("/login/2fa", url.Values{"code": {"000000"}}, ch))
	}
	if loc := last.Header().Get("Location"); loc != "/login?err="+string(mfax.CodeAttemptsExhausted) {
		t.Fatalf("redirection %q", loc)
	}
}

// withSession ouvre une session authentifiée et renvoie le Manager qui la lit.
func withSession(t *testing.T, sessions *fakeSessions, user *authx.User) (*authx.Manager, *http.Cookie) {
	t.Helper()
	sessions.m["tok"] = &authx.Session{Token: "tok", UserID: user.ID, Purpose: authx.PurposeAuth, ExpiresAt: time.Now().Add(time.Hour)}
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, &fakeUsers{byID: map[int64]*authx.User{user.ID: user}}, sessions)
	return mgr, &http.Cookie{Name: "session", Value: "tok"}
}

func TestSetupNeverReflectsArbitraryErrorText(t *testing.T) {
	rend := &setupRenderer{}
	svc, _, _, sessions, user := newService(t, mfax.WithRenderer(rend))
	mgr, cookie := withSession(t, sessions, user)

	for query, want := range map[string]mfax.ErrorCode{
		"?error=invalid_code":              mfax.CodeInvalidCode,
		"?error=Votre+compte+est+suspendu": "",
		"":                                 "",
	} {
		req := httptest.NewRequest(http.MethodGet, "/profile/totp/setup"+query, nil)
		req.AddCookie(cookie)
		mgr.LoadSession(http.HandlerFunc(svc.SetupGET)).ServeHTTP(httptest.NewRecorder(), req)
		if rend.setup.Code != want || rend.setup.Error != mfax.DefaultMessage(want) {
			t.Errorf("%q : vue %+v", query, rend.setup)
		}
	}
}

func TestEnableAndDisableRedirectWithCode(t *testing.T) {
	svc, store, _, sessions, user := newService(t, mfax.WithRenderer(&setupRenderer{}))
	mgr, cookie := withSession(t, sessions, user)
	if _, _, err := svc.Provision(user); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	mgr.LoadSession(http.HandlerFunc(svc.EnablePOST)).ServeHTTP(rec, formRequest("/profile/totp/enable", url.Values{"code": {"000000"}}, cookie))
	if loc := rec.Header().Get("Location"); loc != "/profile/totp/setup?error=invalid_code" {
		t.Fatalf("enable : redirection %q", loc)
	}

	store.m[user.ID].Enabled = true
	rec = httptest.NewRecorder()
	mgr.LoadSession(http.HandlerFunc(svc.DisablePOST)).ServeHTTP(rec, formRequest("/profile/totp/disable", url.Values{"code": {"000000"}}, cookie))
	if loc := rec.Header().Get("Location"); loc != "/?error=invalid_code" {
		t.Fatalf("disable : redirection %q", loc)
	}
}

type recordedError struct {
	status int
	code   mfax.ErrorCode
	err    error
}

type failingTOTP struct{ *fakeTOTP }

func (failingTOTP) Get(int64) (*mfax.TOTP, error) { return nil, errors.New("pq: détail interne") }

func TestErrorHandlerReceivesFormAndInternalErrors(t *testing.T) {
	var got []recordedError
	eh := mfax.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, status int, code mfax.ErrorCode, err error) {
		got = append(got, recordedError{status, code, err})
		w.WriteHeader(status)
	})

	svc, _, _, _, _ := newService(t, eh)
	req := httptest.NewRequest(http.MethodPost, "/login/2fa", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.VerifyPOST(rec, req)
	if rec.Code != http.StatusBadRequest || len(got) != 1 || got[0].code != mfax.CodeInvalidForm {
		t.Fatalf("formulaire : code %d, erreurs %+v", rec.Code, got)
	}

	// VerifyGET avec un challenge valide mais sans renderer : erreur interne.
	svc, store, _, _, user := newService(t, eh)
	ch, _ := beginChallenge(t, svc, store, user)
	vreq := httptest.NewRequest(http.MethodGet, "/login/2fa", nil)
	vreq.AddCookie(ch)
	svc.VerifyGET(httptest.NewRecorder(), vreq)
	if len(got) != 2 || got[1].code != mfax.CodeInternal || got[1].err == nil {
		t.Fatalf("interne : erreurs %+v", got)
	}
}

func TestInternalErrorDefaultResponseHidesCause(t *testing.T) {
	sessions := &fakeSessions{m: map[string]*authx.Session{}}
	user := &authx.User{ID: 7, Email: "carol@example.org", IsActive: true}
	mgr, cookie := withSession(t, sessions, user)
	svc := mfax.New(appconf.MFA{}, mgr, failingTOTP{&fakeTOTP{m: map[int64]*mfax.TOTP{}}}, &fakeChallenges{m: map[string]*mfax.Challenge{}})

	rec := httptest.NewRecorder()
	mgr.LoadSession(http.HandlerFunc(svc.DisablePOST)).ServeHTTP(rec, formRequest("/profile/totp/disable", url.Values{"code": {"000000"}}, cookie))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "détail") {
		t.Fatalf("code %d, corps %q", rec.Code, rec.Body.String())
	}
}
