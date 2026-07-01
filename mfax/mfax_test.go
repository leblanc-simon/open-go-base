package mfax_test

import (
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

// === Fakes ===

type fakeUsers struct{ byID map[int64]*authx.User }

func (f *fakeUsers) GetByEmail(string) (*authx.User, error) { return nil, authx.ErrUserNotFound }
func (f *fakeUsers) GetByID(id int64) (*authx.User, error) {
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return nil, authx.ErrUserNotFound
}
func (f *fakeUsers) UpdateLastLogin(int64) error { return nil }

type fakeSessions struct{ m map[string]*authx.Session }

func (f *fakeSessions) Create(s *authx.Session) error { f.m[s.Token] = s; return nil }
func (f *fakeSessions) Get(t string) (*authx.Session, error) {
	if s, ok := f.m[t]; ok {
		return s, nil
	}
	return nil, authx.ErrSessionNotFound
}
func (f *fakeSessions) Touch(t string, e time.Time) error { return nil }
func (f *fakeSessions) Delete(t string) error             { delete(f.m, t); return nil }
func (f *fakeSessions) DeleteByUser(int64) error          { return nil }
func (f *fakeSessions) PurgeExpired() (int64, error)      { return 0, nil }

type fakeTOTP struct{ m map[int64]*mfax.TOTP }

func (f *fakeTOTP) Get(uid int64) (*mfax.TOTP, error) {
	if t, ok := f.m[uid]; ok {
		return t, nil
	}
	return nil, mfax.ErrTOTPNotFound
}
func (f *fakeTOTP) Set(uid int64, secret string, enabled bool) error {
	if cur, ok := f.m[uid]; ok {
		cur.Secret, cur.Enabled = secret, enabled // LastStep préservé
		return nil
	}
	f.m[uid] = &mfax.TOTP{UserID: uid, Secret: secret, Enabled: enabled}
	return nil
}
func (f *fakeTOTP) SetLastStep(uid int64, step int64) (bool, error) {
	cur, ok := f.m[uid]
	if !ok || step <= cur.LastStep {
		return false, nil
	}
	cur.LastStep = step
	return true, nil
}
func (f *fakeTOTP) Delete(uid int64) error { delete(f.m, uid); return nil }

type fakeChallenges struct{ m map[string]*mfax.Challenge }

func (f *fakeChallenges) Create(c *mfax.Challenge) error { f.m[c.Token] = c; return nil }
func (f *fakeChallenges) Get(t string) (*mfax.Challenge, error) {
	if c, ok := f.m[t]; ok {
		return c, nil
	}
	return nil, mfax.ErrChallengeNotFound
}
func (f *fakeChallenges) IncrAttempts(t string, limit int) (bool, error) {
	c, ok := f.m[t]
	if !ok || c.Attempts >= limit {
		return false, nil
	}
	c.Attempts++
	return true, nil
}
func (f *fakeChallenges) Delete(t string) error        { delete(f.m, t); return nil }
func (f *fakeChallenges) PurgeExpired() (int64, error) { return 0, nil }

type verifyRenderer struct{ last mfax.VerifyView }

func (r *verifyRenderer) RenderVerify(w http.ResponseWriter, req *http.Request, v mfax.VerifyView) {
	r.last = v
}
func (r *verifyRenderer) RenderSetup(w http.ResponseWriter, req *http.Request, v mfax.SetupView) {}

func newService(t *testing.T, opts ...mfax.Option) (*mfax.Service, *fakeTOTP, *fakeChallenges, *fakeSessions, *authx.User) {
	t.Helper()
	user := &authx.User{ID: 7, Email: "carol@example.org", IsActive: true}
	users := &fakeUsers{byID: map[int64]*authx.User{7: user}}
	sessions := &fakeSessions{m: map[string]*authx.Session{}}
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, users, sessions)
	totpStore := &fakeTOTP{m: map[int64]*mfax.TOTP{}}
	chs := &fakeChallenges{m: map[string]*mfax.Challenge{}}
	svc := mfax.New(appconf.MFA{Issuer: "test", MaxAttempts: 3}, mgr, totpStore, chs, opts...)
	return svc, totpStore, chs, sessions, user
}

// === Tests ===

func TestProvisionThenValidate(t *testing.T) {
	svc, store, _, _, user := newService(t)
	secret, provURL, err := svc.Provision(user)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if secret == "" || !strings.HasPrefix(provURL, "otpauth://totp/") {
		t.Fatalf("provisioning inattendu: secret=%q url=%q", secret, provURL)
	}
	if store.m[user.ID].Enabled {
		t.Error("le secret doit être désactivé avant confirmation")
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	ok, err := svc.ValidateCode(user.ID, code)
	if err != nil || !ok {
		t.Fatalf("code valide rejeté: ok=%v err=%v", ok, err)
	}
	bad, _ := svc.ValidateCode(user.ID, "000000")
	if bad {
		// 000000 pourrait théoriquement coïncider ; on tolère mais c'est improbable.
		t.Log("attention: 000000 a coïncidé avec le code courant")
	}
}

func TestBeginEnrollmentRequired(t *testing.T) {
	svc, _, _, sessions, user := newService(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)

	required, redirect, err := svc.Begin(rec, req, user)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if !required || redirect != "/profile/totp/setup" {
		t.Fatalf("enrôlement: required=%v redirect=%q", required, redirect)
	}
	// Une session de setup doit avoir été ouverte.
	var setupFound bool
	for _, s := range sessions.m {
		if s.Purpose == authx.PurposeSetup {
			setupFound = true
		}
	}
	if !setupFound {
		t.Error("aucune session de setup ouverte pour l'enrôlement")
	}
}

func TestBeginOptionalEnrollmentSkips(t *testing.T) {
	svc, _, _, _, user := newService(t, mfax.WithOptionalEnrollment())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)

	required, _, err := svc.Begin(rec, req, user)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if required {
		t.Error("enrôlement facultatif: required devrait être false sans TOTP")
	}
}

func TestBeginChallengeThenVerify(t *testing.T) {
	svc, store, chs, sessions, user := newService(t, mfax.WithRenderer(&verifyRenderer{}))

	// TOTP déjà actif.
	secret, _, _ := svc.Provision(user)
	store.m[user.ID].Enabled = true

	// Begin crée un challenge et pose un cookie.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	required, redirect, err := svc.Begin(rec, req, user)
	if err != nil || !required || redirect != "/login/2fa" {
		t.Fatalf("begin challenge: required=%v redirect=%q err=%v", required, redirect, err)
	}
	if len(chs.m) != 1 {
		t.Fatalf("challenge non créé: %d", len(chs.m))
	}
	chCookie := rec.Result().Cookies()[0]

	// VerifyPOST avec le bon code.
	code, _ := totp.GenerateCode(secret, time.Now())
	form := url.Values{"code": {code}}
	vreq := httptest.NewRequest(http.MethodPost, "/login/2fa", strings.NewReader(form.Encode()))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vreq.AddCookie(chCookie)
	vrec := httptest.NewRecorder()
	svc.VerifyPOST(vrec, vreq)

	if vrec.Code != http.StatusSeeOther {
		t.Fatalf("verify: code %d, want 303", vrec.Code)
	}
	if len(chs.m) != 0 {
		t.Error("le challenge doit être supprimé après succès")
	}
	var authOpened bool
	for _, s := range sessions.m {
		if s.Purpose == authx.PurposeAuth {
			authOpened = true
		}
	}
	if !authOpened {
		t.Error("aucune session authentifiée ouverte après vérification")
	}
}

// TestSetupGETPreservesActiveSecret verrouille le correctif : un GET sur la page
// de configuration ne doit jamais écraser un secret TOTP déjà actif (sinon un
// préchargement de lien ou une CSRF GET désactiverait silencieusement la 2FA).
func TestSetupGETPreservesActiveSecret(t *testing.T) {
	user := &authx.User{ID: 7, Email: "carol@example.org", IsActive: true}
	users := &fakeUsers{byID: map[int64]*authx.User{7: user}}
	sessions := &fakeSessions{m: map[string]*authx.Session{}}
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, users, sessions)
	totpStore := &fakeTOTP{m: map[int64]*mfax.TOTP{}}
	chs := &fakeChallenges{m: map[string]*mfax.Challenge{}}
	svc := mfax.New(appconf.MFA{Issuer: "test"}, mgr, totpStore, chs, mfax.WithRenderer(&verifyRenderer{}))

	// 2FA déjà active.
	secret, _, _ := svc.Provision(user)
	totpStore.m[user.ID].Enabled = true

	// Session authentifiée portée par un cookie.
	sessions.m["tok"] = &authx.Session{
		Token: "tok", UserID: user.ID, Purpose: authx.PurposeAuth,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	handler := mgr.LoadSession(http.HandlerFunc(svc.SetupGET))
	req := httptest.NewRequest(http.MethodGet, "/profile/totp/setup", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "tok"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code %d, want 303 (re-provisionnement refusé)", rec.Code)
	}
	if got := totpStore.m[user.ID]; got.Secret != secret || !got.Enabled {
		t.Fatalf("secret TOTP actif altéré par un GET: secret==before:%v enabled:%v", got.Secret == secret, got.Enabled)
	}
}

// TestVerifyRejectsCodeReplay verrouille l'anti-rejeu : un code TOTP valide ne
// peut servir qu'une fois, même au sein de sa fenêtre de validité.
func TestVerifyRejectsCodeReplay(t *testing.T) {
	svc, store, _, _, user := newService(t, mfax.WithRenderer(&verifyRenderer{}))
	secret, _, _ := svc.Provision(user)
	store.m[user.ID].Enabled = true

	doVerify := func(code string) int {
		rec := httptest.NewRecorder()
		svc.Begin(rec, httptest.NewRequest(http.MethodPost, "/login", nil), user)
		chCookie := rec.Result().Cookies()[0]
		form := url.Values{"code": {code}}
		vreq := httptest.NewRequest(http.MethodPost, "/login/2fa", strings.NewReader(form.Encode()))
		vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		vreq.AddCookie(chCookie)
		vrec := httptest.NewRecorder()
		svc.VerifyPOST(vrec, vreq)
		return vrec.Code
	}

	code, _ := totp.GenerateCode(secret, time.Now())
	if got := doVerify(code); got != http.StatusSeeOther {
		t.Fatalf("1ère vérification: code %d, want 303", got)
	}
	if got := doVerify(code); got != http.StatusUnauthorized {
		t.Fatalf("rejeu du même code accepté: code %d, want 401", got)
	}
}

// TestDisableRequiresValidCode verrouille le step-up : désactiver la 2FA exige
// un code TOTP valide.
func TestDisableRequiresValidCode(t *testing.T) {
	user := &authx.User{ID: 7, Email: "carol@example.org", IsActive: true}
	users := &fakeUsers{byID: map[int64]*authx.User{7: user}}
	sessions := &fakeSessions{m: map[string]*authx.Session{}}
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, users, sessions)
	totpStore := &fakeTOTP{m: map[int64]*mfax.TOTP{}}
	chs := &fakeChallenges{m: map[string]*mfax.Challenge{}}
	svc := mfax.New(appconf.MFA{Issuer: "test"}, mgr, totpStore, chs, mfax.WithRenderer(&verifyRenderer{}))

	secret, _, _ := svc.Provision(user)
	totpStore.m[user.ID].Enabled = true
	sessions.m["tok"] = &authx.Session{
		Token: "tok", UserID: user.ID, Purpose: authx.PurposeAuth,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	disable := func(code string) {
		handler := mgr.LoadSession(http.HandlerFunc(svc.DisablePOST))
		form := url.Values{}
		if code != "" {
			form.Set("code", code)
		}
		req := httptest.NewRequest(http.MethodPost, "/profile/totp/disable", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "session", Value: "tok"})
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// Code invalide : la 2FA reste active.
	disable("invalid")
	if _, err := totpStore.Get(user.ID); err != nil {
		t.Fatalf("2FA désactivée sans code valide: %v", err)
	}

	// Code valide : désactivation effective.
	code, _ := totp.GenerateCode(secret, time.Now())
	disable(code)
	if _, err := totpStore.Get(user.ID); err != mfax.ErrTOTPNotFound {
		t.Fatalf("2FA aurait dû être désactivée: %v", err)
	}
}

func TestVerifyRejectsBadCode(t *testing.T) {
	rend := &verifyRenderer{}
	svc, store, chs, _, user := newService(t, mfax.WithRenderer(rend))
	svc.Provision(user)
	store.m[user.ID].Enabled = true

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	svc.Begin(rec, req, user)
	chCookie := rec.Result().Cookies()[0]

	form := url.Values{"code": {"123456"}}
	vreq := httptest.NewRequest(http.MethodPost, "/login/2fa", strings.NewReader(form.Encode()))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vreq.AddCookie(chCookie)
	vrec := httptest.NewRecorder()
	svc.VerifyPOST(vrec, vreq)

	if vrec.Code != http.StatusUnauthorized {
		t.Fatalf("code %d, want 401", vrec.Code)
	}
	if rend.last.Error == "" {
		t.Error("attendu un message d'erreur")
	}
	for _, c := range chs.m {
		if c.Attempts != 1 {
			t.Errorf("attempts = %d, want 1", c.Attempts)
		}
	}
}
