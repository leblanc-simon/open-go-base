package mfax_test

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	_ "modernc.org/sqlite"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/mfax"
	"leblanc.io/open-go-base/mfax/sqlstore"
)

var dbSeq atomic.Int64

func lockoutStore(t *testing.T) *sqlstore.LockoutStore {
	t.Helper()
	db, err := sql.Open("sqlite", fmt.Sprintf("file:lockout_%d?mode=memory&cache=shared", dbSeq.Add(1)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := sqlstore.Migrate(db, appconf.DialectSQLite); err != nil {
		t.Fatal(err)
	}
	return sqlstore.NewLockoutStore(db, appconf.DialectSQLite)
}

type lockedEvent struct {
	user  int64
	until time.Time
}

// lockoutService : 3 codes par défi, verrouillage au 4e code faux, tous défis confondus.
func lockoutService(t *testing.T, opts ...mfax.Option) (*mfax.Service, string, *authx.User, *[]lockedEvent) {
	t.Helper()
	user := &authx.User{ID: 7, Email: "carol@example.org", IsActive: true}
	users := &fakeUsers{byID: map[int64]*authx.User{7: user}}
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, users, &fakeSessions{m: map[string]*authx.Session{}})
	totpStore := &fakeTOTP{m: map[int64]*mfax.TOTP{}}
	chs := &fakeChallenges{m: map[string]*mfax.Challenge{}}
	var events []lockedEvent
	opts = append([]mfax.Option{
		mfax.WithRenderer(&verifyRenderer{}),
		mfax.WithLockout(lockoutStore(t)),
		mfax.WithLockoutHook(func(_ *http.Request, u *authx.User, until time.Time) {
			events = append(events, lockedEvent{u.ID, until})
		}),
	}, opts...)
	svc := mfax.New(appconf.MFA{Issuer: "test", MaxAttempts: 3, LockoutThreshold: 4}, mgr, totpStore, chs, opts...)
	secret, _, err := svc.Provision(user)
	if err != nil {
		t.Fatal(err)
	}
	totpStore.m[user.ID].Enabled = true
	return svc, secret, user, &events
}

// begin ouvre un défi et renvoie son cookie (nil si Begin n'en a pas ouvert) et la
// redirection.
func begin(t *testing.T, svc *mfax.Service, user *authx.User) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	_, redirect, err := svc.Begin(rec, httptest.NewRequest(http.MethodPost, "/login", nil), user)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == svc.ChallengeCookieName() && c.Value != "" {
			return c, redirect
		}
	}
	return nil, redirect
}

func verify(svc *mfax.Service, cookie *http.Cookie, code string) *httptest.ResponseRecorder {
	form := url.Values{"code": {code}}
	req := httptest.NewRequest(http.MethodPost, "/login/2fa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	svc.VerifyPOST(rec, req)
	return rec
}

// TestLockoutSurvivesNewChallenges : rejouer le mot de passe pour ouvrir un nouveau
// défi ne remet pas le compteur à zéro ; au seuil, le compte est verrouillé et même le
// bon code est refusé, sans être examiné.
func TestLockoutSurvivesNewChallenges(t *testing.T) {
	svc, secret, user, events := lockoutService(t)

	c, _ := begin(t, svc, user)
	for range 2 {
		if rec := verify(svc, c, "000000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("code faux : %d, attendu 401", rec.Code)
		}
	}
	c, _ = begin(t, svc, user) // nouveau défi : le compteur du compte continue
	if rec := verify(svc, c, "000001"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("3e code faux : %d", rec.Code)
	}
	rec := verify(svc, c, "000002")
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusSeeOther || loc != "/login?err="+string(mfax.CodeLocked) {
		t.Fatalf("4e code faux : %d %q, attendu le verrouillage", rec.Code, loc)
	}
	if len(*events) != 1 || (*events)[0].user != user.ID {
		t.Fatalf("crochet de verrouillage : %+v", *events)
	}
	if d := time.Until((*events)[0].until); d < 14*time.Minute || d > 16*time.Minute {
		t.Errorf("premier verrouillage de %s, attendu 15 min", d)
	}
	// Le défi verrouillé est abandonné ; un nouveau mot de passe n'en ouvre pas.
	if rec := verify(svc, c, "000003"); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("défi abandonné encore utilisable : %d %q", rec.Code, rec.Header().Get("Location"))
	}
	c, redirect := begin(t, svc, user)
	if c != nil || redirect != "/login?err="+string(mfax.CodeLocked) {
		t.Fatalf("Begin d'un compte verrouillé : cookie=%v redirection %q", c != nil, redirect)
	}
	until, err := svc.LockedUntil(user.ID)
	if err != nil || until.IsZero() {
		t.Fatalf("LockedUntil : %v %v", until, err)
	}
	// Le bon code est refusé par Confirm sans être consommé.
	code, _ := totp.GenerateCode(secret, time.Now())
	if ok, err := svc.Confirm(httptest.NewRequest(http.MethodPost, "/", nil), user, code); ok || !errors.Is(err, mfax.ErrLocked) {
		t.Fatalf("Confirm d'un compte verrouillé : %v %v", ok, err)
	}
	if len(*events) != 1 {
		t.Errorf("un refus pendant le verrouillage ne doit pas reverrouiller : %d", len(*events))
	}
}

// TestLockoutResetOnSuccess : un code juste efface les échecs.
func TestLockoutResetOnSuccess(t *testing.T) {
	svc, secret, user, events := lockoutService(t)
	c, _ := begin(t, svc, user)
	for range 3 {
		verify(svc, c, "000000")
	}
	c, _ = begin(t, svc, user)
	code, _ := totp.GenerateCode(secret, time.Now())
	if rec := verify(svc, c, code); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("bon code : %d %q", rec.Code, rec.Header().Get("Location"))
	}
	c, _ = begin(t, svc, user)
	for range 3 {
		if rec := verify(svc, c, "000000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("après succès, compteur non remis à zéro : %d", rec.Code)
		}
	}
	if len(*events) != 0 {
		t.Fatalf("verrouillage inattendu : %+v", *events)
	}
}

// TestConfirmCountsFailures : la réauthentification (step-up) compte ses échecs avec
// ceux de la connexion, refuse le rejeu et efface le compteur sur un code juste.
func TestConfirmCountsFailures(t *testing.T) {
	svc, secret, user, events := lockoutService(t)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	for i := range 3 {
		if ok, err := svc.Confirm(r, user, "000000"); ok || err != nil {
			t.Fatalf("échec %d : %v %v", i, ok, err)
		}
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if ok, err := svc.Confirm(r, user, code); !ok || err != nil {
		t.Fatalf("bon code : %v %v", ok, err)
	}
	if ok, err := svc.Confirm(r, user, code); ok || err != nil {
		t.Fatalf("rejeu accepté : %v %v", ok, err)
	}
	for range 2 {
		svc.Confirm(r, user, "000000")
	}
	if ok, err := svc.Confirm(r, user, "000000"); ok || !errors.Is(err, mfax.ErrLocked) {
		t.Fatalf("4e échec depuis le succès : %v %v, attendu ErrLocked", ok, err)
	}
	if len(*events) != 1 {
		t.Fatalf("verrouillages : %d", len(*events))
	}
}

// TestConfirmWithoutLockout : sans WithLockout, Confirm valide et consomme le code.
func TestConfirmWithoutLockout(t *testing.T) {
	svc, store, _, _, user := newService(t)
	secret, _, _ := svc.Provision(user)
	store.m[user.ID].Enabled = true
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	for range 20 {
		if ok, err := svc.Confirm(r, user, "000000"); ok || err != nil {
			t.Fatalf("code faux : %v %v", ok, err)
		}
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if ok, err := svc.Confirm(r, user, code); !ok || err != nil {
		t.Fatalf("bon code : %v %v", ok, err)
	}
	if until, err := svc.LockedUntil(user.ID); !until.IsZero() || err != nil {
		t.Fatalf("LockedUntil sans verrouillage : %v %v", until, err)
	}
}

func TestDisableLockedAccount(t *testing.T) {
	svc, secret, user, _ := lockoutService(t)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	for range 4 {
		svc.Confirm(r, user, "000000")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	form := url.Values{"code": {code}}
	req := httptest.NewRequest(http.MethodPost, "/profile/totp/disable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, user)
	rec := httptest.NewRecorder()
	svc.DisablePOST(rec, req)
	if loc := rec.Header().Get("Location"); loc != "/?error="+string(mfax.CodeLocked) {
		t.Fatalf("désactivation d'un compte verrouillé : %q", loc)
	}
	if !svc.Enabled(user.ID) {
		t.Fatal("TOTP désactivé malgré le verrouillage")
	}
}

// withUser passe la requête par LoadSession avec une session authentifiée de user.
func withUser(req *http.Request, user *authx.User) *http.Request {
	sessions := &fakeSessions{m: map[string]*authx.Session{"tok": {
		Token: "tok", UserID: user.ID, Purpose: authx.PurposeAuth, ExpiresAt: time.Now().Add(time.Hour)}}}
	mgr := authx.New(appconf.Auth{CookieSecure: "off"}, &fakeUsers{byID: map[int64]*authx.User{user.ID: user}}, sessions)
	req.AddCookie(&http.Cookie{Name: "session", Value: "tok"})
	var out *http.Request
	mgr.LoadSession(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { out = r })).
		ServeHTTP(httptest.NewRecorder(), req)
	return out
}

func TestLockDuration(t *testing.T) {
	p := mfax.LockoutPolicy{Duration: 15 * time.Minute, MaxDuration: 2 * time.Hour}
	want := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 2 * time.Hour}
	for n, w := range want {
		if got := p.LockDuration(n); got != w {
			t.Errorf("verrouillage %d : %s, attendu %s", n+1, got, w)
		}
	}
	if got := p.LockDuration(1000); got != 2*time.Hour {
		t.Errorf("plafond : %s", got)
	}
}

func TestChallengeCookieName(t *testing.T) {
	svc, _, user, _ := lockoutService(t, mfax.WithChallengeCookieName("__Host-mfa_challenge"))
	if svc.ChallengeCookieName() != "__Host-mfa_challenge" {
		t.Fatalf("nom : %q", svc.ChallengeCookieName())
	}
	c, _ := begin(t, svc, user)
	if c == nil {
		t.Fatal("aucun cookie __Host-mfa_challenge posé")
	}
	if c.Path != "/" || c.Domain != "" {
		t.Errorf("cookie __Host- : Path=%q Domain=%q", c.Path, c.Domain)
	}
	if rec := verify(svc, c, "000000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("défi relu par son nouveau nom : %d", rec.Code)
	}
	def, _, _, _, _ := newService(t)
	if def.ChallengeCookieName() != mfax.ChallengeCookieName {
		t.Errorf("nom par défaut : %q", def.ChallengeCookieName())
	}
}
