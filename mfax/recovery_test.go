package mfax_test

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/mfax"
	"leblanc.io/open-go-base/mfax/sqlstore"
)

// recoveryRenderer retient la dernière vue de chaque page, codes de secours compris.
type recoveryRenderer struct {
	verifyRenderer
	codes *mfax.RecoveryCodesView
}

func (r *recoveryRenderer) RenderRecoveryCodes(_ http.ResponseWriter, _ *http.Request, v mfax.RecoveryCodesView) {
	r.codes = &v
}

type recoveryEvent struct {
	user      int64
	remaining int
}

func recoveryStore(t *testing.T) *sqlstore.RecoveryStore {
	t.Helper()
	db, err := sql.Open("sqlite", fmt.Sprintf("file:recovery_%d?mode=memory&cache=shared", dbSeq.Add(1)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := sqlstore.Migrate(db, appconf.DialectSQLite); err != nil {
		t.Fatal(err)
	}
	return sqlstore.NewRecoveryStore(db, appconf.DialectSQLite)
}

// recoveryService : service à verrouillage (seuil 4, 3 tentatives par défi) avec codes de
// secours ; renvoie aussi le renderer et les événements du crochet.
func recoveryService(t *testing.T, opts ...mfax.Option) (*mfax.Service, string, *authx.User, *recoveryRenderer, *[]recoveryEvent) {
	t.Helper()
	rend := &recoveryRenderer{}
	var events []recoveryEvent
	opts = append([]mfax.Option{
		mfax.WithRenderer(rend),
		mfax.WithRecoveryCodes(recoveryStore(t)),
		mfax.WithRecoveryHook(func(_ *http.Request, u *authx.User, remaining int) {
			events = append(events, recoveryEvent{u.ID, remaining})
		}),
	}, opts...)
	svc, secret, user, _ := lockoutService(t, opts...)
	return svc, secret, user, rend, &events
}

func verifyRecovery(svc *mfax.Service, cookie *http.Cookie, code string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	svc.VerifyPOST(rec, formRequest("/login/2fa", url.Values{"recovery_code": {code}, "next": {"/projets"}}, cookie))
	return rec
}

var displayedCode = regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{4}(-[0-9a-hjkmnp-tv-z]{4}){3}$`)

func TestGenerateRecoveryCodes(t *testing.T) {
	svc, _, user, _, _ := recoveryService(t)
	if !svc.RecoveryEnabled() {
		t.Fatal("RecoveryEnabled : false")
	}
	codes, err := svc.GenerateRecoveryCodes(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("%d codes, attendu 10 par défaut", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if !displayedCode.MatchString(c) {
			t.Errorf("format d'affichage inattendu : %q", c)
		}
		if seen[c] {
			t.Errorf("code en double : %q", c)
		}
		seen[c] = true
	}
	if n, err := svc.RecoveryRemaining(user.ID); n != 10 || err != nil {
		t.Fatalf("restants : %d %v", n, err)
	}

	// Une régénération invalide l'ancien jeu.
	if _, err := svc.GenerateRecoveryCodes(user.ID); err != nil {
		t.Fatal(err)
	}
	c, _ := begin(t, svc, user)
	if rec := verifyRecovery(svc, c, codes[0]); rec.Code != http.StatusUnauthorized {
		t.Fatalf("code d'un ancien jeu : %d, attendu 401", rec.Code)
	}
}

func TestRecoveryCodesCountFromConfig(t *testing.T) {
	for cfg, want := range map[int]int{0: 10, 3: 3, 500: 50} {
		user := &authx.User{ID: 1, Email: "a@example.org", IsActive: true}
		mgr := authx.New(appconf.Auth{}, &fakeUsers{byID: map[int64]*authx.User{1: user}}, &fakeSessions{m: map[string]*authx.Session{}})
		svc := mfax.New(appconf.MFA{RecoveryCodes: cfg}, mgr, &fakeTOTP{m: map[int64]*mfax.TOTP{}},
			&fakeChallenges{m: map[string]*mfax.Challenge{}}, mfax.WithRecoveryCodes(recoveryStore(t)))
		codes, err := svc.GenerateRecoveryCodes(user.ID)
		if err != nil || len(codes) != want {
			t.Errorf("recovery_codes=%d : %d codes (%v), attendu %d", cfg, len(codes), err, want)
		}
	}
}

// TestRecoveryCodeLogin : un code de secours ouvre la session, une seule fois ; la saisie
// tolère majuscules, espaces et absence de tirets.
func TestRecoveryCodeLogin(t *testing.T) {
	svc, _, user, rend, events := recoveryService(t)
	codes, err := svc.GenerateRecoveryCodes(user.ID)
	if err != nil {
		t.Fatal(err)
	}

	c, _ := begin(t, svc, user)
	rend.last = mfax.VerifyView{}
	get := httptest.NewRequest(http.MethodGet, "/login/2fa", nil)
	get.AddCookie(c)
	svc.VerifyGET(httptest.NewRecorder(), get)
	if !rend.last.Recovery {
		t.Error("VerifyView.Recovery : false avec WithRecoveryCodes")
	}

	typed := " " + strings.ToUpper(strings.ReplaceAll(codes[0], "-", " ")) + " "
	rec := verifyRecovery(svc, c, typed)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/projets" {
		t.Fatalf("connexion par code de secours : %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if len(*events) != 1 || (*events)[0] != (recoveryEvent{user.ID, 9}) {
		t.Fatalf("crochet : %+v, attendu un appel avec 9 restants", *events)
	}

	// Le même code est refusé ensuite.
	c, _ = begin(t, svc, user)
	rec = verifyRecovery(svc, c, codes[0])
	if rec.Code != http.StatusUnauthorized || rend.last.Code != mfax.CodeInvalidRecoveryCode ||
		rend.last.Error != mfax.DefaultMessage(mfax.CodeInvalidRecoveryCode) || !rend.last.Recovery {
		t.Fatalf("code réutilisé : %d %+v", rec.Code, rend.last)
	}
	if n, _ := svc.RecoveryRemaining(user.ID); n != 9 {
		t.Errorf("restants : %d, attendu 9", n)
	}
}

func TestRecoveryLanding(t *testing.T) {
	svc, secret, user, _, _ := recoveryService(t, mfax.WithRecoveryLanding("/account/security"))
	codes, _ := svc.GenerateRecoveryCodes(user.ID)
	c, _ := begin(t, svc, user)
	if loc := verifyRecovery(svc, c, codes[1]).Header().Get("Location"); loc != "/account/security" {
		t.Fatalf("arrivée après un code de secours : %q", loc)
	}
	// Un code TOTP garde la redirection habituelle.
	c, _ = begin(t, svc, user)
	code, _ := totp.GenerateCode(secret, time.Now())
	if loc := verify(svc, c, code).Header().Get("Location"); loc != "/" {
		t.Fatalf("arrivée après un code TOTP : %q", loc)
	}
}

// TestRecoveryCodesFeedLockout : les codes de secours faux comptent dans le verrouillage par
// compte, et un compte verrouillé refuse même un bon code de secours.
func TestRecoveryCodesFeedLockout(t *testing.T) {
	svc, _, user, _, events := recoveryService(t)
	codes, _ := svc.GenerateRecoveryCodes(user.ID)

	c, _ := begin(t, svc, user)
	for i := range 3 {
		if rec := verifyRecovery(svc, c, fmt.Sprintf("aaaa-bbbb-cccc-000%d", i)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("code de secours faux %d : %d", i, rec.Code)
		}
	}
	// Plafond du défi atteint : abandon.
	if rec := verifyRecovery(svc, c, codes[0]); rec.Header().Get("Location") != "/login?err="+string(mfax.CodeAttemptsExhausted) {
		t.Fatalf("plafond du défi : %q", rec.Header().Get("Location"))
	}
	c, _ = begin(t, svc, user)
	if rec := verifyRecovery(svc, c, "pas un code"); rec.Header().Get("Location") != "/login?err="+string(mfax.CodeLocked) {
		t.Fatalf("4e échec : %d %q, attendu le verrouillage", rec.Code, rec.Header().Get("Location"))
	}
	if ok, err := svc.ConfirmRecovery(httptest.NewRequest(http.MethodPost, "/", nil), user, codes[0]); ok || !errors.Is(err, mfax.ErrLocked) {
		t.Fatalf("ConfirmRecovery d'un compte verrouillé : %v %v", ok, err)
	}
	if n, _ := svc.RecoveryRemaining(user.ID); n != 10 {
		t.Errorf("un code a été consommé pendant le verrouillage : %d restants", n)
	}
	if len(*events) != 0 {
		t.Errorf("crochet appelé sans code consommé : %+v", *events)
	}
}

func TestConfirmRecovery(t *testing.T) {
	svc, _, user, _, events := recoveryService(t)
	codes, _ := svc.GenerateRecoveryCodes(user.ID)
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if ok, err := svc.ConfirmRecovery(r, user, "0000-0000-0000-0000"); ok || err != nil {
		t.Fatalf("code faux : %v %v", ok, err)
	}
	if ok, err := svc.ConfirmRecovery(r, user, codes[2]); !ok || err != nil {
		t.Fatalf("bon code : %v %v", ok, err)
	}
	if ok, _ := svc.ConfirmRecovery(r, user, codes[2]); ok {
		t.Fatal("code de secours accepté deux fois")
	}
	if len(*events) != 1 || (*events)[0].remaining != 9 {
		t.Fatalf("crochet : %+v", *events)
	}
}

func TestEnableShowsRecoveryCodes(t *testing.T) {
	svc, store, _, sessions, user := newService(t)
	rend := &recoveryRenderer{}
	svc = mfax.New(appconf.MFA{Issuer: "test", MaxAttempts: 3}, mgrOf(sessions, user), store,
		&fakeChallenges{m: map[string]*mfax.Challenge{}}, mfax.WithRenderer(rend), mfax.WithRecoveryCodes(recoveryStore(t)))
	mgr, cookie := withSession(t, sessions, user)
	secret, _, err := svc.Provision(user)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	rec := httptest.NewRecorder()
	mgr.LoadSession(http.HandlerFunc(svc.EnablePOST)).ServeHTTP(rec, formRequest("/profile/totp/enable", url.Values{"code": {code}}, cookie))
	if rec.Code != http.StatusOK || rend.codes == nil {
		t.Fatalf("enable : %d, codes montrés : %v", rec.Code, rend.codes != nil)
	}
	if len(rend.codes.Codes) != 10 || !rend.codes.Enrollment || rend.codes.Next != "/" {
		t.Fatalf("vue : %+v", rend.codes)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control : %q", cc)
	}
	if !svc.Enabled(user.ID) {
		t.Error("TOTP non activé")
	}
	if n, _ := svc.RecoveryRemaining(user.ID); n != 10 {
		t.Errorf("restants : %d", n)
	}
}

func mgrOf(sessions *fakeSessions, user *authx.User) *authx.Manager {
	return authx.New(appconf.Auth{CookieSecure: "off"}, &fakeUsers{byID: map[int64]*authx.User{user.ID: user}}, sessions)
}

// TestEnableWithoutRecoveryRenderer : WithRecoveryCodes exige une Renderer qui sache montrer
// les codes ; à défaut, erreur interne plutôt qu'un jeu de codes jamais montré.
func TestEnableWithoutRecoveryRenderer(t *testing.T) {
	_, store, _, sessions, user := newService(t)
	var got []recordedError
	svc := mfax.New(appconf.MFA{Issuer: "test"}, mgrOf(sessions, user), store, &fakeChallenges{m: map[string]*mfax.Challenge{}},
		mfax.WithRenderer(&setupRenderer{}), mfax.WithRecoveryCodes(recoveryStore(t)),
		mfax.WithErrorHandler(func(w http.ResponseWriter, _ *http.Request, status int, code mfax.ErrorCode, err error) {
			got = append(got, recordedError{status, code, err})
			w.WriteHeader(status)
		}))
	mgr, cookie := withSession(t, sessions, user)
	secret, _, _ := svc.Provision(user)
	code, _ := totp.GenerateCode(secret, time.Now())
	rec := httptest.NewRecorder()
	mgr.LoadSession(http.HandlerFunc(svc.EnablePOST)).ServeHTTP(rec, formRequest("/profile/totp/enable", url.Values{"code": {code}}, cookie))
	if rec.Code != http.StatusInternalServerError || len(got) != 1 || got[0].code != mfax.CodeInternal {
		t.Fatalf("enable sans RecoveryRenderer : %d %+v", rec.Code, got)
	}
}

func TestRegenerateRecoveryPOST(t *testing.T) {
	svc, secret, user, rend, _ := recoveryService(t)
	old, _ := svc.GenerateRecoveryCodes(user.ID)
	post := func(code string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		svc.RegenerateRecoveryPOST(rec, withUser(formRequest("/profile/recovery", url.Values{"code": {code}}), user))
		return rec
	}
	if loc := post("000000").Header().Get("Location"); loc != "/?error="+string(mfax.CodeInvalidCode) {
		t.Fatalf("code faux : %q", loc)
	}
	if rend.codes != nil {
		t.Fatal("codes montrés sans réauthentification")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	rec := post(code)
	if rec.Code != http.StatusOK || rend.codes == nil || rend.codes.Enrollment || len(rend.codes.Codes) != 10 {
		t.Fatalf("régénération : %d %+v", rec.Code, rend.codes)
	}
	if ok, _ := svc.ConfirmRecovery(httptest.NewRequest(http.MethodPost, "/", nil), user, old[0]); ok {
		t.Error("ancien code encore valable après régénération")
	}
	if ok, _ := svc.ConfirmRecovery(httptest.NewRequest(http.MethodPost, "/", nil), user, rend.codes.Codes[0]); !ok {
		t.Error("nouveau code refusé")
	}
}

// TestDisableWithRecoveryCode : sans application TOTP, un code de secours suffit à retirer
// le TOTP (pour le reconfigurer) ; les codes partent avec lui.
func TestDisableWithRecoveryCode(t *testing.T) {
	svc, _, user, _, _ := recoveryService(t)
	codes, _ := svc.GenerateRecoveryCodes(user.ID)
	disable := func(form url.Values) string {
		rec := httptest.NewRecorder()
		svc.DisablePOST(rec, withUser(formRequest("/profile/totp/disable", form), user))
		return rec.Header().Get("Location")
	}
	if loc := disable(url.Values{"recovery_code": {"0000-0000-0000-0000"}}); loc != "/?error="+string(mfax.CodeInvalidCode) {
		t.Fatalf("code de secours faux : %q", loc)
	}
	if !svc.Enabled(user.ID) {
		t.Fatal("TOTP retiré par un code faux")
	}
	if loc := disable(url.Values{"recovery_code": {codes[0]}}); loc != "/" {
		t.Fatalf("désactivation : %q", loc)
	}
	if svc.Enabled(user.ID) {
		t.Fatal("TOTP toujours actif")
	}
	if n, _ := svc.RecoveryRemaining(user.ID); n != 0 {
		t.Errorf("codes restants après désactivation : %d", n)
	}
}

// TestWithoutRecoveryCodes : sans l'option, rien ne change — champ recovery_code ignoré,
// méthodes en ErrRecoveryDisabled, page sans second champ.
func TestWithoutRecoveryCodes(t *testing.T) {
	svc, _, user, _ := lockoutService(t)
	if svc.RecoveryEnabled() {
		t.Fatal("RecoveryEnabled sans l'option")
	}
	if _, err := svc.GenerateRecoveryCodes(user.ID); !errors.Is(err, mfax.ErrRecoveryDisabled) {
		t.Errorf("GenerateRecoveryCodes : %v", err)
	}
	if _, err := svc.RecoveryRemaining(user.ID); !errors.Is(err, mfax.ErrRecoveryDisabled) {
		t.Errorf("RecoveryRemaining : %v", err)
	}
	if _, err := svc.ConfirmRecovery(httptest.NewRequest(http.MethodPost, "/", nil), user, "x"); !errors.Is(err, mfax.ErrRecoveryDisabled) {
		t.Errorf("ConfirmRecovery : %v", err)
	}
	rend := &verifyRenderer{}
	svc2, _, user2, _ := lockoutService(t, mfax.WithRenderer(rend))
	c, _ := begin(t, svc2, user2)
	if rec := verifyRecovery(svc2, c, "aaaa-bbbb-cccc-dddd"); rec.Code != http.StatusUnauthorized ||
		rend.last.Code != mfax.CodeInvalidCode || rend.last.Recovery {
		t.Fatalf("recovery_code sans l'option : %d %+v", rec.Code, rend.last)
	}
}
