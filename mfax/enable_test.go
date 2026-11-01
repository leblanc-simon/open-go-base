package mfax_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/mfax"
)

func enable(svc *mfax.Service, user *authx.User, code string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	svc.EnablePOST(rec, withUser(formRequest("/profile/totp/enable", url.Values{"code": {code}}), user))
	return rec
}

// TestEnablePOSTOnActiveTOTPDoesNothing : un TOTP actif ne se « réactive » pas. Sans
// cette règle, une session volée devinait un code par force brute sur EnablePOST, hors
// verrouillage, et recevait un nouveau jeu de codes de secours qui invalidait celui du
// titulaire.
func TestEnablePOSTOnActiveTOTPDoesNothing(t *testing.T) {
	svc, secret, user, rend, _ := recoveryService(t)
	old, err := svc.GenerateRecoveryCodes(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		if rec := enable(svc, user, "000000"); rec.Header().Get("Location") != "/" {
			t.Fatalf("code faux sur TOTP actif : %d %q", rec.Code, rec.Header().Get("Location"))
		}
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	rec := enable(svc, user, code)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" || rend.codes != nil {
		t.Fatalf("code juste sur TOTP actif : %d %q, codes rendus : %v", rec.Code, rec.Header().Get("Location"), rend.codes != nil)
	}
	if n, _ := svc.RecoveryRemaining(user.ID); n != len(old) {
		t.Fatalf("codes restants : %d, attendu %d (jeu inchangé)", n, len(old))
	}
	if ok, err := svc.ConfirmRecovery(httptest.NewRequest(http.MethodPost, "/", nil), user, old[0]); !ok || err != nil {
		t.Fatalf("ancien code refusé : %v %v", ok, err)
	}
}

// TestEnablePOSTCountsFailures : pendant l'enrôlement, chaque code faux compte dans le
// verrouillage par compte, et un compte verrouillé est refusé sans examen du code.
func TestEnablePOSTCountsFailures(t *testing.T) {
	svc, _, user, rend, _ := recoveryService(t)
	secret, _, err := svc.Provision(user) // enrôlement en attente
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if loc := enable(svc, user, "000000").Header().Get("Location"); loc != "/profile/totp/setup?error=invalid_code" {
			t.Fatalf("échec %d : %q", i+1, loc)
		}
	}
	if loc := enable(svc, user, "000000").Header().Get("Location"); loc != "/profile/totp/setup?error=2fa_locked" {
		t.Fatalf("4e échec (seuil) : %q", loc)
	}
	if until, _ := svc.LockedUntil(user.ID); until.IsZero() {
		t.Fatal("compte non verrouillé après 4 codes faux par EnablePOST")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if loc := enable(svc, user, code).Header().Get("Location"); loc != "/profile/totp/setup?error=2fa_locked" {
		t.Fatalf("code juste sur compte verrouillé : %q", loc)
	}
	if svc.Enabled(user.ID) || rend.codes != nil {
		t.Fatalf("compte verrouillé enrôlé : actif %v, codes rendus %v", svc.Enabled(user.ID), rend.codes != nil)
	}
}
