package sqlstore_test

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/mfax"
	"leblanc.io/open-go-base/mfax/sqlstore"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:mfax_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := sqlstore.Migrate(db, appconf.DialectSQLite); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := sqlstore.Migrate(db, appconf.DialectSQLite); err != nil {
		t.Fatalf("migrate (2e passage): %v", err)
	}
	return db
}

func TestTOTPStoreUpsert(t *testing.T) {
	db := openDB(t)
	store := sqlstore.NewTOTPStore(db, appconf.DialectSQLite)

	if _, err := store.Get(1); err != mfax.ErrTOTPNotFound {
		t.Errorf("attendu ErrTOTPNotFound, obtenu %v", err)
	}
	if err := store.Set(1, "SECRET1", false); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := store.Get(1)
	if err != nil || got.Secret != "SECRET1" || got.Enabled {
		t.Fatalf("get inattendu: %+v err=%v", got, err)
	}
	// Upsert : on active sans dupliquer.
	if err := store.Set(1, "SECRET1", true); err != nil {
		t.Fatalf("set (upsert): %v", err)
	}
	got, _ = store.Get(1)
	if !got.Enabled {
		t.Error("enabled devrait être true après upsert")
	}
	// Anti-rejeu : last_step n'avance que vers un pas strictement supérieur, et
	// l'upsert Set ne le réinitialise pas.
	if ok, err := store.SetLastStep(1, 100); err != nil || !ok {
		t.Fatalf("setLastStep 100: ok=%v err=%v", ok, err)
	}
	if ok, _ := store.SetLastStep(1, 100); ok {
		t.Error("rejouer le même pas (100) devrait être refusé")
	}
	if ok, _ := store.SetLastStep(1, 50); ok {
		t.Error("revenir en arrière (50) devrait être refusé")
	}
	if err := store.Set(1, "SECRET2", true); err != nil {
		t.Fatalf("set après last_step: %v", err)
	}
	if got, _ := store.Get(1); got.LastStep != 100 {
		t.Errorf("last_step réinitialisé par Set: %d, want 100", got.LastStep)
	}

	if err := store.Delete(1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Get(1); err != mfax.ErrTOTPNotFound {
		t.Errorf("secret toujours présent après delete: %v", err)
	}
}

func TestChallengeStoreRoundTripAndPurge(t *testing.T) {
	db := openDB(t)
	store := sqlstore.NewChallengeStore(db, appconf.DialectSQLite)

	live := &mfax.Challenge{Token: "live", UserID: 5, ExpiresAt: time.Now().Add(time.Hour)}
	dead := &mfax.Challenge{Token: "dead", UserID: 5, ExpiresAt: time.Now().Add(-time.Hour)}
	if err := store.Create(live); err != nil {
		t.Fatalf("create live: %v", err)
	}
	if err := store.Create(dead); err != nil {
		t.Fatalf("create dead: %v", err)
	}

	if ok, err := store.IncrAttempts("live", 2); err != nil || !ok {
		t.Fatalf("incr: ok=%v err=%v", ok, err)
	}
	got, err := store.Get("live")
	if err != nil || got.Attempts != 1 || got.UserID != 5 {
		t.Fatalf("get live: %+v err=%v", got, err)
	}
	// Au plafond (attempts == limit), l'incrément doit être refusé et ne pas
	// modifier le compteur : c'est la borne atomique anti-TOCTOU.
	if ok, err := store.IncrAttempts("live", 1); err != nil || ok {
		t.Fatalf("incr au plafond: attendu refus, ok=%v err=%v", ok, err)
	}
	if got, _ := store.Get("live"); got.Attempts != 1 {
		t.Fatalf("attempts modifié malgré le refus: %d", got.Attempts)
	}

	n, err := store.PurgeExpired()
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purge a effacé %d, want 1", n)
	}
	if _, err := store.Get("dead"); err != mfax.ErrChallengeNotFound {
		t.Errorf("challenge expiré toujours présent: %v", err)
	}
}

func TestLockoutStore(t *testing.T) {
	db := openDB(t)
	store := sqlstore.NewLockoutStore(db, appconf.DialectSQLite)
	p := mfax.LockoutPolicy{Threshold: 3, Window: 15 * time.Minute, Duration: 10 * time.Minute, MaxDuration: 30 * time.Minute}
	t0 := time.Unix(1_800_000_000, 0)

	fail := func(at time.Time) time.Time {
		t.Helper()
		until, err := store.Fail(9, at, p)
		if err != nil {
			t.Fatalf("fail: %v", err)
		}
		return until
	}
	locked := func(at time.Time) time.Time {
		t.Helper()
		until, err := store.LockedUntil(9, at)
		if err != nil {
			t.Fatalf("lockedUntil: %v", err)
		}
		return until
	}

	if !locked(t0).IsZero() {
		t.Fatal("compte inconnu verrouillé")
	}
	// Deux échecs, puis la fenêtre se ferme : le compteur repart de un.
	fail(t0)
	fail(t0.Add(time.Minute))
	if !fail(t0.Add(16*time.Minute)).IsZero() || !fail(t0.Add(17*time.Minute)).IsZero() {
		t.Fatal("verrouillage malgré la fenêtre close")
	}
	until := fail(t0.Add(18 * time.Minute))
	if want := t0.Add(28 * time.Minute); !until.Equal(want) {
		t.Fatalf("premier verrouillage jusqu'à %v, attendu %v", until, want)
	}
	if got := locked(t0.Add(20 * time.Minute)); !got.Equal(until) {
		t.Fatalf("lockedUntil pendant le verrouillage : %v", got)
	}
	if !locked(until).IsZero() {
		t.Fatal("verrouillage encore actif à son échéance")
	}
	// Récidive : durée doublée, puis plafonnée.
	at := until
	for i, want := range []time.Duration{20 * time.Minute, 30 * time.Minute, 30 * time.Minute} {
		fail(at)
		fail(at)
		got := fail(at)
		if !got.Equal(at.Add(want)) {
			t.Fatalf("verrouillage %d jusqu'à %v, attendu +%s", i+2, got, want)
		}
		at = got
	}
	// Un succès efface tout : le verrouillage suivant repart de la première durée.
	if err := store.Reset(9); err != nil {
		t.Fatalf("reset: %v", err)
	}
	fail(at)
	fail(at)
	if got := fail(at); !got.Equal(at.Add(10 * time.Minute)) {
		t.Fatalf("après Reset : %v", got)
	}
}
