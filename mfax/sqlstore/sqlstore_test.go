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
