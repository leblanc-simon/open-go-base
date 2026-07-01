package sqlstore_test

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/authx/sqlstore"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:authx_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := sqlstore.Migrate(db, appconf.DialectSQLite); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Idempotence : un second passage ne doit pas échouer.
	if err := sqlstore.Migrate(db, appconf.DialectSQLite); err != nil {
		t.Fatalf("migrate (2e passage): %v", err)
	}
	return db
}

func TestUserStoreRoundTrip(t *testing.T) {
	db := openDB(t)
	users := sqlstore.NewUserStore(db, appconf.DialectSQLite)

	hash, _ := authx.HashPassword("pw", 4)
	created, err := users.Create("alice@example.org", hash, authx.Role("admin"), true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == 0 || !created.MustChangePwd || created.Role != "admin" {
		t.Fatalf("utilisateur créé inattendu: %+v", created)
	}

	byEmail, err := users.GetByEmail("alice@example.org")
	if err != nil {
		t.Fatalf("getByEmail: %v", err)
	}
	if byEmail.ID != created.ID {
		t.Errorf("ID = %d, want %d", byEmail.ID, created.ID)
	}

	if _, err := users.GetByEmail("inconnu@example.org"); err != authx.ErrUserNotFound {
		t.Errorf("attendu ErrUserNotFound, obtenu %v", err)
	}

	if byEmail.LastLogin != nil {
		t.Error("last_login devrait être nil avant connexion")
	}
	if err := users.UpdateLastLogin(created.ID); err != nil {
		t.Fatalf("updateLastLogin: %v", err)
	}
	after, _ := users.GetByID(created.ID)
	if after.LastLogin == nil {
		t.Error("last_login devrait être renseigné après UpdateLastLogin")
	}
}

func TestSessionStoreRoundTripAndPurge(t *testing.T) {
	db := openDB(t)
	users := sqlstore.NewUserStore(db, appconf.DialectSQLite)
	sessions := sqlstore.NewSessionStore(db, appconf.DialectSQLite)

	hash, _ := authx.HashPassword("pw", 4)
	u, _ := users.Create("bob@example.org", hash, "", false)

	live := &authx.Session{Token: "tok-live", UserID: u.ID, Purpose: authx.PurposeAuth, ExpiresAt: time.Now().Add(time.Hour)}
	dead := &authx.Session{Token: "tok-dead", UserID: u.ID, Purpose: authx.PurposeAuth, ExpiresAt: time.Now().Add(-time.Hour)}
	if err := sessions.Create(live); err != nil {
		t.Fatalf("create live: %v", err)
	}
	if err := sessions.Create(dead); err != nil {
		t.Fatalf("create dead: %v", err)
	}

	got, err := sessions.Get("tok-live")
	if err != nil || got.UserID != u.ID || got.Purpose != authx.PurposeAuth {
		t.Fatalf("get live: %+v err=%v", got, err)
	}

	newExp := time.Now().Add(6 * time.Hour)
	if err := sessions.Touch("tok-live", newExp); err != nil {
		t.Fatalf("touch: %v", err)
	}

	n, err := sessions.PurgeExpired()
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Errorf("purge a effacé %d sessions, want 1", n)
	}
	if _, err := sessions.Get("tok-dead"); err != authx.ErrSessionNotFound {
		t.Errorf("session expirée toujours présente: %v", err)
	}
	if _, err := sessions.Get("tok-live"); err != nil {
		t.Errorf("session vivante effacée à tort: %v", err)
	}

	if err := sessions.DeleteByUser(u.ID); err != nil {
		t.Fatalf("deleteByUser: %v", err)
	}
	if _, err := sessions.Get("tok-live"); err != authx.ErrSessionNotFound {
		t.Errorf("DeleteByUser n'a pas tout effacé: %v", err)
	}
}
