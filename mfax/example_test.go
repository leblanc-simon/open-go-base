package mfax_test

import (
	"database/sql"
	"net/http"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	authsql "leblanc.io/open-go-base/authx/sqlstore"
	"leblanc.io/open-go-base/mfax"
	mfasql "leblanc.io/open-go-base/mfax/sqlstore"
)

type exampleRenderer struct{}

func (exampleRenderer) RenderVerify(http.ResponseWriter, *http.Request, mfax.VerifyView) {}
func (exampleRenderer) RenderSetup(http.ResponseWriter, *http.Request, mfax.SetupView)   {}

// RenderRecoveryCodes montre les codes de secours tout juste générés (une seule fois).
func (exampleRenderer) RenderRecoveryCodes(http.ResponseWriter, *http.Request, mfax.RecoveryCodesView) {
}

// Exemple_recoveryCodes active le verrouillage par compte et les codes de secours : codes
// montrés à l'enrôlement, acceptés à la connexion (champ recovery_code), régénérables
// après un code TOTP.
func Example_recoveryCodes() {
	var db *sql.DB // ouvert par le projet, migrations jouées
	dialect := appconf.DialectPostgres
	mgr := authx.New(appconf.Auth{}, authsql.NewUserStore(db, dialect), authsql.NewSessionStore(db, dialect))

	svc := mfax.New(appconf.MFA{RecoveryCodes: 10}, mgr,
		mfasql.NewTOTPStore(db, dialect), mfasql.NewChallengeStore(db, dialect),
		mfax.WithRenderer(exampleRenderer{}), // implémente aussi mfax.RecoveryRenderer
		mfax.WithLockout(mfasql.NewLockoutStore(db, dialect)),
		mfax.WithRecoveryCodes(mfasql.NewRecoveryStore(db, dialect)),
		mfax.WithRecoveryHook(func(r *http.Request, u *authx.User, remaining int) {
			// journal d'audit ; alerte quand il reste peu de codes
		}),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/2fa", svc.VerifyPOST) // code ou recovery_code
	mux.HandleFunc("POST /profile/totp/enable", svc.EnablePOST)
	mux.Handle("POST /profile/recovery-codes", mgr.RequireAuth()(http.HandlerFunc(svc.RegenerateRecoveryPOST)))
}

// Exemple de câblage de la 2FA TOTP par-dessus authx : le service mfax est
// branché comme second facteur du login, et expose ses propres routes.
func Example() {
	var db *sql.DB                   // ouvert par le projet
	dialect := appconf.DialectSQLite // typiquement cfg.Database.Dialect()
	_ = authsql.Migrate(db, dialect)
	_ = mfasql.Migrate(db, dialect)

	mgr := authx.New(appconf.Auth{}, authsql.NewUserStore(db, dialect), authsql.NewSessionStore(db, dialect))
	rend := exampleRenderer{}

	svc := mfax.New(appconf.MFA{}, mgr,
		mfasql.NewTOTPStore(db, dialect), mfasql.NewChallengeStore(db, dialect),
		mfax.WithRenderer(rend),
	)

	loginHandlers := authx.NewHandlers(mgr, nil, authx.WithSecondFactor(svc))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", loginHandlers.LoginPOST)
	mux.HandleFunc("GET /login/2fa", svc.VerifyGET)
	mux.HandleFunc("POST /login/2fa", svc.VerifyPOST)
	mux.HandleFunc("GET /profile/totp/setup", svc.SetupGET)
	mux.HandleFunc("POST /profile/totp/enable", svc.EnablePOST)

	_ = mgr.LoadSession(mux)
}
