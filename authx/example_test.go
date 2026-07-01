package authx_test

import (
	"database/sql"
	"net/http"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
	"leblanc.io/open-go-base/authx/sqlstore"
)

// renderer minimal : un projet réel rend ici un template HTML.
type exampleRenderer struct{}

func (exampleRenderer) RenderLogin(w http.ResponseWriter, r *http.Request, v authx.LoginView) {}

// Exemple de câblage : stores SQL, Manager, handlers, et routes net/http. Le
// middleware LoadSession attache l'utilisateur ; RequireAuth protège le reste.
func Example() {
	var db *sql.DB                   // ouvert par le projet (driver SQLite, Postgres, ...), puis :
	dialect := appconf.DialectSQLite // typiquement cfg.Database.Dialect()
	_ = sqlstore.Migrate(db, dialect)

	users := sqlstore.NewUserStore(db, dialect)
	sessions := sqlstore.NewSessionStore(db, dialect)

	mgr := authx.New(appconf.Auth{}, users, sessions)
	h := authx.NewHandlers(mgr, exampleRenderer{})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", h.LoginGET)
	mux.HandleFunc("POST /login", h.LoginPOST)
	mux.HandleFunc("POST /logout", h.Logout)

	protected := mgr.RequireAuth()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = authx.UserFrom(r) // utilisateur authentifié
	}))
	mux.Handle("GET /dashboard", protected)

	_ = mgr.LoadSession(mux) // handler racine du serveur
}
