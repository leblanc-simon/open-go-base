// Package authx fournit l'authentification par mot de passe et la gestion de
// sessions : hachage bcrypt, sessions persistées glissantes via cookie
// HttpOnly, middleware de chargement de session et garde par rôle, plus des
// handlers HTTP de connexion/déconnexion montables sur n'importe quel routeur
// net/http.
//
// Il consomme le fragment appconf.Auth (durée de session, nom et politique
// Secure du cookie, coût bcrypt) et délègue deux responsabilités au projet :
//
//   - le stockage, via les interfaces UserStore et SessionStore (une
//     implémentation database/sql + migrations est fournie dans authx/sqlstore) ;
//   - le rendu HTML, via l'interface Renderer (authx fournit les données, le
//     projet le template).
//
// # Câblage minimal
//
//	mgr := authx.New(cfg.Auth, users, sessions)
//	h := authx.NewHandlers(mgr, myRenderer)
//
//	mux := chi.NewRouter()
//	mux.Use(mgr.LoadSession)        // attache l'utilisateur au contexte
//	mux.Get("/login", h.LoginGET)
//	mux.Post("/login", h.LoginPOST)
//	mux.Post("/logout", h.Logout)
//	mux.Group(func(r chi.Router) {
//		r.Use(mgr.RequireAuth())    // exige une session authentifiée
//		r.Get("/", home)            // authx.UserFrom(r) donne l'utilisateur
//	})
//
// # Second facteur
//
// authx fonctionne seul (connexion en une étape). Pour intercaler une 2FA,
// brancher un SecondFactor via authx.WithSecondFactor (le package mfax en
// fournit une implémentation TOTP). Après un mot de passe valide, le hook décide
// s'il faut une étape supplémentaire et où rediriger ; mfax finalise ensuite la
// session via Manager.OpenSession.
//
// # Sécurité
//
// Les échecs de connexion renvoient un message générique (jamais distinguer un
// email inconnu d'un mot de passe erroné). Le paramètre ?next= n'autorise que
// des chemins locaux (pas de redirection ouverte). Le cookie est HttpOnly,
// SameSite=Lax, et Secure selon appconf.Auth.CookieSecure (auto|on|off).
package authx
