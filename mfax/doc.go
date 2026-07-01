// Package mfax ajoute une double authentification TOTP par-dessus authx :
// provisioning (secret + QR code), vérification du code à la connexion, et
// configuration/désactivation par l'utilisateur. C'est le second facteur du
// flux de login ; le premier (mot de passe + sessions) reste à authx.
//
// mfax consomme le fragment appconf.MFA (issuer, durée et nombre de tentatives
// du challenge) et délègue le stockage à TOTPStore/ChallengeStore (une
// implémentation database/sql + migrations est fournie dans mfax/sqlstore) ainsi
// que le rendu HTML à une Renderer fournie par le projet. Son schéma est dédié
// (tables mfa_totp, mfa_challenges) : mfax ne touche jamais aux tables de authx.
//
// # Câblage
//
//	mgr := authx.New(cfg.Auth, users, sessions)
//	svc := mfax.New(cfg.MFA, mgr, totpStore, challengeStore, mfax.WithRenderer(rend))
//
//	// Le login délègue le second facteur au service mfax.
//	h := authx.NewHandlers(mgr, rend, authx.WithSecondFactor(svc))
//
//	mux.Use(mgr.LoadSession)
//	mux.Get("/login", h.LoginGET)
//	mux.Post("/login", h.LoginPOST)
//	mux.Get("/login/2fa", svc.VerifyGET)
//	mux.Post("/login/2fa", svc.VerifyPOST)
//	mux.Get("/profile/totp/setup", svc.SetupGET)   // session de setup ou auth
//	mux.Post("/profile/totp/enable", svc.EnablePOST)
//	mux.Post("/profile/totp/disable", svc.DisablePOST) // derrière RequireAuth
//
// # Enrôlement
//
// Par défaut l'enrôlement est obligatoire : au premier login, un utilisateur
// sans TOTP est dirigé vers la page de configuration via une session de setup
// (restreinte), élevée en session authentifiée une fois le TOTP confirmé.
// WithOptionalEnrollment rend la 2FA facultative (login direct si non
// configurée).
package mfax
