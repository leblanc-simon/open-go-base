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
//
// # Verrouillage par compte
//
// WithLockout compte les codes faux par compte, tous défis confondus (un nouveau
// défi s'obtient en rejouant le mot de passe : le plafond par défi ne borne donc
// pas une force brute). Au seuil, le compte est verrouillé pour une durée qui
// double à chaque récidive ; Confirm offre la même vérification hors connexion
// (réauthentification avant une action sensible).
//
// # Codes de secours
//
// WithRecoveryCodes ajoute des codes de secours à usage unique : un jeu de
// appconf.MFA.RecoveryCodes codes (10 par défaut) de 80 bits d'aléa, dont seules les
// empreintes SHA-256 sont gardées (RecoveryStore, table mfa_recovery_codes). EnablePOST
// les génère à l'enrôlement et les montre une seule fois (RecoveryRenderer) ;
// RegenerateRecoveryPOST, ou GenerateRecoveryCodes après une réauthentification, en tire
// un nouveau jeu qui invalide l'ancien. À la connexion, VerifyPOST accepte un code de
// secours dans le champ recovery_code ; un code faux compte dans le plafond du défi et
// dans le verrouillage par compte, comme un code TOTP faux. ConfirmRecovery réauthentifie
// par un code de secours (DisablePOST l'accepte, pour reconfigurer une application
// perdue). WithRecoveryHook signale chaque code consommé et le nombre restant.
package mfax
