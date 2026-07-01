package mfax

import (
	"errors"
	"net/http"
	"strings"

	"leblanc.io/open-go-base/authx"
)

// Renderer rend les pages dont mfax a besoin. Le projet l'implémente avec son
// moteur de templates.
type Renderer interface {
	// RenderVerify affiche la saisie du code TOTP (étape 2 du login).
	RenderVerify(w http.ResponseWriter, r *http.Request, view VerifyView)
	// RenderSetup affiche la page de configuration TOTP (secret + QR).
	RenderSetup(w http.ResponseWriter, r *http.Request, view SetupView)
}

// VerifyView porte les données de la page de vérification.
type VerifyView struct {
	Next  string
	Error string
}

// SetupView porte les données de la page de configuration TOTP. QRDataURI est un
// data: URI (à typer en template.URL côté template, cf. QRDataURI).
type SetupView struct {
	Secret          string
	ProvisioningURL string
	QRDataURI       string
	Error           string
}

// VerifyGET affiche la page de saisie du code TOTP. Sans challenge valide en
// cours, il renvoie vers la connexion.
func (s *Service) VerifyGET(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.loadChallenge(r); !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.renderer == nil {
		http.Error(w, "no renderer", http.StatusInternalServerError)
		return
	}
	s.renderer.RenderVerify(w, r, VerifyView{Next: r.URL.Query().Get("next")})
}

// VerifyPOST vérifie le code TOTP soumis. En cas de succès, supprime le
// challenge et ouvre une session pleinement authentifiée.
func (s *Service) VerifyPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	user, ch, ok := s.loadChallenge(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	code := strings.TrimSpace(r.PostForm.Get("code"))
	next := r.PostForm.Get("next")

	// Incrément atomique borné par MaxAttempts : si allowed est false, le
	// plafond est déjà atteint. L'atomicité évite qu'un lot de requêtes
	// concurrentes lisant le même compteur ne dépasse le plafond (TOCTOU).
	allowed, err := s.chs.IncrAttempts(ch.Token, s.cfg.MaxAttempts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !allowed {
		_ = s.chs.Delete(ch.Token)
		s.clearChallengeCookie(w, r)
		http.Redirect(w, r, "/login?err=2fa_exhausted", http.StatusSeeOther)
		return
	}

	valid, err := s.consumeCode(user.ID, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !valid {
		if s.renderer == nil {
			http.Error(w, "no renderer", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		s.renderer.RenderVerify(w, r, VerifyView{Next: next, Error: "Code invalide"})
		return
	}

	_ = s.chs.Delete(ch.Token)
	s.clearChallengeCookie(w, r)
	if _, err := s.mgr.OpenSession(w, r, user, authx.PurposeAuth); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authx.SafeRedirectPath(next, s.homePath), http.StatusSeeOther)
}

// SetupGET génère un nouveau secret TOTP et affiche la page de configuration
// (secret + QR). Requiert une session (de setup ou authentifiée).
//
// Un nouveau secret est généré à chaque visite : un échec de confirmation
// renvoyé ici imposera de re-scanner le QR (choix volontaire, orienté sécurité).
func (s *Service) SetupGET(w http.ResponseWriter, r *http.Request) {
	user := authx.UserFrom(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// Provision écrase le secret stocké : on refuse de le faire si une 2FA est
	// déjà active. Sinon un simple GET (préchargement de lien, crawler, CSRF —
	// SameSite=Lax ne couvre pas la navigation GET) détruirait silencieusement
	// le secret fonctionnel de l'utilisateur et désactiverait sa 2FA. Pour
	// re-générer, l'utilisateur doit d'abord désactiver explicitement (DisablePOST).
	if s.Enabled(user.ID) {
		http.Redirect(w, r, s.homePath, http.StatusSeeOther)
		return
	}
	if s.renderer == nil {
		http.Error(w, "no renderer", http.StatusInternalServerError)
		return
	}
	secret, url, err := s.Provision(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	qrURI, _ := QRDataURI(url)
	s.renderer.RenderSetup(w, r, SetupView{
		Secret: secret, ProvisioningURL: url, QRDataURI: qrURI,
		Error: r.URL.Query().Get("error"),
	})
}

// EnablePOST confirme l'activation du TOTP avec un premier code valide. Depuis
// une session de setup (premier login), il élève la session en session
// authentifiée et renvoie vers l'accueil.
func (s *Service) EnablePOST(w http.ResponseWriter, r *http.Request) {
	user := authx.UserFrom(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.PostForm.Get("code"))
	t, err := s.totp.Get(user.ID)
	if err != nil {
		http.Redirect(w, r, s.setupPath, http.StatusSeeOther)
		return
	}
	// consumeCode confirme le code ET enregistre son pas, pour qu'il ne puisse
	// pas être rejoué comme code de connexion juste après l'enrôlement.
	valid, err := s.consumeCode(user.ID, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !valid {
		http.Redirect(w, r, s.setupPath+"?error="+queryEscape("Code invalide, réessayez"), http.StatusSeeOther)
		return
	}
	if err := s.totp.Set(user.ID, t.Secret, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sess := authx.SessionFrom(r); sess != nil && sess.Purpose == authx.PurposeSetup {
		if _, err := s.mgr.Elevate(w, r, user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, s.homePath, http.StatusSeeOther)
}

// DisablePOST désactive et supprime le secret TOTP de l'utilisateur courant.
// À monter derrière une session authentifiée (RequireAuth).
//
// Step-up : la désactivation exige un code TOTP valide dans le champ "code".
// Sans cette ré-authentification, une session compromise (ou une CSRF qui
// passerait la barrière SameSite) pourrait retirer le second facteur sans
// preuve de possession. Sans 2FA active, l'opération est un no-op idempotent.
func (s *Service) DisablePOST(w http.ResponseWriter, r *http.Request) {
	user := authx.UserFrom(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	t, err := s.totp.Get(user.ID)
	if errors.Is(err, ErrTOTPNotFound) || (err == nil && !t.Enabled) {
		// Rien d'actif à désactiver : idempotent.
		http.Redirect(w, r, s.homePath, http.StatusSeeOther)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	code := strings.TrimSpace(r.PostForm.Get("code"))
	valid, err := s.consumeCode(user.ID, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !valid {
		http.Redirect(w, r, s.homePath+"?error="+queryEscape("Code invalide"), http.StatusSeeOther)
		return
	}
	if err := s.totp.Delete(user.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, s.homePath, http.StatusSeeOther)
}

// queryEscape échappe une valeur pour un paramètre de query (évite d'importer
// net/url juste pour ça côté handlers).
func queryEscape(s string) string {
	return strings.NewReplacer(" ", "+", "&", "%26", "?", "%3F", "#", "%23").Replace(s)
}
