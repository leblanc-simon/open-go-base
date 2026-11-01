package mfax

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"leblanc.io/open-go-base/authx"
)

const (
	defaultRecoveryCodes = 10
	maxRecoveryCodes     = 50

	// Alphabet de Crockford (base 32 sans i, l, o ni u) : lisible, sans confusion entre
	// 0/o et 1/i/l, qu'on normalise à la saisie.
	recoveryAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	// 16 caractères de 5 bits : 80 bits d'aléa, hors de portée d'une recherche
	// exhaustive hors ligne sur l'empreinte SHA-256 (pas besoin d'un hachage lent).
	recoveryCodeLen = 16
	recoveryGroup   = 4
)

// ErrRecoveryDisabled est renvoyée par les méthodes des codes de secours quand le service
// a été construit sans WithRecoveryCodes.
var ErrRecoveryDisabled = errors.New("mfax: recovery codes not enabled")

// RecoveryStore persiste les empreintes des codes de secours d'un utilisateur (jamais les
// codes en clair). Une implémentation database/sql est fournie dans mfax/sqlstore.
type RecoveryStore interface {
	// Replace remplace atomiquement tous les codes de userID (utilisés ou non) par
	// hashes : une régénération invalide les anciens.
	Replace(userID int64, hashes []string) error
	// Use marque utilisé, atomiquement, le code non utilisé d'empreinte hash de userID et
	// renvoie true si c'est cet appel qui l'a consommé. Un false signale un code inconnu,
	// déjà utilisé, ou consommé par une requête concurrente.
	Use(userID int64, hash string, now time.Time) (bool, error)
	// Remaining renvoie le nombre de codes non utilisés de userID.
	Remaining(userID int64) (int, error)
	// Delete supprime tous les codes de userID (TOTP désactivé, compte supprimé).
	Delete(userID int64) error
}

// RecoveryHook est appelé après la consommation d'un code de secours (connexion ou
// réauthentification), avec le nombre de codes restants : journal d'audit, alerte quand il
// en reste peu. Il ne doit pas écrire de réponse.
type RecoveryHook func(r *http.Request, user *authx.User, remaining int)

// RecoveryRenderer rend la page qui montre les codes de secours, une seule fois, après leur
// génération (enrôlement, régénération). La Renderer du service doit l'implémenter dès que
// WithRecoveryCodes est utilisé.
type RecoveryRenderer interface {
	RenderRecoveryCodes(w http.ResponseWriter, r *http.Request, view RecoveryCodesView)
}

// RecoveryCodesView porte les codes de secours tout juste générés, en clair : ils ne sont
// plus jamais lisibles ensuite (seules leurs empreintes sont gardées).
type RecoveryCodesView struct {
	// Codes sont les codes, au format d'affichage (groupes de quatre caractères).
	Codes []string
	// Next est la page où continuer une fois les codes notés.
	Next string
	// Enrollment vaut true à l'enrôlement du TOTP, false après une régénération.
	Enrollment bool
}

// WithRecoveryCodes active les codes de secours : codes à usage unique, hachés,
// régénérables, acceptés à la place d'un code TOTP à la connexion (champ recovery_code de
// VerifyPOST). Leur nombre vient de appconf.MFA.RecoveryCodes (10 par défaut). Les codes
// faux comptent dans le verrouillage par compte (WithLockout) comme les codes TOTP faux.
// Sans cette option, rien ne change.
func WithRecoveryCodes(store RecoveryStore) Option { return func(s *Service) { s.recovery = store } }

// WithRecoveryHook fournit le crochet appelé à chaque code de secours consommé.
func WithRecoveryHook(h RecoveryHook) Option { return func(s *Service) { s.onRecovery = h } }

// WithRecoveryLanding change la page d'arrivée après une connexion par code de secours
// (par défaut, la même qu'après un code TOTP) : par exemple une page qui rappelle le
// nombre de codes restants et propose de reconfigurer le TOTP. Une valeur vide garde le
// défaut.
func WithRecoveryLanding(path string) Option { return func(s *Service) { s.recoveryLanding = path } }

// RecoveryEnabled indique si le service accepte des codes de secours.
func (s *Service) RecoveryEnabled() bool { return s.recovery != nil }

// GenerateRecoveryCodes tire un nouveau jeu de codes de secours pour userID, remplace
// l'ancien et renvoie les codes en clair, au format d'affichage, à montrer une seule fois.
func (s *Service) GenerateRecoveryCodes(userID int64) ([]string, error) {
	if s.recovery == nil {
		return nil, ErrRecoveryDisabled
	}
	codes := make([]string, s.recoveryCount)
	hashes := make([]string, s.recoveryCount)
	for i := range codes {
		raw, err := randomRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes[i] = formatRecoveryCode(raw)
		hashes[i] = recoveryHash(userID, raw)
	}
	if err := s.recovery.Replace(userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// RecoveryRemaining renvoie le nombre de codes de secours non utilisés de userID.
func (s *Service) RecoveryRemaining(userID int64) (int, error) {
	if s.recovery == nil {
		return 0, ErrRecoveryDisabled
	}
	return s.recovery.Remaining(userID)
}

// ConfirmRecovery vérifie et consomme un code de secours de user hors du parcours de
// connexion (réauthentification d'un utilisateur qui n'a plus son application TOTP). Comme
// Confirm, il applique le verrouillage par compte : ErrLocked pour un compte verrouillé,
// un code faux compte comme un échec, un code juste efface le compteur.
func (s *Service) ConfirmRecovery(r *http.Request, user *authx.User, code string) (bool, error) {
	if s.recovery == nil {
		return false, ErrRecoveryDisabled
	}
	return s.confirm(r, user, func() (bool, error) { return s.useRecoveryCode(r, user, code) })
}

// useRecoveryCode consomme un code de secours de user et appelle le crochet en cas de
// succès.
func (s *Service) useRecoveryCode(r *http.Request, user *authx.User, code string) (bool, error) {
	raw, ok := normalizeRecoveryCode(code)
	if !ok {
		return false, nil
	}
	used, err := s.recovery.Use(user.ID, recoveryHash(user.ID, raw), time.Now())
	if err != nil || !used {
		return false, err
	}
	if s.onRecovery != nil {
		remaining, err := s.recovery.Remaining(user.ID)
		if err != nil {
			return false, err
		}
		s.onRecovery(r, user, remaining)
	}
	return true, nil
}

// renderRecoveryCodes génère les codes de user et les montre, une seule fois.
func (s *Service) renderRecoveryCodes(w http.ResponseWriter, r *http.Request, user *authx.User, enrollment bool) {
	rr, ok := s.renderer.(RecoveryRenderer)
	if !ok {
		s.onError(w, r, http.StatusInternalServerError, CodeInternal, errNoRecoveryRenderer)
		return
	}
	codes, err := s.GenerateRecoveryCodes(user.ID)
	if err != nil {
		s.onError(w, r, http.StatusInternalServerError, CodeInternal, err)
		return
	}
	// Les codes ne doivent survivre ni dans un cache ni dans l'historique du navigateur.
	w.Header().Set("Cache-Control", "no-store")
	rr.RenderRecoveryCodes(w, r, RecoveryCodesView{Codes: codes, Next: s.homePath, Enrollment: enrollment})
}

// RegenerateRecoveryPOST remplace les codes de secours de l'utilisateur courant et montre
// les nouveaux. À monter derrière une session authentifiée (RequireAuth). Comme
// DisablePOST, il exige un code TOTP valide dans le champ "code" (Confirm : anti-rejeu et
// verrouillage) ; un refus renvoie vers l'accueil avec ?error=invalid_code ou
// ?error=2fa_locked.
func (s *Service) RegenerateRecoveryPOST(w http.ResponseWriter, r *http.Request) {
	user := authx.UserFrom(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.recovery == nil {
		s.onError(w, r, http.StatusInternalServerError, CodeInternal, ErrRecoveryDisabled)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.onError(w, r, http.StatusBadRequest, CodeInvalidForm, err)
		return
	}
	if !s.Enabled(user.ID) {
		http.Redirect(w, r, s.setupPath, http.StatusSeeOther)
		return
	}
	valid, err := s.Confirm(r, user, strings.TrimSpace(r.PostForm.Get("code")))
	if errors.Is(err, ErrLocked) {
		http.Redirect(w, r, s.homePath+"?error="+string(CodeLocked), http.StatusSeeOther)
		return
	}
	if err != nil {
		s.onError(w, r, http.StatusInternalServerError, CodeInternal, err)
		return
	}
	if !valid {
		http.Redirect(w, r, s.homePath+"?error="+string(CodeInvalidCode), http.StatusSeeOther)
		return
	}
	s.renderRecoveryCodes(w, r, user, false)
}

// randomRecoveryCode tire recoveryCodeLen caractères uniformes de l'alphabet (32 symboles :
// un octet aléatoire réduit modulo 32 reste uniforme).
func randomRecoveryCode() (string, error) {
	buf := make([]byte, recoveryCodeLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i, b := range buf {
		buf[i] = recoveryAlphabet[b&31]
	}
	return string(buf), nil
}

// formatRecoveryCode découpe un code en groupes de quatre caractères séparés de tirets.
func formatRecoveryCode(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); i += recoveryGroup {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(raw[i:min(i+recoveryGroup, len(raw))])
	}
	return b.String()
}

// normalizeRecoveryCode ramène une saisie à la forme canonique : minuscules, sans espaces
// ni tirets, avec les substitutions de Crockford (i et l → 1, o → 0). Elle refuse ce qui
// ne peut pas être un code (longueur, caractère hors alphabet).
func normalizeRecoveryCode(code string) (string, bool) {
	var b strings.Builder
	for _, c := range strings.ToLower(code) {
		switch {
		case c == '-' || c == ' ' || c == '\t':
			continue
		case c == 'i' || c == 'l':
			c = '1'
		case c == 'o':
			c = '0'
		}
		if !strings.ContainsRune(recoveryAlphabet, c) {
			return "", false
		}
		b.WriteRune(c)
	}
	if b.Len() != recoveryCodeLen {
		return "", false
	}
	return b.String(), true
}

// recoveryHash est l'empreinte gardée d'un code : liée à l'utilisateur, pour qu'une ligne
// recopiée vers un autre compte n'y vaille rien.
func recoveryHash(userID int64, raw string) string {
	sum := sha256.Sum256([]byte("mfax-recovery\x00" + strconv.FormatInt(userID, 10) + "\x00" + raw))
	return hex.EncodeToString(sum[:])
}

func recoveryCount(n int) int {
	if n <= 0 {
		return defaultRecoveryCodes
	}
	return min(n, maxRecoveryCodes)
}

// errNoRecoveryRenderer : WithRecoveryCodes sans Renderer qui implémente RecoveryRenderer.
var errNoRecoveryRenderer = errors.New("mfax: renderer does not implement RecoveryRenderer")
