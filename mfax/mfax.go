package mfax

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/authx"
)

const (
	defaultChallengeTTL = 10 * time.Minute
	defaultMaxAttempts  = 5
	defaultIssuer       = "open-go-base"
	challengeCookieName = "mfa_challenge"

	// Paramètres TOTP : doivent rester alignés sur ceux que totp.Generate et
	// totp.Validate utilisent par défaut (période 30 s, tolérance ±1 pas).
	totpPeriod = 30
	totpSkew   = 1
)

// Service porte la logique TOTP : provisioning, vérification, et le hook
// authx.SecondFactor qui s'intercale dans le login. Construire via New.
type Service struct {
	cfg       appconf.MFA
	mgr       *authx.Manager
	totp      TOTPStore
	chs       ChallengeStore
	renderer  Renderer
	enrollReq bool

	verifyPath string
	setupPath  string
	homePath   string
}

// Option configure le Service.
type Option func(*Service)

// WithRenderer fournit le moteur de rendu des pages 2FA (obligatoire pour
// utiliser les Handlers ; inutile si seul le hook Begin est employé).
func WithRenderer(r Renderer) Option { return func(s *Service) { s.renderer = r } }

// WithOptionalEnrollment rend la 2FA facultative : un utilisateur sans TOTP
// configuré se connecte directement, sans être forcé vers la page de
// configuration. Par défaut, l'enrôlement est obligatoire.
func WithOptionalEnrollment() Option { return func(s *Service) { s.enrollReq = false } }

// WithPaths personnalise les chemins de redirection (vérification, configuration
// TOTP, accueil). Les valeurs vides conservent les défauts (/login/2fa,
// /profile/totp/setup, /).
func WithPaths(verify, setup, home string) Option {
	return func(s *Service) {
		if verify != "" {
			s.verifyPath = verify
		}
		if setup != "" {
			s.setupPath = setup
		}
		if home != "" {
			s.homePath = home
		}
	}
}

// New construit un Service à partir du fragment appconf.MFA, du Manager authx
// (pour ouvrir la session finale) et des stores. Les valeurs nulles de cfg
// retombent sur des défauts sûrs.
func New(cfg appconf.MFA, mgr *authx.Manager, totpStore TOTPStore, chs ChallengeStore, opts ...Option) *Service {
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = defaultChallengeTTL
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.Issuer == "" {
		cfg.Issuer = defaultIssuer
	}
	s := &Service{
		cfg: cfg, mgr: mgr, totp: totpStore, chs: chs, enrollReq: true,
		verifyPath: "/login/2fa", setupPath: "/profile/totp/setup", homePath: "/",
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Provision génère un nouveau secret TOTP pour user et l'enregistre désactivé
// (en attente de confirmation par un premier code valide). Il renvoie le secret
// en clair et l'URL de provisioning otpauth:// à présenter (texte + QR).
func (s *Service) Provision(user *authx.User) (secret, provisioningURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.cfg.Issuer, AccountName: user.Email})
	if err != nil {
		return "", "", err
	}
	if err := s.totp.Set(user.ID, key.Secret(), false); err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateCode vérifie un code TOTP contre le secret stocké de l'utilisateur,
// sans protection anti-rejeu (validation simple, ±1 pas). Les flux de connexion
// passent par consumeCode, qui consomme le code une seule fois.
func (s *Service) ValidateCode(userID int64, code string) (bool, error) {
	t, err := s.totp.Get(userID)
	if err != nil {
		return false, err
	}
	return totp.Validate(code, t.Secret), nil
}

// matchTOTPStep cherche le pas de temps (parmi now ±totpSkew) pour lequel le
// secret produit code. Renvoie (pas, true) si trouvé. La comparaison est en
// temps constant pour ne pas fuiter d'information par timing.
func matchTOTPStep(secret, code string, now time.Time) (int64, bool) {
	opts := totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	}
	base := now.Unix() / int64(totpPeriod)
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		step := base + d
		expected, err := totp.GenerateCodeCustom(secret, time.Unix(step*int64(totpPeriod), 0), opts)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// consumeCode valide un code TOTP et le consomme : il n'accepte un code que pour
// un pas strictement supérieur au dernier pas enregistré, puis avance ce pas de
// façon atomique. Un code déjà utilisé (même dans sa fenêtre de validité) est
// donc rejeté — protection anti-rejeu. L'avancée atomique via SetLastStep
// garantit qu'une seule requête concurrente consomme un pas donné.
func (s *Service) consumeCode(userID int64, code string) (bool, error) {
	t, err := s.totp.Get(userID)
	if err != nil {
		return false, err
	}
	step, ok := matchTOTPStep(t.Secret, code, time.Now())
	if !ok || step <= t.LastStep {
		return false, nil
	}
	return s.totp.SetLastStep(userID, step)
}

// Enabled indique si l'utilisateur a un TOTP actif.
func (s *Service) Enabled(userID int64) bool {
	t, err := s.totp.Get(userID)
	return err == nil && t.Enabled
}

// Begin implémente authx.SecondFactor. Après un mot de passe valide :
//   - TOTP actif : crée un challenge, pose le cookie, redirige vers la page de
//     vérification ;
//   - pas de TOTP et enrôlement obligatoire : ouvre une session de configuration
//     et redirige vers la page de configuration TOTP ;
//   - pas de TOTP et enrôlement facultatif : laisse le login ouvrir la session.
func (s *Service) Begin(w http.ResponseWriter, r *http.Request, user *authx.User) (bool, string, error) {
	if !s.Enabled(user.ID) {
		if !s.enrollReq {
			return false, "", nil
		}
		if _, err := s.mgr.OpenSession(w, r, user, authx.PurposeSetup); err != nil {
			return false, "", err
		}
		return true, s.setupPath, nil
	}

	token, err := authx.RandomToken()
	if err != nil {
		return false, "", err
	}
	now := time.Now()
	if err := s.chs.Create(&Challenge{
		Token: token, UserID: user.ID, ExpiresAt: now.Add(s.cfg.ChallengeTTL), CreatedAt: now,
	}); err != nil {
		return false, "", err
	}
	s.setChallengeCookie(w, r, token, now.Add(s.cfg.ChallengeTTL))
	return true, s.verifyPath, nil
}

func (s *Service) setChallengeCookie(w http.ResponseWriter, r *http.Request, token string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     challengeCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   s.mgr.CookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) clearChallengeCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     challengeCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.mgr.CookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// loadChallenge récupère le challenge en cours (cookie + store) et l'utilisateur
// associé. Refuse un challenge expiré (au-delà de son TTL) ou pointant vers un
// compte inactif.
func (s *Service) loadChallenge(r *http.Request) (*authx.User, *Challenge, bool) {
	c, err := r.Cookie(challengeCookieName)
	if err != nil || c.Value == "" {
		return nil, nil, false
	}
	ch, err := s.chs.Get(c.Value)
	if err != nil {
		return nil, nil, false
	}
	if ch.Expired(time.Now()) {
		_ = s.chs.Delete(ch.Token)
		return nil, nil, false
	}
	user, err := s.mgr.Users().GetByID(ch.UserID)
	if err != nil || !user.IsActive {
		return nil, nil, false
	}
	return user, ch, true
}

// Vérifie que Service satisfait l'interface SecondFactor de authx.
var _ authx.SecondFactor = (*Service)(nil)
