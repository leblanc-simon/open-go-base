package mfax

import "net/http"

// ErrorCode est la nature stable d'une erreur présentée à l'utilisateur, à
// traduire par le projet. Les valeurs ne changent pas d'une version à l'autre.
type ErrorCode string

const (
	// CodeInvalidCode : code TOTP refusé (faux, expiré ou déjà utilisé). C'est
	// aussi la valeur du paramètre ?error= des redirections d'EnablePOST et de
	// DisablePOST.
	CodeInvalidCode ErrorCode = "invalid_code"
	// CodeAttemptsExhausted : plafond de tentatives atteint, le challenge est
	// abandonné. C'est la valeur du paramètre ?err= de la redirection vers
	// /login.
	CodeAttemptsExhausted ErrorCode = "2fa_exhausted"
	// CodeLocked : compte verrouillé après trop de codes faux (WithLockout). C'est
	// la valeur du paramètre ?err= de la redirection vers /login, et du paramètre
	// ?error= de la redirection de DisablePOST.
	CodeLocked ErrorCode = "2fa_locked"
	// CodeInvalidForm : corps de formulaire illisible (400).
	CodeInvalidForm ErrorCode = "invalid_form"
	// CodeInternal : erreur interne (stockage, aléa, rendu absent…) ; le détail
	// n'est jamais renvoyé au client (500).
	CodeInternal ErrorCode = "internal"
)

// lockedPath est la redirection d'un compte verrouillé.
const lockedPath = "/login?err=" + string(CodeLocked)

// ChallengeCookieName est le nom par défaut du cookie qui porte le challenge en cours entre
// le mot de passe et le code TOTP. Exposé pour qu'un projet relie une tentative
// à son challenge (journal d'audit), jamais pour le modifier.
const ChallengeCookieName = challengeCookieName

var defaultMessages = map[ErrorCode]string{
	CodeInvalidCode:       "Code invalide",
	CodeAttemptsExhausted: "Trop de tentatives",
	CodeLocked:            "Trop de codes refusés : réessayez plus tard",
	CodeInvalidForm:       "invalid form",
	CodeInternal:          "Erreur interne",
}

// DefaultMessage renvoie le texte français par défaut d'un code (vide si le code
// est inconnu). Un projet multilingue traduit plutôt le code lui-même.
func DefaultMessage(code ErrorCode) string { return defaultMessages[code] }

// ErrorHandler écrit la réponse d'une erreur qui interrompt une requête
// (formulaire illisible, erreur interne). err porte la cause technique, à
// journaliser et jamais à renvoyer au client.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, code ErrorCode, err error)

// WithErrorHandler remplace la réponse des erreurs qui interrompent les
// handlers de mfax (400 CodeInvalidForm, 500 CodeInternal). Par défaut, un texte
// brut sans détail technique. Un handler nil est ignoré.
func WithErrorHandler(h ErrorHandler) Option {
	return func(s *Service) {
		if h != nil {
			s.onError = h
		}
	}
}

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, status int, code ErrorCode, _ error) {
	msg := DefaultMessage(code)
	if msg == "" {
		msg = http.StatusText(status)
	}
	http.Error(w, msg, status)
}

// codeFromQuery n'accepte que les codes connus : le paramètre ?error= d'une URL
// n'est jamais réaffiché tel quel (sinon un lien forgé ferait afficher un texte
// arbitraire sur la page).
func codeFromQuery(v string) ErrorCode {
	if c := ErrorCode(v); c == CodeInvalidCode {
		return c
	}
	return ""
}
