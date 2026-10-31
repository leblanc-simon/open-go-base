package authx

import "net/http"

// ErrorCode est la nature stable d'une erreur présentée à l'utilisateur. Le
// projet la traduit (clé de traduction) au lieu d'afficher un texte figé : les
// valeurs ne changent pas d'une version à l'autre.
type ErrorCode string

const (
	// CodeInvalidCredentials : couple email/mot de passe refusé (message
	// générique, qui ne distingue jamais un email inconnu d'un mot de passe
	// erroné).
	CodeInvalidCredentials ErrorCode = "invalid_credentials"
	// CodeInvalidForm : corps de formulaire illisible (400).
	CodeInvalidForm ErrorCode = "invalid_form"
	// CodeForbidden : utilisateur authentifié sans le rôle exigé (403).
	CodeForbidden ErrorCode = "forbidden"
	// CodeInternal : erreur interne (stockage, aléa…) ; le détail n'est jamais
	// renvoyé au client (500).
	CodeInternal ErrorCode = "internal"
)

// defaultMessages garde les textes français historiques, toujours renseignés
// dans LoginView.Error pour les projets qui les affichent tels quels.
var defaultMessages = map[ErrorCode]string{
	CodeInvalidCredentials: "Identifiants invalides",
	CodeInvalidForm:        "invalid form",
	CodeForbidden:          "Accès interdit",
	CodeInternal:           "Erreur interne",
}

// DefaultMessage renvoie le texte français par défaut d'un code (vide si le code
// est inconnu). Un projet multilingue traduit plutôt le code lui-même.
func DefaultMessage(code ErrorCode) string { return defaultMessages[code] }

// ErrorHandler écrit la réponse d'une erreur qui interrompt une requête
// (formulaire illisible, rôle insuffisant, erreur interne). err porte la cause
// technique, à journaliser et jamais à renvoyer au client ; il est nil quand le
// code suffit (CodeForbidden, CodeInvalidForm).
type ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, code ErrorCode, err error)

// defaultErrorHandler répond en texte brut, sans jamais exposer err : un détail
// de stockage n'a rien à faire dans une réponse HTTP.
func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, status int, code ErrorCode, _ error) {
	msg := DefaultMessage(code)
	if msg == "" {
		msg = http.StatusText(status)
	}
	http.Error(w, msg, status)
}
