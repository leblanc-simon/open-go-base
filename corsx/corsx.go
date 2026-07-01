package corsx

import (
	"net/http"

	"github.com/rs/cors"

	"leblanc.io/open-go-base/appconf"
)

// New construit le *cors.Cors sous-jacent à partir de cfg. Utile si l'appelant
// veut composer manuellement ; sinon préférer Middleware.
//
// Sécurité : combiner une origine "*" avec AllowCredentials=true est interdit par
// la spec Fetch (et rejeté par les navigateurs), mais rs/cors sert tout de même
// cette combinaison contradictoire. On la neutralise ici : en présence d'un
// wildcard, le sens "API publique, toutes origines" l'emporte et les credentials
// sont désactivés. Pour autoriser les credentials, lister explicitement les
// origines de confiance (sans "*").
func New(cfg appconf.CORS) *cors.Cors {
	allowCredentials := cfg.AllowCredentials
	if allowCredentials && hasWildcardOrigin(cfg.AllowedOrigins) {
		allowCredentials = false
	}
	return cors.New(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   cfg.AllowedMethods,
		AllowedHeaders:   cfg.AllowedHeaders,
		ExposedHeaders:   cfg.ExposedHeaders,
		AllowCredentials: allowCredentials,
		MaxAge:           cfg.MaxAge,
	})
}

// hasWildcardOrigin indique si la liste autorise toutes les origines (présence
// de "*", ou liste vide que rs/cors interprète aussi comme "toutes").
func hasWildcardOrigin(origins []string) bool {
	if len(origins) == 0 {
		return true
	}
	for _, o := range origins {
		if o == "*" {
			return true
		}
	}
	return false
}

// Middleware retourne un middleware net/http (func(http.Handler) http.Handler)
// appliquant la politique CORS décrite par cfg.
func Middleware(cfg appconf.CORS) func(http.Handler) http.Handler {
	return New(cfg).Handler
}
