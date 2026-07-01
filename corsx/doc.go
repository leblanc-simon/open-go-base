// Package corsx fournit un middleware CORS net/http préconfiguré à partir d'un
// fragment appconf.CORS, en s'appuyant sur github.com/rs/cors.
//
// Middleware retourne un func(http.Handler) http.Handler appliquant la politique
// décrite par la configuration :
//
//	handler := corsx.Middleware(cfg.CORS)(mux)
//
// Sécurité : combiner une origine "*" avec AllowCredentials=true est interdit par
// la spec Fetch. corsx neutralise cette combinaison contradictoire en désactivant
// les credentials lorsqu'un wildcard est présent. Pour autoriser les credentials,
// lister explicitement les origines de confiance (sans "*").
package corsx
