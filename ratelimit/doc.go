// Package ratelimit fournit un limiteur de débit HTTP par client, avec une
// résolution sûre de l'IP réelle derrière des proxys de confiance.
//
// Il consomme directement appconf.Web.RateLimit (requêtes par minute) et
// appconf.Web.TrustedProxies (CIDR des proxys de confiance) :
//
//	limiter, err := ratelimit.New(cfg.Web.RateLimit, cfg.Web.TrustedProxies)
//	handler := limiter.Middleware(mux)
//
// Au-delà du seuil, la réponse est 429 Too Many Requests. Un seuil <= 0 désactive
// la limitation (une mauvaise configuration ne doit pas verrouiller l'app).
//
// La réponse 429 est personnalisable via WithLimitHandler (p. ex. pour renvoyer
// un corps JSON localisé) :
//
//	limiter, _ := ratelimit.New(cfg.Web.RateLimit, cfg.Web.TrustedProxies,
//		ratelimit.WithLimitHandler(myHandler))
//
// Sécurité : les en-têtes X-Forwarded-For / X-Real-IP ne sont pris en compte que
// si la connexion directe (RemoteAddr) provient d'un proxy listé dans
// TrustedProxies ; sinon l'IP de la connexion est utilisée. Un client direct qui
// usurperait X-Forwarded-For ne peut donc pas se faire passer pour une autre IP.
package ratelimit
