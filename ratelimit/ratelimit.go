package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/httprate"
	realclientip "github.com/realclientip/realclientip-go"
)

// window est la fenêtre de comptage. Le brief raisonne en requêtes par minute.
const window = time.Minute

// Option configure le Limiter à la construction.
type Option func(*settings)

type settings struct {
	limitHandler http.HandlerFunc
}

// WithLimitHandler définit le handler appelé lorsqu'une requête dépasse le seuil,
// à la place du 429 par défaut. Le handler est responsable d'écrire le code de
// statut et le corps de la réponse (typiquement 429 avec un message applicatif,
// p. ex. un corps JSON localisé). Les en-têtes Retry-After et X-RateLimit-* sont
// déjà positionnés sur w lorsqu'il est invoqué.
//
// Un handler nil est ignoré (comportement par défaut conservé).
func WithLimitHandler(h http.Handler) Option {
	return func(s *settings) {
		if h != nil {
			s.limitHandler = h.ServeHTTP
		}
	}
}

// Limiter limite le débit par IP client. Sa résolution d'IP ne fait confiance
// aux en-têtes X-Forwarded-For / X-Real-IP que lorsque la connexion provient
// d'un proxy listé dans TrustedProxies ; sinon elle utilise l'IP de la
// connexion (RemoteAddr). C'est la défense contre l'usurpation d'IP.
type Limiter struct {
	requestLimit int
	middleware   func(http.Handler) http.Handler
	trustedNets  []net.IPNet
	strategy     realclientip.Strategy // nil si aucun proxy de confiance
}

// New construit un Limiter pour requestLimit requêtes par minute et par client.
// trustedProxies est une liste de CIDR ou d'IP (ex. "10.0.0.0/8", "192.168.1.5").
// Des options (p. ex. WithLimitHandler) peuvent personnaliser le comportement.
//
// Si requestLimit <= 0, la limitation est désactivée (le middleware laisse tout
// passer) : un seuil mal configuré ne doit pas verrouiller toute l'application.
func New(requestLimit int, trustedProxies []string, opts ...Option) (*Limiter, error) {
	var s settings
	for _, o := range opts {
		o(&s)
	}

	l := &Limiter{requestLimit: requestLimit}

	if len(trustedProxies) > 0 {
		nets, err := realclientip.AddressesAndRangesToIPNets(trustedProxies...)
		if err != nil {
			return nil, fmt.Errorf("ratelimit: trusted proxies invalides: %w", err)
		}
		l.trustedNets = nets
		// X-Forwarded-For en priorité (multi-sauts, on ignore nos propres
		// proxys via rightmost-trusted-range), puis X-Real-IP en repli.
		xff := realclientip.Must(realclientip.NewRightmostTrustedRangeStrategy("X-Forwarded-For", nets))
		xRealIP := realclientip.Must(realclientip.NewSingleIPHeaderStrategy("X-Real-IP"))
		l.strategy = realclientip.NewChainStrategy(xff, xRealIP)
	}

	if requestLimit > 0 {
		hropts := []httprate.Option{
			httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
				return l.ClientIP(r), nil
			}),
		}
		if s.limitHandler != nil {
			hropts = append(hropts, httprate.WithLimitHandler(s.limitHandler))
		}
		l.middleware = httprate.Limit(requestLimit, window, hropts...)
	} else {
		l.middleware = func(next http.Handler) http.Handler { return next }
	}

	return l, nil
}

// Middleware applique la limitation de débit. Une requête au-delà du seuil reçoit
// un 429 Too Many Requests.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return l.middleware(next)
}

// ClientIP résout l'IP réelle du client. Les en-têtes de proxy ne sont pris en
// compte que si la connexion directe (RemoteAddr) provient d'un proxy de
// confiance ; sinon l'IP de la connexion est utilisée telle quelle.
func (l *Limiter) ClientIP(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	if l.strategy != nil && l.peerTrusted(peer) {
		if ip := l.strategy.ClientIP(r.Header, r.RemoteAddr); ip != "" {
			return hostOnly(ip)
		}
	}
	return peer
}

// peerTrusted indique si l'IP de connexion directe appartient à un réseau de
// proxy de confiance.
func (l *Limiter) peerTrusted(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for i := range l.trustedNets {
		if l.trustedNets[i].Contains(ip) {
			return true
		}
	}
	return false
}

// hostOnly extrait l'hôte d'une adresse (retire le port et l'éventuelle zone
// IPv6), pour produire une clé de limitation stable.
func hostOnly(addr string) string {
	if addr == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		addr = h
	}
	if i := strings.IndexByte(addr, '%'); i >= 0 {
		addr = addr[:i]
	}
	return addr
}
