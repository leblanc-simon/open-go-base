# open-go-base

Bibliothèque Go partagée (`leblanc.io/open-go-base`) qui factorise le bootstrap commun à
plusieurs applications web : chargement de configuration, flags `--help`/`--version`, et un
jeu de composants runtime préconfigurés (logger, CORS, rate limiter, i18n).

Principe directeur : **la configuration décrit des données, les composants les consomment.**
Tout se configure via des fragments du package `appconf`, composés dans la `Config` de votre
projet. La dépendance va toujours composant → `appconf`, jamais l'inverse.

## Installation

```bash
go get leblanc.io/open-go-base
```

## Sommaire

- [Vue d'ensemble : assemblage complet](#vue-densemble--assemblage-complet)
- [`appconf` — configuration & bootstrap](#appconf--configuration--bootstrap)
- [`logx` — logger structuré](#logx--logger-structuré)
- [`corsx` — middleware CORS](#corsx--middleware-cors)
- [`csrfx` — protection CSRF](#csrfx--protection-csrf)
- [`ratelimit` — limiteur de débit](#ratelimit--limiteur-de-débit)
- [`i18n` — traductions](#i18n--traductions)
- [`authx` — authentification & sessions](#authx--authentification--sessions)
- [`mfax` — double authentification TOTP](#mfax--double-authentification-totp)

---

## Vue d'ensemble : assemblage complet

Une application type définit sa `Config` en composant les fragments, puis câble les
composants à partir de cette config.

**`config/config.go`** — composition des fragments (le préfixe d'env est posé ici) :

```go
package config

import "leblanc.io/open-go-base/appconf"

type Config struct {
	Web  appconf.Web     `yaml:"web"      env-prefix:"OGS_"`     // OGS_HOST, OGS_PORT, OGS_RATE_LIMIT...
	DB   appconf.Redis   `yaml:"database" env-prefix:"OGS_"`     // OGS_REDIS_HOST, OGS_REDIS_PORT...
	Log  appconf.Logging `yaml:"logging"  env-prefix:"OGS_"`     // OGS_LOG_LEVEL, OGS_LOG_FORMAT...
	CORS appconf.CORS    `yaml:"cors"     env-prefix:"OGS_"`     // OGS_CORS_ALLOWED_ORIGINS...
	I18n appconf.I18n    `yaml:"i18n"     env-prefix:"OGS_"`     // OGS_I18N_DIR, OGS_I18N_DEFAULT_LANGUAGE
	// + vos champs spécifiques (Auth, etc.)
}
```

**`main.go`** — chargement + câblage :

```go
package main

import (
	"fmt"
	"net/http"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/corsx"
	"leblanc.io/open-go-base/i18n"
	"leblanc.io/open-go-base/logx"
	"leblanc.io/open-go-base/ratelimit"

	"open-go-shorten.eu/config"
)

var (
	version = "develop"      // injectée au build via -ldflags "-X 'main.version=...'"
	appName = "OpenGoShorten"
)

func main() {
	var cfg config.Config
	appconf.MustLoad(&cfg, appconf.Options{Name: appName, Version: version})

	logger := logx.New(cfg.Log)

	limiter, err := ratelimit.New(cfg.Web.RateLimit, cfg.Web.TrustedProxies)
	if err != nil {
		logger.Error("rate limiter", "err", err)
		return
	}

	bundle, err := i18n.New(cfg.I18n)
	if err != nil {
		logger.Error("i18n", "err", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		loc := bundle.FromRequest(r)
		fmt.Fprintln(w, loc.T("hello"))
	})

	// Chaîne de middlewares : CORS -> rate limit -> routeur.
	handler := corsx.Middleware(cfg.CORS)(limiter.Middleware(mux))

	addr := fmt.Sprintf("%s:%d", cfg.Web.Host, cfg.Web.Port)
	logger.Info("listening", "addr", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		logger.Error("server stopped", "err", err)
	}
}
```

---

## `appconf` — configuration & bootstrap

Charge la configuration depuis un fichier YAML **s'il existe**, sinon depuis l'environnement,
et câble les flags `--help` / `--version`. Repose sur
[`cleanenv`](https://github.com/ilyakaznacheev/cleanenv).

### API

```go
type Options struct {
	Name           string // nom de l'app (flagset + sortie --version)
	Version        string // injectée depuis main via ldflags, passée ici
	DefaultCfgPath string // défaut "config.yaml" si vide
}

func Load(cfg any, opts Options) error // remplit cfg ; renvoie l'erreur de chargement
func MustLoad(cfg any, opts Options)   // idem mais os.Exit(2) en cas d'erreur
```

### Comportement

- **Flags** : `-c <chemin>` (fichier de config, défaut `config.yaml`) et `--version`.
- `--version` affiche `"<Name> <Version>"` et termine en code 0.
- `--help` affiche l'usage standard **puis** la liste documentée des variables
  d'environnement (générée automatiquement à partir des tags).
- Source de la config : si le fichier `-c` existe → lecture du fichier ; sinon → lecture de
  l'environnement. Dans les deux cas les valeurs par défaut (`env-default`) s'appliquent.

> `Load` ne fait jamais `os.Exit` sur une erreur de chargement : elle est renvoyée. Seul
> `MustLoad` sort en code 2. Les flags terminaux `--help`/`--version` terminent en code 0.

### Le préfixe d'environnement

cleanenv ne supporte qu'un préfixe **statique**. Les fragments d'`appconf` ont donc des tags
`env` **sans préfixe** ; vous posez le préfixe au point de composition, via `env-prefix` sur
le champ imbriqué de votre `Config` (voir l'exemple plus haut). Ainsi `appconf.Web.Port`
(`env:"PORT"`) devient `OGS_PORT` avec `env-prefix:"OGS_"`.

### Fragments disponibles

| Fragment | Champs (tag env, sans préfixe) | Défaut |
|---|---|---|
| `Web` | `HOST` | `127.0.0.1` |
| | `PORT` | `8080` |
| | `RATE_LIMIT` (req/min/client) | `100` |
| | `TRUSTED_PROXIES` (CIDR, séparés par `,`) | — |
| `Redis` | `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` / `REDIS_DB` | `127.0.0.1` / `6379` / — / `0` |
| `Logging` | `LOG_LEVEL` (debug\|info\|warn\|error) | `error` |
| | `LOG_FORMAT` (text\|json) | `text` |
| | `LOG_SOURCE` (bool) | `false` |
| `CORS` | `CORS_ALLOWED_ORIGINS` (séparés par `,`) | `*` |
| | `CORS_ALLOWED_METHODS` | `GET,POST,PUT,DELETE,OPTIONS` |
| | `CORS_ALLOWED_HEADERS` | `*` |
| | `CORS_EXPOSED_HEADERS` | — |
| | `CORS_ALLOW_CREDENTIALS` (bool) | `false` |
| | `CORS_MAX_AGE` (secondes) | `300` |
| `I18n` | `I18N_DIR` | `locales` |
| | `I18N_DEFAULT_LANGUAGE` (BCP 47) | `en` |

### Exemple de fichier `config.yaml`

```yaml
web:
  host: 0.0.0.0
  port: 8443
  rate_limit: 200
  trusted_proxies:
    - 10.0.0.0/8
    - 192.168.0.0/16
logging:
  level: info
  format: json
cors:
  allowed_origins:
    - https://app.example.com
  allow_credentials: true
i18n:
  dir: ./locales
  default_language: fr
```

---

## `logx` — logger structuré

Logger basé sur `log/slog` (stdlib), configuré par `appconf.Logging`.

```go
func New(cfg appconf.Logging) *slog.Logger              // écrit sur os.Stderr
func NewWith(cfg appconf.Logging, w io.Writer) *slog.Logger  // sortie personnalisée
func ParseLevel(s string) slog.Level                    // utilitaire
```

```go
logger := logx.New(cfg.Log)
logger.Info("user signed in", "user_id", 42, "ip", clientIP)
```

- `Format: "json"` → handler JSON ; toute autre valeur → handler texte.
- `Level` filtre les messages (`debug` < `info` < `warn` < `error`). Un niveau inconnu
  retombe sur `info` (le logger ne peut jamais échouer à se construire).
- `Source: true` ajoute le `fichier:ligne` d'origine.

---

## `corsx` — middleware CORS

Middleware net/http basé sur [`rs/cors`](https://github.com/rs/cors), configuré par
`appconf.CORS`.

```go
func Middleware(cfg appconf.CORS) func(http.Handler) http.Handler
func New(cfg appconf.CORS) *cors.Cors // si vous devez composer manuellement
```

```go
handler := corsx.Middleware(cfg.CORS)(mux)
```

> **Sécurité.** Combiner une origine `*` avec `AllowCredentials=true` est interdit par la
> spec Fetch. `corsx` neutralise cette combinaison contradictoire : en présence d'un
> wildcard, les credentials sont automatiquement désactivés (le sens « API publique, toutes
> origines » l'emporte). **Pour autoriser les credentials, listez explicitement les origines
> de confiance** (sans `*`).

---

## `csrfx` — protection CSRF

Middleware net/http de protection CSRF par **double soumission** (double-submit cookie), en
défense en profondeur par-dessus les cookies `SameSite=Lax` d'`authx`.

```go
func New(opts ...Option) *Protector            // WithCookieName/WithFieldName/WithHeaderName/WithSecure
func (p *Protector) Middleware(next http.Handler) http.Handler
func (p *Protector) FuncMap(r *http.Request) template.FuncMap // {{ csrfField }} / {{ csrfToken }}
func Token(r *http.Request) string
```

Le middleware pose un cookie de jeton aléatoire (256 bits, `HttpOnly`, `SameSite=Lax`) sur les
requêtes sûres et **rejette en 403** toute requête mutante (`POST`/`PUT`/`PATCH`/`DELETE`) dont
le jeton (en-tête `X-CSRF-Token` ou champ `csrf_token`) ne correspond pas au cookie.

```go
p := csrfx.New()
handler := p.Middleware(mux)
// Templates : tmpl.Funcs(p.FuncMap(r)) puis {{ csrfField }} dans chaque <form>.
// AJAX : renvoyer csrfx.Token(r) dans l'en-tête X-CSRF-Token.
```

> **Modèle de menace.** Le jeton est porté par un cookie non signé : on suppose qu'un attaquant
> ne peut pas écrire ce cookie sur le domaine. **Évitez de partager un domaine parent avec des
> sous-domaines non fiables.** SameSite=Lax reste la première barrière ; `csrfx` la renforce.

---

## `ratelimit` — limiteur de débit

Limiteur par client (req/minute) basé sur [`go-chi/httprate`](https://github.com/go-chi/httprate),
avec résolution sûre de l'IP réelle derrière des proxys de confiance.

```go
func New(requestLimit int, trustedProxies []string, opts ...Option) (*Limiter, error)
func WithLimitHandler(h http.Handler) Option // réponse 429 personnalisée

func (l *Limiter) Middleware(next http.Handler) http.Handler
func (l *Limiter) ClientIP(r *http.Request) string
```

```go
limiter, err := ratelimit.New(cfg.Web.RateLimit, cfg.Web.TrustedProxies)
if err != nil { /* ... */ }
handler := limiter.Middleware(mux)
```

- Au-delà du seuil, la réponse est `429 Too Many Requests`.
- `requestLimit <= 0` **désactive** la limitation (un seuil mal configuré ne doit pas
  verrouiller toute l'application).
- `WithLimitHandler` remplace la réponse 429 par défaut. Le handler écrit lui-même le statut
  et le corps ; les en-têtes `Retry-After` / `X-RateLimit-*` sont déjà positionnés.

```go
limiter, _ := ratelimit.New(cfg.Web.RateLimit, cfg.Web.TrustedProxies,
	ratelimit.WithLimitHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":"rate limit exceeded"}`)
	})),
)
```

> **Sécurité — résolution de l'IP client.** Les en-têtes `X-Forwarded-For` / `X-Real-IP` ne
> sont pris en compte **que si la connexion directe (`RemoteAddr`) provient d'un proxy listé
> dans `TrustedProxies`**. Sinon, l'IP de la connexion est utilisée telle quelle. Un client
> direct qui usurperait `X-Forwarded-For` ne peut donc pas se faire passer pour une autre IP.
> Dans une chaîne de proxys de confiance, les sauts internes sont retirés pour remonter au
> vrai client.

Renseignez `trusted_proxies` avec les CIDR de **vos** proxys/load-balancers uniquement. Une
liste vide signifie « aucun proxy » : seule l'IP de connexion est utilisée.

---

## `i18n` — traductions

Chargement de traductions et sélection de langue, basé sur
[`go-i18n/v2`](https://github.com/nicksnyder/go-i18n) et `golang.org/x/text`.

```go
func New(cfg appconf.I18n) (*Bundle, error)                   // locales depuis le disque (cfg.Dir)
func NewFS(fsys fs.FS, dir, defaultLanguage string) (*Bundle, error) // locales embarquées (go:embed)

func (b *Bundle) FromRequest(r *http.Request) *Localizer       // ?lang= puis Accept-Language
func (b *Bundle) Localizer(force, acceptLanguage string) *Localizer
func (b *Bundle) Languages() []language.Tag

func (l *Localizer) T(messageID string, data ...any) string        // traduction
func (l *Localizer) Tn(messageID string, count int, data ...any) string // pluriel
func (l *Localizer) FuncMap() map[string]any                       // pour les templates
func (l *Localizer) Lang() language.Tag                            // langue résolue
```

### Fichiers de traduction

Le jeu de langues est **déduit dynamiquement** des fichiers YAML présents dans le dossier
`I18n.Dir` (extensions `.yaml`, `.yml`). Un fichier par langue, nommé d'après le tag BCP 47.
Des locales d'exemple sont fournies dans `locales/`.

### Embarquer les locales dans le binaire (`go:embed`)

`New` lit le disque : le dossier `locales/` doit être déployé à côté de l'exécutable. Pour un
binaire **autonome**, utiliser `NewFS` avec un `embed.FS` — les YAML sont compilés dans le
binaire. `dir` est le chemin des fichiers dans le FS embarqué (`.` pour la racine).

```go
import "embed"

//go:embed locales/*.yaml
var localesFS embed.FS

bundle, err := i18n.NewFS(localesFS, "locales", cfg.I18n.DefaultLanguage)
```

`New(cfg)` est équivalent à `NewFS(os.DirFS(cfg.Dir), ".", cfg.DefaultLanguage)`.

`locales/fr.yaml` :

```yaml
hello: Bonjour
greeting: Bonjour {{.Name}}

cats:
  one: "{{.Count}} chat"
  other: "{{.Count}} chats"
```

`locales/en.yaml` :

```yaml
hello: Hello
greeting: Hello {{.Name}}

cats:
  one: "{{.Count}} cat"
  other: "{{.Count}} cats"
```

### Sélection de la langue

Ordre de priorité dans `FromRequest` : paramètre de requête `?lang=` (forçage) →
en-tête `Accept-Language` (détection automatique) → langue par défaut (repli).

```go
loc := bundle.FromRequest(r)
fmt.Fprintln(w, loc.T("hello"))                          // "Bonjour" si fr
fmt.Fprintln(w, loc.T("greeting", map[string]any{"Name": "Sam"}))  // "Bonjour Sam"
fmt.Fprintln(w, loc.Tn("cats", 3))                       // "3 chats"
```

Forçage explicite hors requête HTTP :

```go
loc := bundle.Localizer("fr", "")           // force le français
loc := bundle.Localizer("", "de-DE,de;q=0.9") // détecte via une chaîne Accept-Language
```

Une traduction absente renvoie le `messageID` tel quel (repli visible, non fatal).

### Dans les templates

`FuncMap()` expose `T` et `Tn`. Le type de retour (`map[string]any`) est assignable aussi
bien à `text/template.FuncMap` qu'à `html/template.FuncMap`.

```go
loc := bundle.FromRequest(r)
tmpl := template.Must(template.New("page").Funcs(loc.FuncMap()).Parse(
	`{{ T "greeting" . }} — {{ Tn "cats" 2 }}`,
))
tmpl.Execute(w, map[string]any{"Name": "Sam"}) // "Bonjour Sam — 2 chats"
```

## `authx` — authentification & sessions

Authentification par mot de passe et sessions persistées, montable sur n'importe quel routeur
`net/http`. Hachage bcrypt, sessions glissantes via cookie `HttpOnly`/`SameSite=Lax`/`Secure`,
middleware de chargement de session et garde par rôle, handlers de connexion/déconnexion.

`authx` délègue deux responsabilités au projet : le **stockage** (interfaces `UserStore` /
`SessionStore`, avec une implémentation `database/sql` + migrations dans `authx/sqlstore`) et
le **rendu HTML** (interface `Renderer` : `authx` fournit les données, le projet le template).

```go
func New(cfg appconf.Auth, users UserStore, sessions SessionStore) *Manager

func (m *Manager) LoadSession(next http.Handler) http.Handler          // attache l'utilisateur au contexte
func (m *Manager) RequireAuth(roles ...Role) func(http.Handler) http.Handler // exige une session (+ rôle)
func (m *Manager) OpenSession(w, r, user *User, purpose Purpose) (*Session, error)
func (m *Manager) Logout(w, r)

func UserFrom(r *http.Request) *User        // utilisateur courant, ou nil
func SessionFrom(r *http.Request) *Session

func NewHandlers(mgr *Manager, renderer Renderer, opts ...HandlerOption) *Handlers
func (h *Handlers) LoginGET / LoginPOST / Logout
```

Configuration via le fragment `appconf.Auth` (`session_ttl`, `cookie_name`, `cookie_secure`
`auto|on|off`, `bcrypt_cost`).

```go
mgr := authx.New(cfg.Auth, sqlstore.NewUserStore(db), sqlstore.NewSessionStore(db))
h := authx.NewHandlers(mgr, myRenderer)

r := chi.NewRouter()
r.Use(mgr.LoadSession)
r.Get("/login", h.LoginGET)
r.Post("/login", h.LoginPOST)
r.Post("/logout", h.Logout)
r.Group(func(r chi.Router) {
	r.Use(mgr.RequireAuth())          // ou RequireAuth("admin")
	r.Get("/", home)                  // authx.UserFrom(r) donne l'utilisateur
})
```

### Stockage

`authx/sqlstore` fournit une implémentation `database/sql` des deux stores et embarque ses
migrations (tables `users`, `sessions`). Le driver est fourni par le projet (`sql.Open`),
jamais importé par la lib.

**Multi-dialecte.** Le dialecte SQL est choisi via `appconf.Dialect` (déduit du driver par le
fragment `appconf.Database`). Dialectes gérés : **SQLite** et **PostgreSQL** (MySQL prévu, point
d'extension en place). Le même code applicatif fonctionne sur les deux ; les migrations vivent
dans un sous-dossier par dialecte et les requêtes adaptent automatiquement les placeholders
(`?` → `$1…` en Postgres).

```go
type Config struct {
	DB appconf.Database `yaml:"database" env-prefix:"OGS_"` // OGS_DB_DRIVER=sqlite|postgres, OGS_DB_DSN=...
}

db, _ := sql.Open(cfg.DB.Driver, cfg.DB.DSN) // driver fourni par le projet
dialect := cfg.DB.Dialect()                  // appconf.DialectSQLite | DialectPostgres

_ = sqlstore.Migrate(db, dialect)            // idempotent, à appeler au démarrage
users := sqlstore.NewUserStore(db, dialect)
sessions := sqlstore.NewSessionStore(db, dialect)
```

Idem pour `mfax/sqlstore` (`Migrate(db, dialect)`, `NewTOTPStore(db, dialect)`,
`NewChallengeStore(db, dialect)`). Migrer `authx` **avant** `mfax`. Un dialecte non géré
(MySQL pour l'instant) fait échouer `Migrate` avec `ErrUnsupportedDialect`.

### Sécurité

- Échec de connexion **générique** (jamais distinguer email inconnu de mot de passe erroné),
  avec **égalisation du temps de réponse** (comparaison bcrypt factice sur email inconnu) pour
  ne pas fuiter l'existence d'un compte par canal temporel.
- `?next=` n'accepte que des chemins **locaux** : rejet de `//host`, `/\host` (normalisé par
  les navigateurs en `//`) et des caractères de contrôle (anti redirection ouverte / CRLF).
- Cookie `HttpOnly`, `SameSite=Lax`, `Secure` selon `cookie_secure` (`auto` = TLS direct ou
  `X-Forwarded-Proto: https`).
- **Mots de passe pré-hachés en SHA-256** avant bcrypt (`bcrypt(base64(sha256(pwd)))`) pour
  éviter la troncature silencieuse de bcrypt au-delà de 72 octets. ⚠️ **Changement cassant** :
  des hash produits par une version antérieure (bcrypt direct) ne valident plus — les mots de
  passe concernés doivent être re-hachés (re-saisie / réinitialisation).

## `mfax` — double authentification TOTP

Second facteur TOTP par-dessus `authx`, basé sur
[`pquerna/otp`](https://github.com/pquerna/otp) (+ QR code via `rsc.io/qr`). Provisioning
(secret + QR), vérification du code à la connexion, configuration/désactivation par
l'utilisateur. Son schéma est **dédié** (tables `mfa_totp`, `mfa_challenges`) : `mfax` ne
touche jamais aux tables de `authx`.

```go
func New(cfg appconf.MFA, mgr *authx.Manager, totp TOTPStore, chs ChallengeStore, opts ...Option) *Service

func (s *Service) Begin(w, r, user *authx.User) (required bool, redirectURL string, err error) // authx.SecondFactor
func (s *Service) VerifyGET / VerifyPOST          // /login/2fa
func (s *Service) SetupGET / EnablePOST / DisablePOST // configuration TOTP
func (s *Service) Provision(user *authx.User) (secret, provisioningURL string, err error)
```

`mfax.Service` implémente `authx.SecondFactor` : on le branche dans le login via
`authx.WithSecondFactor`. Après un mot de passe valide, `Begin` crée un challenge (TOTP actif)
ou dirige vers la configuration (enrôlement obligatoire par défaut, via une session de setup
élevée en session authentifiée une fois le TOTP confirmé).

```go
mgr := authx.New(cfg.Auth, authsql.NewUserStore(db), authsql.NewSessionStore(db))
svc := mfax.New(cfg.MFA, mgr, mfasql.NewTOTPStore(db), mfasql.NewChallengeStore(db),
	mfax.WithRenderer(rend))

h := authx.NewHandlers(mgr, rend, authx.WithSecondFactor(svc)) // login délègue le 2e facteur

r.Use(mgr.LoadSession)
r.Get("/login", h.LoginGET)
r.Post("/login", h.LoginPOST)
r.Get("/login/2fa", svc.VerifyGET)
r.Post("/login/2fa", svc.VerifyPOST)
r.Get("/profile/totp/setup", svc.SetupGET)     // session de setup ou authentifiée
r.Post("/profile/totp/enable", svc.EnablePOST)
r.Group(func(r chi.Router) {
	r.Use(mgr.RequireAuth())
	r.Post("/profile/totp/disable", svc.DisablePOST)
})
```

Configuration via le fragment `appconf.MFA` (`issuer`, `challenge_ttl`, `max_attempts`).
`WithOptionalEnrollment()` rend la 2FA facultative (login direct si non configurée). Le QR
s'obtient via `mfax.QRDataURI(provisioningURL)` (à typer en `template.URL` côté template).

> **Sécurité.** Compteur de tentatives **atomique** (pas de contournement de `max_attempts` par
> requêtes concurrentes). **Anti-rejeu** : un code TOTP n'est accepté qu'une fois (suivi du
> dernier pas de temps consommé). **Step-up** : `DisablePOST` exige un code TOTP valide pour
> désactiver la 2FA. `SetupGET` refuse de re-provisionner une 2FA déjà active (un GET ne peut
> pas écraser un secret en place ; désactiver d'abord via `DisablePOST`). Le champ `last_step`
> de `mfa_totp` est ajouté par la migration `002` (jouée automatiquement par `Migrate`).

### Composition des fragments

```go
type Config struct {
	Web  appconf.Web  `yaml:"web"  env-prefix:"OGS_"`
	Auth appconf.Auth `yaml:"auth" env-prefix:"OGS_"` // OGS_AUTH_SESSION_TTL, OGS_AUTH_COOKIE_SECURE...
	MFA  appconf.MFA  `yaml:"mfa"  env-prefix:"OGS_"` // OGS_MFA_ISSUER, OGS_MFA_CHALLENGE_TTL...
}
```

## License

[WTFPL](https://www.wtfpl.net/)

## Authors

* Simon Leblanc <contact@leblanc-simon.eu>
* [Claude.ai](https://claude.ai/)