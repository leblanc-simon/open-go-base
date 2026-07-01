package appconf

import "time"

// Fragments de configuration standard, à embarquer par composition dans la
// Config de chaque projet. Les tags `env` sont volontairement SANS préfixe : le
// préfixe est ajouté au point de composition via `env-prefix:"..."` sur le champ
// imbriqué (cleanenv ne supporte qu'un préfixe statique, pas dynamique).

// Web décrit la configuration d'un serveur HTTP.
type Web struct {
	Host           string   `yaml:"host"            env:"HOST"            env-default:"127.0.0.1" env-description:"Listen IP for web server"`
	Port           int      `yaml:"port"            env:"PORT"            env-default:"8080"      env-description:"Listen port"`
	RateLimit      int      `yaml:"rate_limit"      env:"RATE_LIMIT"      env-default:"100"       env-description:"Max requests per minute per client"`
	TrustedProxies []string `yaml:"trusted_proxies" env:"TRUSTED_PROXIES"  env-separator:","       env-description:"Trusted proxy CIDRs"`
}

// Redis décrit la connexion à un serveur Redis. Ses variables d'env sont
// préfixées par REDIS_ pour ne pas entrer en collision avec Web (qui expose
// aussi HOST/PORT) lorsque les deux fragments partagent le même env-prefix de
// projet.
type Redis struct {
	Host     string `yaml:"host"     env:"REDIS_HOST"     env-default:"127.0.0.1" env-description:"Redis host"`
	Port     int    `yaml:"port"     env:"REDIS_PORT"     env-default:"6379"      env-description:"Redis port"`
	Password string `yaml:"password" env:"REDIS_PASSWORD"                         env-description:"Redis password"`
	Db       int    `yaml:"db"       env:"REDIS_DB"       env-default:"0"         env-description:"Redis database index"`
}

// Logging décrit la configuration du logger (consommée par logx).
type Logging struct {
	Level  string `yaml:"level"  env:"LOG_LEVEL"  env-default:"error" env-description:"Log level (debug|info|warn|error)"`
	Format string `yaml:"format" env:"LOG_FORMAT" env-default:"text"  env-description:"Log output format (text|json)"`
	Source bool   `yaml:"source" env:"LOG_SOURCE" env-default:"false" env-description:"Include source file:line in logs"`
}

// CORS décrit la politique CORS (consommée par corsx). Une origine "*" autorise
// toutes les origines ; ne PAS combiner "*" avec AllowCredentials=true (interdit
// par la spec et refusé par les navigateurs).
type CORS struct {
	AllowedOrigins   []string `yaml:"allowed_origins"   env:"CORS_ALLOWED_ORIGINS"   env-separator:"," env-default:"*"                          env-description:"Allowed origins, '*' for any"`
	AllowedMethods   []string `yaml:"allowed_methods"   env:"CORS_ALLOWED_METHODS"   env-separator:"," env-default:"GET,POST,PUT,DELETE,OPTIONS" env-description:"Allowed HTTP methods"`
	AllowedHeaders   []string `yaml:"allowed_headers"   env:"CORS_ALLOWED_HEADERS"   env-separator:"," env-default:"*"                          env-description:"Allowed request headers, '*' for any"`
	ExposedHeaders   []string `yaml:"exposed_headers"   env:"CORS_EXPOSED_HEADERS"   env-separator:","                                          env-description:"Response headers exposed to the browser"`
	AllowCredentials bool     `yaml:"allow_credentials" env:"CORS_ALLOW_CREDENTIALS" env-default:"false"                                        env-description:"Allow cookies/credentials"`
	MaxAge           int      `yaml:"max_age"           env:"CORS_MAX_AGE"           env-default:"300"                                          env-description:"Preflight cache duration in seconds"`
}

// I18n décrit la configuration des traductions (consommée par i18n). Les langues
// disponibles sont déduites dynamiquement des fichiers présents dans Dir.
type I18n struct {
	Dir             string `yaml:"dir"              env:"I18N_DIR"              env-default:"locales" env-description:"Directory containing translation files"`
	DefaultLanguage string `yaml:"default_language" env:"I18N_DEFAULT_LANGUAGE" env-default:"en"      env-description:"Fallback language (BCP 47 tag, e.g. en, fr)"`
}

// Auth décrit la configuration de l'authentification par mot de passe et
// sessions (consommée par authx). CookieSecure pilote l'attribut Secure des
// cookies : "auto" (Secure si TLS direct ou X-Forwarded-Proto=https), "on"
// (toujours), "off" (jamais, dev HTTP local uniquement).
type Auth struct {
	SessionTTL   time.Duration `yaml:"session_ttl"   env:"AUTH_SESSION_TTL"   env-default:"12h"     env-description:"Sliding session lifetime"`
	CookieName   string        `yaml:"cookie_name"   env:"AUTH_COOKIE_NAME"   env-default:"session" env-description:"Session cookie name"`
	CookieSecure string        `yaml:"cookie_secure" env:"AUTH_COOKIE_SECURE" env-default:"auto"    env-description:"Secure cookie attribute: auto|on|off"`
	BcryptCost   int           `yaml:"bcrypt_cost"   env:"AUTH_BCRYPT_COST"   env-default:"12"      env-description:"bcrypt cost for password hashing (4-31)"`
}

// MFA décrit la configuration de la double authentification TOTP (consommée par
// mfax). Issuer est le nom affiché dans les applications d'authentification.
type MFA struct {
	Issuer       string        `yaml:"issuer"        env:"MFA_ISSUER"        env-default:"open-go-base" env-description:"Issuer shown in authenticator apps"`
	ChallengeTTL time.Duration `yaml:"challenge_ttl" env:"MFA_CHALLENGE_TTL" env-default:"10m"          env-description:"Lifetime of a pending 2FA challenge"`
	MaxAttempts  int           `yaml:"max_attempts"  env:"MFA_MAX_ATTEMPTS"  env-default:"5"            env-description:"Max verification attempts before a challenge is dropped"`
}

// Dialect identifie le moteur SQL ciblé. Il sélectionne le jeu de migrations et
// la syntaxe des requêtes des sous-packages sqlstore. Cet enum vit dans appconf
// (donnée de configuration) pour ne pas inverser le sens de dépendance : les
// composants consomment appconf, jamais l'inverse.
type Dialect int

const (
	DialectUnknown Dialect = iota
	DialectSQLite
	DialectPostgres
	DialectMySQL
)

// String renvoie le nom court du dialecte (sqlite|postgres|mysql), aussi utilisé
// comme nom de sous-dossier de migrations. Vide pour DialectUnknown.
func (d Dialect) String() string {
	switch d {
	case DialectSQLite:
		return "sqlite"
	case DialectPostgres:
		return "postgres"
	case DialectMySQL:
		return "mysql"
	default:
		return ""
	}
}

// Database décrit la base SQL applicative (consommée par les sqlstore de authx
// et mfax). Le projet ouvre lui-même son *sql.DB ; ce fragment porte le driver
// (pour en déduire le dialecte) et le DSN de connexion.
type Database struct {
	Driver string `yaml:"driver" env:"DB_DRIVER" env-default:"sqlite" env-description:"SQL driver/dialect: sqlite|postgres|mysql"`
	DSN    string `yaml:"dsn"    env:"DB_DSN"                          env-description:"Data source name (connection string)"`
}

// Dialect déduit le dialecte SQL du nom de driver (tolérant aux alias usuels :
// sqlite3, postgresql, pgx, pq, ...). Renvoie DialectUnknown si non reconnu.
func (d Database) Dialect() Dialect {
	switch d.Driver {
	case "", "sqlite", "sqlite3", "libsql":
		return DialectSQLite
	case "postgres", "postgresql", "pgx", "pq":
		return DialectPostgres
	case "mysql", "mariadb":
		return DialectMySQL
	default:
		return DialectUnknown
	}
}
