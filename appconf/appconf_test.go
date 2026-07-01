package appconf

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testConfig reproduit la composition côté projet : des fragments standard
// embarqués avec un env-prefix au point de composition (décision d'archi #3).
type testConfig struct {
	Web Web     `yaml:"web"      env-prefix:"OGS_"`
	DB  Redis   `yaml:"database" env-prefix:"OGS_"`
	Log Logging `yaml:"server"   env-prefix:"OGS_"`
}

func discard() (stdout, stderr *bytes.Buffer) {
	return &bytes.Buffer{}, &bytes.Buffer{}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("OGS_PORT", "9090")
	t.Setenv("OGS_TRUSTED_PROXIES", "10.0.0.0/8,192.168.0.0/16")
	t.Setenv("OGS_REDIS_HOST", "redis.internal")
	t.Setenv("OGS_LOG_LEVEL", "debug")

	var cfg testConfig
	stdout, stderr := discard()
	// chemin de config inexistant -> ReadEnv
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	if err := load(&cfg, Options{Name: "app", DefaultCfgPath: missing}, nil, stdout, stderr); err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Web.Port != 9090 {
		t.Errorf("Web.Port = %d, want 9090", cfg.Web.Port)
	}
	if cfg.Web.Host != "127.0.0.1" {
		t.Errorf("Web.Host = %q, want default 127.0.0.1", cfg.Web.Host)
	}
	if cfg.Web.RateLimit != 100 {
		t.Errorf("Web.RateLimit = %d, want default 100", cfg.Web.RateLimit)
	}
	if len(cfg.Web.TrustedProxies) != 2 {
		t.Errorf("Web.TrustedProxies = %v, want 2 entries", cfg.Web.TrustedProxies)
	}
	if cfg.DB.Host != "redis.internal" {
		t.Errorf("DB.Host = %q, want redis.internal", cfg.DB.Host)
	}
	if cfg.DB.Port != 6379 {
		t.Errorf("DB.Port = %d, want default 6379", cfg.DB.Port)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
web:
  host: 0.0.0.0
  port: 8443
  trusted_proxies:
    - 172.16.0.0/12
database:
  host: db.example.com
  db: 3
server:
  level: warn
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var cfg testConfig
	stdout, stderr := discard()
	if err := load(&cfg, Options{Name: "app", DefaultCfgPath: path}, nil, stdout, stderr); err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Web.Host != "0.0.0.0" || cfg.Web.Port != 8443 {
		t.Errorf("Web = %+v, want host 0.0.0.0 port 8443", cfg.Web)
	}
	if len(cfg.Web.TrustedProxies) != 1 || cfg.Web.TrustedProxies[0] != "172.16.0.0/12" {
		t.Errorf("Web.TrustedProxies = %v", cfg.Web.TrustedProxies)
	}
	if cfg.DB.Host != "db.example.com" || cfg.DB.Db != 3 {
		t.Errorf("DB = %+v", cfg.DB)
	}
	if cfg.Log.Level != "warn" {
		t.Errorf("Log.Level = %q, want warn", cfg.Log.Level)
	}
}

func TestLoadVersion(t *testing.T) {
	var cfg testConfig
	stdout, stderr := discard()
	err := load(&cfg, Options{Name: "OpenGoShorten", Version: "1.2.3"}, []string{"--version"}, stdout, stderr)
	if !errors.Is(err, errVersion) {
		t.Fatalf("err = %v, want errVersion", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "OpenGoShorten 1.2.3" {
		t.Errorf("stdout = %q, want %q", got, "OpenGoShorten 1.2.3")
	}
}

func TestLoadHelpIncludesEnvDoc(t *testing.T) {
	var cfg testConfig
	stdout, stderr := discard()
	err := load(&cfg, Options{Name: "app"}, []string{"--help"}, stdout, stderr)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
	out := stderr.String()
	// usage standard des flags
	if !strings.Contains(out, "-c") {
		t.Errorf("help manque le flag -c:\n%s", out)
	}
	// doc des variables d'env (avec préfixe composé) via cleanenv
	if !strings.Contains(out, "OGS_PORT") {
		t.Errorf("help manque la doc des env OGS_PORT:\n%s", out)
	}
	if !strings.Contains(out, "Listen port") {
		t.Errorf("help manque les descriptions d'env:\n%s", out)
	}
}

func TestLoadDefaultCfgPath(t *testing.T) {
	// DefaultCfgPath vide -> "config.yaml" ; absent ici -> ReadEnv sans erreur.
	var cfg testConfig
	stdout, stderr := discard()
	if err := load(&cfg, Options{Name: "app"}, nil, stdout, stderr); err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Web.Port != 8080 {
		t.Errorf("Web.Port = %d, want default 8080", cfg.Web.Port)
	}
}

func TestLoadParseError(t *testing.T) {
	var cfg testConfig
	stdout, stderr := discard()
	err := load(&cfg, Options{Name: "app"}, []string{"--unknown-flag"}, stdout, stderr)
	if err == nil || errors.Is(err, flag.ErrHelp) || errors.Is(err, errVersion) {
		t.Fatalf("err = %v, want a real parse error", err)
	}
}
