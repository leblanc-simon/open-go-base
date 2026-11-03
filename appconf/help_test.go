package appconf

import (
	"errors"
	"flag"
	"strings"
	"testing"
	"time"
)

type helpNested struct {
	Name string `env:"NAME" env-default:"tag-name" env-description:"Nested name"`
}

type helpFragment struct {
	Port    int               `env:"PORT"      env-default:"8080" env-description:"Listen port"`
	PortMax int               `env:"PORT_MAX"  env-default:"9000" env-description:"Highest port"`
	Host    string            `env:"HOST"      env-default:"127.0.0.1" env-description:"Listen host"`
	NoTag   string            `env:"NO_TAG"    env-description:"Without env-default"`
	Enabled bool              `env:"ENABLED"   env-description:"Enabled flag"`
	Timeout time.Duration     `env:"TIMEOUT"   env-default:"1m" env-description:"Timeout"`
	List    []string          `env:"LIST"      env-separator:";" env-description:"Items"`
	Labels  map[string]string `env:"LABELS" env-default:"a:b" env-description:"Labels"`
	Aliased string            `env:"MAIN,ALT"  env-default:"tag" env-description:"Two names"`
	Nested  helpNested        `env-prefix:"SUB_"`
}

type helpConfig struct {
	App helpFragment `env-prefix:"OGS_"`
}

func helpOutput(t *testing.T, cfg *helpConfig) string {
	t.Helper()
	stdout, stderr := discard()
	if err := load(cfg, Options{Name: "app"}, []string{"--help"}, stdout, stderr); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
	return stderr.String()
}

func TestHelpShowsPresetDefaults(t *testing.T) {
	var cfg helpConfig
	cfg.App.Port = 1758
	cfg.App.NoTag = "preset"
	cfg.App.Enabled = true
	cfg.App.Timeout = 90 * time.Second
	cfg.App.List = []string{"a", "b"}
	cfg.App.Aliased = "both"
	cfg.App.Nested.Name = "preset-name"
	cfg.App.Labels = map[string]string{"c": "d"}
	out := helpOutput(t, &cfg)

	for _, want := range []string{
		"Listen port (default \"1758\")\n",
		"Highest port (default \"9000\")\n", // nom voisin de PORT : inchangé
		"Listen host (default \"127.0.0.1\")\n",
		"Without env-default (default \"preset\")\n",
		"Enabled flag (default \"true\")\n",
		"Timeout (default \"1m30s\")\n",
		"Items (default \"a;b\")\n",
		"Labels (default \"a:b\")\n", // type composé : l'étiquette reste
		"Nested name (default \"preset-name\")\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--help ne contient pas %q :\n%s", want, out)
		}
	}
	if strings.Contains(out, "8080") {
		t.Errorf("--help annonce encore le défaut de l'étiquette :\n%s", out)
	}
	for _, name := range []string{"OGS_MAIN string", "OGS_ALT string (alternative to OGS_MAIN)", "OGS_SUB_NAME string"} {
		if !strings.Contains(out, name) {
			t.Errorf("--help ne contient pas %q :\n%s", name, out)
		}
	}
	if got := strings.Count(out, `Two names (default "both")`); got != 2 {
		t.Errorf("défaut des deux noms d'une variable : %d occurrence(s)\n%s", got, out)
	}
}

// Sans préremplissage, le texte reste exactement celui de cleanenv.
func TestHelpWithoutPresetKeepsTags(t *testing.T) {
	out := helpOutput(t, &helpConfig{})
	for _, want := range []string{
		"Listen port (default \"8080\")\n",
		"Timeout (default \"1m\")\n",
		"Without env-default\n",
		"Enabled flag\n",
		"Nested name (default \"tag-name\")\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--help ne contient pas %q :\n%s", want, out)
		}
	}
}

// Le défaut prérempli affiché par --help reste bien celui qu'une variable remplace.
func TestLoadStillOverridesPresetFromEnv(t *testing.T) {
	t.Setenv("OGS_PORT", "9999")
	var cfg helpConfig
	cfg.App.Port = 1758
	stdout, stderr := discard()
	if err := load(&cfg, Options{Name: "app", DefaultCfgPath: t.TempDir() + "/absent.yaml"}, nil, stdout, stderr); err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.App.Port != 9999 {
		t.Errorf("Port = %d, want 9999", cfg.App.Port)
	}
}
