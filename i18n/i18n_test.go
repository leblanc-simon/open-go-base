package i18n

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"leblanc.io/open-go-base/appconf"
)

const enYAML = `
hello: Hello
greeting: Hello {{.Name}}

cats:
  one: "{{.Count}} cat"
  other: "{{.Count}} cats"
`

const frYAML = `
hello: Bonjour
greeting: Bonjour {{.Name}}

cats:
  one: "{{.Count}} chat"
  other: "{{.Count}} chats"
`

func newBundle(t *testing.T) *Bundle {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "en.yaml"), []byte(enYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fr.yaml"), []byte(frYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := New(appconf.I18n{Dir: dir, DefaultLanguage: "en"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestNew_NoFiles(t *testing.T) {
	if _, err := New(appconf.I18n{Dir: t.TempDir(), DefaultLanguage: "en"}); err == nil {
		t.Error("attendu une erreur quand aucun fichier de traduction n'est présent")
	}
}

func TestNew_BadDefaultLanguage(t *testing.T) {
	if _, err := New(appconf.I18n{Dir: t.TempDir(), DefaultLanguage: "!!!"}); err == nil {
		t.Error("attendu une erreur pour une langue par défaut invalide")
	}
}

func TestLanguagesDiscoveredDynamically(t *testing.T) {
	b := newBundle(t)
	got := map[string]bool{}
	for _, tag := range b.Languages() {
		got[tag.String()] = true
	}
	if !got["en"] || !got["fr"] {
		t.Errorf("langues attendues en+fr, obtenu %v", b.Languages())
	}
}

func TestForceLanguageWins(t *testing.T) {
	b := newBundle(t)
	// Accept-Language dit "en" mais on force "fr".
	loc := b.Localizer("fr", "en-US,en;q=0.9")
	if got := loc.T("hello"); got != "Bonjour" {
		t.Errorf("T(hello) = %q, want Bonjour", got)
	}
	if loc.Lang().String() != "fr" {
		t.Errorf("Lang() = %q, want fr", loc.Lang())
	}
}

func TestAcceptLanguageDetection(t *testing.T) {
	b := newBundle(t)
	loc := b.Localizer("", "fr-CH,fr;q=0.9,en;q=0.5")
	if got := loc.T("hello"); got != "Bonjour" {
		t.Errorf("T(hello) = %q, want Bonjour", got)
	}
}

func TestFallbackToDefault(t *testing.T) {
	b := newBundle(t)
	loc := b.Localizer("", "de-DE,de;q=0.9") // non disponible -> repli en
	if got := loc.T("hello"); got != "Hello" {
		t.Errorf("T(hello) = %q, want Hello (repli défaut)", got)
	}
	if loc.Lang().String() != "en" {
		t.Errorf("Lang() = %q, want en", loc.Lang())
	}
}

func TestTemplateData(t *testing.T) {
	b := newBundle(t)
	loc := b.Localizer("fr", "")
	if got := loc.T("greeting", map[string]any{"Name": "Sam"}); got != "Bonjour Sam" {
		t.Errorf("T(greeting) = %q, want 'Bonjour Sam'", got)
	}
}

func TestPlural(t *testing.T) {
	b := newBundle(t)
	loc := b.Localizer("", "en")
	if got := loc.Tn("cats", 1); got != "1 cat" {
		t.Errorf("Tn(cats,1) = %q, want '1 cat'", got)
	}
	if got := loc.Tn("cats", 3); got != "3 cats" {
		t.Errorf("Tn(cats,3) = %q, want '3 cats'", got)
	}
}

func TestMissingMessageReturnsID(t *testing.T) {
	b := newBundle(t)
	loc := b.Localizer("en", "")
	if got := loc.T("does.not.exist"); got != "does.not.exist" {
		t.Errorf("T(absent) = %q, want l'id renvoyé tel quel", got)
	}
}

func TestFromRequest(t *testing.T) {
	b := newBundle(t)

	// Forçage via ?lang=fr
	r1 := httptest.NewRequest(http.MethodGet, "/?lang=fr", nil)
	r1.Header.Set("Accept-Language", "en")
	if got := b.FromRequest(r1).T("hello"); got != "Bonjour" {
		t.Errorf("?lang=fr: T(hello) = %q, want Bonjour", got)
	}

	// Sans forçage -> Accept-Language
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Accept-Language", "fr")
	if got := b.FromRequest(r2).T("hello"); got != "Bonjour" {
		t.Errorf("Accept-Language fr: T(hello) = %q, want Bonjour", got)
	}
}

func TestFuncMapInTemplate(t *testing.T) {
	b := newBundle(t)
	loc := b.Localizer("fr", "")

	tmpl := template.Must(template.New("t").Funcs(loc.FuncMap()).Parse(
		`{{ T "greeting" . }} | {{ Tn "cats" 2 }}`,
	))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]any{"Name": "Sam"}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	want := "Bonjour Sam | 2 chats"
	if buf.String() != want {
		t.Errorf("template = %q, want %q", buf.String(), want)
	}
}
