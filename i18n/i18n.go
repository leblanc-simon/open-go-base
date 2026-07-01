package i18n

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	goi18n "github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"

	"leblanc.io/open-go-base/appconf"
)

// QueryParam est le nom du paramètre de requête utilisé par FromRequest pour
// forcer une langue (ex. /page?lang=fr).
const QueryParam = "lang"

// Bundle regroupe les traductions chargées et la logique de sélection de langue.
// Il est sûr en lecture concurrente ; à construire une fois au démarrage.
type Bundle struct {
	bundle      *goi18n.Bundle
	matcher     language.Matcher
	defaultLang language.Tag
	languages   []language.Tag
}

// New charge tous les fichiers de traduction YAML (.yaml, .yml) présents dans
// cfg.Dir. La langue par défaut (cfg.DefaultLanguage) sert de repli.
func New(cfg appconf.I18n) (*Bundle, error) {
	def, err := language.Parse(cfg.DefaultLanguage)
	if err != nil {
		return nil, fmt.Errorf("i18n: langue par défaut invalide %q: %w", cfg.DefaultLanguage, err)
	}

	gb := goi18n.NewBundle(def)
	gb.RegisterUnmarshalFunc("yaml", yaml.Unmarshal)
	gb.RegisterUnmarshalFunc("yml", yaml.Unmarshal)

	entries, err := os.ReadDir(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("i18n: lecture du dossier %q: %w", cfg.Dir, err)
	}

	loaded := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(strings.TrimPrefix(filepath.Ext(e.Name()), ".")) {
		case "yaml", "yml":
			if _, err := gb.LoadMessageFile(filepath.Join(cfg.Dir, e.Name())); err != nil {
				return nil, fmt.Errorf("i18n: chargement de %q: %w", e.Name(), err)
			}
			loaded++
		}
	}
	if loaded == 0 {
		return nil, fmt.Errorf("i18n: aucun fichier de traduction YAML dans %q", cfg.Dir)
	}

	// La langue par défaut en tête : le matcher l'utilise comme repli quand
	// aucune préférence ne correspond.
	tags := dedupeTags(append([]language.Tag{def}, gb.LanguageTags()...))

	return &Bundle{
		bundle:      gb,
		matcher:     language.NewMatcher(tags),
		defaultLang: def,
		languages:   tags,
	}, nil
}

// Languages retourne les langues disponibles (la langue par défaut en premier).
func (b *Bundle) Languages() []language.Tag {
	return b.languages
}

// Localizer construit un localizer pour une requête. force (ex. "fr") l'emporte
// s'il est non vide ; sinon acceptLanguage (valeur brute de l'en-tête
// Accept-Language) est utilisé ; la langue par défaut est toujours le dernier
// repli.
func (b *Bundle) Localizer(force, acceptLanguage string) *Localizer {
	langs := make([]string, 0, 3)
	if force != "" {
		langs = append(langs, force)
	}
	if acceptLanguage != "" {
		langs = append(langs, acceptLanguage)
	}
	langs = append(langs, b.defaultLang.String())

	// Détermine la langue résolue pour l'exposer via Lang().
	prefs, _, _ := language.ParseAcceptLanguage(strings.Join(langs, ","))
	tag, _, _ := b.matcher.Match(prefs...)

	return &Localizer{
		loc:  goi18n.NewLocalizer(b.bundle, langs...),
		lang: tag,
	}
}

// FromRequest construit un Localizer pour r : le paramètre de requête QueryParam
// (ex. ?lang=fr) force la langue, à défaut l'en-tête Accept-Language est utilisé.
func (b *Bundle) FromRequest(r *http.Request) *Localizer {
	return b.Localizer(r.URL.Query().Get(QueryParam), r.Header.Get("Accept-Language"))
}

// Localizer est lié à une langue résolue. À créer par requête.
type Localizer struct {
	loc  *goi18n.Localizer
	lang language.Tag
}

// Lang retourne la langue résolue (tag BCP 47).
func (l *Localizer) Lang() language.Tag {
	return l.lang
}

// T traduit messageID. Une donnée de template optionnelle peut être fournie
// (ex. map[string]any{"Name": "Sam"} pour un message "Hello {{.Name}}"). Si la
// traduction est absente, messageID est renvoyé tel quel (repli visible et non
// fatal).
func (l *Localizer) T(messageID string, data ...any) string {
	cfg := &goi18n.LocalizeConfig{MessageID: messageID}
	if len(data) > 0 {
		cfg.TemplateData = data[0]
	}
	s, err := l.loc.Localize(cfg)
	if err != nil {
		return messageID
	}
	return s
}

// Tn traduit messageID en choisissant la forme plurielle selon count.
func (l *Localizer) Tn(messageID string, count int, data ...any) string {
	cfg := &goi18n.LocalizeConfig{MessageID: messageID, PluralCount: count}
	if len(data) > 0 {
		cfg.TemplateData = data[0]
	} else {
		cfg.TemplateData = map[string]any{"Count": count}
	}
	s, err := l.loc.Localize(cfg)
	if err != nil {
		return messageID
	}
	return s
}

// FuncMap expose T et Tn pour les templates Go. Le type de retour
// (map[string]any) est assignable aussi bien à text/template.FuncMap qu'à
// html/template.FuncMap.
//
//	tmpl.Funcs(loc.FuncMap())       // {{ T "greeting" . }}  {{ Tn "cats" 2 }}
func (l *Localizer) FuncMap() map[string]any {
	return map[string]any{
		"T":  l.T,
		"Tn": l.Tn,
	}
}

func dedupeTags(in []language.Tag) []language.Tag {
	seen := make(map[language.Tag]struct{}, len(in))
	out := make([]language.Tag, 0, len(in))
	for _, t := range in {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}
