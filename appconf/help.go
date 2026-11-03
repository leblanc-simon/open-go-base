package appconf

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/ilyakaznacheev/cleanenv"
)

// presetDefault est un défaut posé par le projet avant le chargement.
type presetDefault struct {
	value string
	tag   *string // env-default du champ, s'il en a un
}

// describeEnv renvoie la documentation des variables d'environnement. cleanenv ne connaît
// que l'étiquette env-default : les valeurs déjà présentes dans cfg, qui l'emportent au
// chargement, sont reportées sur le texte qu'il produit.
func describeEnv(cfg any) (string, error) {
	text, err := cleanenv.GetDescription(cfg, nil)
	if err != nil {
		return "", err
	}
	presets := map[string]presetDefault{}
	if v := reflect.ValueOf(cfg); v.Kind() == reflect.Pointer && !v.IsNil() && v.Elem().Kind() == reflect.Struct {
		collectPresets(v.Elem(), "", presets)
	}
	return applyPresets(text, presets), nil
}

// collectPresets relève les champs non nuls, sous leurs noms de variables : même parcours
// et même composition des préfixes que cleanenv.
func collectPresets(s reflect.Value, prefix string, out map[string]presetDefault) {
	for i := range s.NumField() {
		field, v := s.Type().Field(i), s.Field(i)
		if !field.IsExported() {
			continue
		}
		if v.Kind() == reflect.Struct {
			collectPresets(v, prefix+field.Tag.Get(cleanenv.TagEnvPrefix), out)
			continue
		}
		value, ok := presetValue(v, field)
		if !ok {
			continue
		}
		preset := presetDefault{value: value}
		if tag, ok := field.Tag.Lookup(cleanenv.TagEnvDefault); ok {
			preset.tag = &tag
		}
		if names := field.Tag.Get(cleanenv.TagEnv); names != "" {
			for name := range strings.SplitSeq(names, cleanenv.DefaultSeparator) {
				out[prefix+name] = preset
			}
		}
	}
}

// presetValue met en forme une valeur non nulle comme dans l'environnement. Seuls les
// scalaires et leurs listes ont une forme simple : les autres types gardent leur étiquette.
func presetValue(v reflect.Value, field reflect.StructField) (string, bool) {
	if v.IsZero() {
		return "", false
	}
	switch v.Kind() {
	case reflect.Map, reflect.Pointer, reflect.Interface, reflect.Func, reflect.Chan, reflect.Array,
		reflect.Struct, reflect.UnsafePointer, reflect.Complex64, reflect.Complex128:
		return "", false
	case reflect.Slice:
		sep, ok := field.Tag.Lookup(cleanenv.TagEnvSeparator)
		if !ok {
			sep = cleanenv.DefaultSeparator
		}
		items := make([]string, v.Len())
		for i := range items {
			items[i] = fmt.Sprint(v.Index(i).Interface())
		}
		return strings.Join(items, sep), true
	}
	return fmt.Sprint(v.Interface()), true
}

// applyPresets remplace ou ajoute le défaut des variables préremplies. Une entrée du texte
// de cleanenv commence par la ligne « ␣␣NOM type » et finit par son défaut éventuel.
func applyPresets(text string, presets map[string]presetDefault) string {
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		name, ok := entryName(lines[i])
		if !ok {
			continue
		}
		end := i
		for end+1 < len(lines) {
			if _, next := entryName(lines[end+1]); next {
				break
			}
			end++
		}
		if preset, ok := presets[name]; ok {
			if preset.tag != nil {
				lines[end] = strings.TrimSuffix(lines[end], fmt.Sprintf(" (default %q)", *preset.tag))
			}
			lines[end] += fmt.Sprintf(" (default %q)", preset.value)
		}
		i = end
	}
	return strings.Join(lines, "\n")
}

// entryName renvoie la variable décrite par une première ligne d'entrée.
func entryName(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "  ")
	if !ok || rest == "" || rest[0] == ' ' || rest[0] == '\t' {
		return "", false
	}
	name, _, _ := strings.Cut(rest, " ")
	return name, true
}
