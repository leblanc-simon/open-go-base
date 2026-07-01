package i18n_test

import (
	"embed"
	"fmt"

	"leblanc.io/open-go-base/i18n"
)

// localesFS embarque les locales dans le binaire de test. En production, la même
// directive dans le package main rend l'exécutable autonome (aucun dossier
// locales/ à déployer à côté).
//
//go:embed testdata/locales/*.yaml
var localesFS embed.FS

// ExampleNewFS charge des locales embarquées via go:embed plutôt que depuis le
// disque : le binaire est autonome. Le sous-dossier "testdata/locales" est le
// chemin des fichiers dans le FS embarqué.
func ExampleNewFS() {
	bundle, err := i18n.NewFS(localesFS, "testdata/locales", "en")
	if err != nil {
		panic(err)
	}

	loc := bundle.Localizer("fr", "") // force le français
	fmt.Println(loc.T("hello"))
	fmt.Println(loc.T("greeting", map[string]any{"Name": "Sam"}))
	fmt.Println(loc.Tn("cats", 3))

	// Output:
	// Bonjour
	// Bonjour Sam
	// 3 chats
}
