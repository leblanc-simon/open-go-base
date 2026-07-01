package i18n_test

import (
	"fmt"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/i18n"
)

// ExampleLocalizer charge les locales d'exemple du dépôt (../locales depuis le
// dossier du package) et illustre forçage, données de template et pluriel.
func ExampleLocalizer() {
	bundle, err := i18n.New(appconf.I18n{Dir: "../locales", DefaultLanguage: "en"})
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
