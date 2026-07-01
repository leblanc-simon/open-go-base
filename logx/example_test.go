package logx_test

import (
	"fmt"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/logx"
)

// ExampleNew montre la construction d'un logger depuis la configuration. (Non
// exécuté : la sortie inclut un horodatage non déterministe.)
func ExampleNew() {
	logger := logx.New(appconf.Logging{Level: "info", Format: "json"})
	logger.Info("server started", "port", 8080)
}

func ExampleParseLevel() {
	fmt.Println(logx.ParseLevel("warn"))
	fmt.Println(logx.ParseLevel("inconnu")) // repli sur info
	// Output:
	// WARN
	// INFO
}
