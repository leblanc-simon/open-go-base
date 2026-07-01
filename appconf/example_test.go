package appconf_test

import "leblanc.io/open-go-base/appconf"

// Config d'un projet : on embarque les fragments standard et on pose le préfixe
// d'environnement au point de composition.
type Config struct {
	Web  appconf.Web     `yaml:"web"     env-prefix:"OGS_"`
	Log  appconf.Logging `yaml:"logging" env-prefix:"OGS_"`
	CORS appconf.CORS    `yaml:"cors"    env-prefix:"OGS_"`
	I18n appconf.I18n    `yaml:"i18n"    env-prefix:"OGS_"`
}

// Exemple de bootstrap : MustLoad lit le fichier -c s'il existe, sinon
// l'environnement, et câble --help / --version. La version est injectée depuis
// main via -ldflags.
func ExampleMustLoad() {
	var (
		version = "develop"
		appName = "OpenGoShorten"
	)

	var cfg Config
	appconf.MustLoad(&cfg, appconf.Options{Name: appName, Version: version})

	// cfg est désormais rempli (OGS_HOST, OGS_PORT, OGS_LOG_LEVEL, ...).
	_ = cfg
}
