// Package i18n charge des traductions et sélectionne la langue d'une requête.
//
// Caractéristiques :
//   - le jeu de langues est déduit dynamiquement des fichiers YAML présents dans
//     le dossier de configuration (appconf.I18n.Dir) ;
//   - détection automatique via l'en-tête Accept-Language ;
//   - forçage possible d'une langue (ex. paramètre ?lang=fr prioritaire) ;
//   - utilisable dans les templates Go via FuncMap (fonctions T et Tn).
//
// Un fichier YAML par langue, nommé d'après le tag BCP 47 (en.yaml, fr.yaml, ...).
//
//	bundle, err := i18n.New(cfg.I18n)
//	loc := bundle.FromRequest(r) // ?lang= puis Accept-Language, repli sur le défaut
//	fmt.Fprintln(w, loc.T("hello"))
//
// New lit les locales depuis le disque. Pour un binaire autonome, NewFS charge
// les traductions depuis un fs.FS (typiquement un embed.FS) :
//
//	//go:embed locales/*.yaml
//	var localesFS embed.FS
//	bundle, err := i18n.NewFS(localesFS, "locales", "en")
package i18n
