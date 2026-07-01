# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## État actuel

Module `leblanc.io/open-go-base` initialisé (Go 1.26). **Tous les sous-packages sont
implémentés et testés** (`go test -race ./...` au vert) :
`appconf`, `logx`, `corsx`, `ratelimit`, `i18n`, plus `authx` (login + sessions) et `mfax`
(2FA TOTP), récupérés/découplés depuis `open-go-canivet`. Reste à faire (brief étape 3) :
migrer un projet existant dessus comme preuve.

`authx`/`mfax` (hors brief initial) : auth par mot de passe + sessions glissantes et 2FA TOTP,
en **handlers HTTP montables** + rendu délégué au projet (interface `Renderer`), stockage en
**interfaces + impl `database/sql`** (sous-packages `*/sqlstore`, migrations embarquées via
`internal/sqlmigrate`). Sens de dépendance : `mfax → authx → appconf` ; `mfax` s'intercale dans
le login via le hook `authx.SecondFactor`. Fragments `appconf.Auth` et `appconf.MFA`. Deps
directes ajoutées : `golang.org/x/crypto`, `github.com/pquerna/otp`, `rsc.io/qr`
(+ `modernc.org/sqlite` en dépendance de test des sqlstore). Périmètre volontairement exclu :
OTP par email, mailer, CRUD utilisateurs/admin, audit, bootstrap (restés côté projet).

**Multi-dialecte SQL** : les sqlstore gèrent SQLite et PostgreSQL (MySQL prévu, non livré). Le
dialecte vient de `appconf.Dialect` (enum dans `appconf` pour ne pas inverser la dépendance),
typiquement `cfg.Database.Dialect()` (fragment `appconf.Database{Driver,DSN}`). `Migrate` et les
constructeurs prennent le dialecte. Migrations en sous-dossiers `migrations/<dialecte>/` ;
placeholders adaptés via `internal/sqldialect.Rebind` (`?`→`$n` en PG) ; `Create` utilise
`RETURNING` en PG (pas de `LastInsertId`). Booléens stockés en SMALLINT 0/1 partout pour un scan
Go uniforme. Tests réels en SQLite (modernc) ; PG relu/non exécuté (Rebind + mapping Dialect
couverts par tests unitaires). Ajouter MySQL = `migrations/mysql/` + branche upsert
`ON DUPLICATE KEY` + `supported()`.

`specs/00-initial.md` est le brief de référence ; il fait foi sur l'architecture, l'API et
l'ordre d'implémentation. Le lire avant toute tâche. La doc d'utilisation des composants
(API + exemples) est dans `README.md`.

## Objectif

Bibliothèque Go partagée `leblanc.io/open-go-base` qui factorise le code de bootstrap
dupliqué entre plusieurs projets (`open-go-captcha`, `open-go-shorten`, …) : parsing config,
flags `--help`/`--version`, plus des fragments de config et des composants runtime
préconfigurés.

## Architecture cible

Module unique `leblanc.io/open-go-base`, plusieurs sous-packages ciblés (jamais de package
fourre-tout `helper`/`utils`) :

- `appconf/` — `Load`/`MustLoad`/`Options` + fragments de config (`Web`, `Redis`, `Logging`,
  `CORS`, `I18n`). C'est par là qu'on commence.
- `logx/` — logger structuré (`log/slog` stdlib), consomme `appconf.Logging`.
- `corsx/` — middleware CORS, consomme `appconf.CORS`.
- `ratelimit/` — limiteur, consomme `appconf.Web.RateLimit` + `TrustedProxies`.
- `i18n/` — traductions + sélection de langue.

## Dépendances tierces validées (par composant)

Choix arrêtés avec l'utilisateur — empreinte `go.mod` volontairement minimale :

- `logx` → `log/slog` (stdlib, **0 dépendance**). Fragment `Logging` à enrichir : `Format`
  (text|json), `Source` (bool).
- `corsx` → `github.com/rs/cors` (**0 dépendance transitive**). Nécessite un nouveau fragment
  `appconf.CORS` (AllowedOrigins/Methods/Headers, ExposedHeaders, AllowCredentials, MaxAge).
- `ratelimit` → `github.com/go-chi/httprate` (comptage par fenêtre, in-memory) +
  `github.com/realclientip/realclientip-go` pour la vraie IP. La résolution utilise
  `NewRightmostTrustedRangeStrategy` avec les CIDR de `Web.TrustedProxies`. Pas de nouveau
  fragment (réutilise `Web.RateLimit` + `Web.TrustedProxies`).
- `i18n` → `github.com/nicksnyder/go-i18n/v2` (+ `golang.org/x/text`). Fichiers de langue
  **YAML uniquement** (`.yaml`/`.yml`), chargés dynamiquement depuis un dossier ; matcher
  Accept-Language via `x/text/language` ; helper `T` exposé en `template.FuncMap` ; forçage
  de langue par param prioritaire sur le header. Nouveau fragment `appconf.I18n` : `Dir`,
  `DefaultLanguage`. NB : `BurntSushi/toml` n'est plus une dépendance directe.

## Invariants à respecter (décisions arrêtées dans le brief)

1. **Sens de dépendance : composant → config, jamais l'inverse.** Le package `appconf`
   décrit des données et ne connaît aucun composant. Les composants (`logx`, `corsx`,
   `ratelimit`, `i18n`) consomment les fragments de `appconf`.

2. **La version n'appartient pas à la lib.** Elle reste une `var version` dans
   `package main`, injectée au build via `-ldflags "-X 'main.version=...'"`, et est **passée**
   à la lib via `appconf.Options{Version: ...}`. Ne pas déplacer la version dans la lib.

3. **Le préfixe d'env n'est pas un paramètre runtime.** cleanenv ne supporte qu'un tag
   statique `env-prefix` sur une struct imbriquée. Les fragments de `appconf` ont donc des
   tags `env` **sans préfixe** ; le préfixe est ajouté par chaque projet au point de
   composition de sa `Config` (ex. `Web appconf.Web \`env-prefix:"OGS_"\``).

4. **`Load` retourne une `error`** — aucun `os.Exit` caché dans la lib. Seul `MustLoad`
   (confort) fait `os.Exit(2)`.

5. **Tout repose sur `github.com/ilyakaznacheev/cleanenv`** (tags `yaml` + `env` +
   `env-default` + `env-description`). Réutiliser au maximum ses primitives :
   `cleanenv.ReadConfig` (fichier présent), `cleanenv.ReadEnv` (sinon), et `cleanenv.FUsage`
   pour générer l'aide `--help` (qui doit afficher l'usage standard **puis** la doc des
   variables d'env).

6. **Module unique, pas de modules séparés.** Un sous-package non importé ne finit pas dans
   le binaire, mais ses deps tierces apparaissent quand même dans `go.mod`/`go.sum` — c'est
   accepté.

## Comportement de `appconf.Load`

- Flagset nommé d'après `opts.Name`.
- Flag `-c` : chemin de config (défaut `opts.DefaultCfgPath`, ou `"config.yaml"` si vide).
- Flag `--version` : affiche `"<Name> <Version>"` puis sort en code 0.
- `--help` : usage standard + doc des env via `cleanenv.FUsage`.
- Si le fichier de config existe → `cleanenv.ReadConfig`, sinon → `cleanenv.ReadEnv`.

## Contrainte composant : `ratelimit`

Doit résoudre la vraie IP client derrière des proxys de confiance : ne faire confiance aux
en-têtes `X-Forwarded-For` / `X-Real-IP` que si la connexion provient d'un proxy listé dans
`TrustedProxies`, sinon utiliser l'IP de la connexion directe.

## Ordre d'implémentation

1. Initialiser le module `leblanc.io/open-go-base` avec la structure ci-dessus.
2. Implémenter `appconf` (Load/MustLoad/Options + fragments Web, Redis, Logging) **avec tests**.
3. Migrer **un** projet existant dessus comme preuve, en gardant Makefile et injection de
   version inchangés.
4. Puis, sous-package par sous-package : `ratelimit`, `logx`, `corsx`, `i18n`.

**Avant d'écrire du code** : confirmer auprès de l'utilisateur la liste des dépendances
tierces envisagées (CORS, rate limit, i18n) pour valider l'empreinte de `go.mod`.

## Documentation & exemples

- `README.md` : doc d'utilisation par composant + exemple d'assemblage complet.
- Chaque package a un `doc.go` (doc godoc) et un `*_example_test.go` (exemples testables,
  exécutés par `go test`). Le commentaire de package vit dans `doc.go`, pas dans le fichier
  principal — ne pas le dupliquer.
- `locales/` (racine) : locales YAML d'exemple, utilisées par `i18n/example_test.go` via
  `../locales` et par le `config.yaml` documenté.

## Commandes

- Tests : `go test ./...` — un seul test : `go test -run '^TestLoadFromEnv$' ./appconf/`
- Vet : `go vet ./...`
- Mise à jour des deps : `go mod tidy`

Pas de `Makefile` dans ce module (bibliothèque). L'injection de version
`-ldflags "-X 'main.version=...'"` se fait côté projet consommateur, pas ici.

## Décisions de sécurité dans les composants (NE PAS régresser)

- **`ratelimit`** : la résolution de l'IP client ne fait confiance à
  `X-Forwarded-For`/`X-Real-IP` **que si le pair direct (`RemoteAddr`) appartient à un proxy
  listé dans `TrustedProxies`** ; sinon l'IP de connexion est utilisée. On a délibérément
  **écarté `httprate.KeyByRealIP`** qui fait confiance aux en-têtes sans vérifier le pair
  (usurpation triviale). XFF est traité via `realclientip.NewRightmostTrustedRangeStrategy`
  (les sauts internes de confiance sont retirés). `requestLimit <= 0` désactive la
  limitation (un seuil mal configuré ne doit pas verrouiller l'app).
- **`corsx`** : `rs/cors` sert la combinaison interdite origine `*` + `AllowCredentials=true`.
  `corsx.New` la **neutralise** : en présence d'un wildcard, les credentials sont désactivés
  (le sens « API publique » l'emporte). Pour autoriser les credentials, lister les origines
  explicitement.

## Composants — API d'entrée (toute la config vient de `appconf`)

- `logx.New(cfg appconf.Logging) *slog.Logger` (+ `NewWith(cfg, io.Writer)` pour les tests).
- `corsx.Middleware(cfg appconf.CORS) func(http.Handler) http.Handler`.
- `ratelimit.New(cfg.Web.RateLimit, cfg.Web.TrustedProxies, opts...) (*Limiter, error)` →
  `.Middleware`, `.ClientIP(r)`. Option `WithLimitHandler(http.Handler)` pour personnaliser
  la réponse 429 (corps JSON localisé, etc.).
- `i18n.New(cfg appconf.I18n) (*Bundle, error)` → `.FromRequest(r)` / `.Localizer(force,
  acceptLang)` → `Localizer.T/Tn/FuncMap/Lang`. Langues déduites des fichiers de `cfg.Dir`.

## Notes d'implémentation `appconf`

- Toute la logique vit dans une fonction interne non exportée `load(cfg, opts, args,
  stdout, stderr)` qui ne fait **aucun `os.Exit`** et renvoie des sentinelles
  (`errVersion`, `flag.ErrHelp`) ; c'est ce que ciblent les tests. `Load` est le wrapper
  qui traduit ces sentinelles en `os.Exit(0)` et utilise `os.Args`/`os.Stdout`/`os.Stderr`.
- Le flagset utilise `flag.ContinueOnError` (pas `ExitOnError`) pour garder la maîtrise des
  sorties. Flags : `-c` (chemin config) et `--version`.
- `--help` est câblé via `cleanenv.FUsage`, qui appelle chaque `usageFunc` **sans test nil** :
  toujours lui passer une fonction non-nil (on passe un closure qui fait `PrintDefaults`).
- Les tests vérifient la composition avec `env-prefix` (`OGS_`, `OGS_DB_`) pour valider la
  décision d'archi #3 (préfixe au point de composition, fragments sans préfixe).
- Empreinte `go.mod` : seule dépendance directe `cleanenv` ; indirectes tirées par lui
  (toml, godotenv, yaml.v3, edn) — empreinte acceptée par le brief.
