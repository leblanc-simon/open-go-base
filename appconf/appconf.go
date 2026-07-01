package appconf

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
)

// defaultCfgPath est le chemin de config utilisé quand Options.DefaultCfgPath
// est vide.
const defaultCfgPath = "config.yaml"

// errVersion est renvoyée en interne quand l'utilisateur a demandé --version.
// Ce n'est pas une erreur applicative : Load la traduit en os.Exit(0).
var errVersion = errors.New("version requested")

// Options paramètre le chargement de la configuration.
type Options struct {
	Name           string // nom de l'app (flagset + sortie --version)
	Version        string // injectée depuis main via ldflags, passée ici
	DefaultCfgPath string // défaut "config.yaml" si vide
}

// Load remplit cfg depuis le fichier de config s'il existe, sinon depuis
// l'environnement. Il câble --help (avec la doc des variables d'env via
// cleanenv) et --version.
//
// Load ne fait jamais os.Exit sur une erreur de chargement : il la renvoie.
// Les flags terminaux --help et --version, eux, terminent le programme avec le
// code 0 (comportement standard et attendu).
func Load(cfg any, opts Options) error {
	err := load(cfg, opts, os.Args[1:], os.Stdout, os.Stderr)
	if errors.Is(err, errVersion) || errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	return err
}

// MustLoad est identique à Load mais termine le programme avec le code 2 en cas
// d'erreur de chargement.
func MustLoad(cfg any, opts Options) {
	if err := Load(cfg, opts); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", opts.Name, err)
		os.Exit(2)
	}
}

// load contient toute la logique de Load mais sans aucun os.Exit, pour rester
// testable. Il renvoie errVersion si --version a été demandé, flag.ErrHelp si
// --help a été demandé, ou l'erreur de parsing/chargement le cas échéant.
func load(cfg any, opts Options, args []string, stdout, stderr io.Writer) error {
	cfgPathDefault := opts.DefaultCfgPath
	if cfgPathDefault == "" {
		cfgPathDefault = defaultCfgPath
	}

	fs := flag.NewFlagSet(opts.Name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfgPath := fs.String("c", cfgPathDefault, "path to the config file")
	showVersion := fs.Bool("version", false, "print version and exit")

	// --help : usage standard des flags PUIS la doc des variables d'env.
	fs.Usage = cleanenv.FUsage(fs.Output(), cfg, nil, func() {
		fmt.Fprintf(fs.Output(), "Usage of %s:\n", opts.Name)
		fs.PrintDefaults()
	})

	if err := fs.Parse(args); err != nil {
		return err // y compris flag.ErrHelp
	}

	if *showVersion {
		fmt.Fprintf(stdout, "%s %s\n", opts.Name, opts.Version)
		return errVersion
	}

	if _, err := os.Stat(*cfgPath); err == nil {
		return cleanenv.ReadConfig(*cfgPath, cfg)
	}
	return cleanenv.ReadEnv(cfg)
}
