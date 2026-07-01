package logx

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"leblanc.io/open-go-base/appconf"
)

// New construit un *slog.Logger écrivant sur os.Stderr selon cfg.
func New(cfg appconf.Logging) *slog.Logger {
	return NewWith(cfg, os.Stderr)
}

// NewWith est identique à New mais écrit sur w (utile pour les tests ou pour
// rediriger la sortie).
func NewWith(cfg appconf.Logging, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:     ParseLevel(cfg.Level),
		AddSource: cfg.Source,
	}

	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default: // "text" et toute valeur inconnue
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}

// ParseLevel convertit un niveau textuel en slog.Level. Une valeur inconnue ou
// vide retombe sur slog.LevelInfo (un logger ne doit jamais échouer à se
// construire à cause d'une config approximative).
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
