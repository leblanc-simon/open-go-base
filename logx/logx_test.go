package logx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"leblanc.io/open-go-base/appconf"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"INFO":    slog.LevelInfo,
		" warn ":  slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"":        slog.LevelInfo,
		"bogus":   slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestJSONFormatAndLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := NewWith(appconf.Logging{Level: "warn", Format: "json"}, &buf)

	log.Info("ignored") // sous le seuil warn -> ne doit rien écrire
	if buf.Len() != 0 {
		t.Fatalf("info ne devrait pas être loggé au niveau warn: %q", buf.String())
	}

	log.Warn("kept", "key", "val")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("sortie non-JSON: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "kept" || rec["level"] != "WARN" || rec["key"] != "val" {
		t.Errorf("record inattendu: %v", rec)
	}
}

func TestTextFormatDefault(t *testing.T) {
	var buf bytes.Buffer
	log := NewWith(appconf.Logging{Level: "debug", Format: "weird-unknown"}, &buf)
	log.Debug("hello")
	out := buf.String()
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "msg=hello") {
		t.Errorf("format texte attendu, obtenu: %q", out)
	}
}

func TestAddSource(t *testing.T) {
	var buf bytes.Buffer
	log := NewWith(appconf.Logging{Level: "info", Format: "json", Source: true}, &buf)
	log.Info("x")
	if !strings.Contains(buf.String(), "source") {
		t.Errorf("source attendue dans la sortie: %q", buf.String())
	}
}
