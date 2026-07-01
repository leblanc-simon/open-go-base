package sqldialect_test

import (
	"testing"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/internal/sqldialect"
)

func TestRebindPostgres(t *testing.T) {
	in := `INSERT INTO t (a, b, c) VALUES (?, ?, ?)`
	want := `INSERT INTO t (a, b, c) VALUES ($1, $2, $3)`
	if got := sqldialect.Rebind(appconf.DialectPostgres, in); got != want {
		t.Errorf("Rebind(postgres) = %q, want %q", got, want)
	}
}

func TestRebindNonPostgresUnchanged(t *testing.T) {
	in := `UPDATE t SET a = ? WHERE id = ?`
	for _, d := range []appconf.Dialect{appconf.DialectSQLite, appconf.DialectMySQL, appconf.DialectUnknown} {
		if got := sqldialect.Rebind(d, in); got != in {
			t.Errorf("Rebind(%v) a modifié la requête: %q", d, got)
		}
	}
}
