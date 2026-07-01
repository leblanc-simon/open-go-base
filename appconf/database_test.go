package appconf_test

import (
	"testing"

	"leblanc.io/open-go-base/appconf"
)

func TestDatabaseDialect(t *testing.T) {
	cases := map[string]appconf.Dialect{
		"":           appconf.DialectSQLite, // défaut
		"sqlite":     appconf.DialectSQLite,
		"sqlite3":    appconf.DialectSQLite,
		"postgres":   appconf.DialectPostgres,
		"postgresql": appconf.DialectPostgres,
		"pgx":        appconf.DialectPostgres,
		"mysql":      appconf.DialectMySQL,
		"mariadb":    appconf.DialectMySQL,
		"oracle":     appconf.DialectUnknown,
	}
	for driver, want := range cases {
		if got := (appconf.Database{Driver: driver}).Dialect(); got != want {
			t.Errorf("driver %q: dialecte %v, want %v", driver, got, want)
		}
	}
}

func TestDialectString(t *testing.T) {
	cases := map[appconf.Dialect]string{
		appconf.DialectSQLite:   "sqlite",
		appconf.DialectPostgres: "postgres",
		appconf.DialectMySQL:    "mysql",
		appconf.DialectUnknown:  "",
	}
	for d, want := range cases {
		if got := d.String(); got != want {
			t.Errorf("%v.String() = %q, want %q", d, got, want)
		}
	}
}
