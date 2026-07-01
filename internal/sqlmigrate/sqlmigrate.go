// Package sqlmigrate applique des migrations SQL embarquées, idempotemment.
//
// Il est interne au module : les sous-packages sqlstore de authx et mfax s'en
// servent pour appliquer leurs propres migrations. Le suivi se fait dans une
// table partagée schema_migrations, clé = nom de fichier. Les noms étant
// préfixés par composant (001_authx.sql, 001_mfax.sql), il n'y a pas de
// collision et l'ordre d'application au sein d'un composant suit l'ordre
// lexical des fichiers.
//
// La table de suivi et l'INSERT sont écrits de façon portable (type TIMESTAMP,
// placeholders réécrits selon le dialecte) ; le DDL applicatif, lui, est fourni
// par l'appelant dans un sous-dossier par dialecte.
package sqlmigrate

import (
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/internal/sqldialect"
)

// Run applique les fichiers *.sql de dir (dans fsys) non encore appliqués, dans
// l'ordre lexical, chacun dans sa propre transaction. d sélectionne la syntaxe
// des placeholders de la table de suivi (le DDL de dir doit déjà être écrit pour
// ce dialecte).
func Run(db *sql.DB, fsys fs.FS, dir string, d appconf.Dialect) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("sqlmigrate: create tracking table: %w", err)
	}

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return fmt.Errorf("sqlmigrate: read %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	applied := map[string]bool{}
	rows, err := db.Query(`SELECT name FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("sqlmigrate: read applied: %w", err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		applied[n] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, name := range names {
		if applied[name] {
			continue
		}
		body, err := fs.ReadFile(fsys, dir+"/"+name)
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("sqlmigrate: %s: %w", name, err)
		}
		if _, err := tx.Exec(sqldialect.Rebind(d, `INSERT INTO schema_migrations (name) VALUES (?)`), name); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
