// Package sqldialect regroupe les bricoles dépendantes du dialecte SQL
// partagées par les sous-packages sqlstore (authx, mfax). Interne au module.
package sqldialect

import (
	"strconv"
	"strings"

	"leblanc.io/open-go-base/appconf"
)

// Rebind adapte les placeholders d'une requête écrite avec des '?' au dialecte
// cible. Postgres utilise des placeholders numérotés ($1, $2, ...) ; SQLite et
// MySQL gardent '?'. Les requêtes de la lib ne contiennent jamais de '?'
// littéral (pas de chaîne avec '?'), la réécriture naïve est donc sûre.
func Rebind(d appconf.Dialect, query string) string {
	if d != appconf.DialectPostgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}
