package csrfx_test

import (
	"fmt"
	"net/http"

	"leblanc.io/open-go-base/csrfx"
)

// Exemple de montage du middleware CSRF par-dessus un routeur, avec exposition
// du jeton aux templates via FuncMap.
func Example() {
	p := csrfx.New(csrfx.WithSecure("auto"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /form", func(w http.ResponseWriter, r *http.Request) {
		// Le projet fusionne p.FuncMap(r) dans le FuncMap de ses templates ;
		// {{ csrfField }} insère alors l'<input> caché dans le <form>.
		_ = p.FuncMap(r)
		fmt.Fprint(w, "form")
	})
	mux.HandleFunc("POST /action", func(w http.ResponseWriter, r *http.Request) {
		// Atteint seulement si le jeton CSRF est valide (le middleware filtre).
		fmt.Fprint(w, "ok")
	})

	// Monté globalement : pose le cookie et valide les requêtes mutantes.
	var handler http.Handler = p.Middleware(mux)
	_ = handler
	// Output:
}
