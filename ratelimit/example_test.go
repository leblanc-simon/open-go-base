package ratelimit_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"leblanc.io/open-go-base/ratelimit"
)

// ExampleLimiter_ClientIP illustre la résolution sûre de l'IP : derrière un proxy
// de confiance, X-Forwarded-For est honoré...
func ExampleLimiter_ClientIP() {
	l, _ := ratelimit.New(100, []string{"10.0.0.0/8"})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555" // pair = proxy de confiance
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	fmt.Println(l.ClientIP(r))

	// ...mais un client direct (pair non listé) ne peut pas usurper l'en-tête.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.RemoteAddr = "203.0.113.9:6666"
	r2.Header.Set("X-Forwarded-For", "1.2.3.4") // usurpé -> ignoré
	fmt.Println(l.ClientIP(r2))

	// Output:
	// 203.0.113.7
	// 203.0.113.9
}

// ExampleWithKeyFunc limite par jeton plutôt que par IP : la clé vient d'un middleware
// d'authentification précédent, jamais d'un en-tête lu tel quel.
func ExampleWithKeyFunc() {
	type tokenKey struct{}
	l, _ := ratelimit.New(1, nil, ratelimit.WithKeyFunc(func(r *http.Request) string {
		id, _ := r.Context().Value(tokenKey{}).(string)
		return id
	}))
	h := l.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, token := range []string{"jeton-a", "jeton-a", "jeton-b"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r = r.WithContext(context.WithValue(r.Context(), tokenKey{}, token))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		fmt.Println(token, rec.Code)
	}

	// Output:
	// jeton-a 200
	// jeton-a 429
	// jeton-b 200
}
