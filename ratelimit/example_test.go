package ratelimit_test

import (
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
