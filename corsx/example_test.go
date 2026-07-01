package corsx_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"leblanc.io/open-go-base/appconf"
	"leblanc.io/open-go-base/corsx"
)

func ExampleMiddleware() {
	cfg := appconf.CORS{
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET", "POST"},
	}
	handler := corsx.Middleware(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	fmt.Println(rec.Header().Get("Access-Control-Allow-Origin"))
	// Output: https://app.example.com
}
