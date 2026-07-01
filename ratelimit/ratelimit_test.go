package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReq(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIP_NoTrustedProxies_IgnoresHeaders(t *testing.T) {
	l, err := New(100, nil)
	if err != nil {
		t.Fatal(err)
	}
	// XFF présent mais aucun proxy de confiance -> on l'ignore.
	r := newReq("198.51.100.7:4444", map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if got := l.ClientIP(r); got != "198.51.100.7" {
		t.Errorf("ClientIP = %q, want 198.51.100.7 (header ignoré)", got)
	}
}

func TestClientIP_TrustedProxy_UsesXFF(t *testing.T) {
	l, err := New(100, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := newReq("10.0.0.1:5555", map[string]string{"X-Forwarded-For": "203.0.113.7"})
	if got := l.ClientIP(r); got != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want 203.0.113.7", got)
	}
}

// Sécurité : un client direct (pair NON listé) qui usurpe X-Forwarded-For ne
// doit pas pouvoir se faire passer pour une autre IP.
func TestClientIP_UntrustedPeer_SpoofedXFFIgnored(t *testing.T) {
	l, err := New(100, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := newReq("203.0.113.9:6666", map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if got := l.ClientIP(r); got != "203.0.113.9" {
		t.Errorf("ClientIP = %q, want 203.0.113.9 (XFF usurpé ignoré)", got)
	}
}

// Chaîne de proxys : les sauts internes de confiance sont retirés, on remonte au
// vrai client.
func TestClientIP_ChainedProxies(t *testing.T) {
	l, err := New(100, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := newReq("10.0.0.1:7777", map[string]string{"X-Forwarded-For": "203.0.113.7, 10.0.0.2"})
	if got := l.ClientIP(r); got != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want 203.0.113.7", got)
	}
}

func TestClientIP_XRealIPFallback(t *testing.T) {
	l, err := New(100, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := newReq("10.0.0.1:8888", map[string]string{"X-Real-IP": "203.0.113.42"})
	if got := l.ClientIP(r); got != "203.0.113.42" {
		t.Errorf("ClientIP = %q, want 203.0.113.42", got)
	}
}

func TestNew_InvalidTrustedProxy(t *testing.T) {
	if _, err := New(100, []string{"not-an-ip"}); err == nil {
		t.Error("attendu une erreur pour un CIDR/IP invalide")
	}
}

func TestMiddleware_LimitsByClient(t *testing.T) {
	l, err := New(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newReq("203.0.113.1:1000", nil))
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK {
		t.Errorf("les 2 premières requêtes devraient passer: %v", codes)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Errorf("la 3e requête devrait être limitée (429), obtenu %d", codes[2])
	}
}

func TestWithLimitHandler_CustomResponse(t *testing.T) {
	custom := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"slow down"}`))
	})

	l, err := New(1, nil, WithLimitHandler(custom))
	if err != nil {
		t.Fatal(err)
	}
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1re requête : passe.
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, newReq("203.0.113.1:1000", nil))
	if rec1.Code != http.StatusOK {
		t.Fatalf("1re requête: code %d, want 200", rec1.Code)
	}

	// 2e requête : limitée -> réponse personnalisée.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, newReq("203.0.113.1:1000", nil))
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("2e requête: code %d, want 429", rec2.Code)
	}
	if ct := rec2.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if body := rec2.Body.String(); body != `{"error":"slow down"}` {
		t.Errorf("corps = %q, want le JSON personnalisé", body)
	}
	// httprate positionne Retry-After avant d'appeler le handler.
	if rec2.Header().Get("Retry-After") == "" {
		t.Error("Retry-After devrait être positionné par httprate")
	}
}

func TestWithLimitHandler_NilIgnored(t *testing.T) {
	l, err := New(1, nil, WithLimitHandler(nil))
	if err != nil {
		t.Fatal(err)
	}
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, newReq("203.0.113.1:1000", nil))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, newReq("203.0.113.1:1000", nil))
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("handler nil: 429 par défaut attendu, obtenu %d", rec2.Code)
	}
}

func TestMiddleware_DistinctClientsIndependent(t *testing.T) {
	l, err := New(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, newReq("203.0.113.1:1000", nil))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, newReq("203.0.113.2:1000", nil))

	if rec1.Code != http.StatusOK || rec2.Code != http.StatusOK {
		t.Errorf("deux clients distincts ne devraient pas se limiter mutuellement: %d %d", rec1.Code, rec2.Code)
	}
}

func TestMiddleware_DisabledWhenLimitZero(t *testing.T) {
	l, err := New(0, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newReq("203.0.113.1:1000", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("limitation désactivée attendue, obtenu %d à i=%d", rec.Code, i)
		}
	}
}
