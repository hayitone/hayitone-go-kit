package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func get(t *testing.T, p *Probes, path string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	p.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestProbes(t *testing.T) {
	ok := func(context.Context) error { return nil }
	down := func(context.Context) error { return errors.New("connection refused") }
	slow := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

	if rec := get(t, New("auth", time.Second, map[string]Check{"postgres": ok, "redis": ok}), "/readyz"); rec.Code != 200 {
		t.Errorf("all up: got %d", rec.Code)
	}
	rec := get(t, New("auth", time.Second, map[string]Check{"postgres": ok, "redis": down}), "/readyz")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "redis") || strings.Contains(rec.Body.String(), "refused") {
		t.Errorf("one down: got %d %s (must name the check, never the reason)", rec.Code, rec.Body)
	}
	if rec := get(t, New("auth", 50*time.Millisecond, map[string]Check{"postgres": slow}), "/readyz"); rec.Code != 503 {
		t.Errorf("slow dependency: got %d, want 503 after the timeout", rec.Code)
	}

	p := New("auth", time.Second, map[string]Check{"postgres": ok})
	p.Drain()
	if rec := get(t, p, "/readyz"); rec.Code != 503 {
		t.Errorf("draining: got %d", rec.Code)
	}
	if rec := get(t, p, "/healthz"); rec.Code != 200 {
		t.Errorf("liveness while draining: got %d (the process is still alive)", rec.Code)
	}
}

// The gateway's health checks: the probes name the service, and once draining both the
// probe and every other answer say "take me out now".
func TestGatewayHeaders(t *testing.T) {
	ok := func(context.Context) error { return nil }
	p := New("auth", time.Second, map[string]Check{"postgres": ok})
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := get(t, p, path)
		if rec.Header().Get(HeaderHealthChecked) != "auth" || rec.Header().Get(HeaderImmediateFail) != "" {
			t.Errorf("%s: %v", path, rec.Header())
		}
	}
	app := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	call := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/auth/signin", nil))
		return rec
	}
	if rec := call(); rec.Header().Get(HeaderImmediateFail) != "" {
		t.Fatal("marked for removal while not draining")
	}
	p.Drain()
	if rec := get(t, p, "/readyz"); rec.Code != 503 || rec.Header().Get(HeaderImmediateFail) != "true" || rec.Header().Get(HeaderHealthChecked) != "auth" {
		t.Errorf("draining readyz: %d %v", rec.Code, rec.Header())
	}
	if rec := call(); rec.Code != 204 || rec.Header().Get(HeaderImmediateFail) != "true" {
		t.Errorf("draining request: %d %v (still served, but marked)", rec.Code, rec.Header())
	}
}
