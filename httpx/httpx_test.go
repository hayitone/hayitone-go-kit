package httpx

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddleware(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))

	var seen string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ok", func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r.Context())
		w.WriteHeader(http.StatusTeapot)
	})
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("secret internal detail") })
	mux.HandleFunc("GET /readyz", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/", NotFound)
	h := Middleware(log, mux)

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.Header.Set("X-Request-Id", "rid-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if seen != "rid-1" || rec.Code != http.StatusTeapot {
		t.Fatalf("request id %q, status %d", seen, rec.Code)
	}
	for _, want := range []string{`"status":418`, `"request_id":"rid-1"`, `"route":"GET /ok"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("access log missing %s: %s", want, logs.String())
		}
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	body, _ := io.ReadAll(rec.Body)
	if rec.Code != 500 || strings.Contains(string(body), "secret") || !strings.Contains(string(body), `"error":"internal"`) {
		t.Errorf("panic: got %d %s (must be a generic 500)", rec.Code, body)
	}
	if !strings.Contains(logs.String(), "secret internal detail") {
		t.Error("panic value should be logged for us")
	}

	// Unrouted, wrong method, trailing slash, other case: all the plain JSON 404, never a
	// redirect or a 405 that lists methods.
	for _, c := range []struct{ method, path string }{
		{"GET", "/nope"}, {"POST", "/ok"}, {"GET", "/ok/"}, {"GET", "/OK"}, {"GET", "/x/../ok"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if rec.Code != 404 || !strings.Contains(rec.Body.String(), `"error":"not_found"`) || rec.Header().Get("Location") != "" {
			t.Errorf("%s %s: %d %q", c.method, c.path, rec.Code, rec.Body.String())
		}
	}

	logs.Reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if logs.Len() != 0 {
		t.Errorf("probes should not be logged: %s", logs.String())
	}
}
