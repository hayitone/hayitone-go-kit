package metrics

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/hayitone/hayitone-go-kit/httpx"
)

func TestRequestsByRoutePatternNeverByURL(t *testing.T) {
	reg := New("svc", "v1.2.3")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/videos/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /v1/videos", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
	h := httpx.MiddlewareWith(slog.New(slog.NewTextHandler(io.Discard, nil)), mux, httpx.Options{Observe: reg.Observe("public")})

	for _, req := range []*http.Request{
		httptest.NewRequest("GET", "/v1/videos/0b3c9a52-secret-id", nil),
		httptest.NewRequest("GET", "/v1/videos/another-id?token=abc", nil),
		httptest.NewRequest("POST", "/v1/videos", nil),
		httptest.NewRequest("GET", "/nope/someone@example.com", nil),
		httptest.NewRequest("BREW", "/v1/videos", nil),
		httptest.NewRequest("GET", "/readyz", nil), // probes aren't counted
	} {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	if n := testutil.ToFloat64(reg.requests.WithLabelValues("public", "GET", "/v1/videos/{id}", "200")); n != 2 {
		t.Errorf("GET /v1/videos/{id} 200: %v, want 2", n)
	}
	if n := testutil.ToFloat64(reg.requests.WithLabelValues("public", "POST", "/v1/videos", "201")); n != 1 {
		t.Errorf("POST /v1/videos 201: %v, want 1", n)
	}
	if n := testutil.ToFloat64(reg.requests.WithLabelValues("public", "GET", "unmatched", "404")); n != 1 {
		t.Errorf("unmatched 404: %v, want 1", n)
	}

	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, leak := range []string{"secret-id", "another-id", "token=abc", "example.com", "BREW", "readyz"} {
		if strings.Contains(body, leak) {
			t.Errorf("%q became part of a metric", leak)
		}
	}
	for _, want := range []string{
		`http_request_duration_seconds_count{method="GET",route="/v1/videos/{id}",server="public"} 2`,
		`http_requests_total{code="405",method="other",route="unmatched",server="public"} 1`,
		`hayitone_build_info{go_version="`, `service="svc",version="v1.2.3"} 1`,
		"go_goroutines ", "process_resident_memory_bytes ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}
}

func TestOwnCollectors(t *testing.T) {
	reg := New("svc", "dev")
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "svc_things_total", Help: "Things."})
	reg.MustRegister(c)
	c.Add(3)
	if n, err := testutil.GatherAndCount(reg.Gatherer(), "svc_things_total"); err != nil || n != 1 {
		t.Fatalf("own collector: %d %v", n, err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a duplicate metric name must stop start-up")
		}
	}()
	reg.MustRegister(prometheus.NewCounter(prometheus.CounterOpts{Name: "svc_things_total", Help: "Again."}))
}

func TestRoute(t *testing.T) {
	for in, want := range map[string]string{
		"GET /v1/a/{id}": "/v1/a/{id}", "/internal/v1/authz/": "/internal/v1/authz/", "": "unmatched", "/": "/",
	} {
		if got := Route(in); got != want {
			t.Errorf("Route(%q) = %q, want %q", in, got, want)
		}
	}
}
