// Package metrics gives a service Prometheus metrics that read the same everywhere:
// requests and their timing per route, Go runtime and process numbers, and build info,
// on a registry of its own (never the global one) served at /metrics on the internal port.
//
//	reg := metrics.New("auth", version)
//	srv := server.New(addr, httpx.MiddlewareWith(log, mux, httpx.Options{Observe: reg.Observe("public")}), log)
//	internalMux.Handle("GET /metrics", reg.Handler())
//	reg.MustRegister(myCounter)
//
// Labels are bounded by construction: the route is the mux's pattern ("/v1/videos/{id}"),
// never the URL, and unknown methods collapse to "other", so no ID, person or token can
// ever become a label. A service adding its own metrics keeps to the same rule.
package metrics

import (
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry is a service's metrics.
type Registry struct {
	reg       *prometheus.Registry
	requests  *prometheus.CounterVec
	durations *prometheus.HistogramVec
}

// New makes the registry with the standard collectors: HTTP requests, Go runtime,
// process (CPU, memory, open files) and hayitone_build_info{service,version}.
func New(service, version string) *Registry {
	r := &Registry{
		reg: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "HTTP requests answered, by server (public, internal …), method, route pattern and status code.",
		}, []string{"server", "method", "route", "code"}),
		durations: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Time to answer HTTP requests, by server, method and route pattern.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"server", "method", "route"}),
	}
	build := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "hayitone_build_info",
		Help:        "Always 1; its labels say which service and version is running.",
		ConstLabels: prometheus.Labels{"service": service, "version": version, "go_version": runtime.Version()},
	})
	build.Set(1)
	r.reg.MustRegister(
		r.requests, r.durations, build,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return r
}

// MustRegister adds the service's own collectors. It panics on a duplicate name, so a
// mistake shows at start-up.
func (r *Registry) MustRegister(cs ...prometheus.Collector) { r.reg.MustRegister(cs...) }

// Registerer is for code that takes a prometheus.Registerer.
func (r *Registry) Registerer() prometheus.Registerer { return r.reg }

// Gatherer is for tests (testutil) and anything else that reads the metrics.
func (r *Registry) Gatherer() prometheus.Gatherer { return r.reg }

// Handler serves the metrics in Prometheus' text format. Mount it on the internal port
// only: metrics describe the system and are not for the internet.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{
		ErrorHandling:     promhttp.ContinueOnError, // a failing collector doesn't hide the rest
		Registry:          r.reg,                    // promhttp's own errors are counted too
		EnableOpenMetrics: false,
	})
}

// Observe returns the httpx.Options.Observe for one server ("public", "internal" …).
func (r *Registry) Observe(server string) func(*http.Request, int, time.Duration) {
	return func(req *http.Request, status int, took time.Duration) {
		method, route := Method(req.Method), Route(req.Pattern)
		r.requests.WithLabelValues(server, method, route, strconv.Itoa(status)).Inc()
		r.durations.WithLabelValues(server, method, route).Observe(took.Seconds())
	}
}

// Route turns a mux pattern ("POST /v1/videos/{id}") into the route label
// ("/v1/videos/{id}"). No pattern (the request never reached a route) is "unmatched".
func Route(pattern string) string {
	if _, path, ok := strings.Cut(pattern, " "); ok {
		pattern = path
	}
	if pattern == "" {
		return "unmatched"
	}
	return pattern
}

// Method keeps the label set small: anything but the standard methods is "other".
func Method(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions:
		return m
	}
	return "other"
}
