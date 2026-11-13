// Package health serves the two probes every service has:
//
//	GET /healthz  liveness:  the process is running (always 200 while it lives)
//	GET /readyz   readiness: send traffic here. 200 only when every dependency answers and
//	              the service isn't shutting down; otherwise 503 with the failing checks.
//
// The gateway (Envoy) health-checks /readyz. Two headers are for it:
//
//	X-Envoy-Upstream-Healthchecked-Cluster: <service>   on both probes. The gateway checks
//	    it names the service it meant to reach (service_name_matcher), so an address that
//	    now belongs to another service never gets this service's traffic.
//	X-Envoy-Immediate-Health-Check-Fail: true   while draining, on /readyz and (Middleware)
//	    on every response: the gateway stops sending new requests at once instead of
//	    waiting for several failed checks.
package health

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/hayitone/hayitone-go-kit/httpx"
)

// Check reports whether one dependency is usable.
type Check func(ctx context.Context) error

// Header names the gateway reads (see the package comment).
const (
	HeaderHealthChecked = "X-Envoy-Upstream-Healthchecked-Cluster"
	HeaderImmediateFail = "X-Envoy-Immediate-Health-Check-Fail"
)

// Probes holds the readiness checks and the draining flag.
type Probes struct {
	service  string
	checks   map[string]Check
	timeout  time.Duration
	draining atomic.Bool
}

// New: service is the name the gateway's health check expects ("auth"), the gateway's
// cluster name for it.
func New(service string, timeout time.Duration, checks map[string]Check) *Probes {
	return &Probes{service: service, checks: checks, timeout: timeout}
}

// Drain makes /readyz answer 503 from now on (the first step of a graceful shutdown).
func (p *Probes) Drain() { p.draining.Store(true) }

// Register adds /healthz and /readyz to mux.
func (p *Probes) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(HeaderHealthChecked, p.service)
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", p.ready)
}

// Middleware marks every response "take me out now" once draining has begun, so the
// gateway stops routing here at its next request rather than its next health check.
func (p *Probes) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.draining.Load() {
			w.Header().Set(HeaderImmediateFail, "true")
		}
		next.ServeHTTP(w, r)
	})
}

func (p *Probes) ready(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(HeaderHealthChecked, p.service)
	if p.draining.Load() {
		w.Header().Set(HeaderImmediateFail, "true")
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
	defer cancel()

	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(p.checks))
	for name, check := range p.checks {
		go func() { results <- result{name, check(ctx)} }()
	}
	failed := map[string]string{}
	for range p.checks {
		if res := <-results; res.err != nil {
			failed[res.name] = "unavailable" // the reason goes to logs, not to whoever asks
		}
	}
	if len(failed) > 0 {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "failed": failed})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
