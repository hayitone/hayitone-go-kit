// Package httpx holds the small HTTP helpers every handler and server shares:
// JSON responses, the error shape, request IDs, panic recovery and request logging.
package httpx

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"path"
	"runtime/debug"
	"strings"
	"time"
)

// WriteJSON writes v as JSON with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error is the one error shape every Hayitone service returns:
//
//	{"error":"invalid_request","message":"…","fields":{"email":"invalid"}}
//
// "error" is a stable machine-readable code the web and the apps switch on (they show their
// own, translated message); "message" is an optional English hint for developers. Never put
// internal details in any field. Optional extras:
//
//	fields         which inputs are wrong and why (validation), e.g. {"password":"too_short"}
//	retry_after    seconds to wait (429), also sent as the Retry-After header
//	attempts_left  tries left on a code
type Error struct {
	Code         string            `json:"error"`
	Message      string            `json:"message,omitempty"`
	Fields       map[string]string `json:"fields,omitempty"`
	RetryAfter   int               `json:"retry_after,omitempty"`
	AttemptsLeft *int              `json:"attempts_left,omitempty"`
}

// WriteError writes the error shape.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, Error{Code: code, Message: message})
}

// NotFound is the default handler: everything not routed is a JSON 404.
func NotFound(w http.ResponseWriter, _ *http.Request) {
	WriteError(w, http.StatusNotFound, "not_found", "")
}

type ctxKey int

const requestIDKey ctxKey = 0

// RequestID returns the request ID set by the gateway (x-request-id), if any.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// WithRequestID returns ctx carrying a request ID (Middleware does this for requests).
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// statusRecorder remembers the status code for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer (flush, hijack).
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Middleware wraps a handler with: request ID in the context, panic recovery (500, logged
// with the stack, never shown to the client), and one structured log line per request.
func Middleware(log *slog.Logger, next http.Handler) http.Handler {
	return MiddlewareWith(log, next, Options{})
}

// Options adjust Middleware for paths that are not ordinary routes.
type Options struct {
	// Passthrough path prefixes skip the clean-path check and the per-request log line:
	// the gateway's checks (/internal/v1/authz…) carry the original request's path after
	// the prefix, which may end in "/", and arrive on every signed-in request (the handler
	// logs refusals itself; the gateway logs every request).
	Passthrough []string
}

func (o Options) passthrough(p string) bool {
	for _, prefix := range o.Passthrough {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// MiddlewareWith is Middleware with Options.
func MiddlewareWith(log *slog.Logger, next http.Handler, o Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := r.Header.Get("X-Request-Id")
		ctx := context.WithValue(r.Context(), requestIDKey, rid)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		pass := o.passthrough(r.URL.Path)
		req := r.WithContext(ctx) // the mux records the matched pattern on this request

		defer func() {
			if p := recover(); p != nil {
				log.ErrorContext(ctx, "panic", "request_id", rid, "panic", p, "stack", string(debug.Stack()))
				WriteError(rec, http.StatusInternalServerError, "internal", "")
			}
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || pass {
				return // probes every few seconds, gateway checks on every request: not logged
			}
			log.InfoContext(ctx, "request",
				"request_id", rid,
				"method", r.Method,
				"path", r.URL.Path,
				"route", req.Pattern, // e.g. "POST /v1/auth/signup"; "/" when nothing matched
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		}()
		// A path must already be clean ("/a/../b", "//b", "/b/" are not): the standard mux
		// would answer those with a redirect. Exact matches only, like everywhere else.
		if p := r.URL.Path; !pass && (p == "" || path.Clean(p) != p) {
			NotFound(rec, req)
			return
		}
		next.ServeHTTP(rec, req)
	})
}

// Mux is what features register their routes on. *http.ServeMux satisfies it; tests use
// their own to list every route (docs/api/openapi.yaml must describe each one).
type Mux interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}
