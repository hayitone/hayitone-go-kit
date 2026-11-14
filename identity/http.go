package identity

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hayitone/hayitone-go-kit/httpx"
)

// A Policy says who may call a route. Every route on a Router has one.
type Policy interface {
	// allow returns nil, or the refusal to send.
	allow(id Identity, signedIn bool, now time.Time) *refusal
	String() string
}

type refusal struct {
	status    int
	code      string
	challenge string
}

// Challenges, as the gateway and auth send them (RFC 6750, RFC 9470).
const challengeInvalid = `Bearer realm="hayitone", error="invalid_token"`

func notSignedIn() *refusal {
	return &refusal{http.StatusUnauthorized, "unauthorized", challengeInvalid}
}

// Anonymous: anyone. A signed-in caller's identity is still in the context (From).
var Anonymous Policy = anonymous{}

// SignedIn: any signed-in caller.
var SignedIn Policy = signedIn{}

// Grant: signed in, holding the permission in the account they act for. Remember the
// second half (does this resource belong to that account?): only the handler can check it.
func Grant(permission string) Policy { return grant(permission) }

// GrantInAny: signed in, holding the permission for the whole account or for at least one
// department. The route's handler then checks the resource's department with HasIn
// (only it knows which department the resource belongs to).
func GrantInAny(permission string) Policy { return grantInAny(permission) }

// Recent: signed in (or reauthenticated) within maxAge, and if methods are given, with one
// of them (e.g. MethodOTP, MethodPasskey for a second factor). Otherwise 401 with the
// step-up challenge: the client reauthenticates (POST /v1/auth/reauth) and retries.
func Recent(maxAge time.Duration, methods ...string) Policy {
	return recent{maxAge: maxAge, methods: methods}
}

// All: every policy must allow.
func All(policies ...Policy) Policy { return all(policies) }

type anonymous struct{}

func (anonymous) allow(Identity, bool, time.Time) *refusal { return nil }
func (anonymous) String() string                           { return "anonymous" }

type signedIn struct{}

func (signedIn) allow(_ Identity, ok bool, _ time.Time) *refusal {
	if !ok {
		return notSignedIn()
	}
	return nil
}
func (signedIn) String() string { return "signed-in" }

type grant string

func (g grant) allow(id Identity, ok bool, _ time.Time) *refusal {
	switch {
	case !ok:
		return notSignedIn()
	case !id.Has(string(g)):
		return &refusal{http.StatusForbidden, "forbidden", `Bearer realm="hayitone", error="insufficient_scope"`}
	}
	return nil
}
func (g grant) String() string { return "grant:" + string(g) }

type grantInAny string

func (g grantInAny) allow(id Identity, ok bool, _ time.Time) *refusal {
	if !ok {
		return notSignedIn()
	}
	if all, depts := id.Departments(string(g)); !all && len(depts) == 0 {
		return &refusal{http.StatusForbidden, "forbidden", `Bearer realm="hayitone", error="insufficient_scope"`}
	}
	return nil
}
func (g grantInAny) String() string { return "grant-in-any:" + string(g) }

type recent struct {
	maxAge  time.Duration
	methods []string
}

func (p recent) allow(id Identity, ok bool, now time.Time) *refusal {
	if !ok {
		return notSignedIn()
	}
	if id.SignedInWithin(p.maxAge, now) && (len(p.methods) == 0 || id.Used(p.methods...)) {
		return nil
	}
	ch := fmt.Sprintf(`Bearer realm="hayitone", error="insufficient_user_authentication", max_age=%d`, int(p.maxAge.Seconds()))
	code := "reauthentication_required"
	if len(p.methods) > 0 {
		ch = fmt.Sprintf(`Bearer realm="hayitone", error="insufficient_user_authentication", acr_values=%q, max_age=%d`,
			strings.Join(p.methods, " "), int(p.maxAge.Seconds()))
		code = "second_factor_reauthentication_required"
	}
	return &refusal{http.StatusUnauthorized, code, ch}
}
func (p recent) String() string {
	if len(p.methods) == 0 {
		return "recent:" + p.maxAge.String()
	}
	return "recent:" + p.maxAge.String() + ":" + strings.Join(p.methods, "|")
}

type all []Policy

func (a all) allow(id Identity, ok bool, now time.Time) *refusal {
	for _, p := range a {
		if r := p.allow(id, ok, now); r != nil {
			return r
		}
	}
	return nil
}
func (a all) String() string {
	parts := make([]string, len(a))
	for i, p := range a {
		parts[i] = p.String()
	}
	return strings.Join(parts, "+")
}

// Route is one registered route and its policy (for listings and tests).
type Route struct {
	Pattern string
	Policy  string
}

// Router is an http.ServeMux where every route states its Policy. Unmatched requests get
// the standard JSON 404. Wrap it in httpx.Middleware as usual.
type Router struct {
	mux    *http.ServeMux
	v      *Verifier
	log    *slog.Logger
	routes []Route
}

func NewRouter(v *Verifier, log *slog.Logger) *Router {
	rt := &Router{mux: http.NewServeMux(), v: v, log: log}
	rt.mux.HandleFunc("/", httpx.NotFound)
	return rt
}

// Handle registers h for pattern ("GET /v1/videos/{id}") under policy p.
func (rt *Router) Handle(pattern string, p Policy, h http.Handler) {
	if p == nil {
		panic("identity.Router: " + pattern + " has no policy")
	}
	rt.routes = append(rt.routes, Route{Pattern: pattern, Policy: p.String()})
	rt.mux.Handle(pattern, rt.Guard(p, h))
}

func (rt *Router) HandleFunc(pattern string, p Policy, h http.HandlerFunc) {
	rt.Handle(pattern, p, h)
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) { rt.mux.ServeHTTP(w, r) }

// Routes lists every route with its policy, in registration order.
func (rt *Router) Routes() []Route { return append([]Route(nil), rt.routes...) }

// Guard verifies the caller's identity, applies the policy, and puts the identity in the
// request context for h. Use it directly when not using Router.
//
// A token that is present but doesn't verify gets 401 on every route except Anonymous ones,
// where it is logged and the caller treated as anonymous, as the gateway does on optional
// routes.
func (rt *Router) Guard(p Policy, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			id Identity
			ok bool
		)
		if raw := r.Header.Get(Header); raw != "" {
			var err error
			id, err = rt.v.Verify(r.Context(), raw)
			if err != nil {
				rt.log.WarnContext(r.Context(), "identity refused", "reason", err.Error(),
					"request_id", httpx.RequestID(r.Context()), "route", r.Pattern)
				if _, anon := p.(anonymous); !anon {
					refuse(w, notSignedIn())
					return
				}
			} else {
				ok = true
			}
		}
		if ref := p.allow(id, ok, rt.v.now()); ref != nil {
			refuse(w, ref)
			return
		}
		if ok {
			r = r.WithContext(With(r.Context(), id))
		}
		h.ServeHTTP(w, r)
	})
}

func refuse(w http.ResponseWriter, ref *refusal) {
	w.Header().Set("WWW-Authenticate", ref.challenge)
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, ref.status, httpx.Error{Code: ref.code})
}
