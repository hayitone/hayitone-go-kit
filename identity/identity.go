// Package identity is what every Hayitone service does with the caller's identity
// (the gateway's authz contract, section 5):
//
//   - The gateway asks auth "who is calling?" and forwards the answer as a short-lived signed
//     token in X-Hayitone-Identity (PASETO v4.public, 60 s, signed by auth).
//   - The service verifies it with auth's PUBLIC keys (Verifier, KeysFromURL) and reads who
//     the caller is only from the verified claims. The plain X-Hayitone-*-Id headers are for
//     logs; nothing in a request body ever says who is acting.
//   - Every route declares who may call it (Router + Policy): there is no route without a
//     decision, so forgetting one is a compile error, not a hole.
//
// The service then decides "may they do this to this resource?" itself, because only it
// knows whom the resource belongs to.
package identity

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Header carries the identity token from the gateway (and between services).
const Header = "X-Hayitone-Identity"

// The contract's fixed values.
const (
	Issuer   = "hayitone-auth"
	Audience = "hayitone-internal" // identity tokens are for services, never the public edge

	// MaxTokenBytes: anything longer is refused before any crypto runs.
	MaxTokenBytes = 4096
	// ClockSkew tolerated for "issued at" and "not before"; expiry gets none.
	ClockSkew = 5 * time.Second
)

// Methods in AMR (RFC 8176).
const (
	MethodPassword = "pwd"
	MethodOTP      = "otp" // authenticator app code
	MethodPasskey  = "hwk"
	MethodRecovery = "rec" // recovery code
)

// Identity is who is calling, from verified claims only.
type Identity struct {
	UserID    uuid.UUID
	AccountID uuid.UUID // whom they act for
	SessionID uuid.UUID
	Grants    []string  // permissions in that account, e.g. "catalog.publish"
	AuthTime  time.Time // last sign-in or reauthentication; refresh doesn't move it
	AMR       []string  // how they proved it: pwd, otp, hwk, rec
	RequestID string    // the request's x-request-id (jti)
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Has reports whether the identity holds a grant for the whole account.
func (i Identity) Has(grant string) bool { return slices.Contains(i.Grants, grant) }

// Department grants: a role given per department reaches the token as "grant@department"
// (e.g. "platform.content.titles.publish@film"; auth ADR 0014). Holding the plain grant
// covers every department.

// HasIn reports whether the identity holds a grant in a department: for the whole
// account, or for that department.
func (i Identity) HasIn(grant, department string) bool {
	return i.Has(grant) || (department != "" && slices.Contains(i.Grants, grant+"@"+department))
}

// Departments says where the identity holds a grant: everywhere (whole account), or in
// the listed departments (sorted; none means nowhere). For filtering lists.
func (i Identity) Departments(grant string) (everywhere bool, departments []string) {
	for _, g := range i.Grants {
		if g == grant {
			return true, nil
		}
		if d, ok := strings.CutPrefix(g, grant+"@"); ok && d != "" {
			departments = append(departments, d)
		}
	}
	slices.Sort(departments)
	return false, departments
}

// Used reports whether they proved who they are with any of the methods.
func (i Identity) Used(methods ...string) bool {
	for _, m := range methods {
		if slices.Contains(i.AMR, m) {
			return true
		}
	}
	return false
}

// SignedInWithin reports whether they signed in (or reauthenticated) within d of now.
func (i Identity) SignedInWithin(d time.Duration, now time.Time) bool {
	return !i.AuthTime.IsZero() && now.Sub(i.AuthTime) <= d
}

type ctxKey struct{}

// With returns ctx carrying the identity (the middleware does this).
func With(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// From returns the caller's identity; ok=false for an anonymous caller.
func From(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// Must returns the caller's identity, for handlers behind a policy that requires one. It
// panics if there is none: that is a programming error the policy should have prevented.
func Must(ctx context.Context) Identity {
	id, ok := From(ctx)
	if !ok {
		panic("identity.Must: no identity in context; is the route's policy Anonymous?")
	}
	return id
}
