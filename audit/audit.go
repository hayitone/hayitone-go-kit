// Package audit is how a Hayitone service records what staff and partners did, for the
// audit log (hayitone-audit). An entry is written into the service's outbox in the same
// transaction as the change it describes, so the log never misses a change that happened
// and never shows one that rolled back:
//
//	err := postgres.InTx(ctx, pool, func(tx pgx.Tx) error {
//		… approve the title …
//		return audit.Write(ctx, tx, "catalog", audit.Entry{
//			Action:  "title.approved",
//			Target:  audit.Target{Type: "title", ID: titleID.String()},
//			Tenant:  title.PartnerID, // whose activity log it belongs in (uuid.Nil: Hayitone's own)
//			Reason:  req.Note,
//			Changes: map[string]audit.Change{"status": {From: "submitted", To: "approved"}},
//		})
//	})
//
// The rules every service gets from it:
//
//   - Who acted is never taken from the caller. It comes from the verified identity in the
//     context (identity.Router puts it there): the person, and the session they used. With
//     no identity (a scheduled job, an event handler) the actor is "system".
//   - Where from comes from the gateway. Wrap the public handler in Capture: it keeps the
//     client's IP (X-Hayitone-Client-Ip, which only the gateway can set) and user agent in
//     the context for Write.
//   - One topic per service, "<service>.audit.recorded", on the service's own stream.
//     hayitone-audit reads it with its own consumer and labels each entry with the stream
//     it came from, so one service can't write entries in another's name.
//   - Nothing personal or secret. Entries are sealed for good, so no email, phone number,
//     name, code, token or key goes in one: use IDs. Write refuses changes and data whose
//     field names say they hold such a thing (ForbiddenKey); the rest is the caller's care.
//   - Mistakes fail where they're made. A malformed entry (an action that isn't
//     noun.verb, a target ID without a type, too much data) is an error from Write, which
//     rolls the change back in tests and development, rather than an entry audit parks.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hayitone/hayitone-go-kit/httpx"
	"github.com/hayitone/hayitone-go-kit/identity"
	"github.com/hayitone/hayitone-go-kit/outbox"
)

// TopicSuffix follows the service's name in its audit topic.
const TopicSuffix = ".audit.recorded"

// Topic is the service's audit topic: Topic("catalog") is "catalog.audit.recorded".
func Topic(service string) string { return service + TopicSuffix }

// Outcomes. Most entries are successes; record a refusal only where it matters.
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeFailure = "failure"
)

// Actor types, as the audit log knows them.
const (
	ActorAccount = "account" // a signed-in person
	ActorSystem  = "system"  // the service on its own
)

// Limits, the audit log's own: an entry over them would be parked there.
const (
	MaxReason = 1000
	MaxText   = 300
	MaxBlob   = 16 << 10 // changes + data, encoded
)

// Target is what was done to. Label is a name that isn't personal (a plan's code, a
// department); never a person's name or address.
type Target struct {
	Type  string `json:"type,omitempty"`
	ID    string `json:"id,omitempty"`
	Label string `json:"label,omitempty"`
}

// Change is one field's before and after.
type Change struct {
	From any `json:"from"`
	To   any `json:"to"`
}

// Entry is what the service says happened. Who did it, from where, when and in which
// request are added by Write.
type Entry struct {
	Action  string // lower case, noun.verb: "title.approved", "plan.price_changed"
	Outcome string // "" means success
	Target  Target
	// Tenant is the company whose activity log the entry belongs in: the partner a title
	// or live event belongs to. uuid.Nil for Hayitone's own things (staff see every entry;
	// a partner sees only its own).
	Tenant  uuid.UUID
	Reason  string            // the note the person gave, if any
	Changes map[string]Change // fields that changed, with before and after
	Data    map[string]any    // other facts worth keeping (IDs, amounts, a department)
}

// Actor is who did it, as the record carries it.
type Actor struct {
	Type      string     `json:"type"`
	AccountID *uuid.UUID `json:"account_id,omitempty"`
	SessionID *uuid.UUID `json:"session_id,omitempty"`
	IP        string     `json:"ip,omitempty"`
	UserAgent string     `json:"user_agent,omitempty"`
}

// Record is the event published on "<service>.audit.recorded": the contract with
// hayitone-audit (its docs/events.md). The event's own ID (Hayitone-Event-Id) identifies
// the entry; its request ID travels in Hayitone-Request-Id.
type Record struct {
	OccurredAt time.Time         `json:"occurred_at"`
	Action     string            `json:"action"`
	Outcome    string            `json:"outcome"`
	Actor      Actor             `json:"actor"`
	Target     Target            `json:"target"`
	TenantID   *uuid.UUID        `json:"tenant_id,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Changes    map[string]Change `json:"changes,omitempty"`
	Data       map[string]any    `json:"data,omitempty"`
}

// ErrInvalid wraps every reason Write refuses an entry.
var ErrInvalid = errors.New("invalid audit entry")

var (
	serviceRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,40}$`)
	actionRe  = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,5}$`)
	typeRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{1,40}$`)
)

// forbidden: field names that say a value is personal or secret.
var forbidden = []string{"email", "phone", "msisdn", "password", "secret", "token", "otp", "stream_key", "full_name", "first_name", "last_name", "display_name"}

// ForbiddenKey reports whether a field name says its value is personal or secret (an
// email, a phone number, a person's name, a token, a key), which never goes in an entry.
func ForbiddenKey(k string) bool {
	k = strings.ToLower(k)
	for _, f := range forbidden {
		if strings.Contains(k, f) {
			return true
		}
	}
	return false
}

// Write records e in the service's outbox (tx: the change's own transaction), as an event on
// Topic(service).
func Write(ctx context.Context, tx outbox.Execer, service string, e Entry) error {
	rec, err := build(ctx, service, e, time.Now())
	if err != nil {
		return err
	}
	key := rec.Action
	if rec.Target.Type != "" {
		key = rec.Target.Type + ":" + rec.Target.ID
	}
	return outbox.Write(ctx, tx, Topic(service), key, rec)
}

// Build is the record Write would publish, without writing it (tests).
func Build(ctx context.Context, service string, e Entry) (Record, error) {
	return build(ctx, service, e, time.Now())
}

func build(ctx context.Context, service string, e Entry, now time.Time) (Record, error) {
	if !serviceRe.MatchString(service) {
		return Record{}, invalid("service %q", service)
	}
	rec := Record{
		OccurredAt: now.UTC(),
		Action:     strings.TrimSpace(e.Action),
		Outcome:    e.Outcome,
		Actor:      ActorFrom(ctx),
		Target:     Target{Type: strings.TrimSpace(e.Target.Type), ID: strings.TrimSpace(e.Target.ID), Label: strings.TrimSpace(e.Target.Label)},
		Reason:     strings.TrimSpace(e.Reason),
		Changes:    e.Changes,
		Data:       e.Data,
	}
	if !actionRe.MatchString(rec.Action) {
		return Record{}, invalid("action %q must look like noun.verb (lower case, dots)", rec.Action)
	}
	switch rec.Outcome {
	case "":
		rec.Outcome = OutcomeSuccess
	case OutcomeSuccess, OutcomeDenied, OutcomeFailure:
	default:
		return Record{}, invalid("outcome %q", rec.Outcome)
	}
	if rec.Target.Type != "" && !typeRe.MatchString(rec.Target.Type) {
		return Record{}, invalid("target type %q", rec.Target.Type)
	}
	if rec.Target.Type == "" && (rec.Target.ID != "" || rec.Target.Label != "") {
		return Record{}, invalid("target id or label without a type")
	}
	if len(rec.Target.ID) > MaxText || len(rec.Target.Label) > MaxText {
		return Record{}, invalid("target id and label are at most %d bytes", MaxText)
	}
	if len(rec.Reason) > MaxReason {
		return Record{}, invalid("reason is at most %d bytes", MaxReason)
	}
	if e.Tenant != uuid.Nil {
		t := e.Tenant
		rec.TenantID = &t
	}
	if len(rec.Changes) == 0 {
		rec.Changes = nil
	}
	if len(rec.Data) == 0 {
		rec.Data = nil
	}
	for k := range rec.Changes {
		if ForbiddenKey(k) {
			return Record{}, invalid("changes.%s: personal or secret values never go in an audit entry", k)
		}
	}
	for k := range rec.Data {
		if ForbiddenKey(k) {
			return Record{}, invalid("data.%s: personal or secret values never go in an audit entry", k)
		}
	}
	blob, err := json.Marshal(struct {
		C map[string]Change `json:"c"`
		D map[string]any    `json:"d"`
	}{rec.Changes, rec.Data})
	if err != nil {
		return Record{}, invalid("changes/data: %v", err)
	}
	if len(blob) > MaxBlob {
		return Record{}, invalid("changes and data are %d bytes; at most %d", len(blob), MaxBlob)
	}
	return rec, nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// ---- who and where ---------------------------------------------------------------------

type ctxKey struct{}

type client struct {
	ip netip.Addr
	ua string
}

// Capture keeps the client's IP and user agent in each request's context for Write. Wrap
// the public handler with it (outside the identity router). The IP is the one the gateway
// vouches for (httpx.ClientFrom); a request whose app headers are inconsistent keeps only
// its user agent.
func Capture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := client{ua: r.UserAgent()}
		if hc, err := httpx.ClientFrom(r); err == nil {
			c.ip, c.ua = hc.IP, hc.UserAgent
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
	})
}

// ActorFrom is who is acting in ctx: the verified identity (person and session) and, if
// Capture ran, the client's IP and user agent; with no identity, the system.
func ActorFrom(ctx context.Context) Actor {
	id, ok := identity.From(ctx)
	if !ok || id.UserID == uuid.Nil {
		return Actor{Type: ActorSystem}
	}
	a := Actor{Type: ActorAccount, AccountID: &id.UserID}
	if id.SessionID != uuid.Nil {
		s := id.SessionID
		a.SessionID = &s
	}
	if c, ok := ctx.Value(ctxKey{}).(client); ok {
		if c.ip.IsValid() {
			a.IP = c.ip.String()
		}
		a.UserAgent = clip(c.ua, 512)
	}
	return a
}

func clip(s string, max int) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, ""))
	if len(s) <= max {
		return s
	}
	for max > 0 && s[max]&0xC0 == 0x80 {
		max--
	}
	return s[:max]
}
