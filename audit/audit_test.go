package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hayitone/hayitone-go-kit/httpx"
	"github.com/hayitone/hayitone-go-kit/identity"
)

type fakeTx struct {
	sql  string
	args []any
}

func (f *fakeTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.sql, f.args = sql, args
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func TestTopic(t *testing.T) {
	if got := Topic("catalog"); got != "catalog.audit.recorded" {
		t.Fatal(got)
	}
}

func TestWriteAsPerson(t *testing.T) {
	user, session, partner := uuid.New(), uuid.New(), uuid.New()
	var tx fakeTx
	h := Capture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := identity.With(r.Context(), identity.Identity{UserID: user, AccountID: partner, SessionID: session})
		ctx = httpx.WithRequestID(ctx, "req-1")
		err := Write(ctx, &tx, "catalog", Entry{
			Action: "title.approved", Target: Target{Type: "title", ID: "t-1"}, Tenant: partner,
			Reason:  " fine ",
			Changes: map[string]Change{"status": {From: "submitted", To: "approved"}},
			Data:    map[string]any{"department": "film"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/x", nil)
	req.Header.Set("X-Hayitone-Client-Ip", "::ffff:41.210.1.2")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.Contains(tx.sql, "INSERT INTO outbox_events") {
		t.Fatalf("sql %q", tx.sql)
	}
	if tx.args[1] != "catalog.audit.recorded" || tx.args[2] != "title:t-1" {
		t.Fatalf("topic %v key %v", tx.args[1], tx.args[2])
	}
	var rec Record
	if err := json.Unmarshal(tx.args[3].([]byte), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Action != "title.approved" || rec.Outcome != OutcomeSuccess || rec.Reason != "fine" {
		t.Fatalf("%+v", rec)
	}
	if rec.Actor.Type != ActorAccount || *rec.Actor.AccountID != user || *rec.Actor.SessionID != session || *rec.Actor.ActingFor != partner {
		t.Fatalf("actor %+v", rec.Actor)
	}
	if rec.Actor.IP != "41.210.1.2" || rec.Actor.UserAgent != "Mozilla/5.0" {
		t.Fatalf("where %+v", rec.Actor)
	}
	if rec.TenantID == nil || *rec.TenantID != partner {
		t.Fatalf("tenant %v", rec.TenantID)
	}
	if time.Since(rec.OccurredAt) > time.Minute {
		t.Fatalf("occurred_at %v", rec.OccurredAt)
	}
	if !strings.Contains(string(tx.args[4].([]byte)), "req-1") {
		t.Fatalf("headers %s", tx.args[4])
	}
}

func TestSystemWhenNoIdentity(t *testing.T) {
	rec, err := Build(context.Background(), "billing", Entry{Action: "refund.recorded"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Actor.Type != ActorSystem || rec.Actor.AccountID != nil || rec.TenantID != nil {
		t.Fatalf("%+v", rec)
	}
	b, _ := json.Marshal(rec)
	for _, absent := range []string{"tenant_id", "changes", "data", "reason", "account_id"} {
		if strings.Contains(string(b), absent) {
			t.Fatalf("%s in %s", absent, b)
		}
	}
}

func TestNoIPWithoutCapture(t *testing.T) {
	ctx := identity.With(context.Background(), identity.Identity{UserID: uuid.New()})
	rec, err := Build(ctx, "media", Entry{Action: "upload.started"})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Actor.IP != "" || rec.Actor.UserAgent != "" || rec.Actor.SessionID != nil || rec.Actor.ActingFor != nil {
		t.Fatalf("%+v", rec.Actor)
	}
}

func TestRefused(t *testing.T) {
	big := strings.Repeat("x", MaxBlob)
	for name, c := range map[string]struct {
		service string
		e       Entry
	}{
		"service":        {"Catalog!", Entry{Action: "title.created"}},
		"no dot":         {"catalog", Entry{Action: "created"}},
		"upper":          {"catalog", Entry{Action: "Title.Created"}},
		"outcome":        {"catalog", Entry{Action: "title.created", Outcome: "ok"}},
		"id no type":     {"catalog", Entry{Action: "title.created", Target: Target{ID: "x"}}},
		"bad type":       {"catalog", Entry{Action: "title.created", Target: Target{Type: "Title"}}},
		"long reason":    {"catalog", Entry{Action: "title.created", Reason: strings.Repeat("r", MaxReason+1)}},
		"email in data":  {"catalog", Entry{Action: "title.created", Data: map[string]any{"contact_email": "a@b.c"}}},
		"key in changes": {"media", Entry{Action: "live.key_rotated", Changes: map[string]Change{"stream_key": {}}}},
		"too big":        {"catalog", Entry{Action: "title.created", Data: map[string]any{"x": big}}},
		"not json":       {"catalog", Entry{Action: "title.created", Data: map[string]any{"f": func() {}}}},
	} {
		t.Run(name, func(t *testing.T) {
			var tx fakeTx
			err := Write(context.Background(), &tx, c.service, c.e)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("err %v", err)
			}
			if tx.sql != "" {
				t.Fatal("written anyway")
			}
		})
	}
}

func TestForbiddenKey(t *testing.T) {
	for k, want := range map[string]bool{
		"email": true, "Phone_Number": true, "invite_token": true, "display_name": true,
		"plan_code": false, "title": false, "department": false, "amount": false, "name": false,
	} {
		if ForbiddenKey(k) != want {
			t.Errorf("%s: want %v", k, want)
		}
	}
}

func TestCaptureBadAppHeadersKeepsUserAgent(t *testing.T) {
	var got Actor
	h := Capture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ActorFrom(identity.With(r.Context(), identity.Identity{UserID: uuid.New()}))
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Client-Type", "app") // no platform: inconsistent
	req.Header.Set("User-Agent", "HayitoneApp/1.0")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got.IP != "" || got.UserAgent != "HayitoneApp/1.0" {
		t.Fatalf("%+v", got)
	}
}
