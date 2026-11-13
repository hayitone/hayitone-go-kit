package identity_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hayitone/hayitone-go-kit/identity"
	"github.com/hayitone/hayitone-go-kit/identity/identitytest"
)

var ctx = context.Background()

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestVerifyReadsTheClaims(t *testing.T) {
	iss := identitytest.New()
	want := identity.Identity{UserID: uuid.New(), AccountID: uuid.New(), SessionID: uuid.New(),
		Grants: []string{"catalog.publish"}, AMR: []string{"otp", "pwd"}, RequestID: "req-1",
		AuthTime: time.Now().Add(-time.Minute).Truncate(time.Second)}
	got, err := iss.Verifier().Verify(ctx, iss.Token(want))
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != want.UserID || got.AccountID != want.AccountID || got.SessionID != want.SessionID ||
		!got.Has("catalog.publish") || !got.Used(identity.MethodOTP) || got.RequestID != "req-1" || !got.AuthTime.Equal(want.AuthTime) {
		t.Fatalf("%+v", got)
	}
}

func TestVerifyRefuses(t *testing.T) {
	iss, other := identitytest.New(), identitytest.New()
	v := iss.Verifier()
	good := iss.Token(identity.Identity{})
	for name, c := range map[string]struct {
		raw  string
		want error
	}{
		"empty":                 {"", identity.ErrMissing},
		"not v4.public":         {"v4.local.abc.def", identity.ErrMalformed},
		"too long":              {"v4.public." + strings.Repeat("a", 5000), identity.ErrMalformed},
		"no footer":             {"v4.public.abc", identity.ErrMalformed},
		"tampered":              {good[:20] + flip(good[20]) + good[21:], identity.ErrInvalid},
		"another key, same kid": {other.Token(identity.Identity{}), identity.ErrInvalid},
		"unknown kid":           {withKID(t, other, "nope"), identity.ErrUnknownKey},
	} {
		_, err := v.Verify(ctx, c.raw)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}

	// Expiry, with the real key: valid until exp, refused from exp on (no leeway).
	tok := iss.Token(identity.Identity{})
	v.SetClock(func() time.Time { return time.Now().Add(59 * time.Second) })
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("within 60 s: %v", err)
	}
	v.SetClock(func() time.Time { return time.Now().Add(61 * time.Second) })
	if _, err := v.Verify(ctx, tok); !errors.Is(err, identity.ErrInvalid) {
		t.Fatalf("expired: %v", err)
	}
}

func TestRemoteKeysFollowRotationButDontHammer(t *testing.T) {
	first, second := identitytest.New(), identitytest.New()
	second.KID = "rotated"
	var served atomic.Value
	served.Store(first.PublicKeySet())
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		_ = json.NewEncoder(w).Encode(served.Load())
	}))
	defer srv.Close()

	keys := identity.KeysFromURL(srv.URL)
	keys.MinRefetch = 50 * time.Millisecond
	if err := keys.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	v := identity.NewVerifier(keys)
	if _, err := v.Verify(ctx, first.Token(identity.Identity{})); err != nil {
		t.Fatal(err)
	}

	// Made-up kids: at most one fetch per MinRefetch.
	before := fetches.Load()
	for i := 0; i < 20; i++ {
		_, _ = v.Verify(ctx, withKID(t, first, "made-up"))
	}
	if n := fetches.Load() - before; n > 1 {
		t.Fatalf("%d fetches for unknown kids", n)
	}

	// Rotation: auth publishes both keys; the new kid is fetched, the old one still works.
	set := first.PublicKeySet()
	set.Keys = append(set.Keys, second.PublicKeySet().Keys...)
	served.Store(set)
	time.Sleep(60 * time.Millisecond)
	if _, err := v.Verify(ctx, second.Token(identity.Identity{})); err != nil {
		t.Fatalf("new key: %v", err)
	}
	served.Store(second.PublicKeySet()) // old key retired: already-loaded keys stay usable
	if _, err := v.Verify(ctx, first.Token(identity.Identity{})); err != nil {
		t.Fatalf("old key during its last minute: %v", err)
	}
}

// While auth is down (restarting with new keys), a failed fetch doesn't lock out the next
// attempt for MinRefetch: only for a second.
func TestRemoteKeysRetryAfterAFailedFetch(t *testing.T) {
	iss := identitytest.New()
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(iss.PublicKeySet())
	}))
	defer srv.Close()
	keys := identity.KeysFromURL(srv.URL) // MinRefetch 10 s
	v := identity.NewVerifier(keys)
	tok := iss.Token(identity.Identity{})
	if _, err := v.Verify(ctx, tok); err == nil {
		t.Fatal("verified while auth was down")
	}
	up.Store(true)
	time.Sleep(1100 * time.Millisecond)
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("still locked out after auth came back: %v", err)
	}
}

func TestRemoteKeysReady(t *testing.T) {
	down := identity.KeysFromURL("http://127.0.0.1:1/internal/v1/keys")
	if err := down.Ready(ctx); err == nil {
		t.Fatal("ready without keys")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"keys":[{"kid":"x","version":"v4","purpose":"local","public_key_hex":"00"}]}`)
	}))
	defer bad.Close()
	if err := identity.KeysFromURL(bad.URL).Fetch(ctx); err == nil {
		t.Fatal("a set with no usable keys was accepted")
	}
}

func TestRouterPolicies(t *testing.T) {
	iss := identitytest.New()
	rt := identity.NewRouter(iss.Verifier(), quiet())
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, signed := identity.From(r.Context())
		if signed {
			_, _ = io.WriteString(w, id.UserID.String())
			return
		}
		_, _ = io.WriteString(w, "anonymous")
	})
	rt.Handle("GET /videos", identity.Anonymous, ok)
	rt.Handle("GET /me", identity.SignedIn, ok)
	rt.Handle("POST /videos/{id}/publish", identity.Grant("catalog.publish"), ok)
	rt.Handle("DELETE /channel", identity.All(identity.Grant("channel.delete"), identity.Recent(15*time.Minute, identity.MethodOTP, identity.MethodPasskey)), ok)
	rt.Handle("POST /settings", identity.Recent(15*time.Minute), ok)

	user := uuid.New()
	fresh := iss.Token(identity.Identity{UserID: user})
	publisher := iss.Token(identity.Identity{UserID: user, Grants: []string{"catalog.publish", "channel.delete"}})
	stale := iss.Token(identity.Identity{UserID: user, Grants: []string{"channel.delete"}, AuthTime: time.Now().Add(-time.Hour)})
	withOTP := iss.Token(identity.Identity{UserID: user, Grants: []string{"channel.delete"}, AMR: []string{"otp", "pwd"}})
	bad := fresh[:20] + flip(fresh[20]) + fresh[21:]

	for _, c := range []struct {
		name, method, path, token string
		status                    int
		code, body, challenge     string
	}{
		{"anonymous route, no token", "GET", "/videos", "", 200, "", "anonymous", ""},
		{"anonymous route, signed in", "GET", "/videos", fresh, 200, "", user.String(), ""},
		{"anonymous route, bad token: anonymous", "GET", "/videos", bad, 200, "", "anonymous", ""},
		{"signed-in route, no token", "GET", "/me", "", 401, "unauthorized", "", `error="invalid_token"`},
		{"signed-in route, bad token", "GET", "/me", bad, 401, "unauthorized", "", ""},
		{"signed-in route", "GET", "/me", fresh, 200, "", user.String(), ""},
		{"grant missing", "POST", "/videos/v1/publish", fresh, 403, "forbidden", "", `insufficient_scope`},
		{"grant held", "POST", "/videos/v1/publish", publisher, 200, "", user.String(), ""},
		{"recent, stale sign-in", "POST", "/settings", stale, 401, "reauthentication_required", "", `max_age=900`},
		{"recent", "POST", "/settings", fresh, 200, "", user.String(), ""},
		{"second factor needed, password only", "DELETE", "/channel", publisher, 401, "second_factor_reauthentication_required", "", `acr_values="otp hwk"`},
		{"second factor used", "DELETE", "/channel", withOTP, 200, "", user.String(), ""},
		{"no route", "GET", "/nothing", fresh, 404, "not_found", "", ""},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		if c.token != "" {
			req.Header.Set(identity.Header, c.token)
		}
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, req)
		if rec.Code != c.status {
			t.Errorf("%s: status %d, want %d (%s)", c.name, rec.Code, c.status, rec.Body)
			continue
		}
		if c.code != "" && !strings.Contains(rec.Body.String(), `"error":"`+c.code+`"`) {
			t.Errorf("%s: body %s, want %s", c.name, rec.Body, c.code)
		}
		if c.body != "" && rec.Body.String() != c.body {
			t.Errorf("%s: body %q, want %q", c.name, rec.Body, c.body)
		}
		if c.challenge != "" && !strings.Contains(rec.Header().Get("WWW-Authenticate"), c.challenge) {
			t.Errorf("%s: challenge %q, want %q", c.name, rec.Header().Get("WWW-Authenticate"), c.challenge)
		}
	}

	if got := rt.Routes(); len(got) != 5 || got[3].Policy != "grant:channel.delete+recent:15m0s:otp|hwk" {
		t.Fatalf("routes %+v", got)
	}
}

func TestMustPanicsWithoutIdentity(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	identity.Must(ctx)
}

func flip(b byte) string {
	if b == 'A' {
		return "B"
	}
	return "A"
}

// withKID re-signs nothing: it swaps the footer, which is enough to test kid lookup.
func withKID(t *testing.T, iss *identitytest.Issuer, kid string) string {
	t.Helper()
	old := iss.KID
	iss.KID = kid
	defer func() { iss.KID = old }()
	return iss.Token(identity.Identity{})
}
