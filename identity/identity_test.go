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
		AuthTime: time.Now().Add(-time.Minute).Truncate(time.Second), Method: "PATCH", Path: "/v1/me/profile"}
	got, err := iss.Verifier().Verify(ctx, iss.Token(want))
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != want.UserID || got.AccountID != want.AccountID || got.SessionID != want.SessionID ||
		!got.Has("catalog.publish") || !got.Used(identity.MethodOTP) || got.RequestID != "req-1" || !got.AuthTime.Equal(want.AuthTime) ||
		got.Method != "PATCH" || got.Path != "/v1/me/profile" {
		t.Fatalf("%+v", got)
	}
}

// A token is for one request: same method, same escaped path (the query doesn't count).
func TestVerifyRequest(t *testing.T) {
	iss := identitytest.New()
	v := iss.Verifier()
	signed := httptest.NewRequest("PATCH", "/v1/me/profile?x=1", nil)
	iss.Authorize(signed, identity.Identity{})
	tok := signed.Header.Get(identity.Header)
	for _, c := range []struct {
		name, method, target string
		want                 error
	}{
		{"the same request", "PATCH", "/v1/me/profile", nil},
		{"another query", "PATCH", "/v1/me/profile?y=2", nil},
		{"another method", "DELETE", "/v1/me/profile", identity.ErrOtherRequest},
		{"another path", "PATCH", "/v1/me/profile/avatar", identity.ErrOtherRequest},
		{"another service's path", "PATCH", "/v1/catalog/titles/1", identity.ErrOtherRequest},
		{"trailing slash", "PATCH", "/v1/me/profile/", identity.ErrOtherRequest},
	} {
		req := httptest.NewRequest(c.method, c.target, nil)
		req.Header.Set(identity.Header, tok)
		if _, err := v.VerifyRequest(req); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// Escaped paths are compared escaped: %2F is not a slash.
	enc := httptest.NewRequest("GET", "/v1/titles/a%2Fb", nil)
	iss.Authorize(enc, identity.Identity{})
	if _, err := v.VerifyRequest(enc); err != nil {
		t.Errorf("escaped path: %v", err)
	}
	plain := httptest.NewRequest("GET", "/v1/titles/a/b", nil)
	plain.Header.Set(identity.Header, enc.Header.Get(identity.Header))
	if _, err := v.VerifyRequest(plain); !errors.Is(err, identity.ErrOtherRequest) {
		t.Errorf("escaped vs plain: %v", err)
	}
	// A token naming no request at all is refused outright.
	if _, err := v.Verify(ctx, iss.Token(identity.Identity{Path: "nowhere"})); !errors.Is(err, identity.ErrInvalid) {
		t.Errorf("no path: %v", err)
	}
	none := httptest.NewRequest("GET", "/v1/me", nil)
	if _, err := v.VerifyRequest(none); !errors.Is(err, identity.ErrMissing) {
		t.Errorf("no token: %v", err)
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

// A key auth stops publishing (a finished rotation, or a leaked key removed) stops being
// trusted: services look again every MaxAge, and accept a withdrawn key only for
// RetiredGrace (its tokens' last seconds). Without that, a leaked identity key would be
// trusted until every service restarted.
func TestRemoteKeysDropWithdrawnKeys(t *testing.T) {
	leaked, fresh := identitytest.New(), identitytest.New()
	fresh.KID = "fresh"
	var served atomic.Value
	served.Store(leaked.PublicKeySet())
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		_ = json.NewEncoder(w).Encode(served.Load())
	}))
	defer srv.Close()

	keys := identity.KeysFromURL(srv.URL)
	keys.MinRefetch, keys.MaxAge, keys.RetiredGrace = 10*time.Millisecond, 50*time.Millisecond, 150*time.Millisecond
	if err := keys.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	v := identity.NewVerifier(keys)
	if _, err := v.Verify(ctx, leaked.Token(identity.Identity{})); err != nil {
		t.Fatal(err)
	}

	// Auth now publishes only the fresh key. No unknown kid arrives; the next use after
	// MaxAge looks again anyway, and the withdrawn key still works during its grace.
	served.Store(fresh.PublicKeySet())
	time.Sleep(60 * time.Millisecond)
	if _, err := v.Verify(ctx, leaked.Token(identity.Identity{})); err != nil {
		t.Fatalf("a just-withdrawn key, within its grace: %v", err)
	}
	if fetches.Load() < 2 {
		t.Fatal("no fetch after MaxAge")
	}
	if _, err := v.Verify(ctx, fresh.Token(identity.Identity{})); err != nil {
		t.Fatalf("the published key: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := v.Verify(ctx, leaked.Token(identity.Identity{})); err == nil {
		t.Fatal("a withdrawn key is still trusted after its grace")
	}
	if _, err := v.Verify(ctx, fresh.Token(identity.Identity{})); err != nil {
		t.Fatalf("the published key afterwards: %v", err)
	}

	// While auth can't be reached, the keys it last published stay in use.
	srv.Close()
	time.Sleep(60 * time.Millisecond)
	if _, err := v.Verify(ctx, fresh.Token(identity.Identity{})); err != nil {
		t.Fatalf("auth unreachable: the last published key must still work: %v", err)
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

	// Each token is signed for the request it is sent with, as auth does; "bad" is a
	// tampered one, and "elsewhere" one signed for another request (method and path).
	user := uuid.New()
	ids := map[string]identity.Identity{
		"fresh":     {UserID: user},
		"publisher": {UserID: user, Grants: []string{"catalog.publish", "channel.delete"}},
		"stale":     {UserID: user, Grants: []string{"channel.delete"}, AuthTime: time.Now().Add(-time.Hour)},
		"withOTP":   {UserID: user, Grants: []string{"channel.delete"}, AMR: []string{"otp", "pwd"}},
	}
	const fresh, publisher, stale, withOTP, bad = "fresh", "publisher", "stale", "withOTP", "bad"

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
		{"token for another path", "GET", "/me", "elsewhere:GET /videos", 401, "unauthorized", "", ""},
		{"token for another method", "POST", "/videos/v1/publish", "elsewhere:GET /videos/v1/publish", 401, "unauthorized", "", ""},
		{"anonymous route, token for another request: anonymous", "GET", "/videos", "elsewhere:GET /me", 200, "", "anonymous", ""},
	} {
		req := httptest.NewRequest(c.method, c.path, nil)
		switch method, path, other := strings.Cut(strings.TrimPrefix(c.token, "elsewhere:"), " "); {
		case c.token == "":
		case c.token == bad:
			iss.Authorize(req, ids[fresh])
			tok := req.Header.Get(identity.Header)
			req.Header.Set(identity.Header, tok[:20]+flip(tok[20])+tok[21:])
		case other:
			req.Header.Set(identity.Header, iss.Token(identity.Identity{UserID: user, Grants: ids[publisher].Grants, Method: method, Path: path}))
		default:
			iss.Authorize(req, ids[c.token])
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

func TestDepartmentGrants(t *testing.T) {
	const publish = "platform.content.titles.publish"
	film := identity.Identity{Grants: []string{publish + "@film", publish + "@music", "staff"}}
	everywhere := identity.Identity{Grants: []string{publish, "staff"}}
	nobody := identity.Identity{Grants: []string{"staff", publish + "x@film"}}

	for _, c := range []struct {
		name string
		id   identity.Identity
		dept string
		want bool
	}{
		{"its department", film, "film", true},
		{"another of its departments", film, "music", true},
		{"a department it doesn't hold", film, "comedy", false},
		{"no department named", film, "", false},
		{"whole account covers every department", everywhere, "comedy", true},
		{"a look-alike grant isn't it", nobody, "film", false},
	} {
		if got := c.id.HasIn(publish, c.dept); got != c.want {
			t.Errorf("%s: HasIn = %v", c.name, got)
		}
	}
	if film.Has(publish) {
		t.Error("a department grant isn't the whole-account grant")
	}
	if all, depts := film.Departments(publish); all || strings.Join(depts, ",") != "film,music" {
		t.Errorf("Departments = %v %v", all, depts)
	}
	if all, _ := everywhere.Departments(publish); !all {
		t.Error("whole account: everywhere")
	}

	iss := identitytest.New()
	rt := identity.NewRouter(iss.Verifier(), quiet())
	rt.Handle("POST /titles/{id}/publish", identity.GrantInAny(publish), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The handler knows the title's department; here every title is a Comedy one.
		if !identity.Must(r.Context()).HasIn(publish, "comedy") {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	for _, c := range []struct {
		name   string
		grants []string
		status int
	}{
		{"none of it: refused by the policy", []string{"staff"}, 403},
		{"film only: let in, refused by the handler", []string{publish + "@film"}, 403},
		{"comedy: allowed", []string{publish + "@comedy"}, 200},
		{"whole account: allowed", []string{publish}, 200},
	} {
		req := httptest.NewRequest("POST", "/titles/t1/publish", nil)
		iss.Authorize(req, identity.Identity{UserID: uuid.New(), Grants: c.grants})
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, req)
		if rec.Code != c.status {
			t.Errorf("%s: %d", c.name, rec.Code)
		}
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
