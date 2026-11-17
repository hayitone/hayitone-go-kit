package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/hayitone/hayitone-go-kit/events"
	"github.com/hayitone/hayitone-go-kit/postgres"
)

// The tests need Postgres, and the last one a JetStream server (no auth):
//
//	KIT_TEST_NATS_URL=nats://127.0.0.1:4222 KIT_TEST_DATABASE_URL=postgres://... go test ./outbox/
//
// make integration starts both. Each test gets its own database schema (and stream).

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func newPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dbURL := os.Getenv("KIT_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("KIT_TEST_DATABASE_URL not set (make integration)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	schema := "outbox_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	admin, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, Schema); err != nil {
		t.Fatal(err)
	}
	return pool, ctx
}

// fake is a broker: it records what it got, refuses topics in refuse, and is unreachable
// while down.
type fake struct {
	mu     sync.Mutex
	got    []Event
	refuse map[string]bool
	down   bool
}

func (f *fake) Publish(_ context.Context, e Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case f.down:
		return ErrUnavailable
	case f.refuse[e.Topic]:
		return errors.New("refused")
	}
	f.got = append(f.got, e)
	return nil
}

func (f *fake) topics() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.got {
		out = append(out, e.Topic+"/"+e.Key)
	}
	return out
}

func write(t *testing.T, ctx context.Context, pool *pgxpool.Pool, topic, key string, payload any) {
	t.Helper()
	if err := postgres.InTx(ctx, pool, func(tx pgx.Tx) error { return Write(ctx, tx, topic, key, payload) }); err != nil {
		t.Fatal(err)
	}
}

func relay(pool *pgxpool.Pool, pub Publisher, cfg Config) *Relay {
	cfg.LockName = "outbox-test/" + uuid.NewString()
	return NewRelay(pool, pub, quiet, cfg)
}

func TestInOrderNeverRolledBack(t *testing.T) {
	pool, ctx := newPool(t)
	write(t, ctx, pool, "svc.thing.made", "a", map[string]string{"n": "1"})
	_ = postgres.InTx(ctx, pool, func(tx pgx.Tx) error {
		_ = Write(ctx, tx, "svc.thing.ghost", "a", nil)
		return errors.New("the change failed")
	})
	write(t, ctx, pool, "svc.thing.changed", "a", map[string]string{"n": "2"})
	write(t, ctx, pool, "svc.other.made", "b", nil)

	f := &fake{}
	r := relay(pool, f, Config{})
	if _, err := r.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.topics(), " "); got != "svc.thing.made/a svc.thing.changed/a svc.other.made/b" {
		t.Fatalf("published: %s", got)
	}
	if n, _ := r.batch(ctx); n != 0 {
		t.Fatalf("published twice: %d", n)
	}
	if testutil.ToFloat64(r.published.WithLabelValues("svc.thing.made")) != 1 {
		t.Fatal("not counted")
	}
}

func TestRefusedWaitsWithItsKey(t *testing.T) {
	pool, ctx := newPool(t)
	write(t, ctx, pool, "svc.bad", "a", nil)
	write(t, ctx, pool, "svc.after_bad", "a", nil)
	write(t, ctx, pool, "svc.other", "b", nil)
	f := &fake{refuse: map[string]bool{"svc.bad": true}}
	r := relay(pool, f, Config{})
	if _, err := r.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.topics(), " "); got != "svc.other/b" {
		t.Fatalf("a's later event must wait: %s", got)
	}
	var attempts int
	var lastErr string
	if err := pool.QueryRow(ctx, `SELECT attempts, last_error FROM outbox_events WHERE topic = 'svc.bad'`).Scan(&attempts, &lastErr); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || lastErr != "refused" {
		t.Fatalf("%d %q", attempts, lastErr)
	}
	// Due again (backoff over) and accepted: both of a's go, in order.
	f.refuse = nil
	if _, err := pool.Exec(ctx, `UPDATE outbox_events SET next_attempt_at = now()`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.batch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.topics(), " "); got != "svc.other/b svc.bad/a svc.after_bad/a" {
		t.Fatalf("after: %s", got)
	}
}

func TestBrokerDownCostsNothing(t *testing.T) {
	pool, ctx := newPool(t)
	write(t, ctx, pool, "svc.thing", "a", nil)
	f := &fake{down: true}
	r := relay(pool, f, Config{})
	if _, err := r.batch(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want unavailable: %v", err)
	}
	var attempts int
	_ = pool.QueryRow(ctx, `SELECT attempts FROM outbox_events`).Scan(&attempts)
	if attempts != 0 {
		t.Fatalf("charged an attempt: %d", attempts)
	}
}

func TestScrubAndBacklog(t *testing.T) {
	pool, ctx := newPool(t)
	write(t, ctx, pool, "svc.code", "a", map[string]string{"code": "123456", "to": "x"})
	r := relay(pool, &fake{}, Config{Scrub: map[string][]string{"svc.code": {"code"}}})
	reg := prometheus.NewRegistry()
	reg.MustRegister(r.Collectors()...)
	if n, err := testutil.GatherAndCount(reg, "hayitone_outbox_pending"); err != nil || n != 1 {
		t.Fatalf("backlog metric: %d %v", n, err)
	}
	if _, err := r.batch(ctx); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	_ = pool.QueryRow(ctx, `SELECT payload FROM outbox_events`).Scan(&payload)
	var p map[string]string
	_ = json.Unmarshal(payload, &p)
	if _, ok := p["code"]; ok || p["to"] != "x" {
		t.Fatalf("not scrubbed: %s", payload)
	}
	r.cfg.Retain = -time.Second // everything published is old enough
	r.cleanup(ctx)
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events`).Scan(&n)
	if n != 0 {
		t.Fatalf("not cleaned: %d", n)
	}
}

func TestOneActiveRelay(t *testing.T) {
	pool, ctx := newPool(t)
	a := relay(pool, &fake{}, Config{LockRetry: 50 * time.Millisecond})
	b := NewRelay(pool, &fake{}, quiet, a.cfg) // the same lock
	ctxA, stopA := context.WithCancel(ctx)
	doneA := make(chan struct{})
	go func() { _ = a.Run(ctxA); close(doneA) }()
	waitFor(t, a.Active)
	ctxB, stopB := context.WithCancel(ctx)
	defer stopB()
	go func() { _ = b.Run(ctxB) }()
	time.Sleep(200 * time.Millisecond)
	if b.Active() {
		t.Fatal("two active relays")
	}
	stopA()
	<-doneA
	waitFor(t, b.Active) // the standby takes over
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 100 {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out")
}

// Through a real JetStream stream to package events: the event arrives once, with its ID,
// key and request ID, even when the relay sends it twice.
func TestThroughJetStream(t *testing.T) {
	pool, ctx := newPool(t)
	natsURL := os.Getenv("KIT_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("KIT_TEST_NATS_URL not set (make integration)")
	}
	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	id := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	st := Stream{Name: "OUTBOXTEST_" + strings.ToUpper(id), Subject: "outboxtest" + id + ".>"}
	pub, err := NewNATS(nc, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.EnsureStream(ctx, quiet); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pub.js.DeleteStream(context.Background(), st.Name) })

	topic := "outboxtest" + id + ".thing.made"
	write(t, ctx, pool, topic, "k1", map[string]string{"n": "1"})
	r := relay(pool, pub, Config{})
	if _, err := r.batch(ctx); err != nil {
		t.Fatal(err)
	}
	// A commit that failed after the publish: the event goes out again; the stream drops it.
	if _, err := pool.Exec(ctx, `UPDATE outbox_events SET published_at = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.batch(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := pub.js.Stream(ctx, st.Name)
	if err != nil {
		t.Fatal(err)
	}
	if si, _ := info.Info(ctx); si.State.Msgs != 1 {
		t.Fatalf("the stream kept %d copies", si.State.Msgs)
	}

	if _, err := pool.Exec(ctx, events.Schema); err != nil {
		t.Fatal(err)
	}
	got := make(chan events.Event, 2)
	c, err := events.New(nc, pool, events.Config{Stream: st.Name, Consumer: "test", Logger: quiet,
		Handlers: map[string]events.Handler{topic: func(_ context.Context, _ pgx.Tx, ev events.Event) error { got <- ev; return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	cctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = c.Run(cctx) }()
	select {
	case ev := <-got:
		var outboxID uuid.UUID
		_ = pool.QueryRow(ctx, `SELECT id FROM outbox_events`).Scan(&outboxID)
		if ev.ID != outboxID.String() || ev.Key != "k1" || string(ev.Data) != `{"n": "1"}` {
			t.Fatalf("%+v", ev)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("never arrived")
	}
}
