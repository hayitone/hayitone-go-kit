package events

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
)

// The tests need a JetStream server (no auth) and Postgres:
//
//	KIT_TEST_NATS_URL=nats://127.0.0.1:4222 KIT_TEST_DATABASE_URL=postgres://... go test ./events/
//
// make integration starts both. Each test gets its own stream and database schema.

type env struct {
	ctx     context.Context
	nc      *nats.Conn
	js      jetstream.JetStream
	pool    *pgxpool.Pool
	stream  string
	subject string // prefix: <subject>.created, <subject>.erased
}

func newEnv(t *testing.T) *env {
	t.Helper()
	natsURL, dbURL := os.Getenv("KIT_TEST_NATS_URL"), os.Getenv("KIT_TEST_DATABASE_URL")
	if natsURL == "" || dbURL == "" {
		t.Skip("KIT_TEST_NATS_URL and KIT_TEST_DATABASE_URL not set (make integration)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	e := &env{ctx: ctx, nc: nc, js: js, stream: "KITTEST_" + strings.ToUpper(id), subject: "kittest" + id}
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: e.stream, Subjects: []string{e.subject + ".>"}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(context.Background(), e.stream) })

	// A schema of its own, with the package's tables and the test's "seen" table.
	schema := "events_" + id
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
	if e.pool, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.pool.Close)
	if _, err := e.pool.Exec(ctx, Schema+`; CREATE TABLE seen (n serial, topic text, key text, attempt int)`); err != nil {
		t.Fatal(err)
	}
	return e
}

// publish sends an event as auth's relay does (headers, Nats-Msg-Id = event ID). An empty
// id sends neither, like a producer that forgot.
func (e *env) publish(t *testing.T, topic, id, key string) {
	t.Helper()
	msg := nats.NewMsg(e.subject + "." + topic)
	msg.Data = []byte(`{"user_id":"` + key + `"}`)
	if id != "" {
		msg.Header.Set(HeaderEventID, id)
	}
	msg.Header.Set(HeaderKey, key)
	msg.Header.Set(HeaderCreatedAt, time.Now().UTC().Format(time.RFC3339Nano))
	msg.Header.Set(HeaderRequestID, "req-1")
	if _, err := e.js.PublishMsg(e.ctx, msg); err != nil {
		t.Fatal(err)
	}
}

// record is a handler that writes what it got to "seen".
func record(ctx context.Context, tx pgx.Tx, ev Event) error {
	_, err := tx.Exec(ctx, `INSERT INTO seen (topic, key, attempt) VALUES ($1, $2, $3)`, ev.Topic, ev.Key, ev.Attempt)
	return err
}

func (e *env) consumer(t *testing.T, handlers map[string]Handler) (*Consumer, *prometheus.Registry) {
	t.Helper()
	full := map[string]Handler{}
	for topic, h := range handlers {
		full[e.subject+"."+topic] = h
	}
	reg := prometheus.NewRegistry()
	c, err := New(e.nc, e.pool, Config{
		Stream: e.stream, Consumer: "test", Handlers: full, MaxAttempts: 3,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Registerer: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.pause = func(int) time.Duration { return 20 * time.Millisecond }
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return c, reg
}

func (e *env) seen(t *testing.T) []string {
	t.Helper()
	rows, err := e.pool.Query(e.ctx, `SELECT topic, key FROM seen ORDER BY n`)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		var topic, key string
		if err := rows.Scan(&topic, &key); err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.TrimPrefix(topic, e.subject+".")+":"+key)
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func handled(reg *prometheus.Registry, topic, result string) float64 {
	n := 0.0
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if strings.HasSuffix(labels["topic"], "."+topic) && labels["result"] == result {
				n += m.GetCounter().GetValue()
			}
		}
	}
	return n
}

func TestInOrderExactlyOnce(t *testing.T) {
	e := newEnv(t)
	e.publish(t, "created", "e1", "a")
	e.publish(t, "created", "e2", "b")
	e.publish(t, "erased", "e3", "a")
	e.publish(t, "created", "e1", "a") // the same event again (a redelivery from the producer)
	e.publish(t, "ignored", "e4", "a") // a topic nobody handles: never delivered
	c, reg := e.consumer(t, map[string]Handler{"created": record, "erased": record})
	waitFor(t, "the events", func() bool { return len(e.seen(t)) >= 3 && handled(reg, "created", "duplicate") == 1 })
	if got := strings.Join(e.seen(t), " "); got != "created:a created:b erased:a" {
		t.Fatalf("handled %q", got)
	}
	if !c.Ready() {
		t.Error("not ready")
	}
	var n int
	_ = e.pool.QueryRow(e.ctx, `SELECT count(*) FROM events_processed WHERE consumer = 'test'`).Scan(&n)
	if n != 3 {
		t.Errorf("%d events recorded as processed, want 3", n)
	}
	if got := handled(reg, "created", "ok"); got != 2 {
		t.Errorf("ok %v", got)
	}
}

// A failing handler's changes are rolled back and the event comes again, until it works.
func TestRetriedUntilItWorks(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	attempts := 0
	flaky := func(ctx context.Context, tx pgx.Tx, ev Event) error {
		if err := record(ctx, tx, ev); err != nil { // written, then rolled back on failure
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			return errors.New("database hiccup")
		}
		return nil
	}
	e.publish(t, "created", "e1", "a")
	e.publish(t, "created", "e2", "b") // waits behind e1: in order
	_, reg := e.consumer(t, map[string]Handler{"created": func(ctx context.Context, tx pgx.Tx, ev Event) error {
		if ev.Key == "a" {
			return flaky(ctx, tx, ev)
		}
		return record(ctx, tx, ev)
	}})
	waitFor(t, "both", func() bool { return len(e.seen(t)) == 2 })
	if got := strings.Join(e.seen(t), " "); got != "created:a created:b" {
		t.Fatalf("handled %q (failed attempts must leave nothing)", got)
	}
	var attempt int
	_ = e.pool.QueryRow(e.ctx, `SELECT attempt FROM seen WHERE key = 'a'`).Scan(&attempt)
	if attempt != 3 || handled(reg, "created", "retry") != 2 {
		t.Errorf("attempt %d, retries %v", attempt, handled(reg, "created", "retry"))
	}
}

// An event that can't be handled is parked, never dropped; the next ones go on; once the
// cause is fixed it is replayed.
func TestParkedThenReplayed(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	fixed := false
	h := func(ctx context.Context, tx pgx.Tx, ev Event) error {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case ev.Key == "bad" && !fixed:
			return Permanent(errors.New("unreadable payload"))
		case ev.Key == "slow" && !fixed:
			return errors.New("still failing")
		}
		return record(ctx, tx, ev)
	}
	e.publish(t, "created", "e1", "bad")  // parked at once
	e.publish(t, "created", "e2", "slow") // parked after MaxAttempts (3)
	e.publish(t, "created", "e3", "good")
	c, reg := e.consumer(t, map[string]Handler{"created": h})
	waitFor(t, "the good one", func() bool { return len(e.seen(t)) == 1 })
	if n, _ := c.ParkedCount(e.ctx); n != 2 {
		t.Fatalf("%d parked, want 2", n)
	}
	var errText string
	var attempts int
	_ = e.pool.QueryRow(e.ctx, `SELECT error, attempts FROM events_parked WHERE event_id = 'e1'`).Scan(&errText, &attempts)
	if errText != "unreadable payload" || attempts != 1 {
		t.Errorf("e1 parked with %q after %d attempts", errText, attempts)
	}
	_ = e.pool.QueryRow(e.ctx, `SELECT attempts FROM events_parked WHERE event_id = 'e2'`).Scan(&attempts)
	if attempts != 3 || handled(reg, "created", "parked") != 2 {
		t.Errorf("e2 parked after %d attempts; parked %v", attempts, handled(reg, "created", "parked"))
	}

	// Still broken: stays parked, with the new error.
	if err := c.ReplayParked(e.ctx, "e2"); err == nil {
		t.Fatal("replay of a still-failing event succeeded")
	}
	mu.Lock()
	fixed = true
	mu.Unlock()
	for _, id := range []string{"e1", "e2"} {
		if err := c.ReplayParked(e.ctx, id); err != nil {
			t.Fatalf("replay %s: %v", id, err)
		}
	}
	if err := c.ReplayParked(e.ctx, "e1"); !errors.Is(err, ErrNotParked) {
		t.Errorf("replaying twice: %v", err)
	}
	if n, _ := c.ParkedCount(e.ctx); n != 0 {
		t.Errorf("%d still parked", n)
	}
	if got := strings.Join(e.seen(t), " "); got != "created:good created:bad created:slow" {
		t.Errorf("handled %q", got)
	}
}

// A producer that leaves out the event ID still gets exactly-once by stream sequence.
func TestNoEventID(t *testing.T) {
	e := newEnv(t)
	e.publish(t, "created", "", "a")
	_, _ = e.consumer(t, map[string]Handler{"created": record})
	waitFor(t, "the event", func() bool { return len(e.seen(t)) == 1 })
	var id string
	_ = e.pool.QueryRow(e.ctx, `SELECT event_id FROM events_processed`).Scan(&id)
	if id != e.stream+":1" {
		t.Errorf("event id %q, want %s:1", id, e.stream)
	}
}

// Handled-event records go after Retention; a restart picks up where it stopped.
func TestCleanupAndRestart(t *testing.T) {
	e := newEnv(t)
	if _, err := e.pool.Exec(e.ctx, `INSERT INTO events_processed (consumer, event_id, topic, processed_at)
		SELECT 'test', 'old-' || g, 't', now() - interval '20 days' FROM generate_series(1, 1500) g`); err != nil {
		t.Fatal(err)
	}
	e.publish(t, "created", "e1", "a")
	c, _ := e.consumer(t, map[string]Handler{"created": record})
	waitFor(t, "the event", func() bool { return len(e.seen(t)) == 1 })
	var n int
	_ = e.pool.QueryRow(e.ctx, `SELECT count(*) FROM events_processed WHERE event_id LIKE 'old-%'`).Scan(&n)
	if n != 0 {
		t.Errorf("%d old records left", n)
	}
	_ = c

	// A second consumer with the same durable name continues after the first one's events.
	e.publish(t, "created", "e2", "b")
	_, _ = e.consumer(t, map[string]Handler{"created": record})
	waitFor(t, "the second event", func() bool { return len(e.seen(t)) == 2 })
	time.Sleep(200 * time.Millisecond)
	if got := strings.Join(e.seen(t), " "); got != "created:a created:b" {
		t.Errorf("handled %q", got)
	}
}

func TestConfig(t *testing.T) {
	if _, err := New(nil, nil, Config{Stream: "AUTH"}); err == nil {
		t.Error("accepted a config without consumer and handlers")
	}
	for attempt, want := range map[int]time.Duration{0: time.Second, 1: time.Second, 2: 2 * time.Second, 6: 32 * time.Second, 7: time.Minute, 100: time.Minute} {
		if got := Pause(attempt); got != want {
			t.Errorf("Pause(%d) = %v", attempt, got)
		}
	}
	c, err := New(nil, nil, Config{Stream: "AUTH", Consumer: "x", Handlers: map[string]Handler{"a.b": record}})
	if err != nil || c.Ready() || c.Run(context.Background()) == nil {
		t.Errorf("without NATS: %v, ready %v", err, c.Ready())
	}
	if !IsPermanent(fmt.Errorf("wrapped: %w", Permanent(errors.New("x")))) || IsPermanent(errors.New("x")) {
		t.Error("IsPermanent")
	}
	if !strings.Contains(Schema, "CREATE TABLE events_processed") {
		t.Error("Schema not embedded")
	}
}
