// Package events reads another service's events from a NATS JetStream stream and hands each
// one to a handler inside a database transaction of the reading service, exactly once.
//
//	c, err := events.New(nc, pool, events.Config{
//		Stream:   "AUTH",
//		Consumer: "profile",
//		Handlers: map[string]events.Handler{
//			"auth.user.created": profiles.Create,
//			"auth.user.erased":  profiles.Erase,
//		},
//	})
//	go c.Run(ctx)
//
// The rules every service gets from it:
//
//   - Exactly once, as far as the service can tell. The event's ID (header Hayitone-Event-Id)
//     is recorded in events_processed in the same transaction as the handler's changes; a
//     redelivered event finds it there and is acknowledged without running the handler again.
//   - Acknowledged only after the commit. A crash between the two redelivers the event, and
//     the record above skips it.
//   - In order. One event at a time per consumer (MaxAckPending 1), in the stream's order, so
//     auth.user.created is handled before that user's auth.user.erased. A failing event is
//     retried with growing pauses (1 s doubling to 1 min) while later events wait.
//   - Never dropped. After MaxAttempts failures, or at once for an error marked Permanent (a
//     payload that can never be read), the event is parked in events_parked with its error,
//     logged at ERROR and counted (hayitone_events_handled_total{result="parked"}); later
//     events go on. Fix the cause, then ReplayParked. Handlers must therefore cope with a later
//     event whose earlier one was parked (an update for a profile that doesn't exist yet).
//
// The tables are in schema.sql: copy it into one of the service's migrations.
package events

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
)

// Schema is schema.sql: the tables a consuming service needs.
//
//go:embed schema.sql
var Schema string

// Headers auth's relay sets on every event (and every Hayitone producer should).
const (
	HeaderEventID   = "Hayitone-Event-Id"
	HeaderKey       = "Hayitone-Key"
	HeaderCreatedAt = "Hayitone-Created-At"
	HeaderRequestID = "Hayitone-Request-Id"
)

// Event is one message from the stream.
type Event struct {
	ID        string // Hayitone-Event-Id; "<stream>:<sequence>" if a producer left it out
	Topic     string // the subject, e.g. "auth.user.created"
	Key       string // Hayitone-Key: what the event is about (a user ID, ...)
	CreatedAt time.Time
	RequestID string // the request that caused it, for logs
	Data      []byte // the JSON payload
	Attempt   int    // 1 on the first delivery
}

// Handler applies one event. Do everything through tx: it commits only if the handler returns
// nil, together with the record that the event was handled. Return Permanent(err) for an event
// that can never succeed (unreadable payload) to park it at once; any other error is retried.
type Handler func(ctx context.Context, tx pgx.Tx, ev Event) error

type permanent struct{ err error }

func (p permanent) Error() string { return p.err.Error() }
func (p permanent) Unwrap() error { return p.err }

// Permanent marks err as one no retry can fix: the event is parked at once.
func Permanent(err error) error { return permanent{err} }

// IsPermanent reports whether err (or one it wraps) was marked Permanent.
func IsPermanent(err error) bool {
	var p permanent
	return errors.As(err, &p)
}

// Config of a Consumer.
type Config struct {
	Stream   string             // the producer's stream, e.g. "AUTH"
	Consumer string             // durable name: the reading service, e.g. "profile"
	Handlers map[string]Handler // by topic; only these subjects are delivered
	// MaxAttempts before an event is parked. Default 8 (about 2 minutes of retries).
	MaxAttempts int
	// Retention of events_processed rows. Default 14 days (twice the stream's 7).
	Retention time.Duration
	Logger    *slog.Logger
	// Registerer for the metrics (hayitone_events_handled_total). Nil: not registered.
	Registerer prometheus.Registerer
}

// Consumer reads one durable JetStream consumer. Create it with New, then Run it.
type Consumer struct {
	cfg     Config
	nc      *nats.Conn
	js      jetstream.JetStream
	pool    *pgxpool.Pool
	log     *slog.Logger
	handled *prometheus.CounterVec
	ready   atomic.Bool
	now     func() time.Time
	pause   func(attempt int) time.Duration
}

// New checks the configuration. Nothing is created on the server until Run. nc may be nil
// for a command that only replays or counts parked events (Run then fails).
func New(nc *nats.Conn, pool *pgxpool.Pool, cfg Config) (*Consumer, error) {
	if cfg.Stream == "" || cfg.Consumer == "" || len(cfg.Handlers) == 0 {
		return nil, errors.New("events: Stream, Consumer and Handlers are required")
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 8
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 14 * 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	var js jetstream.JetStream
	if nc != nil { // nil: only for ReplayParked and ParkedCount (a command, no stream)
		var err error
		if js, err = jetstream.New(nc); err != nil {
			return nil, err
		}
	}
	c := &Consumer{
		cfg: cfg, nc: nc, js: js, pool: pool, now: time.Now, pause: Pause,
		log: cfg.Logger.With("consumer", cfg.Consumer, "stream", cfg.Stream),
		handled: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hayitone_events_handled_total",
			Help: "Events read from a stream, by result: ok, duplicate (already handled), retry, parked.",
		}, []string{"consumer", "topic", "result"}),
	}
	if cfg.Registerer != nil {
		if err := cfg.Registerer.Register(c.handled); err != nil {
			// A second consumer in the same service (another stream) shares the counter:
			// its topics are its own labels.
			are, ok := err.(prometheus.AlreadyRegisteredError)
			if !ok {
				return nil, err
			}
			existing, ok := are.ExistingCollector.(*prometheus.CounterVec)
			if !ok {
				return nil, err
			}
			c.handled = existing
		}
	}
	return c, nil
}

// Pause before retry number attempt+1: 1 s, 2 s, 4 s ... at most 1 minute.
func Pause(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 7 {
		return time.Minute
	}
	return min(time.Second<<(attempt-1), time.Minute)
}

// Ready reports whether the consumer is set up on the server and connected: for /readyz.
func (c *Consumer) Ready() bool { return c.nc != nil && c.ready.Load() && c.nc.IsConnected() }

// Topics the consumer reads, sorted.
func (c *Consumer) Topics() []string {
	topics := make([]string, 0, len(c.cfg.Handlers))
	for t := range c.cfg.Handlers {
		topics = append(topics, t)
	}
	slices.Sort(topics)
	return topics
}

// Run creates (or updates) the durable consumer and handles events until ctx ends. It keeps
// going through NATS and database outages, waiting and trying again; it returns only when ctx
// is done.
func (c *Consumer) Run(ctx context.Context) error {
	if c.js == nil {
		return errors.New("events: Run needs a NATS connection")
	}
	cleanup := time.NewTicker(time.Hour)
	defer cleanup.Stop()
	c.cleanup(ctx)
	wait := time.Second
	for ctx.Err() == nil {
		cons, err := c.js.CreateOrUpdateConsumer(ctx, c.cfg.Stream, jetstream.ConsumerConfig{
			Durable:        c.cfg.Consumer,
			FilterSubjects: c.Topics(),
			DeliverPolicy:  jetstream.DeliverAllPolicy,
			AckPolicy:      jetstream.AckExplicitPolicy,
			AckWait:        30 * time.Second,
			MaxAckPending:  1,  // in order, one at a time
			MaxDeliver:     -1, // we decide when to give up (park), not the server
		})
		if err != nil {
			c.ready.Store(false)
			if ctx.Err() == nil {
				c.log.Warn("events: can't set up the consumer; trying again", "err", err, "in", wait)
			}
			sleep(ctx, wait)
			wait = min(2*wait, 30*time.Second)
			continue
		}
		wait = time.Second
		c.ready.Store(true)
		for ctx.Err() == nil {
			select {
			case <-cleanup.C:
				c.cleanup(ctx)
			default:
			}
			batch, err := cons.Fetch(1, jetstream.FetchMaxWait(2*time.Second))
			if err != nil {
				if errors.Is(err, jetstream.ErrConsumerNotFound) || errors.Is(err, jetstream.ErrStreamNotFound) {
					break // set it up again
				}
				sleep(ctx, time.Second)
				continue
			}
			for msg := range batch.Messages() {
				c.handle(ctx, msg)
			}
			if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) && ctx.Err() == nil {
				c.log.Debug("events: fetch", "err", err)
			}
		}
		c.ready.Store(false)
	}
	return ctx.Err()
}

var errDuplicate = errors.New("already handled")

func (c *Consumer) handle(ctx context.Context, msg jetstream.Msg) {
	ev := c.event(msg)
	log := c.log.With("topic", ev.Topic, "event_id", ev.ID, "key", ev.Key, "attempt", ev.Attempt, "request_id", ev.RequestID)
	h := c.cfg.Handlers[ev.Topic]
	if h == nil { // filtered out by the server; acknowledge anything else
		_ = msg.DoubleAck(ctx)
		return
	}
	err := c.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO events_processed (consumer, event_id, topic) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			c.cfg.Consumer, ev.ID, ev.Topic)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errDuplicate
		}
		return h(ctx, tx, ev)
	})
	switch {
	case err == nil:
		c.count(ev.Topic, "ok")
		c.ack(ctx, msg, log)
	case errors.Is(err, errDuplicate):
		c.count(ev.Topic, "duplicate")
		c.ack(ctx, msg, log)
	case ctx.Err() != nil:
		// shutting down: no answer, the server redelivers after AckWait
	default:
		if IsPermanent(err) || ev.Attempt >= c.cfg.MaxAttempts {
			if perr := c.park(ctx, ev, err); perr != nil {
				log.Warn("events: can't park; trying again", "err", perr, "handler_err", err)
				_ = msg.NakWithDelay(c.pause(ev.Attempt))
				return
			}
			c.count(ev.Topic, "parked")
			log.Error("events: parked: fix the cause, then replay it", "err", err)
			c.ack(ctx, msg, log)
			return
		}
		c.count(ev.Topic, "retry")
		log.Warn("events: failed; trying again", "err", err, "in", c.pause(ev.Attempt))
		_ = msg.NakWithDelay(c.pause(ev.Attempt))
	}
}

func (c *Consumer) ack(ctx context.Context, msg jetstream.Msg, log *slog.Logger) {
	// If the acknowledgement is lost the event comes again, and events_processed skips it.
	if err := msg.DoubleAck(ctx); err != nil && ctx.Err() == nil {
		log.Warn("events: acknowledgement not confirmed (it will be skipped if it comes again)", "err", err)
	}
}

func (c *Consumer) event(msg jetstream.Msg) Event {
	h := msg.Headers()
	ev := Event{
		ID: h.Get(HeaderEventID), Topic: msg.Subject(), Key: h.Get(HeaderKey),
		RequestID: h.Get(HeaderRequestID), Data: msg.Data(), Attempt: 1,
	}
	if t, err := time.Parse(time.RFC3339Nano, h.Get(HeaderCreatedAt)); err == nil {
		ev.CreatedAt = t
	}
	if meta, err := msg.Metadata(); err == nil {
		ev.Attempt = int(meta.NumDelivered)
		if ev.ID == "" {
			ev.ID = meta.Stream + ":" + strconv.FormatUint(meta.Sequence.Stream, 10)
		}
	}
	return ev
}

func (c *Consumer) park(ctx context.Context, ev Event, cause error) error {
	return c.inTx(ctx, func(tx pgx.Tx) error {
		var created *time.Time
		if !ev.CreatedAt.IsZero() {
			created = &ev.CreatedAt
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO events_parked (consumer, event_id, topic, key, created_at, request_id, data, error, attempts)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (consumer, event_id) DO UPDATE SET error = EXCLUDED.error, attempts = EXCLUDED.attempts, parked_at = now()`,
			c.cfg.Consumer, ev.ID, ev.Topic, ev.Key, created, ev.RequestID, ev.Data, cause.Error(), ev.Attempt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO events_processed (consumer, event_id, topic) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			c.cfg.Consumer, ev.ID, ev.Topic)
		return err
	})
}

// ErrNotParked: ReplayParked found no such parked event.
var ErrNotParked = errors.New("events: no such parked event")

// ReplayParked runs a parked event's handler again (after the cause was fixed). On success the
// event leaves events_parked in the same transaction; on failure it stays, with the new error.
func (c *Consumer) ReplayParked(ctx context.Context, eventID string) error {
	var ev Event
	var created *time.Time
	err := c.pool.QueryRow(ctx, `
		SELECT topic, key, created_at, request_id, data, attempts FROM events_parked
		WHERE consumer = $1 AND event_id = $2`, c.cfg.Consumer, eventID).
		Scan(&ev.Topic, &ev.Key, &created, &ev.RequestID, &ev.Data, &ev.Attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotParked
	} else if err != nil {
		return err
	}
	ev.ID = eventID
	if created != nil {
		ev.CreatedAt = *created
	}
	ev.Attempt++
	h := c.cfg.Handlers[ev.Topic]
	if h == nil {
		return fmt.Errorf("events: no handler for %s", ev.Topic)
	}
	err = c.inTx(ctx, func(tx pgx.Tx) error {
		if err := h(ctx, tx, ev); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM events_parked WHERE consumer = $1 AND event_id = $2`, c.cfg.Consumer, eventID)
		return err
	})
	if err != nil {
		_, _ = c.pool.Exec(ctx, `UPDATE events_parked SET error = $3, attempts = $4 WHERE consumer = $1 AND event_id = $2`,
			c.cfg.Consumer, eventID, err.Error(), ev.Attempt)
		return err
	}
	c.count(ev.Topic, "replayed")
	return nil
}

// ParkedCount is how many events wait in events_parked: a gauge worth alerting on (> 0).
func (c *Consumer) ParkedCount(ctx context.Context) (int, error) {
	var n int
	err := c.pool.QueryRow(ctx, `SELECT count(*) FROM events_parked WHERE consumer = $1`, c.cfg.Consumer).Scan(&n)
	return n, err
}

func (c *Consumer) cleanup(ctx context.Context) {
	cut := c.now().Add(-c.cfg.Retention)
	for ctx.Err() == nil {
		tag, err := c.pool.Exec(ctx, `
			DELETE FROM events_processed WHERE ctid IN (
				SELECT ctid FROM events_processed WHERE consumer = $1 AND processed_at < $2 LIMIT 1000)`,
			c.cfg.Consumer, cut)
		if err != nil {
			c.log.Warn("events: cleaning up events_processed", "err", err)
			return
		}
		if tag.RowsAffected() < 1000 {
			return
		}
	}
}

func (c *Consumer) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (c *Consumer) count(topic, result string) {
	c.handled.WithLabelValues(c.cfg.Consumer, topic, result).Inc()
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
