package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hayitone/hayitone-go-kit/postgres"
)

// Event is one outbox row on its way to the broker.
type Event struct {
	ID        uuid.UUID
	Topic     string // the NATS subject, e.g. catalog.title.published
	Key       string // events with the same key are delivered in order
	Payload   []byte // JSON
	Headers   map[string]string
	CreatedAt time.Time
	TTL       time.Duration // > 0: the stream drops the message after this long
}

// Publisher delivers one event. It returns ErrUnavailable (wrapped) when the broker can't be
// reached at all: the relay then waits instead of charging the event an attempt.
type Publisher interface {
	Publish(ctx context.Context, e Event) error
}

// ErrUnavailable means the broker is down or unreachable, not that this event is bad.
var ErrUnavailable = errors.New("broker unavailable")

// Config of a Relay. LockName is required; zero values elsewhere take the defaults.
type Config struct {
	// LockName names the advisory lock that keeps one relay active per service, e.g.
	// "hayitone-catalog/outbox-relay".
	LockName     string
	BatchSize    int           // events per transaction (50)
	PollEvery    time.Duration // how often to look for due events (250 ms)
	PublishWait  time.Duration // longest wait for one broker acknowledgement (5 s)
	MaxBackoff   time.Duration // retry delay cap for a failing event (2 min); retries never stop
	AlertAfter   time.Duration // an unpublished event older than this is logged as an error (5 min)
	Retain       time.Duration // published rows are deleted after this (7 days)
	CleanupEvery time.Duration // (1 h)
	LockRetry    time.Duration // how often a standby relay tries to take over (5 s)
	// Scrub lists, by topic, payload fields deleted from the stored row once the event is
	// delivered (a code that was only stored so it could travel).
	Scrub map[string][]string
	// ScrubDelay > 0 scrubs that long after delivery instead of at once. Dev only: local
	// tests read codes from the outbox.
	ScrubDelay time.Duration
	// TTL by topic: the stream keeps these messages only this long.
	TTL map[string]time.Duration
}

func (c Config) withDefaults() Config {
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 50
	}
	set(&c.PollEvery, 250*time.Millisecond)
	set(&c.PublishWait, 5*time.Second)
	set(&c.MaxBackoff, 2*time.Minute)
	set(&c.AlertAfter, 5*time.Minute)
	set(&c.Retain, 7*24*time.Hour)
	set(&c.CleanupEvery, time.Hour)
	set(&c.LockRetry, 5*time.Second)
	return c
}

// Relay publishes outbox events. Exactly one relay is active at a time (a Postgres advisory
// lock held on its own connection), so events keep their order; others wait as standbys and
// take over within LockRetry when the active one dies.
type Relay struct {
	pool   *pgxpool.Pool
	pub    Publisher
	log    *slog.Logger
	cfg    Config
	now    func() time.Time
	active atomic.Bool

	published, failures *prometheus.CounterVec
	unavailable         prometheus.Counter
}

// NewRelay makes a relay; register its Collectors on the process's registry.
func NewRelay(pool *pgxpool.Pool, pub Publisher, log *slog.Logger, cfg Config) *Relay {
	if cfg.LockName == "" {
		panic("outbox: Config.LockName is required")
	}
	return &Relay{pool: pool, pub: pub, log: log, cfg: cfg.withDefaults(), now: time.Now,
		published: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hayitone_outbox_published_total", Help: "Outbox events published, by topic.",
		}, []string{"topic"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hayitone_outbox_publish_failures_total", Help: "Outbox events the broker refused (retried), by topic.",
		}, []string{"topic"}),
		unavailable: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hayitone_outbox_broker_unavailable_total", Help: "Batches stopped because the broker couldn't be reached.",
		}),
	}
}

// Collectors are the relay's metrics: published and failed events, broker outages, whether
// this relay is the active one, and the backlog (pending events, the oldest one's age).
func (r *Relay) Collectors() []prometheus.Collector {
	active := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "hayitone_outbox_relay_active", Help: "1 if this relay holds the lock and publishes.",
	}, func() float64 {
		if r.Active() {
			return 1
		}
		return 0
	})
	return []prometheus.Collector{r.published, r.failures, r.unavailable, active, backlog{r}}
}

// Active reports whether this relay holds the lock.
func (r *Relay) Active() bool { return r.active.Load() }

// Run relays until ctx is cancelled. A batch in progress finishes first.
func (r *Relay) Run(ctx context.Context) error {
	standbyLogged := false
	for ctx.Err() == nil {
		lock, ok, err := r.takeLock(ctx)
		if err != nil {
			r.log.WarnContext(ctx, "relay lock: database unavailable", "err", err)
		}
		if !ok {
			if !standbyLogged && err == nil {
				r.log.InfoContext(ctx, "relay standing by: another relay is active")
				standbyLogged = true
			}
			_ = sleep(ctx, r.cfg.LockRetry)
			continue
		}
		standbyLogged = false
		r.log.InfoContext(ctx, "relay active")
		r.active.Store(true)
		err = r.lead(ctx, lock)
		r.active.Store(false)
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = lock.Close(closeCtx) // closing the connection releases the lock
		cancel()
		if err != nil && ctx.Err() == nil {
			r.log.ErrorContext(ctx, "relay lost its lock; trying again", "err", err)
		}
	}
	return nil
}

// takeLock opens a dedicated connection (a pooled one would carry the lock back into the
// pool) and tries the advisory lock on it.
func (r *Relay) takeLock(ctx context.Context) (*pgx.Conn, bool, error) {
	conn, err := pgx.ConnectConfig(ctx, r.pool.Config().ConnConfig.Copy())
	if err != nil {
		return nil, false, err
	}
	var ok bool
	err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, r.cfg.LockName).Scan(&ok)
	if err != nil || !ok {
		_ = conn.Close(context.Background())
		return nil, false, err
	}
	return conn, true, nil
}

// lead publishes while the lock is held. It returns when ctx ends (nil) or the lock
// connection fails (the lock may be gone, so another relay may already be publishing).
func (r *Relay) lead(ctx context.Context, lock *pgx.Conn) error {
	poll := time.NewTicker(r.cfg.PollEvery)
	defer poll.Stop()
	var (
		lastCleanup, lastAlertCheck, lastLockCheck time.Time
		brokerDown                                 time.Time // zero while the broker answers
		wait                                       time.Duration
	)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-poll.C:
		}
		now := r.now()
		if now.Sub(lastLockCheck) >= time.Second {
			pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := lock.Ping(pctx)
			cancel()
			if err != nil {
				return err
			}
			lastLockCheck = now
		}
		if wait > 0 { // the broker was down: don't hammer it
			if sleep(ctx, wait) != nil {
				return nil
			}
		}

		// Finish the batch even if shutdown starts meanwhile: the events were claimed.
		err := r.drain(context.WithoutCancel(ctx))
		switch {
		case errors.Is(err, ErrUnavailable):
			if brokerDown.IsZero() {
				brokerDown = now
				r.log.WarnContext(ctx, "broker unavailable; events wait in the outbox", "err", err)
			} else if now.Sub(brokerDown) > r.cfg.AlertAfter {
				r.log.ErrorContext(ctx, "broker unavailable for too long", "down_for", now.Sub(brokerDown).Round(time.Second).String(), "err", err)
			}
			wait = min(max(2*wait, time.Second), 30*time.Second)
		case err != nil:
			r.log.ErrorContext(ctx, "relay batch failed", "err", err)
			wait = time.Second
		default:
			if !brokerDown.IsZero() {
				r.log.InfoContext(ctx, "broker back", "was_down_for", now.Sub(brokerDown).Round(time.Second).String())
			}
			brokerDown, wait = time.Time{}, 0
		}

		if now.Sub(lastAlertCheck) >= 30*time.Second {
			r.checkBacklog(ctx)
			r.scrubLater(ctx)
			lastAlertCheck = now
		}
		if now.Sub(lastCleanup) >= r.cfg.CleanupEvery {
			r.cleanup(ctx)
			lastCleanup = now
		}
	}
}

// drain publishes due events, batch after batch, until none are left. Each batch is one
// transaction: claim (locked), publish, record, commit.
func (r *Relay) drain(ctx context.Context) error {
	for {
		n, err := r.batch(ctx)
		if err != nil || n < r.cfg.BatchSize {
			return err
		}
	}
}

// claimDue takes the next events to publish, oldest first, locked until the batch's
// transaction ends. An event waits while an earlier event with the same key is still
// unpublished and backing off, so events about one thing always go out in order.
const claimDue = `
SELECT e.id, e.topic, e.key, e.payload, e.headers, e.attempts, e.created_at
FROM outbox_events e
WHERE e.published_at IS NULL
  AND e.next_attempt_at <= now()
  AND NOT EXISTS (
      SELECT 1 FROM outbox_events earlier
      WHERE earlier.key = e.key AND earlier.published_at IS NULL
        AND (earlier.created_at, earlier.id) < (e.created_at, e.id)
        AND earlier.next_attempt_at > now()
  )
ORDER BY e.created_at, e.id
LIMIT $1
FOR UPDATE SKIP LOCKED`

type row struct {
	id        uuid.UUID
	topic     string
	key       string
	payload   []byte
	headers   []byte
	attempts  int32
	createdAt time.Time
}

func (r *Relay) batch(ctx context.Context) (int, error) {
	var (
		claimed     int
		unavailable error // the broker went away mid-batch
	)
	err := postgres.InTx(ctx, r.pool, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, claimDue, r.cfg.BatchSize)
		if err != nil {
			return err
		}
		rows, err := pgx.CollectRows(rs, func(s pgx.CollectableRow) (row, error) {
			var x row
			err := s.Scan(&x.id, &x.topic, &x.key, &x.payload, &x.headers, &x.attempts, &x.createdAt)
			return x, err
		})
		if err != nil {
			return err
		}
		claimed = len(rows)
		failedKeys := map[string]bool{} // a key whose event failed: its later events wait
		for _, x := range rows {
			if failedKeys[x.key] {
				continue
			}
			ev := Event{ID: x.id, Topic: x.topic, Key: x.key, Payload: x.payload, CreatedAt: x.createdAt,
				TTL: r.cfg.TTL[x.topic], Headers: decodeHeaders(x.headers)}
			pctx, cancel := context.WithTimeout(ctx, r.cfg.PublishWait)
			err := r.pub.Publish(pctx, ev)
			cancel()
			switch {
			case errors.Is(err, ErrUnavailable):
				// Not this event's fault: it keeps its attempt count. Commit what was already
				// published (so it isn't sent again) and wait for the broker.
				r.unavailable.Inc()
				unavailable = err
				return nil
			case err != nil:
				r.failures.WithLabelValues(x.topic).Inc()
				failedKeys[x.key] = true
				attempts := x.attempts + 1
				msg := truncate(err.Error(), 500)
				if _, err := tx.Exec(ctx, `UPDATE outbox_events SET attempts = attempts + 1, last_error = $2, next_attempt_at = $3 WHERE id = $1`,
					x.id, msg, r.now().Add(r.backoff(attempts))); err != nil {
					return err
				}
				level := slog.LevelWarn
				if attempts >= 20 {
					level = slog.LevelError
				}
				r.log.Log(ctx, level, "event publish failed; will retry", "event_id", x.id, "topic", x.topic, "attempts", attempts, "err", err)
			default:
				if _, err := tx.Exec(ctx, `UPDATE outbox_events
					SET published_at = now(), attempts = attempts + 1, last_error = NULL,
					    payload = CASE WHEN jsonb_typeof(payload) = 'object' THEN payload - $2::text[] ELSE payload END
					WHERE id = $1`, x.id, r.scrub(x.topic)); err != nil {
					return err
				}
				// Counted when sent; if the commit fails it is sent (and counted) again, and the
				// stream drops the repeat.
				r.published.WithLabelValues(x.topic).Inc()
			}
		}
		return nil
	})
	if err == nil && unavailable != nil {
		return 0, unavailable
	}
	// If the commit itself failed, events sent this batch are still marked unpublished and go
	// out again; the stream drops a repeat within its duplicate window (Nats-Msg-Id).
	return claimed, err
}

func (r *Relay) scrub(topic string) []string {
	if s := r.cfg.Scrub[topic]; s != nil && r.cfg.ScrubDelay == 0 {
		return s
	}
	return []string{}
}

// backoff: 1 s, 2 s, 4 s … capped at MaxBackoff, plus up to 250 ms of jitter so many
// failing events don't retry in lockstep.
func (r *Relay) backoff(attempts int32) time.Duration {
	d := r.cfg.MaxBackoff
	if attempts < 20 {
		d = min(time.Second<<(attempts-1), r.cfg.MaxBackoff)
	}
	return d + time.Duration(rand.Int64N(int64(250*time.Millisecond)))
}

func (r *Relay) pending(ctx context.Context) (time.Time, int64, error) {
	var oldest time.Time
	var n int64
	err := r.pool.QueryRow(ctx, `SELECT coalesce(min(created_at), now())::timestamptz, count(*)
		FROM outbox_events WHERE published_at IS NULL`).Scan(&oldest, &n)
	return oldest, n, err
}

func (r *Relay) checkBacklog(ctx context.Context) {
	oldest, n, err := r.pending(ctx)
	if err != nil {
		r.log.WarnContext(ctx, "outbox backlog check failed", "err", err)
		return
	}
	if age := r.now().Sub(oldest); n > 0 && age > r.cfg.AlertAfter {
		r.log.ErrorContext(ctx, "outbox backlog: events are waiting too long", "pending", n, "oldest_age", age.Round(time.Second).String())
	}
}

// scrubLater applies Scrub to events delivered more than ScrubDelay ago (dev only).
func (r *Relay) scrubLater(ctx context.Context) {
	if r.cfg.ScrubDelay == 0 {
		return
	}
	for topic, fields := range r.cfg.Scrub {
		if _, err := r.pool.Exec(ctx, `UPDATE outbox_events SET payload = payload - $2::text[]
			WHERE topic = $1 AND published_at IS NOT NULL AND published_at < $3
			  AND jsonb_typeof(payload) = 'object' AND payload ?| $2::text[]`,
			topic, fields, r.now().Add(-r.cfg.ScrubDelay)); err != nil {
			r.log.WarnContext(ctx, "outbox scrub failed", "topic", topic, "err", err)
		}
	}
}

// cleanup deletes published rows older than Retain, 1000 at a time so it never holds locks
// for long. Consumers keep their own copy (the stream keeps 7 days).
func (r *Relay) cleanup(ctx context.Context) {
	before := r.now().Add(-r.cfg.Retain)
	var total int64
	for ctx.Err() == nil {
		tag, err := r.pool.Exec(ctx, `DELETE FROM outbox_events WHERE id IN (
			SELECT id FROM outbox_events WHERE published_at IS NOT NULL AND published_at < $1 LIMIT 1000)`, before)
		if err != nil {
			r.log.WarnContext(ctx, "outbox clean-up failed", "err", err)
			return
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < 1000 {
			break
		}
	}
	if total > 0 {
		r.log.InfoContext(ctx, "outbox cleaned", "deleted", total)
	}
}

// backlog reports the pending events and the oldest one's age at scrape time.
type backlog struct{ r *Relay }

var (
	pendingDesc = prometheus.NewDesc("hayitone_outbox_pending", "Outbox events not yet published.", nil, nil)
	ageDesc     = prometheus.NewDesc("hayitone_outbox_oldest_pending_seconds", "Age of the oldest unpublished event (0 when none).", nil, nil)
)

func (b backlog) Describe(ch chan<- *prometheus.Desc) { ch <- pendingDesc; ch <- ageDesc }

func (b backlog) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	oldest, n, err := b.r.pending(ctx)
	if err != nil {
		return // the scrape goes on without them
	}
	age := 0.0
	if n > 0 {
		age = b.r.now().Sub(oldest).Seconds()
	}
	ch <- prometheus.MustNewConstMetric(pendingDesc, prometheus.GaugeValue, float64(n))
	ch <- prometheus.MustNewConstMetric(ageDesc, prometheus.GaugeValue, age)
}

// decodeHeaders turns the stored {"request_id": "…"} into broker headers (Hayitone-Request-Id).
func decodeHeaders(raw []byte) map[string]string {
	var in map[string]string
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if v == "" {
			continue
		}
		out["Hayitone-"+headerCase(k)] = v
	}
	return out
}

// headerCase: request_id -> Request-Id.
func headerCase(k string) string {
	parts := strings.FieldsFunc(k, func(r rune) bool { return r == '_' || r == '-' })
	for i, p := range parts {
		parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	return strings.Join(parts, "-")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
