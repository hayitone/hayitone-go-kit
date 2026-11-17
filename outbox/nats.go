package outbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/hayitone/hayitone-go-kit/events"
)

// Stream is a service's own JetStream stream: every subject under its prefix, kept on disk
// for 7 days so a consumer that was down catches up. The service's relay owns it and keeps
// its settings up to date at start-up.
type Stream struct {
	Name        string // e.g. "CATALOG"
	Subject     string // e.g. "catalog.>"
	Description string
	Replicas    int  // copies: 1 on a single server, 3 on a cluster
	AllowMsgTTL bool // per-message lifetimes (Config.TTL)
}

// NATS publishes to one stream and waits for its acknowledgement, so "published" means
// stored on disk, not merely sent. Connect with natsx.Connect.
type NATS struct {
	nc     *nats.Conn
	js     jetstream.JetStream
	stream Stream
}

// NewNATS publishes to stream over nc.
func NewNATS(nc *nats.Conn, stream Stream) (*NATS, error) {
	if stream.Name == "" || stream.Subject == "" {
		return nil, errors.New("outbox: Stream.Name and Stream.Subject are required")
	}
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	return &NATS{nc: nc, js: js, stream: stream}, nil
}

// EnsureStream creates the stream or brings its settings up to date, retrying until NATS
// answers or ctx ends.
func (n *NATS) EnsureStream(ctx context.Context, log *slog.Logger) error {
	cfg := jetstream.StreamConfig{
		Name:        n.stream.Name,
		Description: n.stream.Description,
		Subjects:    []string{n.stream.Subject},
		Retention:   jetstream.LimitsPolicy,
		Storage:     jetstream.FileStorage,
		Replicas:    max(n.stream.Replicas, 1),
		MaxAge:      7 * 24 * time.Hour,
		Duplicates:  2 * time.Minute, // a resend with the same Nats-Msg-Id is dropped
		Discard:     jetstream.DiscardOld,
		MaxMsgSize:  1 << 20,
		DenyDelete:  true, // events are history: no deleting single messages
		AllowMsgTTL: n.stream.AllowMsgTTL,
	}
	wait := time.Second
	for {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := n.js.CreateOrUpdateStream(cctx, cfg)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Warn("stream not ready; retrying", "stream", n.stream.Name, "err", err, "in", wait.String())
		if sleep(ctx, wait) != nil {
			return ctx.Err()
		}
		wait = min(2*wait, 30*time.Second)
	}
}

// Publish sends one event and waits for the stream to store it.
func (n *NATS) Publish(ctx context.Context, e Event) error {
	if !n.nc.IsConnected() {
		return fmt.Errorf("%w: %s", ErrUnavailable, n.nc.Status())
	}
	msg := nats.NewMsg(e.Topic)
	msg.Data = e.Payload
	for k, v := range e.Headers {
		msg.Header.Set(k, v)
	}
	msg.Header.Set("Content-Type", "application/json")
	msg.Header.Set(events.HeaderEventID, e.ID.String())
	msg.Header.Set(events.HeaderKey, e.Key)
	msg.Header.Set(events.HeaderCreatedAt, e.CreatedAt.UTC().Format(time.RFC3339Nano))

	opts := []jetstream.PublishOpt{
		jetstream.WithMsgID(e.ID.String()), // the stream's duplicate check
		jetstream.WithExpectStream(n.stream.Name),
	}
	if e.TTL > 0 {
		opts = append(opts, jetstream.WithMsgTTL(e.TTL))
	}
	_, err := n.js.PublishMsg(ctx, msg, opts...)
	if err == nil {
		return nil
	}
	if unavailable(err) {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return err
}

// unavailable separates "the broker didn't answer" from "the broker refused this event".
func unavailable(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) ||
		errors.Is(err, nats.ErrNoResponders) || errors.Is(err, jetstream.ErrNoStreamResponse) ||
		errors.Is(err, nats.ErrConnectionClosed) || errors.Is(err, nats.ErrConnectionReconnecting) ||
		errors.Is(err, nats.ErrDisconnected) ||
		strings.Contains(err.Error(), "jetstream not enabled") // a server starting up
}

// Ready is the readiness check: connected to NATS.
func (n *NATS) Ready(context.Context) error {
	if !n.nc.IsConnected() {
		return fmt.Errorf("nats %s", n.nc.Status())
	}
	return nil
}
