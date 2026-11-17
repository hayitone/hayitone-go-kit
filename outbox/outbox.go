// Package outbox is how a Hayitone service publishes events: Write records an event in the
// same transaction as the change it describes, and a Relay (a process of its own) publishes
// them to the service's NATS JetStream stream afterwards. An event is never lost while the
// broker is down and never sent for a change that rolled back. Consumers read them with
// package events.
//
//	err := postgres.InTx(ctx, pool, func(tx pgx.Tx) error {
//		... the change ...
//		return outbox.Write(ctx, tx, "catalog.title.published", titleID.String(), payload)
//	})
//
//	relay := outbox.NewRelay(pool, publisher, log, outbox.Config{LockName: "hayitone-catalog/outbox-relay"})
//	go relay.Run(ctx)
//
// The rules every service gets from it:
//
//   - In order per key. Exactly one relay publishes at a time (a Postgres advisory lock on a
//     connection of its own); others stand by and take over within seconds. An event waits
//     while an earlier event with the same key is unpublished.
//   - At least once, without duplicates downstream. Each event carries its outbox ID as
//     Nats-Msg-Id (the stream drops a resend within its duplicate window) and as the header
//     Hayitone-Event-Id (package events skips one it has handled).
//   - Retried for ever. A refused event backs off (1 s doubling to 2 min) and is logged at
//     ERROR from the 20th try; a broker that can't be reached costs no attempt, and the
//     relay waits for it.
//   - Scrubbed. Fields named in Config.Scrub (a code, a token) are deleted from the stored
//     row once delivered; published rows are deleted after Config.Retain.
//
// The table is in schema.sql: copy it into one of the service's migrations.
package outbox

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hayitone/hayitone-go-kit/httpx"
)

// Schema is schema.sql: the table a producing service needs.
//
//go:embed schema.sql
var Schema string

// Execer is a transaction (pgx.Tx) or anything else that runs a statement; Write belongs in
// the transaction of the change the event describes.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Write records one event. topic is the NATS subject (it must start with the service's
// stream subject, e.g. "catalog."); key orders events about one thing (usually its ID); the
// payload is marshalled to JSON. The request ID travels along so the event can be traced
// back to its request.
func Write(ctx context.Context, tx Execer, topic, key string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("event %s: %w", topic, err)
	}
	headers, err := json.Marshal(map[string]string{"request_id": httpx.RequestID(ctx)})
	if err != nil {
		return fmt.Errorf("event %s: %w", topic, err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO outbox_events (id, topic, key, payload, headers) VALUES ($1, $2, $3, $4, $5)`,
		id, topic, key, body, headers)
	if err != nil {
		return fmt.Errorf("event %s: %w", topic, err)
	}
	return nil
}
