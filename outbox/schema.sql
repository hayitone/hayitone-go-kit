-- The table package outbox needs in the producing service's own database. Copy this into
-- one of the service's migrations (it is the same for every service; hayitone-auth's
-- 00009_outbox.sql is the original).
--
-- Events are written in the same transaction as the change they describe; the relay
-- publishes them afterwards. An event is never lost when the broker is down, and never sent
-- for a change that rolled back. A failed publish is retried after next_attempt_at, pushed
-- back further each time, so one broken event can't spin the relay.
CREATE TABLE outbox_events (
    id              uuid        PRIMARY KEY,             -- uuidv7, made by outbox.Write
    topic           text        NOT NULL CHECK (topic ~ '^[a-z][a-z0-9_.]*$'),
    key             text        NOT NULL,                -- events with one key go out in order
    payload         jsonb       NOT NULL,
    headers         jsonb       NOT NULL DEFAULT '{}',   -- request id
    created_at      timestamptz NOT NULL DEFAULT now(),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error      text,
    published_at    timestamptz
);

-- The relay's queue. Small, because published rows drop out of it.
CREATE INDEX outbox_due ON outbox_events (next_attempt_at) WHERE published_at IS NULL;
