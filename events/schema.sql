-- The tables package events needs in the consuming service's own database. Copy this into
-- one of the service's migrations (it is the same for every service).

-- Each event this service has handled, so a redelivery is handled at most once. Written in
-- the same transaction as the handler's own changes. Kept for 14 days (the stream keeps
-- events 7), then deleted by the consumer.
CREATE TABLE events_processed (
    consumer     text        NOT NULL,
    event_id     text        NOT NULL,
    topic        text        NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer, event_id)
);
CREATE INDEX events_processed_at ON events_processed (processed_at);

-- Events the handler could not take (a bad payload, or failing every attempt): parked here
-- instead of being dropped, with the last error, until someone fixes the cause and replays
-- them (Consumer.ReplayParked). Kept until then.
CREATE TABLE events_parked (
    consumer   text        NOT NULL,
    event_id   text        NOT NULL,
    topic      text        NOT NULL,
    key        text        NOT NULL,
    created_at timestamptz,
    request_id text        NOT NULL DEFAULT '',
    data       bytea       NOT NULL,
    error      text        NOT NULL,
    attempts   integer     NOT NULL,
    parked_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer, event_id)
);
