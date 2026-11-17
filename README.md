# hayitone-go-kit

Shared Go building blocks for Hayitone's services. Every Go service uses the standard
library's `net/http` plus this kit, so they all behave the same at the edges: the same
errors, logs, health checks, shutdown and identity rules.

```
go get github.com/hayitone/hayitone-go-kit@latest
```

| Package | What it gives a service |
|---|---|
| `httpx` | Middleware (request ID, panic recovery, one JSON access-log line per request, exact paths only), the standard JSON error shape, `DecodeJSON`, and the client behind a request from the gateway's headers (`ClientFrom`: real IP, web or app, device) |
| `health` | `/healthz` and `/readyz` the gateway's health checks understand, and draining on shutdown |
| `server` | `server.New` (sane timeouts) and `server.Run`: serve, then on SIGTERM drain, wait, and stop gracefully |
| `logx` | JSON logs tagged with service and environment |
| `metrics` | Prometheus metrics on a registry of the service's own: requests and timing per route pattern (via `httpx.Options.Observe`), Go runtime, process, build info; `/metrics` handler for the internal port |
| `postgres`, `redisx` | Open a connection; `postgres.InTx`, `NotFound`, constraint-error helpers |
| `identity` | Verify the gateway's identity token with auth's public keys; a router where **every route declares who may call it**; step-up (recent sign-in, second factor) |
| `identity/identitytest` | Make identity tokens in a service's own tests |
| `natsx` | Connect to NATS as the service's own user (NKey seed outside dev, TLS with a private CA), reconnecting for as long as the process lives; `Config.Check` for start-up validation |
| `outbox` | Publish a service's own events: written in the same transaction as the change (`outbox.Write`), sent to the service's JetStream stream by a relay (one active, the others standing by), in order per key, retried, scrubbed and cleaned up |
| `events` | Read another service's events from NATS JetStream: each one handled exactly once inside the service's own database transaction, in order, acknowledged after the commit, retried, and parked (never dropped) when it keeps failing |

## Identity in a service

```go
keys := identity.KeysFromURL("http://auth.internal:8081/internal/v1/keys")
if err := keys.Fetch(ctx); err != nil { … }          // and keys.Ready in /readyz
rt := identity.NewRouter(identity.NewVerifier(keys), log)

rt.HandleFunc("GET /v1/catalog/videos", identity.Anonymous, list)
rt.HandleFunc("POST /v1/catalog/videos", identity.Grant("catalog.write"), create)
rt.HandleFunc("DELETE /v1/channels/{id}", identity.All(
    identity.Grant("channel.delete"),
    identity.Recent(15*time.Minute, identity.MethodOTP, identity.MethodPasskey),
), deleteChannel)

func create(w http.ResponseWriter, r *http.Request) {
    me := identity.Must(r.Context()) // who is acting: never from the request body
    // …and check the resource belongs to me.AccountID: only the service can.
}
```

The keys follow auth by themselves: a new kid is fetched when a token first uses it, the
set is looked at again every minute, and a key auth stops publishing (a finished rotation,
or a leaked key removed) is refused within about two and a half minutes (90 seconds of grace for tokens it already
signed). No restart is needed for either.

Some staff permissions are given for one department only and arrive as `key@department`
(`platform.content.titles.publish@film`). Let anyone holding the permission in some
department onto the route, then check the resource's own department:

```go
rt.HandleFunc("POST /v1/titles/{id}/publish",
    identity.GrantInAny("platform.content.titles.publish"), publish)

func publish(w http.ResponseWriter, r *http.Request) {
    me := identity.Must(r.Context())
    title := load(r.PathValue("id"))
    if !me.HasIn("platform.content.titles.publish", title.Department) { // whole account or that department
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    // …
}
```

`me.Departments(key)` lists where a permission applies, e.g. to filter a list.

**Each token is for one request.** Auth signs a fresh identity token for every request,
naming its method and escaped path (`PATCH /v1/me/profile`; the query doesn't count). The
router refuses it for any other request (`identity.ErrOtherRequest`, answered as 401), so a
token taken from one service, or from one request, can't be replayed on another. Never
forward the identity header to another service: calls between services get their own
credentials. Outside the router, use `verifier.VerifyRequest(r)`, never `Verify` alone.
Since v0.4.0; tokens from an older auth (without the request) are refused.

In tests, sign for the request you send:

```go
req := httptest.NewRequest("PATCH", "/v1/me/profile", body)
issuer.Authorize(req, identity.Identity{UserID: u}) // sets X-Hayitone-Identity for this request
```

The gateway's `docs/authz_contract.md` (section 5) is the contract this implements.

## Rules for this repo

- **Plumbing only.** Nothing about payments, catalogue, permissions or any other business
  rule belongs here: those stay in the owning service's private repo.
- **No secrets, ever.** No keys, tokens or passwords, not even for tests (tests make their
  own). GitHub's secret scanning blocks pushes that contain them.
- **Versioned releases.** Services depend on tags (`v0.1.0`), created only from a green
  `main`. While on `v0`, a minor version may change the API (say so in the tag notes);
  from `v1`, breaking changes need a new major version.
- **A package moves here when a second service needs it**, not before.

## Development

Everything runs in containers: `make check` (format, vet, race tests, and `make integration`:
the events and outbox tests against throw-away NATS and Postgres containers), `make vuln`, `make deps`
after changing imports.

## Metrics in a service

```go
reg := metrics.New("catalog", version)
public := httpx.MiddlewareWith(log, publicMux, httpx.Options{Observe: reg.Observe("public")})
internalMux.Handle("GET /metrics", reg.Handler()) // internal port only, never through the gateway

uploads := prometheus.NewCounterVec(prometheus.CounterOpts{
    Name: "catalog_uploads_total", Help: "Uploads finished, by result.",
}, []string{"result"}) // a small, fixed set of values
reg.MustRegister(uploads)
```

Every service gets `http_requests_total{server,method,route,code}`,
`http_request_duration_seconds{server,method,route}`, `go_*`, `process_*` and
`hayitone_build_info{service,version,go_version}`. The route is the mux pattern
(`/v1/videos/{id}`), never the URL. Labels must stay a small, fixed set: never an ID, a
person, an email or a token.

## Events in a service

```go
nc, err := natsx.Connect(cfg.NATS, "hayitone-profile", log)
c, err := events.New(nc, pool, events.Config{
    Stream:   "AUTH",    // the producer's stream
    Consumer: "profile", // durable name: this service
    Handlers: map[string]events.Handler{
        "auth.user.created": profiles.Create, // func(ctx, tx pgx.Tx, ev events.Event) error
        "auth.user.erased":  profiles.Erase,
    },
    Logger: log, Registerer: reg,
})
go c.Run(ctx) // until ctx ends; rides out NATS and database outages
```

`c.Ready()` says whether it is reading (set up and connected) and `c.ParkedCount(ctx)` how
many events wait in `events_parked`: export both as metrics and alert on them. Whether
reading events belongs in `/readyz` is the service's call (profile leaves it out: its API
works without NATS).

- Copy `events/schema.sql` (also `events.Schema`) into one of the service's migrations:
  `events_processed` (what was handled, kept 14 days) and `events_parked`.
- A handler does all its work through the `tx` it's given. It commits together with the
  record that the event was handled, so a redelivered event is skipped, never applied twice.
- Return `events.Permanent(err)` for a payload that can never work: the event is parked at
  once. Any other error is retried (1 s, 2 s, 4 s ... 1 min); after 8 attempts it is parked.
  Parked events are logged at ERROR and counted in
  `hayitone_events_handled_total{result="parked"}`; alert on `ParkedCount() > 0`. Fix the
  cause, then `ReplayParked(ctx, eventID)`.
- One event at a time per consumer, in the stream's order. Because a parked event doesn't
  stop the ones after it, handlers must cope with an event whose earlier one was parked
  (an update for a profile that doesn't exist yet).
- Check payloads against the producer's schemas (auth: `docs/events/`) in your tests.

## Publishing events (outbox)

```go
// In the change's own transaction: never sent if it rolls back, never lost if NATS is down.
err := postgres.InTx(ctx, pool, func(tx pgx.Tx) error {
    // … the change …
    return outbox.Write(ctx, tx, "catalog.title.published", titleID.String(), payload)
})

// The relay, a process of its own (`catalog relay`): a slow broker never slows the API.
nc, err := natsx.Connect(cfg.NATS, "hayitone-catalog-relay", log)
pub, err := outbox.NewNATS(nc, outbox.Stream{Name: "CATALOG", Subject: "catalog.>"})
go pub.EnsureStream(ctx, log) // then:
relay := outbox.NewRelay(pool, pub, log, outbox.Config{LockName: "hayitone-catalog/outbox-relay"})
reg.MustRegister(relay.Collectors()...)
err = relay.Run(ctx)
```

- Copy `outbox/schema.sql` (also `outbox.Schema`) into one of the service's migrations.
- The key orders events about one thing (a title's ID): one key's events go out in the order
  they were written, and a refused one holds back only its own key's later events.
- Each event carries `Hayitone-Event-Id` (its outbox ID, also the stream's duplicate check),
  `Hayitone-Key`, `Hayitone-Created-At` and `Hayitone-Request-Id`: what package `events` reads.
- `Config.Scrub` removes fields (a code, a token) from the stored row once delivered;
  published rows are deleted after 7 days (the stream keeps them as long).
- Metrics: `hayitone_outbox_published_total`, `…_publish_failures_total`,
  `…_broker_unavailable_total`, `hayitone_outbox_pending`, `…_oldest_pending_seconds` and
  `hayitone_outbox_relay_active`. Alert on the oldest pending event's age.
- Auth's relay (`internal/platform/outbox`) is the original; it moves onto this package later.
