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
| `postgres`, `redisx` | Open a connection; `postgres.InTx`, `NotFound`, constraint-error helpers |
| `identity` | Verify the gateway's identity token with auth's public keys; a router where **every route declares who may call it**; step-up (recent sign-in, second factor) |
| `identity/identitytest` | Make identity tokens in a service's own tests |

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

Everything runs in containers: `make check` (format, vet, race tests), `make vuln`,
`make deps` after changing imports.
