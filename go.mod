module github.com/hayitone/hayitone-go-kit

go 1.26.0

// `make deps` (go mod tidy) resolves the full graph and writes go.sum. Commit both.

require (
	aidanwoods.dev/go-paseto v1.6.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.13.0
	github.com/redis/go-redis/v9 v9.23.0
	golang.org/x/sync v0.25.0
)

require (
	aidanwoods.dev/go-result v0.3.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
)
