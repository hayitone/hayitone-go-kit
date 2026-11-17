// Package natsx connects a service to NATS the same way everywhere: its own user (an NKey
// seed or .creds file in staging and production, a user and password locally), TLS with a
// private CA when there is one, and reconnecting for as long as the process lives, so a
// NATS restart only pauses the service.
package natsx

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// Config of a connection. Exactly one way to authenticate: CredsFile, or User and Password.
type Config struct {
	URL       string // nats://host:4222 locally, tls://host:4222 elsewhere
	User      string
	Password  string
	CredsFile string // an NKey user seed file, or a .creds file (JWT + seed)
	CAFile    string // the CA that signed NATS's certificate, when it is a private one
}

// Check reports what's wrong with cfg, by the names of the environment variables it came
// from (prefix "PROFILE_NATS" names PROFILE_NATS_URL, ...). dev allows plain nats:// and a
// password; anywhere else needs tls:// and a seed or .creds file.
func (cfg Config) Check(prefix string, dev bool) error {
	var errs []error
	fail := func(key, msg string) { errs = append(errs, fmt.Errorf("%s_%s %s", prefix, key, msg)) }
	switch {
	case cfg.URL == "":
		fail("URL", "is required")
	case !dev && !strings.HasPrefix(cfg.URL, "tls://"):
		fail("URL", "must start with tls:// outside dev")
	case cfg.CAFile != "" && !strings.HasPrefix(cfg.URL, "tls://"):
		fail("CA_FILE", "is only used with a tls:// URL")
	}
	switch {
	case cfg.CredsFile != "" && cfg.User != "":
		fail("CREDS", "and "+prefix+"_USER can't both be set")
	case !dev && cfg.CredsFile == "":
		fail("CREDS", "is required outside dev (an NKey seed file)")
	case cfg.User != "" && cfg.Password == "":
		fail("PASSWORD", "is required with "+prefix+"_USER")
	}
	return errors.Join(errs...)
}

// Connect connects as name (shown in NATS's monitoring), retrying in the background if the
// server isn't up yet. extra options come last, so they can replace the handlers below.
func Connect(cfg Config, name string, log *slog.Logger, extra ...nats.Option) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name(name),
		nats.Timeout(5 * time.Second),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("nats disconnected", "err", err)
		}),
		nats.ReconnectHandler(func(c *nats.Conn) { log.Info("nats reconnected", "server", c.ConnectedUrlRedacted()) }),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { log.Warn("nats error", "err", err) }),
	}
	switch {
	case cfg.CredsFile != "":
		opt, err := credentials(cfg.CredsFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, opt)
	case cfg.User != "":
		opts = append(opts, nats.UserInfo(cfg.User, cfg.Password))
	}
	if cfg.CAFile != "" {
		opts = append(opts, nats.RootCAs(cfg.CAFile))
	}
	opts = append(opts, extra...)
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats: %w", err)
	}
	return nc, nil
}

// credentials reads a .creds file (JWT and seed) or a bare NKey user seed. Errors name the
// path, never the contents.
func credentials(path string) (nats.Option, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nats credentials: %w", err)
	}
	defer clear(b)
	if bytes.Contains(b, []byte("BEGIN NATS USER JWT")) {
		return nats.UserCredentials(path), nil
	}
	opt, err := nats.NkeyOptionFromSeed(path)
	if err != nil {
		return nil, errors.New("nats credentials: " + path + " is neither a .creds file nor an NKey user seed")
	}
	return opt, nil
}
