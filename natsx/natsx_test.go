package natsx

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func TestCheck(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  Config
		dev  bool
		want string // part of the error, "" for none
	}{
		{"dev with a password", Config{URL: "nats://nats:4222", User: "profile", Password: "x"}, true, ""},
		{"production with a seed", Config{URL: "tls://nats:4222", CredsFile: "/run/secrets/nats"}, false, ""},
		{"no url", Config{}, true, "P_URL is required"},
		{"plain text outside dev", Config{URL: "nats://nats:4222", CredsFile: "/s"}, false, "must start with tls://"},
		{"no seed outside dev", Config{URL: "tls://nats:4222", User: "u", Password: "p"}, false, "P_CREDS is required outside dev"},
		{"both ways", Config{URL: "nats://n", CredsFile: "/s", User: "u"}, true, "can't both be set"},
		{"user without password", Config{URL: "nats://n", User: "u"}, true, "P_PASSWORD is required"},
		{"CA without TLS", Config{URL: "nats://n", CAFile: "/ca"}, true, "only used with a tls:// URL"},
	} {
		err := c.cfg.Check("P", c.dev)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestCredentials(t *testing.T) {
	dir := t.TempDir()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := kp.Seed()
	good := filepath.Join(dir, "seed")
	if err := os.WriteFile(good, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials(good); err != nil {
		t.Errorf("a seed file: %v", err)
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("SUAnotaseed-secretvalue"), 0o600)
	_, err = credentials(bad)
	if err == nil || strings.Contains(err.Error(), "secretvalue") {
		t.Errorf("a bad file: %v (must name the path, never the contents)", err)
	}
	if _, err := credentials(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file was accepted")
	}
	// Connecting with a bad seed fails before any network.
	if _, err := Connect(Config{URL: "nats://127.0.0.1:1", CredsFile: bad}, "t", slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("connected with a bad seed")
	}
}
