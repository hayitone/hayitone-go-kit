package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"
)

// KeySet is the body of auth's GET /internal/v1/keys (contract section 3).
type KeySet struct {
	Keys []PublicKey `json:"keys"`
}

// PublicKey is one published identity key.
type PublicKey struct {
	KID          string `json:"kid"`
	Version      string `json:"version"` // "v4"
	Purpose      string `json:"purpose"` // "public"
	PublicKeyHex string `json:"public_key_hex"`
}

// StaticKeys is a fixed set (auth itself, tests).
type StaticKeys map[string]paseto.V4AsymmetricPublicKey

func (s StaticKeys) Key(_ context.Context, kid string) (paseto.V4AsymmetricPublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return paseto.V4AsymmetricPublicKey{}, ErrUnknownKey
}

// RemoteKeys fetches auth's public keys and keeps them. A kid it doesn't know makes it
// fetch again (that is how services follow a key rotation without restarting): at most
// once per MinRefetch after a successful fetch, so tokens with made-up kids can't make it
// hammer auth, and at most once per second after a failed one (auth may be restarting).
type RemoteKeys struct {
	url    string
	client *http.Client

	MinRefetch time.Duration

	mu        sync.Mutex // one fetch at a time
	keys      sync.Map   // kid -> paseto.V4AsymmetricPublicKey
	nextFetch time.Time  // no fetch for an unknown kid before this
	now       func() time.Time
}

// KeysFromURL makes a RemoteKeys for auth's key endpoint, e.g.
// http://auth.internal:8081/internal/v1/keys.
func KeysFromURL(url string) *RemoteKeys {
	return &RemoteKeys{url: url, client: &http.Client{Timeout: 2 * time.Second}, MinRefetch: 10 * time.Second, now: time.Now}
}

// Fetch loads the key set now. Call it at start-up, and use Ready as a readiness check, so a
// service that can't reach auth doesn't take traffic it would refuse anyway.
func (r *RemoteKeys) Fetch(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fetchLocked(ctx)
}

// Ready reports whether at least one key is loaded (fetching if none is).
func (r *RemoteKeys) Ready(ctx context.Context) error {
	if r.count() > 0 {
		return nil
	}
	return r.Fetch(ctx)
}

func (r *RemoteKeys) Key(ctx context.Context, kid string) (paseto.V4AsymmetricPublicKey, error) {
	if k, ok := r.keys.Load(kid); ok {
		return k.(paseto.V4AsymmetricPublicKey), nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keys.Load(kid); ok { // fetched while we waited
		return k.(paseto.V4AsymmetricPublicKey), nil
	}
	if r.now().Before(r.nextFetch) {
		return paseto.V4AsymmetricPublicKey{}, ErrUnknownKey
	}
	if err := r.fetchLocked(ctx); err != nil {
		return paseto.V4AsymmetricPublicKey{}, err
	}
	if k, ok := r.keys.Load(kid); ok {
		return k.(paseto.V4AsymmetricPublicKey), nil
	}
	return paseto.V4AsymmetricPublicKey{}, ErrUnknownKey
}

// fetchLocked replaces nothing: keys only accumulate, so a token signed with a key that
// was just retired still verifies for the rest of its 60 seconds.
func (r *RemoteKeys) fetchLocked(ctx context.Context) (err error) {
	r.nextFetch = r.now().Add(time.Second)
	defer func() {
		if err == nil {
			r.nextFetch = r.now().Add(r.MinRefetch)
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return err
	}
	res, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("identity: fetch keys: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("identity: fetch keys: status %d", res.StatusCode)
	}
	var set KeySet
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&set); err != nil {
		return fmt.Errorf("identity: fetch keys: %w", err)
	}
	loaded := 0
	for _, k := range set.Keys {
		if k.Version != "v4" || k.Purpose != "public" || k.KID == "" {
			continue
		}
		pk, err := paseto.NewV4AsymmetricPublicKeyFromHex(k.PublicKeyHex)
		if err != nil {
			continue
		}
		r.keys.Store(k.KID, pk)
		loaded++
	}
	if loaded == 0 {
		return errors.New("identity: fetch keys: no usable keys")
	}
	return nil
}

func (r *RemoteKeys) count() int {
	n := 0
	r.keys.Range(func(any, any) bool { n++; return true })
	return n
}
