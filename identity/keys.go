package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
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

// RemoteKeys fetches auth's public keys and keeps them in step with auth:
//
//   - A kid it doesn't know makes it fetch again (how services follow a key rotation
//     without restarting): at most once per MinRefetch after a successful fetch, so
//     tokens with made-up kids can't make it hammer auth, and at most once per second
//     after a failed one (auth may be restarting).
//   - Every MaxAge it fetches again on the next use, so a key auth has withdrawn (a
//     rotation finished, or a leaked key removed) stops being trusted here too.
//   - A withdrawn key is still accepted for RetiredGrace after it disappears, because
//     tokens it signed in their last seconds (identity tokens live 60 s) are still valid;
//     then it is dropped. So a removed key is refused within MaxAge + RetiredGrace.
//
// If auth can't be reached, the keys it last published stay in use: an outage of auth's
// key endpoint must not lock every service out.
type RemoteKeys struct {
	url    string
	client *http.Client

	MinRefetch   time.Duration
	MaxAge       time.Duration
	RetiredGrace time.Duration

	mu        sync.Mutex   // one fetch at a time
	keys      sync.Map     // kid -> *remoteKey
	nextFetch time.Time    // no fetch for an unknown kid before this
	fetched   atomic.Int64 // when the last successful fetch ended (unix nanos)
	now       func() time.Time
}

type remoteKey struct {
	key       paseto.V4AsymmetricPublicKey
	withdrawn time.Time // zero while auth publishes it
}

// KeysFromURL makes a RemoteKeys for auth's key endpoint, e.g.
// http://auth.internal:8081/internal/v1/keys.
func KeysFromURL(url string) *RemoteKeys {
	return &RemoteKeys{
		url: url, client: &http.Client{Timeout: 2 * time.Second},
		MinRefetch: 10 * time.Second, MaxAge: time.Minute, RetiredGrace: 90 * time.Second,
		now: time.Now,
	}
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
	if r.stale() {
		r.refresh(ctx)
	}
	if k, ok := r.usable(kid); ok {
		return k, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.usable(kid); ok { // fetched while we waited
		return k, nil
	}
	if r.now().Before(r.nextFetch) {
		return paseto.V4AsymmetricPublicKey{}, ErrUnknownKey
	}
	if err := r.fetchLocked(ctx); err != nil {
		return paseto.V4AsymmetricPublicKey{}, err
	}
	if k, ok := r.usable(kid); ok {
		return k, nil
	}
	return paseto.V4AsymmetricPublicKey{}, ErrUnknownKey
}

// usable: the key for kid, if auth publishes it or withdrew it less than RetiredGrace ago.
func (r *RemoteKeys) usable(kid string) (paseto.V4AsymmetricPublicKey, bool) {
	v, ok := r.keys.Load(kid)
	if !ok {
		return paseto.V4AsymmetricPublicKey{}, false
	}
	k := v.(*remoteKey)
	if !k.withdrawn.IsZero() && r.now().Sub(k.withdrawn) > r.RetiredGrace {
		return paseto.V4AsymmetricPublicKey{}, false
	}
	return k.key, true
}

func (r *RemoteKeys) stale() bool {
	last := r.fetched.Load()
	return last != 0 && r.MaxAge > 0 && r.now().Sub(time.Unix(0, last)) > r.MaxAge
}

// refresh fetches if the set is still stale once it holds the lock, and not too soon after
// a failed attempt. A failure keeps the keys already held.
func (r *RemoteKeys) refresh(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stale() || r.now().Before(r.nextFetch) {
		return
	}
	_ = r.fetchLocked(ctx)
}

// fetchLocked takes the published set. Keys auth no longer publishes are marked withdrawn
// (and dropped once RetiredGrace has passed), so a token signed with a key that was just
// retired still verifies for the rest of its 60 seconds, and no longer.
func (r *RemoteKeys) fetchLocked(ctx context.Context) (err error) {
	r.nextFetch = r.now().Add(time.Second)
	defer func() {
		if err == nil {
			r.nextFetch = r.now().Add(r.MinRefetch)
			r.fetched.Store(r.now().UnixNano())
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
	published := map[string]paseto.V4AsymmetricPublicKey{}
	for _, k := range set.Keys {
		if k.Version != "v4" || k.Purpose != "public" || k.KID == "" {
			continue
		}
		pk, err := paseto.NewV4AsymmetricPublicKeyFromHex(k.PublicKeyHex)
		if err != nil {
			continue
		}
		published[k.KID] = pk
	}
	if len(published) == 0 {
		return errors.New("identity: fetch keys: no usable keys")
	}
	now := r.now()
	r.keys.Range(func(kid, v any) bool {
		if _, ok := published[kid.(string)]; ok {
			return true
		}
		switch k := v.(*remoteKey); {
		case k.withdrawn.IsZero():
			r.keys.Store(kid, &remoteKey{key: k.key, withdrawn: now})
		case now.Sub(k.withdrawn) > r.RetiredGrace:
			r.keys.Delete(kid)
		}
		return true
	})
	for kid, pk := range published {
		r.keys.Store(kid, &remoteKey{key: pk})
	}
	return nil
}

func (r *RemoteKeys) count() int {
	n := 0
	r.keys.Range(func(any, any) bool { n++; return true })
	return n
}
