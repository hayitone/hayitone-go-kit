package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/google/uuid"
)

// Refusal reasons. They are for the service's logs; callers only ever see "unauthorized".
var (
	ErrMissing      = errors.New("identity: no token")
	ErrMalformed    = errors.New("identity: malformed token")
	ErrUnknownKey   = errors.New("identity: unknown key id")
	ErrInvalid      = errors.New("identity: signature or claims invalid")
	ErrOtherRequest = errors.New("identity: token is for another request")
)

// RequestPath is the path a token is bound to: the request's escaped path, without the
// query. Auth and the services both use this, so the two always agree.
func RequestPath(r *http.Request) string { return r.URL.EscapedPath() }

// VerifyRequest verifies the token in r's identity header (Verify) and that it was signed
// for this very request: same method, same path. Anything else is ErrOtherRequest.
func (v *Verifier) VerifyRequest(r *http.Request) (Identity, error) {
	id, err := v.Verify(r.Context(), r.Header.Get(Header))
	if err != nil {
		return Identity{}, err
	}
	if id.Method != r.Method || id.Path != RequestPath(r) {
		return Identity{}, ErrOtherRequest
	}
	return id, nil
}

// Keys finds auth's public key for a kid (see KeysFromURL, StaticKeys).
type Keys interface {
	Key(ctx context.Context, kid string) (paseto.V4AsymmetricPublicKey, error)
}

// Verifier checks identity tokens.
type Verifier struct {
	keys Keys
	now  func() time.Time
}

func NewVerifier(keys Keys) *Verifier { return &Verifier{keys: keys, now: time.Now} }

// SetClock is for tests.
func (v *Verifier) SetClock(now func() time.Time) { v.now = now }

// Verify checks the signature with the key named by the footer's kid, the issuer, the
// audience and the times (expired at exp, no leeway), and reads the claims. Any failure is
// one of the errors above. It does NOT check which request the token is for: services use
// VerifyRequest (the Router does).
func (v *Verifier) Verify(ctx context.Context, raw string) (Identity, error) {
	if raw == "" {
		return Identity{}, ErrMissing
	}
	if len(raw) > MaxTokenBytes || !strings.HasPrefix(raw, "v4.public.") {
		return Identity{}, ErrMalformed
	}
	kid, err := FooterKID(raw)
	if err != nil {
		return Identity{}, ErrMalformed
	}
	key, err := v.keys.Key(ctx, kid)
	if err != nil {
		return Identity{}, err
	}
	p := paseto.NewParserWithoutExpiryCheck()
	p.AddRule(paseto.IssuedBy(Issuer), paseto.ForAudience(Audience), v.validNow())
	tok, err := p.ParseV4Public(key, raw, nil)
	if err != nil {
		return Identity{}, ErrInvalid
	}

	var (
		id   Identity
		errs []error
	)
	id.UserID, err = uuidClaim(tok, "sub")
	errs = append(errs, err)
	id.AccountID, err = uuidClaim(tok, "acct")
	errs = append(errs, err)
	id.SessionID, err = uuidClaim(tok, "sid")
	errs = append(errs, err)
	errs = append(errs, tok.Get("grants", &id.Grants), tok.Get("amr", &id.AMR))
	authTime, err := tok.GetString("auth_time")
	errs = append(errs, err)
	id.AuthTime, err = time.Parse(time.RFC3339, authTime)
	errs = append(errs, err)
	id.RequestID, err = tok.GetJti()
	errs = append(errs, err)
	id.Method, err = tok.GetString("method")
	errs = append(errs, err)
	id.Path, err = tok.GetString("path")
	errs = append(errs, err)
	if id.Method == "" || !strings.HasPrefix(id.Path, "/") {
		errs = append(errs, errors.New("no request"))
	}
	id.IssuedAt, err = tok.GetIssuedAt()
	errs = append(errs, err)
	id.ExpiresAt, err = tok.GetExpiration()
	errs = append(errs, err)
	if errors.Join(errs...) != nil {
		return Identity{}, ErrInvalid
	}
	return id, nil
}

// validNow: expired at or after exp (no leeway); iat and nbf may be up to ClockSkew ahead.
func (v *Verifier) validNow() paseto.Rule {
	return func(tok paseto.Token) error {
		now := v.now()
		exp, err1 := tok.GetExpiration()
		iat, err2 := tok.GetIssuedAt()
		nbf, err3 := tok.GetNotBefore()
		switch {
		case err1 != nil || err2 != nil || err3 != nil:
			return errors.New("time claims missing")
		case !now.Before(exp):
			return errors.New("expired")
		case iat.After(now.Add(ClockSkew)) || nbf.After(now.Add(ClockSkew)):
			return errors.New("not valid yet")
		case !iat.Before(exp):
			return errors.New("issued after expiry")
		}
		return nil
	}
}

// FooterKID reads the kid from "v4.<purpose>.<payload>.<footer>" without verifying
// anything: it only picks the key to verify with. Strict: exactly one field, "kid".
func FooterKID(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 || len(parts[3]) > 256 {
		return "", errors.New("no footer")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", err
	}
	var f map[string]any
	if err := json.Unmarshal(b, &f); err != nil || len(f) != 1 {
		return "", errors.New("bad footer")
	}
	kid, ok := f["kid"].(string)
	if !ok || kid == "" || len(kid) > 64 {
		return "", errors.New("bad kid")
	}
	return kid, nil
}

func uuidClaim(tok *paseto.Token, name string) (uuid.UUID, error) {
	s, err := tok.GetString(name)
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(s)
}
