// Package identitytest makes identity tokens for a service's own tests, signed the way auth
// signs them, with a key that exists only in the test.
//
//	issuer := identitytest.New()
//	router := identity.NewRouter(issuer.Verifier(), log)
//	req.Header.Set(identity.Header, issuer.Token(identity.Identity{UserID: u, Grants: []string{"catalog.publish"}}))
package identitytest

import (
	"encoding/json"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/google/uuid"

	"github.com/hayitone/hayitone-go-kit/identity"
)

// Issuer signs test identity tokens.
type Issuer struct {
	KID    string
	secret paseto.V4AsymmetricSecretKey
	Now    func() time.Time
}

// New makes an issuer with a fresh key ("test-key").
func New() *Issuer {
	return &Issuer{KID: "test-key", secret: paseto.NewV4AsymmetricSecretKey(), Now: time.Now}
}

// Keys is the issuer's public key set, for identity.NewVerifier.
func (i *Issuer) Keys() identity.StaticKeys {
	return identity.StaticKeys{i.KID: i.secret.Public()}
}

// Verifier accepts this issuer's tokens.
func (i *Issuer) Verifier() *identity.Verifier { return identity.NewVerifier(i.Keys()) }

// PublicKeySet is the issuer's key set as auth's /internal/v1/keys serves it.
func (i *Issuer) PublicKeySet() identity.KeySet {
	return identity.KeySet{Keys: []identity.PublicKey{{KID: i.KID, Version: "v4", Purpose: "public", PublicKeyHex: i.secret.Public().ExportHex()}}}
}

// Token signs id. Zero fields get defaults: random IDs, signed in now with a password,
// valid for 60 s.
func (i *Issuer) Token(id identity.Identity) string {
	now := i.Now().UTC().Truncate(time.Second)
	if id.UserID == uuid.Nil {
		id.UserID = uuid.New()
	}
	if id.AccountID == uuid.Nil {
		id.AccountID = uuid.New()
	}
	if id.SessionID == uuid.Nil {
		id.SessionID = uuid.New()
	}
	if id.AuthTime.IsZero() {
		id.AuthTime = now
	}
	if id.AMR == nil {
		id.AMR = []string{identity.MethodPassword}
	}
	if id.Grants == nil {
		id.Grants = []string{}
	}
	if id.RequestID == "" {
		id.RequestID = uuid.NewString()
	}
	iat, exp := now, now.Add(60*time.Second)
	if !id.IssuedAt.IsZero() {
		iat = id.IssuedAt
	}
	if !id.ExpiresAt.IsZero() {
		exp = id.ExpiresAt
	}
	t := paseto.NewToken()
	t.SetIssuer(identity.Issuer)
	t.SetAudience(identity.Audience)
	t.SetSubject(id.UserID.String())
	t.SetString("acct", id.AccountID.String())
	t.SetString("sid", id.SessionID.String())
	_ = t.Set("grants", id.Grants)
	_ = t.Set("amr", id.AMR)
	t.SetString("auth_time", id.AuthTime.UTC().Format(time.RFC3339))
	t.SetJti(id.RequestID)
	t.SetIssuedAt(iat)
	t.SetNotBefore(iat)
	t.SetExpiration(exp)
	footer, _ := json.Marshal(map[string]string{"kid": i.KID})
	t.SetFooter(footer)
	return t.V4Sign(i.secret, nil)
}
