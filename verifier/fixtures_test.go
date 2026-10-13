package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Shared verification fixtures (SDK-009): accepted and rejected access tokens
// with the key set that signs them, so independent services and other SDKs can
// test their verification without real customer data. Regenerate with
// PROUDAUTH_REGENERATE_FIXTURES=1 go test ./verifier -run TestFixtures.

const fixtureDir = "../testdata/contracts/access-tokens"

type fixtureFile struct {
	Description string             `json:"description"`
	Issuer      string             `json:"issuer"`
	Audience    string             `json:"audience"`
	Now         int64              `json:"now"`
	JWKS        jose.JSONWebKeySet `json:"jwks"`
	Cases       []fixtureCase      `json:"cases"`
}

type fixtureCase struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Expect string `json:"expect"` // "accept" or an error code
	Why    string `json:"why"`
}

var fixtureErrors = map[string]error{
	"malformed": ErrMalformed, "duplicate_claim": ErrDuplicateClaim, "token_type": ErrTokenType, "algorithm": ErrAlgorithm,
	"unknown_key": ErrUnknownKey, "signature": ErrSignature, "issuer": ErrIssuer, "audience": ErrAudience, "expired": ErrExpired,
	"not_yet_valid": ErrNotYetValid, "future_issued": ErrFutureIssued, "token_kind": ErrTokenKind, "too_large": ErrTooLarge,
	"sender_constraint": ErrSenderConstraint,
}

// TestFixtures covers SDK-001's negative test vectors: the first-party
// verifier, configured with one issuer and audience, accepts the published
// good tokens (with their organization) and rejects each bad one with its own
// error (algorithm, token type, key, signature, issuer, audience, time).
func TestFixtures(t *testing.T) {
	path := filepath.Join(fixtureDir, "cases.json")
	if os.Getenv("PROUDAUTH_REGENERATE_FIXTURES") == "1" {
		generateFixtures(t, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fx fixtureFile
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fx.JWKS)
	}))
	defer srv.Close()
	v, err := New(Config{Issuer: fx.Issuer, Audience: fx.Audience, JWKSURL: srv.URL, Now: func() time.Time { return time.Unix(fx.Now, 0) },
		MinRefreshInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range fx.Cases {
		if _, known := fixtureErrors[c.Expect]; c.Expect != "accept" && !known {
			t.Errorf("%s: unknown expected category %q", c.Name, c.Expect)
			continue
		}
		_, err := v.Verify(context.Background(), c.Token)
		switch {
		case c.Expect == "accept" && err != nil:
			t.Errorf("%s: rejected a valid token: %v", c.Name, err)
		case c.Expect != "accept" && !errors.Is(err, fixtureErrors[c.Expect]):
			t.Errorf("%s: want %s, got %v", c.Name, c.Expect, err)
		}
	}
}

// generateFixtures writes the fixture file with fresh test-only keys.
func generateFixtures(t *testing.T, path string) {
	rsKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	const iss, aud = "https://id.example.test/realms/main", "https://api.example.test/orders"
	const now = int64(1_900_000_000)
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: rsKey.Public(), KeyID: "rs-fixture-1", Algorithm: "RS256", Use: "sig"},
		{Key: edKey.Public(), KeyID: "ed-fixture-1", Algorithm: "EdDSA", Use: "sig"},
	}}
	claims := func(over map[string]any) map[string]any {
		c := map[string]any{"iss": iss, "aud": aud, "sub": "usr_fixture", "client_id": "fixture-client", "iat": now - 10, "nbf": now - 10,
			"exp": now + 300, "jti": "tok_fixture", "scope": "orders:read", "token_kind": "user_access", "org_id": "org_fixture"}
		for k, v := range over {
			if v == nil {
				delete(c, k)
			} else {
				c[k] = v
			}
		}
		return c
	}
	sign := func(key any, alg jose.SignatureAlgorithm, kid, typ string, payload map[string]any) string {
		opts := (&jose.SignerOptions{}).WithHeader("kid", kid)
		if typ != "" {
			opts = opts.WithType(jose.ContentType(typ))
		}
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(payload)
		obj, err := s.Sign(body)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := obj.CompactSerialize()
		return out
	}
	rs := func(payload map[string]any) string { return sign(rsKey, jose.RS256, "rs-fixture-1", "at+jwt", payload) }
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	valid := rs(claims(nil))
	parts := strings.Split(valid, ".")
	tampered := parts[0] + "." + b64(strings.Replace(string(mustB64(t, parts[1])), "orders:read", "orders:admin", 1)) + "." + parts[2]
	hdrNone := b64(`{"alg":"none","kid":"rs-fixture-1","typ":"at+jwt"}`)
	dupPayload := b64(`{"iss":"` + iss + `","aud":"` + aud + `","sub":"usr_fixture","sub":"usr_admin","exp":1900000300}`)
	cases := []fixtureCase{
		{"valid_rs256_user_access", valid, "accept", "well-formed user access token"},
		{"valid_eddsa_service_access", sign(edKey, jose.EdDSA, "ed-fixture-1", "at+jwt", claims(map[string]any{"token_kind": "service_access",
			"sub": "svc_fixture", "org_id": nil})), "accept", "service principal token signed with EdDSA"},
		{"wrong_issuer", rs(claims(map[string]any{"iss": "https://evil.example.test/realms/main"})), "issuer", "issuer must match exactly"},
		{"wrong_audience", rs(claims(map[string]any{"aud": "https://api.example.test/billing"})), "audience", "token for another API"},
		{"multiple_audiences", rs(claims(map[string]any{"aud": []string{aud, "https://api.example.test/billing"}})), "audience", "exactly one audience"},
		{"expired", rs(claims(map[string]any{"exp": now - 120})), "expired", "beyond the 30s skew"},
		{"missing_exp", rs(claims(map[string]any{"exp": nil})), "expired", "exp is mandatory"},
		{"not_yet_valid", rs(claims(map[string]any{"nbf": now + 600})), "not_yet_valid", "nbf in the future"},
		{"issued_in_future", rs(claims(map[string]any{"iat": now + 600})), "future_issued", "iat in the future"},
		{"tampered_payload", tampered, "signature", "payload changed after signing"},
		{"signed_by_unknown_key", sign(other, jose.RS256, "rs-unknown-9", "at+jwt", claims(nil)), "unknown_key", "kid not in the key set"},
		{"signed_by_other_key_same_kid", sign(other, jose.RS256, "rs-fixture-1", "at+jwt", claims(nil)), "signature", "key confusion"},
		{"alg_none", hdrNone + "." + parts[1] + ".", "algorithm", "unsigned tokens are never accepted"},
		{"id_token_type", sign(rsKey, jose.RS256, "rs-fixture-1", "JWT", claims(nil)), "token_type", "an ID token is not an access token"},
		{"impersonation_kind", rs(claims(map[string]any{"token_kind": "impersonation_access"})), "token_kind", "support tokens are online-only"},
		{"missing_client_id", rs(claims(map[string]any{"client_id": nil})), "token_kind", "client_id is mandatory"},
		{"duplicate_claim", parts[0] + "." + dupPayload + "." + parts[2], "duplicate_claim", "duplicate JSON members are rejected"},
		{"not_a_jwt", "not.a.jwt.at.all", "malformed", "five segments"},
		{"dpop_requires_sender_proof", rs(claims(map[string]any{"cnf": map[string]any{"jkt": b64(strings.Repeat("x", 32))}})), "sender_constraint", "token-only APIs cannot verify the DPoP sender"},
		{"mtls_requires_certificate", rs(claims(map[string]any{"cnf": map[string]any{"x5t#S256": b64(strings.Repeat("x", 32))}})), "sender_constraint", "token-only APIs cannot verify the TLS sender"},
		{"unknown_confirmation", rs(claims(map[string]any{"cnf": map[string]any{"unknown": "binding"}})), "sender_constraint", "unsupported confirmation cannot become bearer authority"},
		{"null_confirmation", rs(claims(map[string]any{"cnf": json.RawMessage(`null`)})), "sender_constraint", "an explicit malformed confirmation cannot be ignored"},
	}
	fx := fixtureFile{Description: "ProudAuth access-token verification fixtures (SDK-009). Test-only keys; never trust them in production.",
		Issuer: iss, Audience: aud, Now: now, JWKS: jwks, Cases: cases}
	out, _ := json.MarshalIndent(fx, "", "  ")
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustB64(t *testing.T, s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
