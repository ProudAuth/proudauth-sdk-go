package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// TestMultiIssuer covers INT-009: tokens of explicitly registered issuers
// verify and carry their tenant; a validly signed token from an unrelated
// issuer is refused even when its subject collides with a known one.
func TestMultiIssuer(t *testing.T) {
	const aud = "https://api.example.test/orders"
	type issuer struct {
		url string
		key ed25519.PrivateKey
		srv *httptest.Server
	}
	mk := func(url, kid string) *issuer {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: k.Public(), KeyID: kid, Algorithm: "EdDSA", Use: "sig"}}}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(set) }))
		return &issuer{url: url, key: k, srv: srv}
	}
	a, b, rogue := mk("https://id.example.test/realms/acme", "a1"), mk("https://id.example.test/realms/globex", "b1"), mk("https://rogue.example.test", "r1")
	defer a.srv.Close()
	defer b.srv.Close()
	defer rogue.srv.Close()
	sign := func(i *issuer, kid string) string {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: i.key}, (&jose.SignerOptions{}).WithHeader("kid", kid).WithType("at+jwt"))
		now := time.Now().Unix()
		body, _ := json.Marshal(map[string]any{"iss": i.url, "aud": aud, "sub": "usr_same", "client_id": "web", "iat": now, "exp": now + 300,
			"jti": "j", "scope": "orders:read", "token_kind": "user_access"})
		obj, _ := s.Sign(body)
		out, _ := obj.CompactSerialize()
		return out
	}
	verifier := func(i *issuer) *Verifier {
		v, err := New(Config{Issuer: i.url, Audience: aud, JWKSURL: i.srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	m, err := NewMultiIssuer(map[string]IssuerRegistration{a.url: {Verifier: verifier(a), Tenant: "acme"}, b.url: {Verifier: verifier(b), Tenant: "globex"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ta, err := m.VerifyTenant(ctx, sign(a, "a1"))
	if err != nil || ta.Tenant != "acme" || ta.Subject != "usr_same" {
		t.Fatalf("acme token: %+v %v", ta, err)
	}
	tb, err := m.VerifyTenant(ctx, sign(b, "b1"))
	if err != nil || tb.Tenant != "globex" {
		t.Fatalf("globex token: %+v %v", tb, err)
	}
	if _, err := m.VerifyTenant(ctx, sign(rogue, "r1")); !errors.Is(err, ErrIssuer) {
		t.Fatalf("unrelated issuer: %v", err)
	}
	if _, err := NewMultiIssuer(map[string]IssuerRegistration{b.url: {Verifier: verifier(a), Tenant: "x"}}); err == nil {
		t.Fatal("a registration must use a verifier for exactly its issuer")
	}
}
