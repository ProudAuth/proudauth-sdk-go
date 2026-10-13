package verifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type senderFixture struct {
	v     *Verifier
	s     *SenderVerifier
	now   time.Time
	issue func(any) string
}

func newSenderFixture(t *testing.T) *senderFixture {
	t.Helper()
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: "sender-issuer", Algorithm: "EdDSA"}}})
	}))
	t.Cleanup(srv.Close)
	v, err := New(Config{Issuer: "https://id.example.test", Audience: "orders", JWKSURL: srv.URL, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	replay, _ := NewMemoryProofReplayStore(1000)
	s, err := NewSenderVerifier(SenderConfig{Offline: v, PublicOrigin: "https://api.example.test", Replay: replay, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return &senderFixture{v: v, s: s, now: now, issue: func(cnf any) string {
		claims := map[string]any{"iss": "https://id.example.test", "aud": "orders", "sub": "user", "client_id": "client", "jti": "access",
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "token_kind": "user_access", "org_id": "org"}
		if cnf != nil {
			claims["cnf"] = cnf
		}
		return senderSign(t, private, jose.EdDSA, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "sender-issuer"), claims)
	}}
}

func senderSign(t *testing.T, key any, alg jose.SignatureAlgorithm, options *jose.SignerOptions, claims any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(claims)
	obj, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := obj.CompactSerialize()
	return raw
}

func senderThumbprint(t *testing.T, key jose.JSONWebKey) string {
	t.Helper()
	b, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func senderProof(t *testing.T, key any, alg jose.SignatureAlgorithm, token string, now time.Time, override map[string]any, options *jose.SignerOptions) string {
	t.Helper()
	pub := (&jose.JSONWebKey{Key: key}).Public()
	if options == nil {
		options = (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", pub)
	}
	sum := sha256.Sum256([]byte(token))
	c := map[string]any{"htm": "GET", "htu": "https://api.example.test/orders", "iat": now.Unix(), "jti": "proof-unique", "ath": base64.RawURLEncoding.EncodeToString(sum[:])}
	for k, v := range override {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return senderSign(t, key, alg, options, c)
}

func senderRequest(token, proof string) *http.Request {
	r := httptest.NewRequest("GET", "https://api.example.test/orders?view=small", nil)
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("DPoP", proof)
	return r
}

// TestSenderProofs exercises the resource-side sender constraint, including
// the default bearer rejection and all four cryptographic profiles (TEST-067).
func TestSenderProofs(t *testing.T) {
	f := newSenderFixture(t)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		alg jose.SignatureAlgorithm
		key any
	}{{jose.RS256, rsaKey}, {jose.PS256, rsaKey}, {jose.ES256, ecKey}, {jose.EdDSA, edKey}} {
		t.Run(string(tc.alg), func(t *testing.T) {
			pub := (&jose.JSONWebKey{Key: tc.key}).Public()
			token := f.issue(map[string]any{"jkt": senderThumbprint(t, pub)})
			if _, err := f.v.Verify(context.Background(), token); !errors.Is(err, ErrSenderConstraint) {
				t.Fatalf("bare Verify accepted bound token: %v", err)
			}
			proof := senderProof(t, tc.key, tc.alg, token, f.now, map[string]any{"jti": string(tc.alg)}, nil)
			r := senderRequest(token, proof)
			var reached bool
			w := httptest.NewRecorder()
			Middleware(f.s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				if c := FromContext(r.Context()); c.Confirmation.JWKThumbprint != senderThumbprint(t, pub) || c.OrgID != "org" {
					t.Fatal("verified context lost sender or tenant")
				}
			})).ServeHTTP(w, r)
			if !reached || w.Code != 200 {
				t.Fatalf("valid proof refused: HTTP %d", w.Code)
			}
			if _, err := f.s.AuthenticateRequest(r); !errors.Is(err, ErrProofReplay) {
				t.Fatalf("replay: %v", err)
			}
		})
	}
}

func TestSenderProofNegativeCases(t *testing.T) {
	f := newSenderFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := (&jose.JSONWebKey{Key: key}).Public()
	token := f.issue(map[string]any{"jkt": senderThumbprint(t, pub)})
	for _, tc := range []struct {
		name string
		edit map[string]any
	}{
		{"wrong method", map[string]any{"htm": "POST"}},
		{"method case", map[string]any{"htm": "get"}},
		{"wrong claim case", map[string]any{"htm": nil, "HTM": "GET"}},
		{"wrong time claim case", map[string]any{"iat": nil, "IAT": f.now.Unix()}},
		{"wrong path", map[string]any{"htu": "https://api.example.test/billing"}},
		{"wrong origin", map[string]any{"htu": "https://evil.example.test/orders"}},
		{"userinfo", map[string]any{"htu": "https://user@api.example.test/orders"}},
		{"insecure URI", map[string]any{"htu": "http://api.example.test/orders"}},
		{"stale", map[string]any{"iat": f.now.Add(-121 * time.Second).Unix()}},
		{"future", map[string]any{"iat": f.now.Add(31 * time.Second).Unix()}},
		{"missing iat", map[string]any{"iat": nil}},
		{"fractional iat", map[string]any{"iat": float64(f.now.Unix()) + 0.5}},
		{"missing jti", map[string]any{"jti": nil}},
		{"large jti", map[string]any{"jti": string(make([]byte, 129))}},
		{"wrong ath", map[string]any{"ath": "wrong"}},
		{"missing ath", map[string]any{"ath": nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := senderProof(t, key, jose.ES256, token, f.now, tc.edit, nil)
			if _, err := f.s.AuthenticateRequest(senderRequest(token, p)); !errors.Is(err, ErrDPoPProof) {
				t.Fatalf("invalid proof: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		opts *jose.SignerOptions
	}{
		{"private key", (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: key})},
		{"wrong type", (&jose.SignerOptions{}).WithType("JWT").WithHeader("jwk", pub)},
		{"missing key", (&jose.SignerOptions{}).WithType("dpop+jwt")},
		{"unknown critical header", (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", pub).WithHeader("crit", []string{"unknown"}).WithHeader("unknown", true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := senderProof(t, key, jose.ES256, token, f.now, nil, tc.opts)
			if _, err := f.s.AuthenticateRequest(senderRequest(token, p)); !errors.Is(err, ErrDPoPProof) {
				t.Fatalf("unsafe header: %v", err)
			}
		})
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := f.s.AuthenticateRequest(senderRequest(token, senderProof(t, other, jose.ES256, token, f.now, nil, nil))); !errors.Is(err, ErrSenderConstraint) {
		t.Fatalf("wrong binding: %v", err)
	}
	p := senderProof(t, key, jose.ES256, token, f.now, nil, nil)
	for _, edit := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
		func(r *http.Request) { r.Header.Del("DPoP") },
		func(r *http.Request) { r.Header.Add("DPoP", p) },
		func(r *http.Request) { r.Header.Add("Authorization", "DPoP "+token) },
	} {
		r := senderRequest(token, p)
		edit(r)
		if _, err := f.s.AuthenticateRequest(r); err == nil {
			t.Fatal("missing or ambiguous header accepted")
		}
	}
	// A failed proof does not consume an otherwise valid proof's JTI.
	r := senderRequest(token, p)
	r.Host = "evil.example.test"
	r.Header.Set("Forwarded", "host=evil.example.test;proto=http")
	r.Header.Set("X-Forwarded-Host", "evil.example.test")
	if _, err := f.s.AuthenticateRequest(r); err != nil {
		t.Fatalf("trusted configured public origin was replaced: %v", err)
	}
}

func TestSenderCertificateAndBearerPolicy(t *testing.T) {
	f := newSenderFixture(t)
	cert := &x509.Certificate{Raw: []byte("synthetic-certificate-DER")}
	sum := sha256.Sum256(cert.Raw)
	token := f.issue(map[string]any{"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:])})
	r := httptest.NewRequest("GET", "/orders", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Client-Cert", string(cert.Raw))
	if _, err := f.s.AuthenticateRequest(r); !errors.Is(err, ErrSenderConstraint) {
		t.Fatalf("forged certificate header accepted: %v", err)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("wrong")}}}
	if _, err := f.s.AuthenticateRequest(r); !errors.Is(err, ErrSenderConstraint) {
		t.Fatalf("wrong TLS certificate: %v", err)
	}
	r.TLS.PeerCertificates[0] = cert
	if _, err := f.s.AuthenticateRequest(r); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Authenticate(context.Background(), token); !errors.Is(err, ErrSenderConstraint) {
		t.Fatalf("token-only sender call: %v", err)
	}
	for _, cnf := range []any{map[string]any{}, map[string]any{"jkt": ""}, map[string]any{"other": base64.RawURLEncoding.EncodeToString(sum[:])},
		map[string]any{"jkt": base64.RawURLEncoding.EncodeToString(sum[:]), "x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:])}, "invalid", []string{"invalid"}} {
		r.Header.Set("Authorization", "Bearer "+f.issue(cnf))
		if _, err := f.s.AuthenticateRequest(r); !errors.Is(err, ErrSenderConstraint) {
			t.Fatalf("malformed confirmation %#v: %v", cnf, err)
		}
	}
	r.Header.Set("Authorization", "Bearer "+f.issue(nil))
	if _, err := f.s.AuthenticateRequest(r); err != nil {
		t.Fatal(err)
	}
	s, _ := NewSenderVerifier(SenderConfig{Offline: f.v, PublicOrigin: "https://api.example.test", RequireBinding: true})
	if _, err := s.AuthenticateRequest(r); !errors.Is(err, ErrSenderConstraint) {
		t.Fatalf("binding-required API accepted bearer: %v", err)
	}
}

type brokenProofStore struct{}

func (brokenProofStore) UseProof(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("unavailable")
}

func TestSenderReplayConcurrencyAndFailure(t *testing.T) {
	f := newSenderFixture(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	token := f.issue(map[string]any{"jkt": senderThumbprint(t, (&jose.JSONWebKey{Key: key}).Public())})
	proof := senderProof(t, key, jose.EdDSA, token, f.now, nil, nil)
	var winners atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_, err := f.s.AuthenticateRequest(senderRequest(token, proof))
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrProofReplay) {
				t.Errorf("concurrent check: %v", err)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("proof accepted %d times", winners.Load())
	}
	f.s.cfg.Replay = brokenProofStore{}
	if _, err := f.s.AuthenticateRequest(senderRequest(token, proof)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("store outage: %v", err)
	}
	f.s.cfg.Replay = nil
	if _, err := f.s.AuthenticateRequest(senderRequest(token, proof)); !errors.Is(err, ErrMisconfigured) {
		t.Fatalf("missing store: %v", err)
	}
	store, _ := NewMemoryProofReplayStore(1)
	if ok, err := store.UseProof(context.Background(), "one", f.now.Add(time.Minute)); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if _, err := store.UseProof(context.Background(), "two", f.now.Add(time.Minute)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("full cache evicted replay state: %v", err)
	}
	if ok, err := store.UseProof(context.Background(), "one", f.now.Add(time.Minute)); ok || err != nil {
		t.Fatal("original proof lost", ok, err)
	}
	store.now = func() time.Time { return f.now.Add(2 * time.Minute) }
	if ok, err := store.UseProof(context.Background(), "two", f.now.Add(3*time.Minute)); !ok || err != nil {
		t.Fatal("expired entries not removed", ok, err)
	}
}

func TestSenderOnlineOpaqueTokens(t *testing.T) {
	f := newSenderFixture(t)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	jkt := senderThumbprint(t, (&jose.JSONWebKey{Key: key}).Public())
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.FormValue("token") != "opaque-token" {
			t.Error("wrong introspection token")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "iss": "https://id.example.test", "aud": "orders", "sub": "user", "client_id": "client",
			"token_kind": "user_access", "cnf": map[string]any{"jkt": jkt}})
	}))
	defer srv.Close()
	i := &Introspector{Endpoint: srv.URL, Issuer: "https://id.example.test", Audience: "orders"}
	if _, err := i.Authenticate(context.Background(), "opaque-token"); !errors.Is(err, ErrSenderConstraint) {
		t.Fatalf("bare online call accepted bound token: %v", err)
	}
	replay, _ := NewMemoryProofReplayStore(10)
	s, _ := NewSenderVerifier(SenderConfig{Online: i, PublicOrigin: "https://api.example.test", Replay: replay, Now: func() time.Time { return f.now }})
	proof := senderProof(t, key, jose.EdDSA, "opaque-token", f.now, nil, nil)
	if c, err := s.AuthenticateRequest(senderRequest("opaque-token", proof)); err != nil || !c.Online || c.Confirmation.JWKThumbprint != jkt {
		t.Fatal("opaque proof", c, err)
	}
	if _, err := s.AuthenticateRequest(senderRequest("opaque-token", proof)); !errors.Is(err, ErrProofReplay) {
		t.Fatal("opaque replay", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("positive introspection cache: calls %d", calls.Load())
	}
}

func TestSenderURLNormalization(t *testing.T) {
	for input, want := range map[string]string{
		"HTTPS://API.EXAMPLE.TEST:443/orders?x=1#part": "https://api.example.test/orders",
		"https://api.example.test":                     "https://api.example.test/",
		"https://api.example.test/%6f%72ders":          "https://api.example.test/orders",
		"https://api.example.test/a%2fb//c":            "https://api.example.test/a%2Fb//c",
		"https://[fe80::1%25lo0]:443/orders":           "https://[fe80::1%25lo0]/orders",
	} {
		got, err := normalizeProofURL(input)
		if err != nil || got != want {
			t.Errorf("%s: %s, %v", input, got, err)
		}
	}
}

func FuzzSenderURLNormalization(f *testing.F) {
	for _, seed := range []string{"https://api.example.test/orders?view=1", "https://[fe80::1%25lo0]:443/a%2fb", "https://host/%", "https://:443/"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		first, err := normalizeProofURL(raw)
		if err != nil {
			return
		}
		second, err := normalizeProofURL(first)
		if err != nil || second != first {
			t.Fatalf("normalization is not stable: %q -> %q -> %q (%v)", raw, first, second, err)
		}
	})
}

func TestSenderUntrustedTransport(t *testing.T) {
	f := newSenderFixture(t)
	r := httptest.NewRequest("GET", "http://api.example.test/orders", nil)
	r.Header.Set("Authorization", "Bearer "+f.issue(nil))
	r.Header.Set("X-Forwarded-Proto", "https")
	if _, err := f.s.AuthenticateRequest(r); !errors.Is(err, ErrSenderConstraint) {
		t.Fatalf("untrusted plaintext transport: %v", err)
	}
	f.s.cfg.IsTrustedTLSProxy = func(r *http.Request) bool { return r.RemoteAddr == "127.0.0.1:1234" }
	if _, err := f.s.AuthenticateRequest(r); !errors.Is(err, ErrSenderConstraint) {
		t.Fatalf("untrusted proxy: %v", err)
	}
	r.RemoteAddr = "127.0.0.1:1234"
	if _, err := f.s.AuthenticateRequest(r); err != nil {
		t.Fatalf("authenticated proxy rejected: %v", err)
	}
}

func TestIntrospectionRejectsAmbiguousOrOversizedJSON(t *testing.T) {
	for _, body := range []string{
		`{"active":false,"active":true,"iss":"https://id.example.test","aud":"orders","token_kind":"user_access"}`,
		`{"active":true,"iss":"https://id.example.test","aud":"orders","token_kind":"user_access"} {}`,
		`{"active":true,"pad":"` + strings.Repeat("x", 64<<10) + `"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		i := &Introspector{Endpoint: srv.URL, Issuer: "https://id.example.test", Audience: "orders"}
		_, err := i.Authenticate(context.Background(), "opaque-token")
		srv.Close()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("ambiguous/oversized response accepted: %v", err)
		}
	}
}
