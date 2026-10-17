package verifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Confirmation is the RFC 9449 / RFC 8705 sender constraint (TOK-019, MCH-014).
// Exactly one supported binding must be present; unknown bindings fail closed.
type Confirmation struct {
	JWKThumbprint         string `json:"jkt,omitempty"`
	CertificateThumbprint string `json:"x5t#S256,omitempty"`
}

func parseConfirmation(raw []byte) (*Confirmation, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || len(m) != 1 {
		return nil, ErrSenderConstraint
	}
	c := &Confirmation{}
	for k, v := range m {
		var value string
		if json.Unmarshal(v, &value) != nil {
			return nil, ErrSenderConstraint
		}
		b, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || len(b) != sha256.Size || base64.RawURLEncoding.EncodeToString(b) != value {
			return nil, ErrSenderConstraint
		}
		switch k {
		case "jkt":
			c.JWKThumbprint = value
		case "x5t#S256":
			c.CertificateThumbprint = value
		default:
			return nil, ErrSenderConstraint
		}
	}
	return c, nil
}

// ProofReplayStore atomically reserves a hashed key/JTI until expiresAt. Return
// false for a replay and an error when the authoritative store is unavailable.
// All instances serving the same API must share this store (SEC-008, TEST-067).
type ProofReplayStore interface {
	UseProof(ctx context.Context, digest string, expiresAt time.Time) (bool, error)
}

// MemoryProofReplayStore is bounded and safe for one resource-server process.
// Multiple processes require an application-provided shared atomic store.
type MemoryProofReplayStore struct {
	mu       sync.Mutex
	entries  map[string]time.Time
	capacity int
	now      func() time.Time
}

// NewMemoryProofReplayStore requires a positive maximum entry count. A full
// store denies new proofs instead of evicting still-valid replay evidence.
func NewMemoryProofReplayStore(capacity int) (*MemoryProofReplayStore, error) {
	if capacity < 1 {
		return nil, ErrMisconfigured
	}
	return &MemoryProofReplayStore{entries: make(map[string]time.Time), capacity: capacity, now: time.Now}, nil
}

func (s *MemoryProofReplayStore) UseProof(ctx context.Context, digest string, expiresAt time.Time) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for key, expiry := range s.entries {
		if !now.Before(expiry) {
			delete(s.entries, key)
		}
	}
	if _, present := s.entries[digest]; present {
		return false, nil
	}
	if len(s.entries) >= s.capacity {
		return false, ErrUnavailable
	}
	s.entries[digest] = expiresAt
	return true, nil
}

// SenderConfig selects exactly one token verifier and a trusted HTTPS public
// origin. Public request paths must reach this handler without rewriting.
type SenderConfig struct {
	Offline *Verifier
	Online  *Introspector
	// PublicOrigin has no path/query/fragment, e.g. https://api.example.com.
	// Host, Forwarded and X-Forwarded-* request headers never establish this URL.
	PublicOrigin string
	Replay       ProofReplayStore
	// IsTrustedTLSProxy permits a plaintext backend hop only when the caller
	// authenticates the TLS-terminating proxy through its deployment boundary.
	// No request header is trusted by default. Direct requests need r.TLS.
	IsTrustedTLSProxy func(*http.Request) bool
	// ClientCertificate is optional for explicitly authenticated TLS proxies.
	// It must obtain a certificate only from a trusted, integrity-protected
	// channel, strip spoofed headers and verify the proxy's handshake evidence.
	// By default, only r.TLS.PeerCertificates[0] is used (SEC-001, TEST-055).
	ClientCertificate func(*http.Request) (*x509.Certificate, error)
	// RequireBinding refuses ordinary bearer tokens when true.
	RequireBinding bool
	Now            func() time.Time
}

// SenderVerifier authenticates bearer, DPoP-bound and certificate-bound access
// tokens for an HTTP request. DPoP proofs use RS256/PS256 (RSA >=2048 bits),
// ES256 (P-256) or EdDSA (Ed25519), a two-minute age and 30-second future skew.
// This profile does not issue nonces; it always requires single-use replay state.
type SenderVerifier struct {
	cfg    SenderConfig
	origin string
}

func NewSenderVerifier(cfg SenderConfig) (*SenderVerifier, error) {
	if (cfg.Offline == nil) == (cfg.Online == nil) {
		return nil, ErrMisconfigured
	}
	u, err := url.Parse(cfg.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrMisconfigured
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	origin, err := normalizeProofURL(cfg.PublicOrigin)
	if err != nil {
		return nil, ErrMisconfigured
	}
	return &SenderVerifier{cfg: cfg, origin: strings.TrimSuffix(origin, "/")}, nil
}

// Authenticate refuses token-only calls: sender verification needs an HTTP
// request. Middleware dispatches to AuthenticateRequest; metadata adapters
// cannot silently drop the sender constraint (INT-001).
func (s *SenderVerifier) Authenticate(context.Context, string) (*Claims, error) {
	return nil, ErrSenderConstraint
}

func (s *SenderVerifier) AuthenticateRequest(r *http.Request) (*Claims, error) {
	if r == nil || r.URL == nil {
		return nil, ErrMalformed
	}
	if r.URL.Query().Has("access_token") {
		return nil, ErrTokenInQuery
	}
	if r.TLS == nil && (s.cfg.IsTrustedTLSProxy == nil || !s.cfg.IsTrustedTLSProxy(r)) {
		return nil, ErrSenderConstraint
	}
	auth := headerValues(r, "Authorization")
	if len(auth) == 0 {
		return nil, ErrMissingToken
	}
	if len(auth) != 1 {
		return nil, ErrMalformed
	}
	parts := strings.Fields(auth[0])
	if len(parts) != 2 || (!strings.EqualFold(parts[0], "Bearer") && !strings.EqualFold(parts[0], "DPoP")) {
		return nil, ErrMalformed
	}
	var c *Claims
	var err error
	if s.cfg.Offline != nil {
		c, err = s.cfg.Offline.verify(r.Context(), parts[1], true)
	} else {
		c, err = s.cfg.Online.authenticate(r.Context(), parts[1], true)
	}
	if err != nil {
		return nil, err
	}
	proofs := headerValues(r, "DPoP")
	if c.Confirmation == nil {
		if s.cfg.RequireBinding || !strings.EqualFold(parts[0], "Bearer") || len(proofs) != 0 {
			return nil, ErrSenderConstraint
		}
		return c, nil
	}
	if c.Confirmation.JWKThumbprint != "" {
		if !strings.EqualFold(parts[0], "DPoP") || len(proofs) != 1 || proofs[0] == "" {
			return nil, ErrDPoPProof
		}
		if s.cfg.Replay == nil {
			return nil, ErrMisconfigured
		}
		if err := s.verifyProof(r, parts[1], proofs[0], c.Confirmation.JWKThumbprint); err != nil {
			return nil, err
		}
		return c, nil
	}
	if !strings.EqualFold(parts[0], "Bearer") || len(proofs) != 0 {
		return nil, ErrSenderConstraint
	}
	var cert *x509.Certificate
	if s.cfg.ClientCertificate != nil {
		cert, err = s.cfg.ClientCertificate(r)
		if err != nil {
			return nil, ErrSenderConstraint
		}
	} else if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert = r.TLS.PeerCertificates[0]
	}
	if cert == nil || len(cert.Raw) == 0 {
		return nil, ErrSenderConstraint
	}
	sum := sha256.Sum256(cert.Raw)
	if !equalString(base64.RawURLEncoding.EncodeToString(sum[:]), c.Confirmation.CertificateThumbprint) {
		return nil, ErrSenderConstraint
	}
	return c, nil
}

func headerValues(r *http.Request, name string) []string {
	var out []string
	for k, values := range r.Header {
		if strings.EqualFold(k, name) {
			out = append(out, values...)
		}
	}
	return out
}

func equalString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *SenderVerifier) verifyProof(r *http.Request, accessToken, proof, binding string) error {
	if len(proof) > 4096 {
		return ErrDPoPProof
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return ErrDPoPProof
	}
	for _, p := range parts[:2] {
		b, err := base64.RawURLEncoding.Strict().DecodeString(p)
		if err != nil || rejectDuplicates(b) != nil {
			return ErrDPoPProof
		}
	}
	tok, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256, jose.EdDSA})
	if err != nil || len(tok.Headers) != 1 {
		return ErrDPoPProof
	}
	h := tok.Headers[0]
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	if typ != "dpop+jwt" || h.JSONWebKey == nil || !h.JSONWebKey.IsPublic() || !h.JSONWebKey.Valid() {
		return ErrDPoPProof
	}
	if _, critical := h.ExtraHeaders[jose.HeaderKey("crit")]; critical {
		return ErrDPoPProof
	}
	if h.JSONWebKey.Algorithm != "" && h.JSONWebKey.Algorithm != h.Algorithm {
		return ErrDPoPProof
	}
	if h.JSONWebKey.Use != "" && h.JSONWebKey.Use != "sig" {
		return ErrDPoPProof
	}
	switch key := h.JSONWebKey.Key.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 || (h.Algorithm != "RS256" && h.Algorithm != "PS256") {
			return ErrDPoPProof
		}
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() || h.Algorithm != "ES256" {
			return ErrDPoPProof
		}
	case ed25519.PublicKey:
		if h.Algorithm != "EdDSA" {
			return ErrDPoPProof
		}
	default:
		return ErrDPoPProof
	}
	var c struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT *int64 `json:"iat"`
		ATH string `json:"ath"`
	}
	if tok.Claims(h.JSONWebKey.Key, &c) != nil || c.IAT == nil || c.JTI == "" || len(c.JTI) > 128 || c.HTM != r.Method {
		return ErrDPoPProof
	}
	now := s.cfg.Now()
	iat := time.Unix(*c.IAT, 0)
	if iat.After(now.Add(30*time.Second)) || now.After(iat.Add(2*time.Minute)) {
		return ErrDPoPProof
	}
	target, err := normalizeProofURL(s.origin + r.URL.EscapedPath())
	if err != nil {
		return ErrDPoPProof
	}
	proofURL, err := normalizeProofURL(c.HTU)
	if err != nil || proofURL != target {
		return ErrDPoPProof
	}
	sum := sha256.Sum256([]byte(accessToken))
	if !equalString(c.ATH, base64.RawURLEncoding.EncodeToString(sum[:])) {
		return ErrDPoPProof
	}
	thumbprint, err := h.JSONWebKey.Thumbprint(crypto.SHA256)
	if err != nil || !equalString(binding, base64.RawURLEncoding.EncodeToString(thumbprint)) {
		return ErrSenderConstraint
	}
	digest := sha256.Sum256([]byte(binding + "\x00" + c.JTI))
	used, err := s.cfg.Replay.UseProof(r.Context(), base64.RawURLEncoding.EncodeToString(digest[:]), iat.Add(2*time.Minute+time.Second))
	if err != nil {
		return ErrUnavailable
	}
	if !used {
		return ErrProofReplay
	}
	return nil
}

// validProofHost reports whether the URL's authority is a host a proof may
// name: a bracketed IP literal (with an optional zone) or a DNS name of
// letters, digits, hyphens and dots, with an optional numeric port. net/url
// accepts authorities such as "::443" (hostname ":"), which would normalize
// to a URL with no host; the proof is invalid instead.
func validProofHost(u *url.URL) bool {
	hostname := u.Hostname()
	if hostname == "" {
		return false
	}
	if strings.HasPrefix(u.Host, "[") {
		ip, _, _ := strings.Cut(hostname, "%")
		return net.ParseIP(ip) != nil && strings.Contains(ip, ":")
	}
	for i := 0; i < len(hostname); i++ {
		b := hostname[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '.') {
			return false
		}
	}
	return true
}

// Normalization covers scheme/host case, the default HTTPS port, empty paths
// and percent-encoded unreserved characters. Queries/fragments are excluded
// by RFC 9449. Reserved escapes and repeated slashes remain significant.
func normalizeProofURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || !validProofHost(u) || u.User != nil || u.Opaque != "" {
		return "", ErrDPoPProof
	}
	// Authorities use ASCII (IDNs must use their A-label/punycode form).
	// net/url may accept raw non-ASCII zone bytes that it cannot round-trip.
	for _, b := range []byte(u.Host) {
		if b < 0x21 || b > 0x7e {
			return "", ErrDPoPProof
		}
	}
	host := strings.ToLower(u.Host)
	if u.Port() == "443" {
		host = strings.TrimSuffix(host, ":443")
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	var out strings.Builder
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(p); i++ {
		if p[i] != '%' {
			out.WriteByte(p[i])
			continue
		}
		decoded, err := url.PathUnescape(p[i : i+3])
		if err != nil {
			return "", ErrDPoPProof
		}
		b := decoded[0]
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b)) {
			out.WriteByte(b)
		} else {
			out.WriteByte('%')
			out.WriteByte(hex[b>>4])
			out.WriteByte(hex[b&15])
		}
		i += 2
	}
	// Let net/url serialize the authority (including escaped IPv6 zones) and
	// preserve significant reserved path escapes without double-encoding.
	u.Scheme, u.Host = "https", host
	u.Path, err = url.PathUnescape(out.String())
	if err != nil {
		return "", ErrDPoPProof
	}
	u.RawPath = out.String()
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	u.ForceQuery = false
	return u.String(), nil
}
