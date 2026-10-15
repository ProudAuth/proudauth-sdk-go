// Package verifier is the first-party resource-server verification library
// (SDK-001, SDK-002). It is independent of the server's internal packages.
//
// Offline mode verifies JWT access tokens with the §14.4 algorithm: a preconfigured
// trusted issuer, strict parsing with duplicate-member rejection, explicit "at+jwt"
// typing, an asymmetric algorithm allowlist, key IDs resolved only from that
// issuer's key set with bounded, coalesced refreshes, exact issuer and audience
// checks, and fail-closed errors. Offline verification cannot observe revocation
// before expiry (SES-023); use the Introspector for strict-online resources.
package verifier

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/proudauth/proudauth-sdk-go/internal/httpclient"
)

// Errors are stable categories safe to log; they never contain token material (SDK-008).
var (
	ErrMissingToken     = errors.New("verifier: missing bearer token")
	ErrMalformed        = errors.New("verifier: malformed token")
	ErrTokenType        = errors.New("verifier: wrong token type")
	ErrAlgorithm        = errors.New("verifier: algorithm not allowed")
	ErrUnknownKey       = errors.New("verifier: unknown signing key")
	ErrSignature        = errors.New("verifier: invalid signature")
	ErrIssuer           = errors.New("verifier: untrusted issuer")
	ErrAudience         = errors.New("verifier: wrong audience")
	ErrExpired          = errors.New("verifier: token expired")
	ErrNotYetValid      = errors.New("verifier: token not yet valid")
	ErrFutureIssued     = errors.New("verifier: token issued in the future")
	ErrTokenKind        = errors.New("verifier: token kind not accepted")
	ErrInactive         = errors.New("verifier: token is not active")
	ErrUnavailable      = errors.New("verifier: verification dependency unavailable")
	ErrOrganization     = errors.New("verifier: organization mismatch")
	ErrScope            = errors.New("verifier: required scope missing")
	ErrSupportPolicy    = errors.New("verifier: support access not permitted for this operation")
	ErrTooLarge         = errors.New("verifier: token too large")
	ErrDuplicateClaim   = errors.New("verifier: duplicate JSON member")
	ErrSenderConstraint = errors.New("verifier: sender constraint not satisfied")
	ErrDPoPProof        = errors.New("verifier: invalid DPoP proof")
	ErrProofReplay      = errors.New("verifier: DPoP proof replayed")
	// ErrTokenInQuery is a malformed request: bearer tokens are accepted only in
	// the Authorization header (TOK-023).
	ErrTokenInQuery = fmt.Errorf("%w: access token in query string", ErrMalformed)
	// ErrMisconfigured reports an unsafe verifier configuration.
	ErrMisconfigured = errors.New("verifier: issuer and audience must be configured")
)

// Actor is the RFC 8693 actor claim.
type Actor struct {
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub"`
	Act     *Actor `json:"act,omitempty"`
}

// Claims is the verified security context.
type Claims struct {
	Issuer               string
	Subject              string
	Audience             string
	ClientID             string
	Scopes               []string
	OrgID                string
	SessionID            string
	TokenKind            string
	JTI                  string
	IssuedAt             time.Time
	Expiry               time.Time
	AuthTime             time.Time
	ACR                  string
	AuthzVersion         int64
	Actor                *Actor
	SupportMode          string
	ImpersonationGrantID string
	// Confirmation is the verified sender binding, enforced by SenderVerifier.
	Confirmation *Confirmation
	// Online is true when live server state was consulted.
	Online bool
}

// HasScope reports whether the token carries scope s.
func (c *Claims) HasScope(s string) bool { return slices.Contains(c.Scopes, s) }

// RequireScope returns ErrScope unless all scopes are present.
func (c *Claims) RequireScope(scopes ...string) error {
	for _, s := range scopes {
		if !c.HasScope(s) {
			return ErrScope
		}
	}
	return nil
}

// RequireOrganization matches the verified organization context to the organization
// of the requested resource, which the caller must take from its own trusted data,
// never from the request body or a header (§14.4 step 8, TEST-007/008).
func (c *Claims) RequireOrganization(resourceOrgID string) error {
	if c.OrgID == "" || resourceOrgID == "" || c.OrgID != resourceOrgID {
		return ErrOrganization
	}
	return nil
}

// IsSupport reports whether the request is support impersonation.
func (c *Claims) IsSupport() bool { return c.TokenKind == "impersonation_access" }

// Config configures offline verification.
type Config struct {
	// Issuer is the exact trusted issuer. Tokens from any other issuer are rejected
	// without fetching anything (TEST-003).
	Issuer string
	// Audience is this API's registered audience.
	Audience string
	// JWKSURL defaults to Issuer + "/jwks". It is never taken from a token.
	JWKSURL string
	// Algorithms is the asymmetric allowlist; "none" and HMAC are never accepted.
	Algorithms []string
	// ClockSkew is the permitted tolerance (at most 60s).
	ClockSkew time.Duration
	// AcceptedKinds lists accepted token_kind values. Default: user_access,
	// service_access and exchange_access. Support tokens are opaque and handled by
	// the Introspector.
	AcceptedKinds []string
	// MinRefreshInterval bounds JWKS refreshes triggered by unknown key IDs (TEST-005).
	MinRefreshInterval time.Duration
	// MaxTokenBytes bounds token size.
	MaxTokenBytes int
	HTTPClient    *http.Client
	Now           func() time.Time
}

// Verifier verifies JWT access tokens offline.
type Verifier struct {
	cfg        Config
	mu         sync.Mutex
	keys       map[string]jose.JSONWebKey
	lastFetch  time.Time
	lastErr    error
	fetching   chan struct{}
	fetchCount int
}

// New validates configuration and returns a verifier.
func New(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("verifier: issuer and audience are required")
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = strings.TrimSuffix(cfg.Issuer, "/") + "/jwks"
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"RS256", "PS256", "ES256", "EdDSA"}
	}
	for _, a := range cfg.Algorithms {
		if a == "none" || strings.HasPrefix(a, "HS") {
			return nil, fmt.Errorf("verifier: algorithm %s is not allowed (no symmetric or unsigned tokens)", a)
		}
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	if cfg.ClockSkew > 60*time.Second {
		return nil, errors.New("verifier: clock skew must be at most 60s")
	}
	if len(cfg.AcceptedKinds) == 0 {
		cfg.AcceptedKinds = []string{"user_access", "service_access", "exchange_access"}
	}
	if slices.Contains(cfg.AcceptedKinds, "impersonation_access") {
		// Support tokens are opaque and must be validated online per request
		// through SupportGuard (IMP-010).
		return nil, errors.New("verifier: impersonation_access cannot be verified offline")
	}
	if cfg.MinRefreshInterval == 0 {
		cfg.MinRefreshInterval = 30 * time.Second
	}
	if cfg.MaxTokenBytes == 0 {
		cfg.MaxTokenBytes = 8192
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg, keys: map[string]jose.JSONWebKey{}}, nil
}

// FetchCount reports how many JWKS fetches occurred (diagnostics and tests).
func (v *Verifier) FetchCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.fetchCount
}

// refresh fetches the JWKS at most once per MinRefreshInterval; concurrent callers
// wait for the in-flight fetch (coalescing).
func (v *Verifier) refresh(ctx context.Context, force bool) error {
	v.mu.Lock()
	if ch := v.fetching; ch != nil {
		v.mu.Unlock()
		select {
		case <-ch:
			return nil
		case <-ctx.Done():
			return ErrUnavailable
		}
	}
	if !force && len(v.keys) > 0 {
		v.mu.Unlock()
		return nil
	}
	if !v.lastFetch.IsZero() && v.cfg.Now().Sub(v.lastFetch) < v.cfg.MinRefreshInterval {
		err := v.lastErr
		if len(v.keys) > 0 {
			err = nil
		}
		v.mu.Unlock()
		return err // a recent failed fetch keeps reporting unavailability, not "unknown key"
	}
	ch := make(chan struct{})
	v.fetching = ch
	v.lastFetch = v.cfg.Now()
	v.fetchCount++
	v.mu.Unlock()
	var fetchErr error
	defer func() {
		v.mu.Lock()
		v.fetching = nil
		v.lastErr = fetchErr
		v.mu.Unlock()
		close(ch)
	}()
	fetchErr = v.fetch(ctx)
	return fetchErr
}

func (v *Verifier) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return ErrUnavailable
	}
	res, err := httpclient.Do(v.cfg.HTTPClient, req)
	if err != nil {
		return ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return ErrUnavailable
	}
	// Keys are parsed individually so one unsupported key type does not make the
	// whole set unusable; duplicate key IDs are ambiguous and dropped (TEST-004).
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return ErrUnavailable
	}
	keys := map[string]jose.JSONWebKey{}
	dup := map[string]bool{}
	for _, raw := range set.Keys {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(raw); err != nil {
			continue
		}
		if k.KeyID == "" || !k.IsPublic() || (k.Use != "" && k.Use != "sig") {
			continue
		}
		if _, seen := keys[k.KeyID]; seen || dup[k.KeyID] {
			dup[k.KeyID] = true
			delete(keys, k.KeyID)
			continue
		}
		keys[k.KeyID] = k
	}
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return nil
}

func (v *Verifier) key(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	if err := v.refresh(ctx, false); err != nil {
		return jose.JSONWebKey{}, err
	}
	v.mu.Lock()
	k, ok := v.keys[kid]
	v.mu.Unlock()
	if ok {
		return k, nil
	}
	// One bounded refresh for an unknown kid; floods of random kids cannot cause
	// unbounded fetches (§14.4, TEST-005).
	if err := v.refresh(ctx, true); err != nil {
		return jose.JSONWebKey{}, err
	}
	v.mu.Lock()
	k, ok = v.keys[kid]
	v.mu.Unlock()
	if !ok {
		return jose.JSONWebKey{}, ErrUnknownKey
	}
	return k, nil
}

type rawClaims struct {
	Issuer       string           `json:"iss"`
	Subject      string           `json:"sub"`
	Audience     jwt.Audience     `json:"aud"`
	ClientID     string           `json:"client_id"`
	IssuedAt     *jwt.NumericDate `json:"iat"`
	NotBefore    *jwt.NumericDate `json:"nbf"`
	Expiry       *jwt.NumericDate `json:"exp"`
	JTI          string           `json:"jti"`
	SessionID    string           `json:"sid"`
	Scope        string           `json:"scope"`
	OrgID        string           `json:"org_id"`
	TokenKind    string           `json:"token_kind"`
	AuthzVersion int64            `json:"authz_version"`
	AuthTime     int64            `json:"auth_time"`
	ACR          string           `json:"acr"`
	Act          *Actor           `json:"act"`
	Confirmation json.RawMessage  `json:"cnf"`
}

// Verify verifies an ordinary bearer JWT access token offline. Sender-bound
// tokens require SenderVerifier.AuthenticateRequest, including on offline APIs.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	return v.verify(ctx, raw, false)
}

func (v *Verifier) verify(ctx context.Context, raw string, allowBound bool) (*Claims, error) {
	if raw == "" {
		return nil, ErrMissingToken
	}
	if len(raw) > v.cfg.MaxTokenBytes {
		return nil, ErrTooLarge
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	for _, p := range parts[:2] {
		seg, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return nil, ErrMalformed
		}
		if err := rejectDuplicates(seg); err != nil {
			return nil, err
		}
	}
	// Check the issuer before any key lookup so unrelated issuers never trigger fetches.
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var peek struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &peek); err != nil {
		return nil, ErrMalformed
	}
	if peek.Iss != v.cfg.Issuer {
		return nil, ErrIssuer
	}
	algs := make([]jose.SignatureAlgorithm, 0, len(v.cfg.Algorithms))
	for _, a := range v.cfg.Algorithms {
		algs = append(algs, jose.SignatureAlgorithm(a))
	}
	tok, err := jwt.ParseSigned(raw, algs)
	if err != nil {
		if strings.Contains(err.Error(), "algorithm") {
			return nil, ErrAlgorithm
		}
		return nil, ErrMalformed
	}
	if len(tok.Headers) != 1 {
		return nil, ErrMalformed
	}
	h := tok.Headers[0]
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	if t := strings.ToLower(typ); t != "at+jwt" && t != "application/at+jwt" {
		return nil, ErrTokenType // e.g. an ID token sent to an API (TEST-002)
	}
	if h.KeyID == "" {
		return nil, ErrUnknownKey
	}
	k, err := v.key(ctx, h.KeyID)
	if err != nil {
		return nil, err
	}
	if k.Algorithm != "" && k.Algorithm != h.Algorithm {
		return nil, ErrAlgorithm
	}
	var c rawClaims
	if err := tok.Claims(k.Key, &c); err != nil {
		return nil, ErrSignature
	}
	if c.Issuer != v.cfg.Issuer {
		return nil, ErrIssuer
	}
	if len(c.Audience) != 1 || c.Audience[0] != v.cfg.Audience {
		return nil, ErrAudience
	}
	now := v.cfg.Now()
	if c.Expiry == nil || now.After(c.Expiry.Time().Add(v.cfg.ClockSkew)) {
		return nil, ErrExpired
	}
	if c.NotBefore != nil && now.Add(v.cfg.ClockSkew).Before(c.NotBefore.Time()) {
		return nil, ErrNotYetValid
	}
	if c.IssuedAt != nil && c.IssuedAt.Time().After(now.Add(v.cfg.ClockSkew)) {
		return nil, ErrFutureIssued
	}
	if c.Subject == "" || c.ClientID == "" || c.JTI == "" || !slices.Contains(v.cfg.AcceptedKinds, c.TokenKind) {
		return nil, ErrTokenKind
	}
	confirmation, err := parseConfirmation(c.Confirmation)
	if err != nil || confirmation != nil && !allowBound {
		return nil, ErrSenderConstraint
	}
	out := &Claims{Issuer: c.Issuer, Subject: c.Subject, Audience: c.Audience[0], ClientID: c.ClientID, Scopes: strings.Fields(c.Scope),
		OrgID: c.OrgID, SessionID: c.SessionID, TokenKind: c.TokenKind, JTI: c.JTI, Expiry: c.Expiry.Time(), ACR: c.ACR,
		AuthzVersion: c.AuthzVersion, Actor: c.Act, Confirmation: confirmation}
	if c.IssuedAt != nil {
		out.IssuedAt = c.IssuedAt.Time()
	}
	if c.AuthTime > 0 {
		out.AuthTime = time.Unix(c.AuthTime, 0)
	}
	return out, nil
}

func rejectDuplicates(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 32 {
			return ErrMalformed
		}
		t, err := dec.Token()
		if err != nil {
			return ErrMalformed
		}
		d, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return ErrMalformed
				}
				k, _ := kt.(string)
				if seen[k] {
					return ErrDuplicateClaim
				}
				seen[k] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		}
		if err != nil {
			return ErrMalformed
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrMalformed
	}
	return nil
}

// BearerToken extracts a bearer token from the Authorization header only; tokens in
// query strings are refused (TOK-023).
func BearerToken(r *http.Request) (string, error) {
	if r.URL.Query().Has("access_token") {
		return "", ErrTokenInQuery
	}
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:]), nil
	}
	return "", ErrMissingToken
}

type ctxKey struct{}

// FromContext returns claims stored by Middleware.
func FromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxKey{}).(*Claims)
	return c
}

// WithClaims stores claims in a context.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// Authenticator is satisfied by Verifier and Introspector.
type Authenticator interface {
	Authenticate(ctx context.Context, raw string) (*Claims, error)
}

// RequestAuthenticator validates credentials and sender proofs for this request.
type RequestAuthenticator interface {
	AuthenticateRequest(r *http.Request) (*Claims, error)
}

// Authenticate implements Authenticator for offline verification.
func (v *Verifier) Authenticate(ctx context.Context, raw string) (*Claims, error) {
	return v.Verify(ctx, raw)
}

// Middleware authenticates requests and stores claims in the context. Failures
// never call next (deny by default) and are never cached (Cache-Control:
// no-store). The status follows the same mapping as the Node SDK's challenge:
// 401 with a WWW-Authenticate challenge for missing or invalid tokens, 400 for
// a token in the query string, 403 insufficient_scope for scope or
// organization errors, 403 for support-policy denials, 503 when a
// verification dependency is unavailable and 500 for an unsafe configuration.
func Middleware(a Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c *Claims
		var err error
		if requestAuth, ok := a.(RequestAuthenticator); ok {
			c, err = requestAuth.AuthenticateRequest(r)
		} else {
			var raw string
			raw, err = BearerToken(r)
			if err == nil {
				c, err = a.Authenticate(r.Context(), raw)
			}
		}
		if err == nil {
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), c)))
			return
		}
		status := challengeStatus(w.Header(), err)
		if status == http.StatusUnauthorized && strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "dpop ") {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, http.StatusText(status), status)
	})
}

// challengeStatus maps an authentication error to an HTTP status and sets the
// RFC 6750 challenge: no error code when no credentials were supplied,
// invalid_request for a malformed request, insufficient_scope when the token
// lacks the required scope or organization, invalid_token otherwise.
func challengeStatus(h http.Header, err error) int {
	switch {
	case errors.Is(err, ErrUnavailable), errors.Is(err, ErrStateStale):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrMisconfigured), errors.Is(err, ErrContract), errors.Is(err, ErrSupportKind):
		return http.StatusInternalServerError
	case errors.Is(err, ErrMissingToken):
		h.Set("WWW-Authenticate", `Bearer`)
		return http.StatusUnauthorized
	case errors.Is(err, ErrTokenInQuery):
		h.Set("WWW-Authenticate", `Bearer error="invalid_request"`)
		return http.StatusBadRequest
	case errors.Is(err, ErrScope), errors.Is(err, ErrOrganization):
		h.Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
		return http.StatusForbidden
	case errors.Is(err, ErrSupportPolicy):
		return http.StatusForbidden
	default:
		h.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		return http.StatusUnauthorized
	}
}
