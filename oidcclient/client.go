// Package oidcclient is a confidential-client helper for backends-for-frontends
// (SDK-004): authorization code + PKCE, state and nonce handling, strict ID-token
// validation (OIDC-016), server-side token storage with serialized refresh
// (SES-009), revocation and RP-initiated logout.
package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/proudbase/proudauth-sdk-go/internal/httpclient"
)

// Errors.
var (
	ErrState          = errors.New("oidcclient: state mismatch")
	ErrIDToken        = errors.New("oidcclient: invalid ID token")
	ErrNonce          = errors.New("oidcclient: nonce mismatch")
	ErrReauthenticate = errors.New("oidcclient: refresh failed; the user must authenticate again")
	ErrProvider       = errors.New("oidcclient: provider error")
)

// Config configures the client.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	Resource     string
	HTTPClient   *http.Client
	Now          func() time.Time
	Algorithms   []string
}

// Client is an OIDC relying-party client.
type Client struct {
	cfg       Config
	mu        sync.Mutex
	meta      map[string]any
	keys      map[string]jose.JSONWebKey
	lastFetch time.Time
}

// minKeyRefresh bounds JWKS refreshes triggered by unknown key IDs (TEST-005).
const minKeyRefresh = 30 * time.Second

// New returns a client. The issuer is trusted configuration; discovery is fetched
// only from it (never from a token or redirect).
func New(cfg Config) (*Client, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURI == "" {
		return nil, errors.New("oidcclient: issuer, client ID and redirect URI are required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"RS256", "PS256", "ES256", "EdDSA"}
	}
	return &Client{cfg: cfg, keys: map[string]jose.JSONWebKey{}}, nil
}

func (c *Client) discovery(ctx context.Context) (map[string]any, error) {
	c.mu.Lock()
	if c.meta != nil {
		m := c.meta
		c.mu.Unlock()
		return m, nil
	}
	c.mu.Unlock()
	var m map[string]any
	if err := c.getJSON(ctx, strings.TrimSuffix(c.cfg.Issuer, "/")+"/.well-known/openid-configuration", &m); err != nil {
		return nil, err
	}
	if m["issuer"] != c.cfg.Issuer {
		return nil, fmt.Errorf("%w: discovery issuer mismatch", ErrProvider)
	}
	c.mu.Lock()
	c.meta = m
	c.mu.Unlock()
	return m, nil
}

func (c *Client) endpoint(ctx context.Context, name string) (string, error) {
	m, err := c.discovery(ctx)
	if err != nil {
		return "", err
	}
	s, _ := m[name].(string)
	if s == "" || !sameOrigin(s, c.cfg.Issuer) {
		return "", fmt.Errorf("%w: missing or foreign endpoint %s", ErrProvider, name)
	}
	return s, nil
}

// sameOrigin requires an endpoint on the issuer's exact scheme and host, so
// discovery cannot redirect token traffic to a look-alike host.
func sameOrigin(endpoint, issuer string) bool {
	e, err1 := url.Parse(endpoint)
	i, err2 := url.Parse(issuer)
	return err1 == nil && err2 == nil && e.Scheme == i.Scheme && strings.EqualFold(e.Host, i.Host) && e.User == nil
}

func (c *Client) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	res, err := httpclient.Do(c.cfg.HTTPClient, req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("%w: %s returned %d", ErrProvider, u, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(v)
}

// Random returns a URL-safe random value (state, nonce, PKCE verifier).
func Random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Challenge returns the S256 PKCE challenge for a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthRequest is the per-login state that must be stored server-side (never only
// in a client-readable cookie).
type AuthRequest struct {
	State    string
	Nonce    string
	Verifier string
	URL      string
}

// AuthCodeURL builds an authorization request with state, nonce and PKCE S256.
func (c *Client) AuthCodeURL(ctx context.Context, extra url.Values) (*AuthRequest, error) {
	ep, err := c.endpoint(ctx, "authorization_endpoint")
	if err != nil {
		return nil, err
	}
	ar := &AuthRequest{State: Random(), Nonce: Random(), Verifier: Random()}
	q := url.Values{"client_id": {c.cfg.ClientID}, "redirect_uri": {c.cfg.RedirectURI}, "response_type": {"code"},
		"scope": {strings.Join(c.cfg.Scopes, " ")}, "state": {ar.State}, "nonce": {ar.Nonce}, "code_challenge": {Challenge(ar.Verifier)},
		"code_challenge_method": {"S256"}}
	if c.cfg.Resource != "" {
		q.Set("resource", c.cfg.Resource)
	}
	for k, v := range extra {
		switch k {
		case "client_id", "redirect_uri", "response_type", "state", "nonce", "code_challenge", "code_challenge_method":
			return nil, fmt.Errorf("oidcclient: parameter %q cannot be overridden", k)
		}
		q[k] = v
	}
	ar.URL = ep + "?" + q.Encode()
	return ar, nil
}

// Tokens is a token response.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	Scope        string    `json:"scope"`
	Expiry       time.Time `json:"-"`
}

func (c *Client) tokenRequest(ctx context.Context, form url.Values) (*Tokens, error) {
	ep, err := c.endpoint(ctx, "token_endpoint")
	if err != nil {
		return nil, err
	}
	if c.cfg.ClientSecret == "" {
		form.Set("client_id", c.cfg.ClientID) // public client: identify in the body
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	}
	res, err := httpclient.Do(c.cfg.HTTPClient, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "invalid_grant" {
			return nil, ErrReauthenticate
		}
		return nil, fmt.Errorf("%w: token endpoint %d %s", ErrProvider, res.StatusCode, e.Error)
	}
	var t Tokens
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	t.Expiry = c.cfg.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	return &t, nil
}

// Exchange validates state, redeems the code with the PKCE verifier and validates
// the ID token (nonce, at_hash) before returning tokens.
func (c *Client) Exchange(ctx context.Context, ar *AuthRequest, callback url.Values) (*Tokens, *IDClaims, error) {
	if callback.Get("error") != "" {
		return nil, nil, fmt.Errorf("%w: %s", ErrProvider, callback.Get("error"))
	}
	if ar == nil || callback.Get("state") == "" || callback.Get("state") != ar.State {
		return nil, nil, ErrState
	}
	meta, err := c.discovery(ctx)
	if err != nil {
		return nil, nil, err
	}
	iss := callback.Get("iss")
	if (iss == "" && meta["authorization_response_iss_parameter_supported"] == true) || (iss != "" && iss != c.cfg.Issuer) {
		// RFC 9207 mix-up defense: required when the provider advertises it.
		return nil, nil, fmt.Errorf("%w: authorization response issuer missing or mismatched", ErrProvider)
	}
	t, err := c.tokenRequest(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {callback.Get("code")},
		"code_verifier": {ar.Verifier}, "redirect_uri": {c.cfg.RedirectURI}})
	if err != nil {
		return nil, nil, err
	}
	var claims *IDClaims
	if t.IDToken == "" && slices.Contains(c.cfg.Scopes, "openid") {
		return nil, nil, fmt.Errorf("%w: missing ID token for an openid request", ErrIDToken)
	}
	if t.IDToken != "" {
		claims, err = c.ValidateIDToken(ctx, t.IDToken, ar.Nonce, t.AccessToken)
		if err != nil {
			return nil, nil, err
		}
	}
	return t, claims, nil
}

// IDClaims are validated ID-token claims.
type IDClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience []string `json:"-"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce"`
	ACR      string   `json:"acr"`
	AMR      []string `json:"amr"`
	AZP      string   `json:"azp"`
	SID      string   `json:"sid"`
	AtHash   string   `json:"at_hash"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
}

func (c *Client) key(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	c.mu.Lock()
	k, ok := c.keys[kid]
	recent := !c.lastFetch.IsZero() && c.cfg.Now().Sub(c.lastFetch) < minKeyRefresh
	c.mu.Unlock()
	if ok {
		return k, nil
	}
	if recent {
		return jose.JSONWebKey{}, ErrIDToken
	}
	ep, err := c.endpoint(ctx, "jwks_uri")
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	c.mu.Lock()
	c.lastFetch = c.cfg.Now()
	c.mu.Unlock()
	if err := c.getJSON(ctx, ep, &set); err != nil {
		return jose.JSONWebKey{}, err
	}
	// The fetched set replaces the old one, so retired keys stop verifying.
	keys := map[string]jose.JSONWebKey{}
	dup := map[string]bool{}
	for _, raw := range set.Keys {
		var jk jose.JSONWebKey
		if jk.UnmarshalJSON(raw) != nil || jk.KeyID == "" || !jk.IsPublic() || (jk.Use != "" && jk.Use != "sig") {
			continue
		}
		if _, seen := keys[jk.KeyID]; seen || dup[jk.KeyID] {
			dup[jk.KeyID] = true
			delete(keys, jk.KeyID)
			continue
		}
		keys[jk.KeyID] = jk
	}
	c.mu.Lock()
	c.keys = keys
	k, ok = c.keys[kid]
	c.mu.Unlock()
	if !ok {
		return jose.JSONWebKey{}, ErrIDToken
	}
	return k, nil
}

// ValidateIDToken verifies signature and then claims: exact issuer, audience
// containing the client, azp for multi-audience tokens, expiry, nonce and at_hash
// (OIDC-016). The payload is never trusted before signature verification.
func (c *Client) ValidateIDToken(ctx context.Context, raw, nonce, accessToken string) (*IDClaims, error) {
	algs := []jose.SignatureAlgorithm{}
	for _, a := range c.cfg.Algorithms {
		algs = append(algs, jose.SignatureAlgorithm(a))
	}
	tok, err := jwt.ParseSigned(raw, algs)
	if err != nil || len(tok.Headers) != 1 {
		return nil, ErrIDToken
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "" && !strings.EqualFold(typ, "JWT") {
		return nil, ErrIDToken // an access token (at+jwt) is not an ID token
	}
	k, err := c.key(ctx, h.KeyID)
	if err != nil {
		return nil, err
	}
	var rawClaims map[string]any
	if err := tok.Claims(k.Key, &rawClaims); err != nil {
		return nil, ErrIDToken
	}
	b, _ := json.Marshal(rawClaims)
	var cl IDClaims
	_ = json.Unmarshal(b, &cl)
	switch aud := rawClaims["aud"].(type) {
	case string:
		cl.Audience = []string{aud}
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				cl.Audience = append(cl.Audience, s)
			}
		}
	}
	now := c.cfg.Now()
	switch {
	case cl.Issuer != c.cfg.Issuer:
		return nil, fmt.Errorf("%w: issuer", ErrIDToken)
	case !slices.Contains(cl.Audience, c.cfg.ClientID):
		return nil, fmt.Errorf("%w: audience", ErrIDToken)
	case len(cl.Audience) > 1 && cl.AZP != c.cfg.ClientID:
		return nil, fmt.Errorf("%w: authorized party", ErrIDToken)
	case cl.AZP != "" && cl.AZP != c.cfg.ClientID:
		return nil, fmt.Errorf("%w: authorized party", ErrIDToken)
	case cl.Subject == "":
		return nil, fmt.Errorf("%w: subject", ErrIDToken)
	case cl.Expiry == 0 || now.After(time.Unix(cl.Expiry, 0).Add(30*time.Second)):
		return nil, fmt.Errorf("%w: expired", ErrIDToken)
	case cl.IssuedAt != 0 && time.Unix(cl.IssuedAt, 0).After(now.Add(30*time.Second)):
		return nil, fmt.Errorf("%w: issued in the future", ErrIDToken)
	}
	if nonce != "" && cl.Nonce != nonce {
		return nil, ErrNonce
	}
	if accessToken != "" && cl.AtHash != "" && cl.AtHash != halfHash(h.Algorithm, accessToken) {
		return nil, fmt.Errorf("%w: at_hash", ErrIDToken)
	}
	return &cl, nil
}

func halfHash(alg, v string) string {
	var hf hash.Hash
	switch alg {
	case "RS384", "PS384", "ES384":
		hf = sha512.New384()
	case "RS512", "PS512", "ES512", "EdDSA":
		hf = sha512.New()
	default:
		hf = sha256.New()
	}
	hf.Write([]byte(v))
	s := hf.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(s[:len(s)/2])
}

// Session holds server-side tokens for one browser session. Refresh is serialized
// per session so concurrent requests never present the same refresh token twice
// (SES-009); the server would treat that as reuse.
type Session struct {
	mu     sync.Mutex
	client *Client
	tokens *Tokens
}

// NewSession wraps tokens.
func (c *Client) NewSession(t *Tokens) *Session { return &Session{client: c, tokens: t} }

// AccessToken returns a valid access token, refreshing once (serialized) when needed.
func (s *Session) AccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokens == nil {
		return "", ErrReauthenticate
	}
	if s.client.cfg.Now().Add(15 * time.Second).Before(s.tokens.Expiry) {
		return s.tokens.AccessToken, nil
	}
	if s.tokens.RefreshToken == "" {
		return "", ErrReauthenticate
	}
	nt, err := s.client.tokenRequest(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.tokens.RefreshToken}})
	if err != nil {
		// A lost refresh response cannot be retried safely: reauthenticate (§24.3).
		s.tokens = nil
		return "", err
	}
	if nt.RefreshToken == "" {
		nt.RefreshToken = s.tokens.RefreshToken
	}
	if nt.IDToken != "" {
		// OIDC Core §12.2: a refreshed ID token must be for the same subject.
		nc, err := s.client.ValidateIDToken(ctx, nt.IDToken, "", nt.AccessToken)
		if err != nil {
			s.tokens = nil
			return "", err
		}
		if prev := s.tokens.IDToken; prev != "" {
			if old, err := s.client.parseUnverifiedSubject(prev); err == nil && old != nc.Subject {
				s.tokens = nil
				return "", fmt.Errorf("%w: refreshed ID token subject changed", ErrIDToken)
			}
		}
	} else {
		nt.IDToken = s.tokens.IDToken
	}
	s.tokens = nt
	return nt.AccessToken, nil
}

// Tokens returns the current tokens (for logout).
func (s *Session) Tokens() *Tokens {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens
}

// Revoke revokes a refresh token at the provider (logout).
func (c *Client) Revoke(ctx context.Context, refreshToken string) error {
	ep, err := c.endpoint(ctx, "revocation_endpoint")
	if err != nil {
		return err
	}
	form := url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}
	if c.cfg.ClientSecret == "" {
		form.Set("client_id", c.cfg.ClientID)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	}
	res, err := httpclient.Do(c.cfg.HTTPClient, req)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: revocation returned %d", ErrProvider, res.StatusCode)
	}
	return nil
}

// parseUnverifiedSubject reads sub from a previously validated ID token.
func (c *Client) parseUnverifiedSubject(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", ErrIDToken
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrIDToken
	}
	var v struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", ErrIDToken
	}
	return v.Sub, nil
}

// LogoutURL builds an RP-initiated logout URL.
func (c *Client) LogoutURL(ctx context.Context, idToken, postLogoutRedirect, state string) (string, error) {
	ep, err := c.endpoint(ctx, "end_session_endpoint")
	if err != nil {
		return "", err
	}
	q := url.Values{"id_token_hint": {idToken}, "client_id": {c.cfg.ClientID}}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	if state != "" {
		q.Set("state", state)
	}
	return ep + "?" + q.Encode(), nil
}
