package oidcclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// TestExchangeRejectsStateMismatch covers OIDC-002 on the client side: the
// callback's state must equal the state of the authorization request this
// browser started. A missing, different or unpaired state returns ErrState
// before the client contacts the provider, so an attacker's code is never
// redeemed; a provider error is reported as such, not as a state mismatch.
func TestExchangeRejectsStateMismatch(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "the provider must not be contacted", http.StatusTeapot)
	}))
	defer srv.Close()
	c, err := New(Config{Issuer: srv.URL, ClientID: "web", RedirectURI: "https://app.test/cb", Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	ar := &AuthRequest{State: Random(), Nonce: Random(), Verifier: Random()}
	cases := []struct {
		name     string
		ar       *AuthRequest
		callback url.Values
	}{
		{"different state", ar, url.Values{"code": {"c1"}, "state": {Random()}, "iss": {srv.URL}}},
		{"missing state", ar, url.Values{"code": {"c1"}, "iss": {srv.URL}}},
		{"empty state on both sides", &AuthRequest{Verifier: ar.Verifier}, url.Values{"code": {"c1"}, "state": {""}}},
		{"no stored request", nil, url.Values{"code": {"c1"}, "state": {ar.State}}},
		{"state differing only in case", ar, url.Values{"code": {"c1"}, "state": {flipCase(ar.State)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := c.Exchange(context.Background(), tc.ar, tc.callback)
			if !errors.Is(err, ErrState) {
				t.Fatalf("Exchange returned %v, want ErrState", err)
			}
		})
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("the provider was contacted %d times for callbacks with a bad state", n)
	}
	// An error response is the provider's error, whatever its state.
	_, _, err = c.Exchange(context.Background(), ar, url.Values{"error": {"access_denied"}, "state": {ar.State}})
	if !errors.Is(err, ErrProvider) || errors.Is(err, ErrState) {
		t.Fatalf("provider error reported as %v", err)
	}
}

// flipCase changes the case of the first letter of s (state comparison is
// exact, not case-insensitive).
func flipCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = c - 'a' + 'A'
			return string(b)
		case c >= 'A' && c <= 'Z':
			b[i] = c - 'A' + 'a'
			return string(b)
		}
	}
	return s + "x"
}
