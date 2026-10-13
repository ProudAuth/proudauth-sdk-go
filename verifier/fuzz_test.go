package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// FuzzVerify feeds arbitrary token strings to the offline verifier. Nothing that is
// not signed by the published key may verify, and parsing must never panic (QA-003).
func FuzzVerify(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: "k1", Algorithm: "ES256", Use: "sig"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	}))
	f.Cleanup(srv.Close)
	now := time.Unix(1_800_000_000, 0)
	v, err := New(Config{Issuer: "https://id.test/realms/main", Audience: "https://api.test", JWKSURL: srv.URL,
		Now: func() time.Time { return now }, MinRefreshInterval: time.Hour})
	if err != nil {
		f.Fatal(err)
	}
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	payload := `{"iss":"https://id.test/realms/main","aud":"https://api.test","sub":"usr_1","exp":1800000600,"iat":1800000000,"token_kind":"user_access","jti":"j"}`
	f.Add(enc(`{"alg":"none","typ":"at+jwt"}`) + "." + enc(payload) + ".")
	f.Add(enc(`{"alg":"HS256","typ":"at+jwt","kid":"k1"}`) + "." + enc(payload) + ".c2ln")
	f.Add(enc(`{"alg":"ES256","typ":"at+jwt","kid":"k1"}`) + "." + enc(payload) + "." + enc("sig"))
	f.Add(enc(`{"alg":"ES256","typ":"at+jwt","kid":"k1","kid":"k2"}`) + "." + enc(payload) + "." + enc("sig"))
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, raw string) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if c, err := v.Verify(ctx, raw); err == nil {
			t.Fatalf("forged token verified: %q -> %+v", raw, c)
		}
	})
}
