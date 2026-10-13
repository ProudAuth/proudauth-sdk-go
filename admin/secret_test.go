package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecretsRedacted covers SDK-007/SDK-008: one-time secrets in untyped
// results never print, log or serialize; Reveal returns them. Requests carry
// the SDK version and deprecated operations are reported.
func TestSecretsRedacted(t *testing.T) {
	var gotSDK, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSDK, gotUA = r.Header.Get("ProudAuth-SDK"), r.Header.Get("User-Agent")
		w.Header().Set("Deprecation", "@1767225600")
		w.Header().Set("Sunset", "Wed, 01 Jul 2026 00:00:00 GMT")
		_, _ = w.Write([]byte(`{"client":{"client_id":"web"},"client_secret":"pa_cs_supersecret","recovery_codes":["aaaa-bbbb"],"webhook_secrets":{"feed":"whsec_x"}}`))
	}))
	defer srv.Close()
	var deprecated string
	c := &Client{BaseURL: srv.URL, Realm: "main", UserAgent: "tool/1", OnDeprecated: func(m, p, d, s string) { deprecated = m + " " + p + " " + d }}
	var out map[string]any
	if _, err := c.Do(context.Background(), http.MethodPost, "/clients", map[string]any{}, &out); err != nil {
		t.Fatal(err)
	}
	if gotSDK != "go/"+Version || !strings.HasPrefix(gotUA, "tool/1 proudauth-sdk-go/") || !strings.HasPrefix(deprecated, "POST /clients @") {
		t.Fatalf("headers: %q %q, deprecation %q", gotSDK, gotUA, deprecated)
	}
	secret, ok := out["client_secret"].(Secret)
	if !ok || secret.Reveal() != "pa_cs_supersecret" {
		t.Fatalf("client secret not wrapped: %#v", out["client_secret"])
	}
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("created", "result", out, "secret", secret)
	js, _ := json.Marshal(out)
	for _, s := range []string{fmt.Sprintf("%v %+v %#v %s", out, out, out, secret), logs.String(), string(js)} {
		if strings.Contains(s, "supersecret") || strings.Contains(s, "aaaa-bbbb") || strings.Contains(s, "whsec_x") {
			t.Fatalf("secret leaked: %s", s)
		}
	}
	if out["client"].(map[string]any)["client_id"] != "web" {
		t.Fatal("non-secret members changed")
	}
}

// TestDeprecationPathOmitsQuery: OnDeprecated never receives the query
// string, which can carry search terms or other personal data.
func TestDeprecationPathOmitsQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Deprecation", "@1767225600")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()
	var got []string
	c := &Client{BaseURL: srv.URL, Realm: "main", OnDeprecated: func(m, p, d, s string) { got = append(got, p) }}
	if err := c.Users(context.Background(), "alice@example.com", func(User) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), http.MethodGet, "/audit-events?actor=usr_1#frag", nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "/users" || got[1] != "/audit-events" {
		t.Fatalf("deprecation paths %q", got)
	}
	for _, p := range got {
		if strings.Contains(p, "alice") || strings.Contains(p, "usr_1") {
			t.Fatalf("query leaked to OnDeprecated: %q", p)
		}
	}
}
