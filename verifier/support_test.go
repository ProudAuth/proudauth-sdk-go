package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

// The support-operation table is shared with the Node SDK
// (sdk/node/test/support-operations.test.ts) so both guards classify every
// operation identically.
const supportFixture = "../testdata/contracts/support-operations/cases.json"

type supportFixtureFile struct {
	WriteOperations    []string `json:"write_operations"`
	ClassificationOnly []struct {
		Operation string `json:"operation"`
		Protected bool   `json:"protected"`
		Write     bool   `json:"write"`
	} `json:"classification_only"`
	Cases []struct {
		Operation   string `json:"operation"`
		Read        bool   `json:"read"`
		SupportMode string `json:"support_mode"`
		Protected   bool   `json:"protected"`
		Write       bool   `json:"write"`
		Expect      string `json:"expect"`
		Why         string `json:"why"`
	} `json:"cases"`
}

const (
	testIss = "https://id.test/realms/main"
	testAud = "https://api.test/orders"
)

// introspectionServer answers every introspection with resp(token).
func introspectionServer(t *testing.T, resp func(token string) map[string]any) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(resp(r.PostForm.Get("token")))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func supportToken(mode string) map[string]any {
	return map[string]any{"active": true, "iss": testIss, "aud": testAud, "sub": "usr_customer", "client_id": "support-bff",
		"token_kind": "impersonation_access", "act": map[string]any{"sub": "usr_agent"}, "impersonation_grant_id": "imp_1",
		"support_mode": mode, "jti": "tok_support_1", "org_id": "org_a"}
}

type recordingAuditor struct {
	mu     sync.Mutex
	events []SupportEvent
}

func (a *recordingAuditor) RecordSupportAccess(_ context.Context, ev SupportEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func TestSupportOperationFixtures(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash(supportFixture))
	if err != nil {
		t.Fatal(err)
	}
	var fx supportFixtureFile
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range fx.ClassificationOnly {
		if got := IsProtectedOperation(c.Operation); got != c.Protected {
			t.Errorf("IsProtectedOperation(%q) = %v, want %v", c.Operation, got, c.Protected)
		}
		if got := IsWriteOperation(c.Operation); got != c.Write {
			t.Errorf("IsWriteOperation(%q) = %v, want %v", c.Operation, got, c.Write)
		}
	}
	srv, _ := introspectionServer(t, func(tok string) map[string]any { return supportToken(tok) })
	for _, c := range fx.Cases {
		if got := IsProtectedOperation(c.Operation); got != c.Protected {
			t.Errorf("IsProtectedOperation(%q) = %v, want %v (%s)", c.Operation, got, c.Protected, c.Why)
		}
		if got := IsWriteOperation(c.Operation); got != c.Write {
			t.Errorf("IsWriteOperation(%q) = %v, want %v (%s)", c.Operation, got, c.Write, c.Why)
		}
		aud := &recordingAuditor{}
		g := &SupportGuard{Introspector: &Introspector{Endpoint: srv.URL, ClientID: "rs", ClientSecret: "s", Issuer: testIss, Audience: testAud},
			Auditor: aud, WriteOperations: fx.WriteOperations}
		// The test server echoes the token as the support mode.
		_, err := g.Authorize(context.Background(), c.SupportMode, c.Operation, c.Read)
		if c.Expect == "allow" {
			if err != nil {
				t.Errorf("%q read=%v %s: %v, want allowed (%s)", c.Operation, c.Read, c.SupportMode, err, c.Why)
			}
		} else if !errors.Is(err, ErrSupportPolicy) {
			t.Errorf("%q read=%v %s: %v, want %s (%s)", c.Operation, c.Read, c.SupportMode, err, c.Expect, c.Why)
		}
		if len(aud.events) != 1 {
			t.Fatalf("%q: %d audit events, want 1", c.Operation, len(aud.events))
		}
		ev := aud.events[0]
		wantReason := c.Expect
		if wantReason == "allow" {
			wantReason = ""
		}
		if ev.Allowed != (c.Expect == "allow") || ev.DenyReason != wantReason || ev.Actor != "usr_agent" || ev.Operation != c.Operation {
			t.Errorf("%q: audit event %+v, want reason %q", c.Operation, ev, wantReason)
		}
		if ev.Read != (c.Read && !c.Write) {
			t.Errorf("%q: audit event read=%v, want %v", c.Operation, ev.Read, c.Read && !c.Write)
		}
	}
}

func TestSupportGuardExtraProtectedAndEmptyOperation(t *testing.T) {
	srv, _ := introspectionServer(t, func(string) map[string]any { return supportToken("allowlisted_write") })
	aud := &recordingAuditor{}
	g := &SupportGuard{Introspector: &Introspector{Endpoint: srv.URL, ClientID: "rs", ClientSecret: "s", Issuer: testIss, Audience: testAud},
		Auditor: aud, WriteOperations: []string{"orders.export"}, ProtectedOperations: []string{"orders.export"}}
	if _, err := g.Authorize(context.Background(), "t", "Orders.Export", false); !errors.Is(err, ErrSupportPolicy) {
		t.Fatalf("extra protected operation: %v", err)
	}
	if _, err := g.Authorize(context.Background(), "t", "  ", true); !errors.Is(err, ErrSupportPolicy) {
		t.Fatalf("empty operation: %v", err)
	}
	if len(aud.events) != 1 || aud.events[0].DenyReason != DenyProtectedOperation {
		t.Fatalf("events: %+v", aud.events)
	}
}

// TestSupportListsAreReadOnly: the default protected operations and write
// verbs are only reachable as copies, so code importing the package cannot
// weaken the support protections at run time.
func TestSupportListsAreReadOnly(t *testing.T) {
	protected, writes := ProtectedOperationList(), WriteSegmentList()
	if !slices.Contains(protected, "payment") || !slices.Contains(protected, "delete") || !slices.Contains(writes, "update") {
		t.Fatalf("lists: %v %v", protected, writes)
	}
	clear(protected)
	clear(writes)
	if !IsProtectedOperation("orders.refund") || !IsProtectedOperation("payments.create") {
		t.Fatal("clearing the returned protected list changed the classification")
	}
	if !IsWriteOperation("orders.update") {
		t.Fatal("clearing the returned write list changed the classification")
	}
	if again := ProtectedOperationList(); len(again) == 0 || again[0] == "" {
		t.Fatalf("protected list after clearing a copy: %v", again)
	}
	if again := WriteSegmentList(); len(again) == 0 || again[0] == "" {
		t.Fatalf("write list after clearing a copy: %v", again)
	}
}

// TestIntrospectorRefusesSupportTokens mirrors the Node SDK: impersonation_access
// is never an ordinary kind, and listing it is a configuration error.
func TestIntrospectorRefusesSupportTokens(t *testing.T) {
	srv, calls := introspectionServer(t, func(tok string) map[string]any {
		if tok == "user" {
			return map[string]any{"active": true, "iss": testIss, "aud": testAud, "sub": "usr_1", "token_kind": "user_access"}
		}
		return supportToken("read_only")
	})
	i := &Introspector{Endpoint: srv.URL, ClientID: "rs", ClientSecret: "s", Issuer: testIss, Audience: testAud}
	if _, err := i.Authenticate(context.Background(), "support"); !errors.Is(err, ErrTokenKind) {
		t.Fatalf("default kinds: %v", err)
	}
	if c, err := i.Authenticate(context.Background(), "user"); err != nil || c.Subject != "usr_1" {
		t.Fatalf("user token: %v", err)
	}
	before := calls.Load()
	i.AcceptedKinds = []string{"user_access", "impersonation_access"}
	for _, tok := range []string{"support", "user"} {
		if _, err := i.Authenticate(context.Background(), tok); !errors.Is(err, ErrSupportKind) {
			t.Fatalf("%s with impersonation_access listed: %v", tok, err)
		}
	}
	if calls.Load() != before {
		t.Fatal("a misconfigured introspector called the endpoint")
	}
	rec := httptest.NewRecorder()
	Middleware(i, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next called") })).
		ServeHTTP(rec, bearerRequest("support"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("middleware status %d, want 500", rec.Code)
	}
}

type errAuthenticator struct{ err error }

func (a errAuthenticator) Authenticate(context.Context, string) (*Claims, error) { return nil, a.err }

func bearerRequest(tok string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/orders", nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	return r
}

// TestMiddlewareErrorResponses: the HTTP middleware maps verification errors
// to 401/403/503 challenges and refuses an access token in the query string
// before authenticating (INT-004: no reusable bearer credential in a logged
// URL, also on a WebSocket upgrade).
func TestMiddlewareErrorResponses(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		req    *http.Request
		status int
		www    string
	}{
		{"missing", nil, bearerRequest(""), 401, "Bearer"},
		{"query token", nil, httptest.NewRequest(http.MethodGet, "/orders?access_token=x", nil), 400, `Bearer error="invalid_request"`},
		{"invalid", ErrSignature, bearerRequest("t"), 401, `Bearer error="invalid_token"`},
		{"revoked", ErrRevoked, bearerRequest("t"), 401, `Bearer error="invalid_token"`},
		{"scope", ErrScope, bearerRequest("t"), 403, `Bearer error="insufficient_scope"`},
		{"organization", ErrOrganization, bearerRequest("t"), 403, `Bearer error="insufficient_scope"`},
		{"wrapped scope", errors.Join(errors.New("ctx"), ErrScope), bearerRequest("t"), 403, `Bearer error="insufficient_scope"`},
		{"support policy", ErrSupportPolicy, bearerRequest("t"), 403, ""},
		{"unavailable", ErrUnavailable, bearerRequest("t"), 503, ""},
		{"stale", ErrStateStale, bearerRequest("t"), 503, ""},
		{"misconfigured", ErrMisconfigured, bearerRequest("t"), 500, ""},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		Middleware(errAuthenticator{c.err}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatalf("%s: next called", c.name) })).
			ServeHTTP(rec, c.req)
		if rec.Code != c.status || rec.Header().Get("WWW-Authenticate") != c.www {
			t.Errorf("%s: %d %q, want %d %q", c.name, rec.Code, rec.Header().Get("WWW-Authenticate"), c.status, c.www)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", c.name, rec.Header().Get("Cache-Control"))
		}
	}
}
