package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestBoundedStateBeforeStart: the zero value and calls before Start never
// panic; Sync reports ErrNotStarted, Check fails closed and Run starts the
// stream itself before applying events.
func TestBoundedStateBeforeStart(t *testing.T) {
	var started atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("from") == "now" {
			started.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{}, "next_cursor": "1"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"next_cursor": "2", "events": []any{
			map[string]any{"event_type": "session.revoked", "occurred_at": time.Now().UTC(), "data": map[string]any{"session_id": "ses_1"}},
			map[string]any{"event_type": "user.suspended", "occurred_at": time.Now().UTC(), "data": map[string]any{"user_id": "usr_2"}},
			map[string]any{"event_type": "organization.suspended", "occurred_at": time.Now().UTC(), "organization_id": "org_3"},
			map[string]any{"event_type": "organization.membership.removed", "occurred_at": time.Now().UTC(), "organization_id": "org_4",
				"data": map[string]any{"user_id": "usr_4"}},
		}})
	}))
	defer srv.Close()

	var zero BoundedState
	if err := zero.Sync(context.Background(), 0); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("zero-value Sync: %v", err)
	}
	if err := zero.Check(&Claims{Subject: "usr_1"}); !errors.Is(err, ErrStateStale) {
		t.Fatalf("zero-value Check: %v", err)
	}
	if err := zero.Start(context.Background()); err == nil {
		t.Fatal("Start without a token source succeeded")
	}

	b := &BoundedState{BaseURL: srv.URL, Realm: "main", MaxStaleness: time.Minute,
		Token: func(context.Context) (string, error) { return "svc", nil }}
	if err := b.Sync(context.Background(), 0); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("Sync before Start: %v", err)
	}
	if started.Load() {
		t.Fatal("Sync before Start contacted the stream")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Run(ctx, func(err error) {
			if ctx.Err() == nil {
				t.Errorf("Run: %v", err)
			}
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !errors.Is(b.Check(&Claims{Subject: "usr_9", SessionID: "ses_1"}), ErrRevoked) {
		if time.Now().After(deadline) {
			t.Fatal("Run did not apply events")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if !started.Load() {
		t.Fatal("Run did not start the stream")
	}
	old := time.Now().Add(-time.Hour)
	for _, c := range []*Claims{{Subject: "usr_2", IssuedAt: old}, {Subject: "usr_3", OrgID: "org_3", IssuedAt: old},
		{Subject: "usr_4", OrgID: "org_4", IssuedAt: old}} {
		if err := b.Check(c); !errors.Is(err, ErrRevoked) {
			t.Fatalf("%+v: %v", c, err)
		}
	}
}

// streamServer serves the session-event stream from handle, keyed by the
// requested cursor ("now" for from=now). handle returns the status and body.
func streamServer(t *testing.T, handle func(cursor string) (int, any)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		if r.URL.Query().Get("from") == "now" {
			cursor = "now"
		}
		status, body := handle(cursor)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func revokedSession(sid string, at time.Time) map[string]any {
	return map[string]any{"event_type": "session.revoked", "occurred_at": at, "data": map[string]any{"session_id": sid}}
}

// TestBoundedStateRestartKeepsRevocations: calling Start again moves the
// position to "now" but keeps the revocations already replayed (there is no
// snapshot that could supersede them).
func TestBoundedStateRestartKeepsRevocations(t *testing.T) {
	at := time.Now().UTC()
	srv := streamServer(t, func(cursor string) (int, any) {
		switch cursor {
		case "now":
			return 200, map[string]any{"events": []any{}, "next_cursor": "1.0"}
		case "1.0":
			return 200, map[string]any{"next_cursor": "2.0", "events": []any{revokedSession("ses_1", at),
				map[string]any{"event_type": "user.suspended", "occurred_at": at, "data": map[string]any{"user_id": "usr_2"}}}}
		}
		return 200, map[string]any{"events": []any{}, "next_cursor": cursor}
	})
	b := &BoundedState{BaseURL: srv.URL, Realm: "main", MaxStaleness: time.Minute,
		Token: func(context.Context) (string, error) { return "svc", nil }}
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Check(&Claims{Subject: "usr_9", SessionID: "ses_1"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("session revocation lost on restart: %v", err)
	}
	if err := b.Check(&Claims{Subject: "usr_2", IssuedAt: at.Add(-time.Minute)}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("subject revocation lost on restart: %v", err)
	}
}

// TestBoundedStateCursorExpired: a 410 rewinds to the beginning of the
// retained history and keeps the known revocations; the replay applies the
// events after the expired cursor, and the state counts as fresh only once
// the replay has caught up.
func TestBoundedStateCursorExpired(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	full := make([]any, 0, streamPageLimit)
	for i := range streamPageLimit {
		full = append(full, revokedSession(fmt.Sprintf("ses_old_%d", i), now.Add(-time.Hour)))
	}
	var midReplayFails atomic.Bool
	midReplayFails.Store(true)
	srv := streamServer(t, func(cursor string) (int, any) {
		switch cursor {
		case "now":
			return 200, map[string]any{"events": []any{}, "next_cursor": "5.0"}
		case "5.0":
			return 200, map[string]any{"events": []any{revokedSession("ses_known", now)}, "next_cursor": "6.0"}
		case "6.0":
			return http.StatusGone, map[string]any{"code": "cursor_expired"}
		case "":
			return 200, map[string]any{"events": full, "next_cursor": "p1"}
		case "p1":
			if midReplayFails.Load() {
				return http.StatusServiceUnavailable, map[string]any{}
			}
			return 200, map[string]any{"events": []any{revokedSession("ses_gap", now)}, "next_cursor": "9.0"}
		}
		return 200, map[string]any{"events": []any{}, "next_cursor": cursor}
	})
	clock := now
	b := &BoundedState{BaseURL: srv.URL, Realm: "main", MaxStaleness: time.Minute, Now: func() time.Time { return clock },
		Token: func(context.Context) (string, error) { return "svc", nil }}
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync(ctx, 0); !errors.Is(err, ErrCursorExpired) {
		t.Fatalf("410: %v, want ErrCursorExpired", err)
	}
	if err := b.Check(&Claims{Subject: "usr_1", SessionID: "ses_known"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("known revocation lost after 410: %v", err)
	}
	// The replay applies a full page, then fails: the state must not count
	// as fresh, because it has not reached the end of the stream.
	clock = clock.Add(30 * time.Second)
	if err := b.Sync(ctx, 0); err == nil {
		t.Fatal("Sync succeeded although the replay failed")
	}
	clock = clock.Add(40 * time.Second)
	if err := b.Check(&Claims{Subject: "usr_1", SessionID: "ses_other"}); !errors.Is(err, ErrStateStale) {
		t.Fatalf("partly replayed state passed for fresh: %v", err)
	}
	midReplayFails.Store(false)
	if err := b.Sync(ctx, 0); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"ses_known", "ses_gap", "ses_old_0"} {
		if err := b.Check(&Claims{Subject: "usr_1", SessionID: sid}); !errors.Is(err, ErrRevoked) {
			t.Fatalf("%s after replay: %v", sid, err)
		}
	}
	if err := b.Check(&Claims{Subject: "usr_1", SessionID: "ses_other"}); err != nil {
		t.Fatalf("unaffected session after replay: %v", err)
	}
}

// TestBoundedStateRunRecoversFromCursorExpired: Run reports the 410, replays
// the retained history and keeps following the stream.
func TestBoundedStateRunRecoversFromCursorExpired(t *testing.T) {
	at := time.Now().UTC()
	var expired atomic.Int64
	srv := streamServer(t, func(cursor string) (int, any) {
		switch cursor {
		case "now":
			return 200, map[string]any{"events": []any{}, "next_cursor": "1.0"}
		case "1.0":
			expired.Add(1)
			return http.StatusGone, map[string]any{"code": "cursor_expired"}
		case "":
			return 200, map[string]any{"events": []any{revokedSession("ses_gap", at)}, "next_cursor": "2.0"}
		case "2.0":
			return 200, map[string]any{"events": []any{revokedSession("ses_next", at)}, "next_cursor": "3.0"}
		}
		time.Sleep(5 * time.Millisecond) // a long poll with nothing new
		return 200, map[string]any{"events": []any{}, "next_cursor": cursor}
	})
	b := &BoundedState{BaseURL: srv.URL, Realm: "main", MaxStaleness: time.Minute,
		Token: func(context.Context) (string, error) { return "svc", nil }}
	ctx, cancel := context.WithCancel(context.Background())
	var reported atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Run(ctx, func(err error) {
			if errors.Is(err, ErrCursorExpired) {
				reported.Add(1)
			} else if ctx.Err() == nil {
				t.Errorf("Run: %v", err)
			}
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !errors.Is(b.Check(&Claims{Subject: "usr_1", SessionID: "ses_next"}), ErrRevoked) {
		if time.Now().After(deadline) {
			t.Fatal("Run did not recover from the expired cursor")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if err := b.Check(&Claims{Subject: "usr_1", SessionID: "ses_gap"}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("event after the expired cursor not replayed: %v", err)
	}
	if expired.Load() != 1 || reported.Load() != 1 {
		t.Fatalf("410 served %d times, reported %d times; want 1 and 1", expired.Load(), reported.Load())
	}
}

// TestBoundedStateReplayNeverWeakens: an older event replayed after a newer
// one for the same subject keeps the later revocation time.
func TestBoundedStateReplayNeverWeakens(t *testing.T) {
	t2 := time.Now().UTC().Truncate(time.Second)
	t1 := t2.Add(-time.Hour)
	suspended := func(at time.Time) map[string]any {
		return map[string]any{"event_type": "user.suspended", "occurred_at": at, "data": map[string]any{"user_id": "usr_1"}}
	}
	srv := streamServer(t, func(cursor string) (int, any) {
		switch cursor {
		case "now":
			return 200, map[string]any{"events": []any{}, "next_cursor": "1.0"}
		case "1.0":
			return 200, map[string]any{"events": []any{suspended(t2), suspended(t1)}, "next_cursor": "2.0"}
		}
		return 200, map[string]any{"events": []any{}, "next_cursor": cursor}
	})
	b := &BoundedState{BaseURL: srv.URL, Realm: "main", MaxStaleness: time.Minute,
		Token: func(context.Context) (string, error) { return "svc", nil }}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if err := b.Check(&Claims{Subject: "usr_1", IssuedAt: t2.Add(-time.Minute)}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("older replayed event weakened the revocation: %v", err)
	}
	if err := b.Check(&Claims{Subject: "usr_1", IssuedAt: t2.Add(time.Second)}); err != nil {
		t.Fatalf("token issued after the revocation: %v", err)
	}
}

// TestBoundedStateSubjectIDEvents: a role unassignment and a refresh reuse
// name their subject as subject_id (the server's payload); user subjects are
// revoked, service principal and group subjects are not mistaken for users.
func TestBoundedStateSubjectIDEvents(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	ev := func(typ, org, subject string) map[string]any {
		return map[string]any{"event_type": typ, "occurred_at": at, "organization_id": org, "data": map[string]any{"subject_id": subject}}
	}
	srv := streamServer(t, func(cursor string) (int, any) {
		switch cursor {
		case "now":
			return 200, map[string]any{"events": []any{}, "next_cursor": "1.0"}
		case "1.0":
			return 200, map[string]any{"next_cursor": "2.0", "events": []any{
				ev("authorization.role.unassigned", "org_1", "usr_1"),
				ev("authorization.role.unassigned", "org_1", "svc_2"),
				ev("authorization.role.unassigned", "org_1", "grp_3"),
				ev("security.refresh_reuse_detected", "", "usr_4"),
				ev("security.refresh_reuse_detected", "", "svc_5"),
			}}
		}
		return 200, map[string]any{"events": []any{}, "next_cursor": cursor}
	})
	b := &BoundedState{BaseURL: srv.URL, Realm: "main", MaxStaleness: time.Minute,
		Token: func(context.Context) (string, error) { return "svc", nil }}
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync(ctx, 0); err != nil {
		t.Fatal(err)
	}
	old := at.Add(-time.Minute)
	for _, c := range []*Claims{{Subject: "usr_1", OrgID: "org_1", IssuedAt: old}, {Subject: "usr_4", IssuedAt: old}} {
		if err := b.Check(c); !errors.Is(err, ErrRevoked) {
			t.Fatalf("%+v not revoked: %v", c, err)
		}
	}
	if len(b.subjects) != 1 || len(b.members) != 1 {
		t.Fatalf("non-user subjects tracked: subjects %v members %v", b.subjects, b.members)
	}
}

// TestBoundedStateWaitClamped: a long-poll longer than the stream's 25 s
// maximum is clamped instead of being sent (the server answers 400 above it).
func TestBoundedStateWaitClamped(t *testing.T) {
	var waits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("from") != "now" {
			waits = append(waits, r.URL.Query().Get("wait"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"events": []any{}, "next_cursor": "1.0"})
	}))
	defer srv.Close()
	b := &BoundedState{BaseURL: srv.URL, Realm: "main", MaxStaleness: time.Minute,
		Token: func(context.Context) (string, error) { return "svc", nil }}
	ctx := context.Background()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for _, wait := range []time.Duration{time.Minute, 10 * time.Second, -time.Second} {
		if err := b.Sync(ctx, wait); err != nil {
			t.Fatal(err)
		}
	}
	if fmt.Sprint(waits) != "[25 10 ]" {
		t.Fatalf("waits sent: %q", waits)
	}
}
