package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/proudbase/proudauth-sdk-go/internal/httpclient"
)

// Bounded-state verification (SDK-002) is the middle consistency mode between
// offline JWT verification and per-request introspection: tokens are verified
// locally, then checked against revocation state replayed from the identity
// provider's session-event stream (SES-019). The state is trusted only while
// it is fresher than MaxStaleness; beyond that every check fails with
// ErrStateStale. It never silently downgrades to offline acceptance.
var (
	ErrStateStale = errors.New("verifier: revocation state is older than the configured bound")
	ErrRevoked    = errors.New("verifier: session or subject was revoked")
	// ErrNotStarted reports Sync on a BoundedState whose Start has not
	// succeeded yet; there is no stream position to continue from.
	ErrNotStarted = errors.New("verifier: bounded state not started (call Start first)")
	// ErrCursorExpired reports a 410 from the session-event stream: the
	// cursor is older than the retained history. Sync has already rewound to
	// the beginning of the retained history (keeping every revocation it
	// knows), so the next Sync replays it; Run does so immediately.
	ErrCursorExpired = errors.New("verifier: session-event cursor is older than the retained history")
)

const (
	// streamPageLimit is the page size requested from the stream (its maximum).
	streamPageLimit = 500
	// maxPagesPerSync bounds the pages one Sync call reads.
	maxPagesPerSync = 100
	// maxStreamWait is the longest long-poll the stream accepts.
	maxStreamWait = 25 * time.Second
)

// BoundedState follows the session-event stream and answers revocation
// questions for verified claims.
type BoundedState struct {
	// BaseURL is the identity provider origin (https://id.example.com).
	BaseURL string
	Realm   string
	// Token returns a service access token for the admin audience carrying
	// realm.session_events.read.
	Token        func(ctx context.Context) (string, error)
	MaxStaleness time.Duration
	HTTP         *http.Client
	Now          func() time.Time

	mu       sync.RWMutex
	started  bool
	cursor   string
	synced   time.Time
	sessions map[string]time.Time // session ID -> revoked at
	subjects map[string]time.Time // subject -> tokens issued before this are revoked
	orgs     map[string]time.Time // organization -> tokens issued before this are revoked
	members  map[string]time.Time // subject|org -> tokens issued before this are revoked
}

func (b *BoundedState) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// Start positions the stream at "now". Revocations that happened before Start
// are not replayed, so callers start it before accepting traffic and rely on
// token lifetimes (or introspection) for older state. Calling Start again
// keeps every revocation already replayed: the stream has no snapshot that
// could supersede them, so a restart only moves the position forward.
func (b *BoundedState) Start(ctx context.Context) error {
	var page streamPage
	if err := b.get(ctx, url.Values{"from": {"now"}}, &page); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ensureMaps()
	b.cursor = page.NextCursor
	b.synced = b.now()
	b.started = true
	return nil
}

func (b *BoundedState) isStarted() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.started
}

// ensureMaps makes the zero value safe to update; callers hold b.mu.
func (b *BoundedState) ensureMaps() {
	if b.sessions == nil {
		b.sessions = map[string]time.Time{}
	}
	if b.subjects == nil {
		b.subjects = map[string]time.Time{}
	}
	if b.orgs == nil {
		b.orgs = map[string]time.Time{}
	}
	if b.members == nil {
		b.members = map[string]time.Time{}
	}
}

type streamEvent struct {
	EventType  string         `json:"event_type"`
	OccurredAt time.Time      `json:"occurred_at"`
	OrgID      string         `json:"organization_id"`
	Data       map[string]any `json:"data"`
}

type streamPage struct {
	Events     []streamEvent `json:"events"`
	NextCursor string        `json:"next_cursor"`
}

// Sync reads all pending events (wait is the long-poll duration; longer
// than 25s is clamped to 25s, the stream's maximum).
// The state counts as fresh (for MaxStaleness) only once a read reaches the
// end of the stream, so a partly replayed backlog never passes for current
// state. A 410 (the cursor is older than the retained history) rewinds the
// stream to the beginning of the retained history, keeping every revocation
// already known, and returns ErrCursorExpired; the next Sync replays the
// retained history, which includes the events after the expired cursor. Sync
// before a successful Start returns ErrNotStarted.
func (b *BoundedState) Sync(ctx context.Context, wait time.Duration) error {
	for i := 0; i < maxPagesPerSync; i++ {
		b.mu.RLock()
		cur, started := b.cursor, b.started
		b.mu.RUnlock()
		if !started {
			return ErrNotStarted
		}
		var page streamPage
		q := url.Values{"cursor": {cur}, "limit": {strconv.Itoa(streamPageLimit)}}
		if i == 0 && wait > 0 {
			// The stream accepts 0..25 seconds and answers 400 above, so a
			// longer wait is clamped rather than turned into an error.
			q.Set("wait", strconv.Itoa(int(min(wait, maxStreamWait).Seconds())))
		}
		if err := b.get(ctx, q, &page); err != nil {
			if errors.Is(err, ErrCursorExpired) {
				// No snapshot exists, so the full resynchronization is a
				// replay of the retained history ("" is its beginning). The
				// known revocations stay; synced is left alone, so the state
				// turns stale if the replay does not catch up in time.
				b.mu.Lock()
				if b.cursor == cur {
					b.cursor = ""
				}
				b.mu.Unlock()
			}
			return err
		}
		caughtUp := len(page.Events) < streamPageLimit
		b.mu.Lock()
		b.ensureMaps()
		for _, ev := range page.Events {
			b.apply(ev)
		}
		b.cursor = page.NextCursor
		if caughtUp {
			b.synced = b.now()
		}
		b.mu.Unlock()
		if caughtUp {
			return nil
		}
	}
	return nil
}

// apply records one event; callers hold b.mu. A revocation time only moves
// forward, so replaying older events (after a 410) never weakens the state.
func (b *BoundedState) apply(ev streamEvent) {
	str := func(k string) string { s, _ := ev.Data[k].(string); return s }
	at := ev.OccurredAt
	// Most events name the affected user as user_id. A role unassignment and
	// a refresh reuse name the assignment's or grant's subject as subject_id
	// instead, which may also be a service principal (svc_) or a group
	// (grp_); the ID prefix tells them apart, and only users are tracked.
	user := str("user_id")
	if ev.EventType == "authorization.role.unassigned" || ev.EventType == "security.refresh_reuse_detected" {
		user = ""
		if s := str("subject_id"); strings.HasPrefix(s, "usr_") {
			user = s
		}
	}
	switch ev.EventType {
	case "session.revoked":
		if sid := str("session_id"); sid != "" {
			revokeAt(b.sessions, sid, at)
		}
	// user.recovery_restricted is not a revocation: the server keeps the
	// session that signed in with the recovery code (restricted) and other
	// sessions valid, so local verification must not reject them either.
	case "user.suspended", "user.locked", "user.deleted", "user.password_reset",
		"security.refresh_reuse_detected", "security.credential_compromised":
		if user != "" {
			revokeAt(b.subjects, user, at)
		}
	case "organization.suspended", "organization.deleted", "organization.archived":
		if o := firstNonEmpty(str("organization_id"), ev.OrgID); o != "" {
			revokeAt(b.orgs, o, at)
		}
	case "organization.membership.removed", "organization.membership.suspended", "authorization.role.unassigned":
		if user != "" && ev.OrgID != "" {
			revokeAt(b.members, user+"|"+ev.OrgID, at)
		}
	}
}

// revokeAt keeps the latest revocation time for key.
func revokeAt(m map[string]time.Time, key string, at time.Time) {
	if prev, ok := m[key]; !ok || at.After(prev) {
		m[key] = at
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Run keeps the state current until ctx ends, long-polling the stream. If
// Start has not succeeded yet, Run starts the stream first (positioned at
// "now"). Errors are reported to onError and retried with backoff; the state
// becomes stale (and checks fail) if they persist beyond MaxStaleness. After
// ErrCursorExpired (reported to onError too) Run replays the retained history
// at once instead of waiting, then continues following the stream.
func (b *BoundedState) Run(ctx context.Context, onError func(error)) {
	backoff := time.Second
	resyncing := false
	for ctx.Err() == nil {
		var err error
		if b.isStarted() {
			err = b.Sync(ctx, 20*time.Second)
		} else {
			err = b.Start(ctx)
		}
		if err != nil {
			if onError != nil {
				onError(err)
			}
			if errors.Is(err, ErrCursorExpired) && !resyncing {
				// Sync rewound to the retained history: replay it now. A
				// second 410 in a row waits like any other error.
				resyncing = true
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff, resyncing = time.Second, false
	}
}

// Check rejects claims affected by a replayed revocation, and fails closed
// when the state is older than MaxStaleness (no downgrade).
func (b *BoundedState) Check(c *Claims) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.synced.IsZero() || b.MaxStaleness <= 0 || b.now().Sub(b.synced) > b.MaxStaleness {
		return ErrStateStale
	}
	if c.SessionID != "" {
		if _, ok := b.sessions[c.SessionID]; ok {
			return ErrRevoked
		}
	}
	if at, ok := b.subjects[c.Subject]; ok && !c.IssuedAt.After(at) {
		return ErrRevoked
	}
	if c.OrgID != "" {
		if at, ok := b.orgs[c.OrgID]; ok && !c.IssuedAt.After(at) {
			return ErrRevoked
		}
		if at, ok := b.members[c.Subject+"|"+c.OrgID]; ok && !c.IssuedAt.After(at) {
			return ErrRevoked
		}
	}
	return nil
}

func (b *BoundedState) get(ctx context.Context, q url.Values, out any) error {
	if b.Token == nil {
		return errors.New("verifier: BoundedState.Token is required")
	}
	tok, err := b.Token(ctx)
	if err != nil {
		return err
	}
	u := strings.TrimRight(b.BaseURL, "/") + "/api/v1/realms/" + url.PathEscape(b.Realm) + "/session-events?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	hc := b.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := httpclient.Do(hc, req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusGone {
		return ErrCursorExpired
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("verifier: session-event stream returned %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out)
}

// BoundedVerifier combines offline verification with bounded-state checks.
type BoundedVerifier struct {
	Verifier *Verifier
	State    *BoundedState
}

// Authenticate implements Authenticator.
func (bv *BoundedVerifier) Authenticate(ctx context.Context, raw string) (*Claims, error) {
	c, err := bv.Verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if err := bv.State.Check(c); err != nil {
		return nil, err
	}
	return c, nil
}
