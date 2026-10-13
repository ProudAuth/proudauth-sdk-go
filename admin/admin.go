// Package admin is a typed client for the ProudAuth administration and self-service
// APIs (SDK-003, SDK-007). It preserves structured problem details, supports
// opaque-cursor pagination, request deadlines, cancellation and idempotency
// keys, sends its version, reports deprecated operations, wraps one-time
// secrets in Secret, and never logs request bodies or tokens (SDK-008).
package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/proudbase/proudauth-sdk-go/internal/httpclient"
)

// Problem is an RFC 9457 problem returned by the API.
type Problem struct {
	Status    int               `json:"status"`
	Code      string            `json:"code"`
	Title     string            `json:"title"`
	Detail    string            `json:"detail"`
	Errors    map[string]string `json:"errors"`
	RequestID string            `json:"request_id"`
	Extra     map[string]any    `json:"-"`
}

func (p *Problem) Error() string {
	msg := fmt.Sprintf("%d %s: %s", p.Status, p.Code, p.Title)
	if p.Detail != "" {
		msg += " (" + p.Detail + ")"
	}
	for k, v := range p.Errors {
		msg += fmt.Sprintf(" [%s: %s]", k, v)
	}
	return msg
}

// TokenSource supplies bearer tokens.
type TokenSource func(ctx context.Context) (string, error)

// Version is this SDK's version, sent with every request.
const Version = "0.2.0"

// Client calls one realm's custom APIs.
type Client struct {
	BaseURL    string // e.g. https://id.example.com
	Realm      string
	Token      TokenSource
	HTTPClient *http.Client
	Timeout    time.Duration
	UserAgent  string
	// OnDeprecated, when set, is called for responses of operations the
	// server marks deprecated (Deprecation and Sunset headers, API-013).
	// path is the request path without its query string, which can carry
	// search terms or other personal data.
	OnDeprecated func(method, path, deprecation, sunset string)
}

// StaticToken returns a fixed token source.
func StaticToken(tok string) TokenSource {
	return func(context.Context) (string, error) { return tok, nil }
}

// RequestOption customizes one request.
type RequestOption func(*http.Request)

// WithIdempotencyKey sets an idempotency key for safe retries of creates (API-005).
func WithIdempotencyKey(key string) RequestOption {
	return func(r *http.Request) { r.Header.Set("Idempotency-Key", key) }
}

// WithIfMatch sets an optimistic-concurrency precondition (API-010).
func WithIfMatch(etag string) RequestOption {
	return func(r *http.Request) { r.Header.Set("If-Match", etag) }
}

// NewIdempotencyKey returns a random key.
func NewIdempotencyKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Response carries status and headers for callers that need ETags.
type Response struct {
	Status int
	Header http.Header
	// Deprecation and Sunset report an operation the server marks
	// deprecated (API-013); empty otherwise.
	Deprecation, Sunset string
}

// Do performs a request against /api/v1/realms/{realm}{path} and decodes JSON into out.
func (c *Client) Do(ctx context.Context, method, path string, body, out any, opts ...RequestOption) (*Response, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	u := strings.TrimSuffix(c.BaseURL, "/") + "/api/v1/realms/" + url.PathEscape(c.Realm) + path
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("ProudAuth-SDK", "go/"+Version)
	ua := "proudauth-sdk-go/" + Version
	if c.UserAgent != "" {
		ua = c.UserAgent + " " + ua
	}
	req.Header.Set("User-Agent", ua)
	if c.Token != nil {
		tok, err := c.Token(ctx)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for _, o := range opts {
		o(req)
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := httpclient.Do(hc, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	meta := &Response{Status: res.StatusCode, Header: res.Header, Deprecation: res.Header.Get("Deprecation"), Sunset: res.Header.Get("Sunset")}
	if meta.Deprecation != "" && c.OnDeprecated != nil {
		c.OnDeprecated(method, stripQuery(path), meta.Deprecation, meta.Sunset)
	}
	if res.StatusCode >= 400 {
		p := &Problem{Status: res.StatusCode}
		_ = json.Unmarshal(raw, p)
		_ = json.Unmarshal(raw, &p.Extra)
		if p.Code == "" {
			p.Code = http.StatusText(res.StatusCode)
		}
		return meta, p
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return meta, err
		}
		// Untyped results never expose one-time secrets as plain strings.
		switch o := out.(type) {
		case *map[string]any:
			wrapSecrets(*o)
		case *any:
			*o = wrapSecrets(*o)
		}
	}
	return meta, nil
}

// stripQuery returns path without its query string or fragment.
func stripQuery(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		return path[:i]
	}
	return path
}

// Page is a cursor-paginated list.
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor"`
}

// List iterates every page of a list endpoint.
func List[T any](ctx context.Context, c *Client, path string, fn func(T) error) error {
	cursor := ""
	seen := map[string]bool{}
	for {
		p := path
		if cursor != "" {
			sep := "?"
			if strings.Contains(p, "?") {
				sep = "&"
			}
			p += sep + "cursor=" + url.QueryEscape(cursor)
		}
		var page Page[T]
		if _, err := c.Do(ctx, http.MethodGet, p, nil, &page); err != nil {
			return err
		}
		for _, it := range page.Items {
			if err := fn(it); err != nil {
				return err
			}
		}
		if page.NextCursor == "" {
			return nil
		}
		if seen[page.NextCursor] {
			return errors.New("admin: pagination cursor repeated")
		}
		seen[page.NextCursor] = true
		cursor = page.NextCursor
	}
}

// Typed models for common resources.
type (
	User struct {
		ID          string           `json:"id"`
		State       string           `json:"state"`
		DisplayName string           `json:"display_name"`
		Identifiers []map[string]any `json:"identifiers"`
		Version     int64            `json:"version"`
	}
	Organization struct {
		ID          string `json:"id"`
		Slug        string `json:"slug"`
		DisplayName string `json:"display_name"`
		State       string `json:"state"`
		Version     int64  `json:"version"`
	}
	Membership struct {
		ID     string   `json:"id"`
		UserID string   `json:"user_id"`
		State  string   `json:"state"`
		Roles  []string `json:"roles"`
	}
	Role struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Boundary    string   `json:"boundary_type"`
		Permissions []string `json:"permissions"`
	}
)

// Users lists users.
func (c *Client) Users(ctx context.Context, query string, fn func(User) error) error {
	return List(ctx, c, "/users?q="+url.QueryEscape(query), fn)
}

// CreateUser creates a user; the setup token is returned only when email delivery
// is off. Pass WithIdempotencyKey to make retries of the same logical request
// safe (API-005); otherwise a fresh key is generated per call.
func (c *Client) CreateUser(ctx context.Context, in map[string]any, opts ...RequestOption) (map[string]any, error) {
	var out map[string]any
	_, err := c.Do(ctx, http.MethodPost, "/users", in, &out, withDefaultKey(opts)...)
	return out, err
}

// withDefaultKey prepends a generated idempotency key; a caller-supplied key
// (applied later) replaces it.
func withDefaultKey(opts []RequestOption) []RequestOption {
	return append([]RequestOption{WithIdempotencyKey(NewIdempotencyKey())}, opts...)
}

// SetUserState suspends, reactivates or locks a user.
func (c *Client) SetUserState(ctx context.Context, userID, action, reason string) error {
	switch action {
	case "suspend", "reactivate", "lock":
	default:
		return fmt.Errorf("admin: unsupported user state action %q", action)
	}
	_, err := c.Do(ctx, http.MethodPost, "/users/"+url.PathEscape(userID)+"/"+action, map[string]any{"reason": reason}, nil)
	return err
}

// RevokeSessions revokes all sessions of a user.
func (c *Client) RevokeSessions(ctx context.Context, userID string) (int, error) {
	var out struct {
		Revoked int `json:"revoked_sessions"`
	}
	_, err := c.Do(ctx, http.MethodPost, "/users/"+url.PathEscape(userID)+"/revoke-sessions", map[string]any{}, &out)
	return out.Revoked, err
}

// Organizations lists organizations.
func (c *Client) Organizations(ctx context.Context, fn func(Organization) error) error {
	return List(ctx, c, "/organizations", fn)
}

// CreateOrganization creates an organization.
func (c *Client) CreateOrganization(ctx context.Context, slug, name string, opts ...RequestOption) (*Organization, error) {
	var o Organization
	_, err := c.Do(ctx, http.MethodPost, "/organizations", map[string]any{"slug": slug, "display_name": name}, &o, withDefaultKey(opts)...)
	return &o, err
}

// Members lists organization members.
func (c *Client) Members(ctx context.Context, orgID string, fn func(Membership) error) error {
	return List(ctx, c, "/organizations/"+url.PathEscape(orgID)+"/members", fn)
}

// AddMember adds an existing user to an organization.
func (c *Client) AddMember(ctx context.Context, orgID, userID string, roleIDs []string) (*Membership, error) {
	var m Membership
	_, err := c.Do(ctx, http.MethodPost, "/organizations/"+url.PathEscape(orgID)+"/members", map[string]any{"user_id": userID, "role_ids": roleIDs}, &m)
	return &m, err
}

// Invite creates an invitation.
func (c *Client) Invite(ctx context.Context, orgID, email string, roleIDs []string, opts ...RequestOption) (map[string]any, error) {
	var out map[string]any
	_, err := c.Do(ctx, http.MethodPost, "/organizations/"+url.PathEscape(orgID)+"/invitations", map[string]any{"email": email, "role_ids": roleIDs}, &out,
		withDefaultKey(opts)...)
	return out, err
}

// Roles lists roles.
func (c *Client) Roles(ctx context.Context, boundary string) ([]Role, error) {
	var out Page[Role]
	_, err := c.Do(ctx, http.MethodGet, "/roles?boundary_type="+url.QueryEscape(boundary), nil, &out)
	return out.Items, err
}

// Assign assigns a role. scopeType and scopeID name an organization or
// project (for a realm scope, the realm's ID, not its name); leave both empty
// for a realm role in the client's realm.
func (c *Client) Assign(ctx context.Context, roleID, subjectType, subjectID, scopeType, scopeID string) (map[string]any, error) {
	var out map[string]any
	_, err := c.Do(ctx, http.MethodPost, "/role-assignments", map[string]any{"role_id": roleID, "subject": map[string]any{"type": subjectType, "id": subjectID},
		"scope": map[string]any{"type": scopeType, "id": scopeID}}, &out)
	return out, err
}

// CreateClient registers an OAuth client; the secret is returned once.
func (c *Client) CreateClient(ctx context.Context, in map[string]any) (map[string]any, error) {
	var out map[string]any
	_, err := c.Do(ctx, http.MethodPost, "/clients", in, &out)
	return out, err
}

// RotateClientSecret issues an overlapping secret.
func (c *Client) RotateClientSecret(ctx context.Context, clientRef string, retireOthersAfter time.Duration) (map[string]any, error) {
	var out map[string]any
	_, err := c.Do(ctx, http.MethodPost, "/clients/"+url.PathEscape(clientRef)+"/credentials", map[string]any{"retire_others_after_seconds": int(retireOthersAfter.Seconds())}, &out)
	return out, err
}

// RequestImpersonation requests support access.
func (c *Client) RequestImpersonation(ctx context.Context, in map[string]any) (map[string]any, error) {
	var out map[string]any
	_, err := c.Do(ctx, http.MethodPost, "/impersonation-requests", in, &out)
	return out, err
}

// IssueImpersonation issues an approved support grant.
func (c *Client) IssueImpersonation(ctx context.Context, requestID string) (map[string]any, error) {
	var out map[string]any
	_, err := c.Do(ctx, http.MethodPost, "/impersonation-requests/"+url.PathEscape(requestID)+"/issue", nil, &out)
	return out, err
}

// RevokeImpersonation ends a support grant.
func (c *Client) RevokeImpersonation(ctx context.Context, grantID, reason string) error {
	_, err := c.Do(ctx, http.MethodPost, "/impersonation-grants/"+url.PathEscape(grantID)+"/revoke", map[string]any{"reason": reason}, nil)
	return err
}

// AuditEvents queries audit evidence.
func (c *Client) AuditEvents(ctx context.Context, filter url.Values, fn func(map[string]any) error) error {
	return List(ctx, c, "/audit-events?"+filter.Encode(), fn)
}

// Additional typed models (SDK-003).
type (
	OAuthClient struct {
		ID         string   `json:"id"`
		ClientID   string   `json:"client_id"`
		Name       string   `json:"name"`
		Type       string   `json:"client_type"`
		GrantTypes []string `json:"grant_types"`
		State      string   `json:"state"`
	}
	Session struct {
		ID             string    `json:"id"`
		CreatedAt      time.Time `json:"created_at"`
		LastActivityAt time.Time `json:"last_activity_at"`
		AMR            []string  `json:"amr"`
		ACR            string    `json:"acr"`
		DeviceLabel    string    `json:"device_label"`
		Network        string    `json:"network"`
	}
	Invitation struct {
		ID             string    `json:"id"`
		OrganizationID string    `json:"organization_id"`
		Purpose        string    `json:"purpose"`
		TargetEmail    string    `json:"target_email"`
		State          string    `json:"state"`
		DeliveryState  string    `json:"delivery_state"`
		ExpiresAt      time.Time `json:"expires_at"`
	}
	SupportGrant struct {
		ID             string    `json:"id"`
		ActorUserID    string    `json:"actor_user_id"`
		TargetUserID   string    `json:"target_user_id"`
		OrganizationID string    `json:"organization_id"`
		Mode           string    `json:"mode"`
		State          string    `json:"state"`
		ExpiresAt      time.Time `json:"expires_at"`
	}
	PermissionSource struct {
		RoleName    string   `json:"role_name"`
		Via         string   `json:"via"`
		Conditional bool     `json:"conditional"`
		Applies     bool     `json:"applies"`
		Permissions []string `json:"permissions"`
		Redacted    bool     `json:"redacted"`
	}
	EffectivePermissions struct {
		Permissions         []string            `json:"permissions"`
		Provenance          map[string][]string `json:"provenance"`
		Sources             []PermissionSource  `json:"sources"`
		RestrictingPolicies int                 `json:"restricting_policies"`
	}
	InvitationBatchResult struct {
		Index        int            `json:"index"`
		Status       int            `json:"status"`
		InvitationID string         `json:"invitation_id"`
		Error        map[string]any `json:"error"`
	}
)

// Clients lists OAuth clients.
func (c *Client) Clients(ctx context.Context, fn func(OAuthClient) error) error {
	return List(ctx, c, "/clients", fn)
}

// SetResourceGrant sets the scopes and subject types a client may request for a resource.
func (c *Client) SetResourceGrant(ctx context.Context, clientRef, resourceID string, scopes, subjectTypes []string) error {
	_, err := c.Do(ctx, http.MethodPut, "/clients/"+url.PathEscape(clientRef)+"/resource-grants/"+url.PathEscape(resourceID),
		map[string]any{"allowed_scopes": scopes, "subject_types": subjectTypes}, nil)
	return err
}

// UserSessions lists a user's active sessions.
func (c *Client) UserSessions(ctx context.Context, userID string) ([]Session, error) {
	var out Page[Session]
	_, err := c.Do(ctx, http.MethodGet, "/users/"+url.PathEscape(userID)+"/sessions", nil, &out)
	return out.Items, err
}

// RevokeSession revokes one session of a user.
func (c *Client) RevokeSession(ctx context.Context, userID, sessionID string) error {
	_, err := c.Do(ctx, http.MethodDelete, "/users/"+url.PathEscape(userID)+"/sessions/"+url.PathEscape(sessionID), nil, nil)
	return err
}

// Invitations lists an organization's invitations, optionally by state.
func (c *Client) Invitations(ctx context.Context, orgID, state string, fn func(Invitation) error) error {
	return List(ctx, c, "/organizations/"+url.PathEscape(orgID)+"/invitations?state="+url.QueryEscape(state), fn)
}

// RevokeInvitation revokes a pending invitation.
func (c *Client) RevokeInvitation(ctx context.Context, orgID, invitationID string) error {
	_, err := c.Do(ctx, http.MethodPost, "/organizations/"+url.PathEscape(orgID)+"/invitations/"+url.PathEscape(invitationID)+"/revoke", nil, nil)
	return err
}

// InviteBatch creates up to 100 invitations with per-item results (INV-011).
func (c *Client) InviteBatch(ctx context.Context, orgID string, items []map[string]any, opts ...RequestOption) ([]InvitationBatchResult, error) {
	var out struct {
		Results []InvitationBatchResult `json:"results"`
	}
	_, err := c.Do(ctx, http.MethodPost, "/organizations/"+url.PathEscape(orgID)+"/invitations/batch", map[string]any{"items": items}, &out,
		withDefaultKey(opts)...)
	return out.Results, err
}

// ImpersonationGrants lists support grants (filters: actor_user_id, target_user_id, organization_id, state).
func (c *Client) ImpersonationGrants(ctx context.Context, filter url.Values) ([]SupportGrant, error) {
	var out Page[SupportGrant]
	_, err := c.Do(ctx, http.MethodGet, "/impersonation-grants?"+filter.Encode(), nil, &out)
	return out.Items, err
}

// SubjectPermissions inspects a subject's effective permissions with provenance (AZ-009).
func (c *Client) SubjectPermissions(ctx context.Context, subjectID, orgID string) (*EffectivePermissions, error) {
	var out EffectivePermissions
	q := ""
	if orgID != "" {
		q = "?organization_id=" + url.QueryEscape(orgID)
	}
	_, err := c.Do(ctx, http.MethodGet, "/subjects/"+url.PathEscape(subjectID)+"/permissions"+q, nil, &out)
	return &out, err
}
