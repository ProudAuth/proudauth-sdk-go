package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/proudbase/proudauth-sdk-go/internal/httpclient"
)

// Introspector verifies tokens online against the identity provider (strict-online
// mode, §13.2). Every call consults authoritative state; there is no positive cache,
// and any failure denies rather than downgrading to offline checks (SDK-002).
type Introspector struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	Issuer       string
	Audience     string
	HTTPClient   *http.Client
	Timeout      time.Duration
	// AcceptedKinds defaults to user_access, service_access, exchange_access,
	// api_key and personal_access. Support tokens are accepted only through
	// SupportGuard: listing impersonation_access here is a configuration
	// error (ErrSupportKind) and every Authenticate call fails, as the Node
	// SDK refuses the same configuration at construction.
	AcceptedKinds []string
}

// SupportTokenKind is the token_kind of support (impersonation) tokens.
const SupportTokenKind = "impersonation_access"

// ErrSupportKind reports an Introspector configured to accept
// impersonation_access as an ordinary token kind. Support tokens must go
// through SupportGuard, which enforces the support contract (IMP-001, IMP-010).
var ErrSupportKind = errors.New("verifier: impersonation_access must be handled by SupportGuard, not accepted as an ordinary kind")

// defaultOnlineKinds are the token kinds Introspector.Authenticate accepts
// when AcceptedKinds is empty. Read them with DefaultOnlineKindList: the list
// is not a mutable package variable, so no importing code can widen it.
var defaultOnlineKinds = []string{"user_access", "service_access", "exchange_access", "api_key", "personal_access"}

// DefaultOnlineKindList returns a copy of the default accepted token kinds.
func DefaultOnlineKindList() []string { return slices.Clone(defaultOnlineKinds) }

func (i *Introspector) introspect(ctx context.Context, raw string) (map[string]any, error) {
	if i.Issuer == "" || i.Audience == "" {
		// Every API must pin its issuer and audience (§28.2).
		return nil, ErrMisconfigured
	}
	if raw == "" {
		return nil, ErrMissingToken
	}
	timeout := i.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.Endpoint, strings.NewReader(url.Values{"token": {raw}}.Encode()))
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(i.ClientID), url.QueryEscape(i.ClientSecret))
	client := i.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	res, err := httpclient.Do(client, req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, ErrUnavailable
	}
	var m map[string]any
	body, err := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 || rejectDuplicates(body) != nil || json.Unmarshal(body, &m) != nil {
		return nil, ErrUnavailable
	}
	if m["active"] != true {
		return nil, ErrInactive
	}
	return m, nil
}

func toClaims(m map[string]any) (*Claims, error) {
	str := func(k string) string { s, _ := m[k].(string); return s }
	num := func(k string) int64 {
		switch v := m[k].(type) {
		case float64:
			return int64(v)
		case json.Number:
			n, _ := v.Int64()
			return n
		}
		return 0
	}
	c := &Claims{Issuer: str("iss"), Subject: str("sub"), Audience: str("aud"), ClientID: str("client_id"), Scopes: strings.Fields(str("scope")),
		OrgID: str("org_id"), SessionID: str("sid"), TokenKind: str("token_kind"), JTI: str("jti"), ACR: str("acr"),
		AuthzVersion: num("authz_version"), SupportMode: str("support_mode"), ImpersonationGrantID: str("impersonation_grant_id"), Online: true}
	if v := num("exp"); v > 0 {
		c.Expiry = time.Unix(v, 0)
	}
	if v := num("iat"); v > 0 {
		c.IssuedAt = time.Unix(v, 0)
	}
	if v := num("auth_time"); v > 0 {
		c.AuthTime = time.Unix(v, 0)
	}
	if act, ok := m["act"].(map[string]any); ok {
		c.Actor = &Actor{}
		c.Actor.Subject, _ = act["sub"].(string)
		c.Actor.Issuer, _ = act["iss"].(string)
	}
	if cnf, present := m["cnf"]; present {
		raw, err := json.Marshal(cnf)
		if err != nil {
			return nil, ErrSenderConstraint
		}
		c.Confirmation, err = parseConfirmation(raw)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (i *Introspector) check(c *Claims) error {
	if c.Issuer != i.Issuer {
		return ErrIssuer
	}
	if c.Audience != i.Audience {
		return ErrAudience
	}
	return nil
}

// Authenticate verifies a non-support token online. impersonation_access is
// never accepted here, whatever AcceptedKinds says: support tokens go through
// SupportGuard.
func (i *Introspector) Authenticate(ctx context.Context, raw string) (*Claims, error) {
	return i.authenticate(ctx, raw, false)
}

func (i *Introspector) authenticate(ctx context.Context, raw string, allowBound bool) (*Claims, error) {
	kinds := i.AcceptedKinds
	if len(kinds) == 0 {
		kinds = defaultOnlineKinds
	}
	if slices.Contains(kinds, SupportTokenKind) {
		// Refuse the configuration before any network call, as the Node SDK's
		// Introspector constructor does.
		return nil, ErrSupportKind
	}
	m, err := i.introspect(ctx, raw)
	if err != nil {
		return nil, err
	}
	c, err := toClaims(m)
	if err != nil {
		return nil, err
	}
	if c.Confirmation != nil && !allowBound {
		return nil, ErrSenderConstraint
	}
	if err := i.check(c); err != nil {
		return nil, err
	}
	if c.TokenKind == SupportTokenKind || !slices.Contains(kinds, c.TokenKind) {
		// A support token presented to an API that has not implemented the support
		// contract is rejected (IMP-001, TEST-045).
		return nil, ErrTokenKind
	}
	return c, nil
}

// SupportEvent is the actor-aware record a resource must persist for every support
// request (IMP-006).
type SupportEvent struct {
	GrantID   string
	Actor     string
	Subject   string
	OrgID     string
	Operation string
	// Read is the effective classification: false when the caller declared a
	// write or the operation name carries a write-like segment.
	Read    bool
	Allowed bool
	// DenyReason is DenyProtectedOperation or DenyWriteNotAllowlisted when
	// access was denied, empty otherwise.
	DenyReason string
	At         time.Time
}

// Support denial reasons recorded in SupportEvent.DenyReason (the same values
// the Node SDK reports).
const (
	DenyProtectedOperation  = "protected_operation"
	DenyWriteNotAllowlisted = "write_not_allowlisted"
)

// SupportAuditor persists support evidence. A resource that cannot record the
// actor must not serve support requests.
type SupportAuditor interface {
	RecordSupportAccess(ctx context.Context, ev SupportEvent) error
}

// SupportGuard implements the downstream support-access contract: strict-online
// validation per request, preserved actor identity, read-only default, explicit
// write allowlist, protected identity operations always denied, and an audit
// record before access (§16.2, INT-010).
type SupportGuard struct {
	Introspector *Introspector
	Auditor      SupportAuditor
	// WriteOperations lists operations allowed in allowlisted_write mode,
	// matched case-insensitively against the whole operation name.
	WriteOperations []string
	// ProtectedOperations adds operations that are always denied; the
	// defaults (ProtectedOperationList) cannot be removed.
	ProtectedOperations []string
}

// ErrContract signals a resource that does not satisfy the support contract.
var ErrContract = errors.New("verifier: support contract not satisfied (auditor required)")

// Validate checks the guard configuration; call it at startup (contract validation).
func (g *SupportGuard) Validate() error {
	if g == nil || g.Introspector == nil || g.Auditor == nil {
		return ErrContract
	}
	if g.Introspector.Issuer == "" || g.Introspector.Audience == "" {
		return ErrMisconfigured
	}
	return nil
}

// protectedOperations can never be performed with support access (IMP-012,
// IMP-013). Each entry is one or more operation-name segments; see
// IsProtectedOperation for how they match. The list is unexported so that no
// importing package can weaken the support protections at run time;
// ProtectedOperationList returns a copy.
var protectedOperations = []string{"password.change", "password.reset", "mfa.change", "identifier.change", "account.link",
	"credential.export", "api_key.create", "personal_token.create", "consent.modify", "idp.admin", "payment", "refund",
	"ownership.transfer", "secret.read", "secret", "delete", "purge"}

// writeSegments are verbs that make an operation a write wherever they
// appear as a segment of its name, even when the caller declared it a read
// ("orders.read.update" is a write). Matching is exact per segment. Like
// protectedOperations it is unexported; WriteSegmentList returns a copy.
var writeSegments = []string{"create", "add", "insert", "update", "edit", "modify", "change", "set", "put", "patch", "write",
	"upsert", "replace", "delete", "remove", "destroy", "erase", "purge", "archive", "unarchive", "restore", "reset", "rotate",
	"revoke", "grant", "assign", "unassign", "link", "unlink", "transfer", "issue", "approve", "reject", "cancel", "enable",
	"disable", "suspend", "reactivate", "activate", "deactivate", "lock", "unlock", "invite", "send", "submit", "publish",
	"unpublish", "import", "merge", "move", "rename", "refund", "pay", "execute"}

// ProtectedOperationList returns a copy of the operations that can never be
// performed with support access (IMP-012, IMP-013), the defaults every
// SupportGuard denies. Changing the returned slice has no effect on the guard;
// add operations of your own with SupportGuard.ProtectedOperations.
func ProtectedOperationList() []string { return slices.Clone(protectedOperations) }

// WriteSegmentList returns a copy of the write verbs that make an operation a
// write wherever they appear as a segment of its name (see IsWriteOperation).
// Changing the returned slice has no effect on the classification.
func WriteSegmentList() []string { return slices.Clone(writeSegments) }

// operationSegments normalizes an operation name for classification: trimmed,
// lowercased, '-' read as '_', split into segments on '.', ':' and '/', with
// empty segments dropped.
func operationSegments(operation string) []string {
	op := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(operation)), "-", "_")
	return strings.FieldsFunc(op, func(r rune) bool { return r == '.' || r == ':' || r == '/' })
}

// segmentMatches compares one operation segment with one entry segment,
// tolerating a simple plural on either side ("payments" matches "payment",
// "secret" matches "secrets").
func segmentMatches(seg, entry string) bool {
	return seg == entry || seg == entry+"s" || seg+"s" == entry
}

// containsRun reports whether entry's segments occur as a contiguous run in segs.
func containsRun(segs, entry []string) bool {
	if len(entry) == 0 || len(entry) > len(segs) {
		return false
	}
	for start := 0; start+len(entry) <= len(segs); start++ {
		ok := true
		for k, e := range entry {
			if !segmentMatches(segs[start+k], e) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// IsProtectedOperation reports whether an operation touches a protected
// identity, money or secret operation anywhere in its name: the segments of a
// default entry (ProtectedOperationList) or of an extra entry occur as a contiguous run of the
// operation's segments, case-insensitively and tolerating simple plurals
// ("orders.refund", "refunds.issue", "payments.create", "secrets.read",
// "orders.purge", "users.password.change", "Account.Delete"). An empty
// operation is treated as protected (deny by default).
func IsProtectedOperation(operation string, extra ...string) bool {
	segs := operationSegments(operation)
	if len(segs) == 0 {
		return true
	}
	for _, list := range [][]string{protectedOperations, extra} {
		for _, p := range list {
			if containsRun(segs, operationSegments(p)) {
				return true
			}
		}
	}
	return false
}

// IsWriteOperation reports whether any segment of the operation name is a
// write-like verb (WriteSegmentList). Such operations are writes even when the
// caller declares them reads.
func IsWriteOperation(operation string) bool {
	for _, s := range operationSegments(operation) {
		if slices.Contains(writeSegments, s) {
			return true
		}
	}
	return false
}

// supportDecision applies the support policy to one operation. It returns
// the effective read classification and the deny reason ("" when allowed).
func (g *SupportGuard) supportDecision(c *Claims, operation string, read bool) (bool, string) {
	read = read && !IsWriteOperation(operation)
	if IsProtectedOperation(operation, g.ProtectedOperations...) {
		return read, DenyProtectedOperation
	}
	if !read && (c.SupportMode != "allowlisted_write" || !g.writeAllowed(operation)) {
		return read, DenyWriteNotAllowlisted
	}
	return read, ""
}

func (g *SupportGuard) writeAllowed(operation string) bool {
	op := strings.TrimSpace(operation)
	for _, w := range g.WriteOperations {
		if strings.EqualFold(strings.TrimSpace(w), op) {
			return true
		}
	}
	return false
}

// Authorize validates a support token for one operation. read is true for
// non-mutating operations; an operation whose name carries a write-like
// segment is a write regardless. The audit record is written before access
// is granted; if it cannot be written, access is denied.
func (g *SupportGuard) Authorize(ctx context.Context, raw, operation string, read bool) (*Claims, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	m, err := g.Introspector.introspect(ctx, raw)
	if err != nil {
		return nil, err
	}
	c, err := toClaims(m)
	if err != nil {
		return nil, err
	}
	if c.Confirmation != nil {
		return nil, ErrSenderConstraint
	}
	if err := g.Introspector.check(c); err != nil {
		return nil, err
	}
	if c.TokenKind != SupportTokenKind || c.Actor == nil || c.Actor.Subject == "" || c.ImpersonationGrantID == "" {
		return nil, ErrTokenKind
	}
	if strings.TrimSpace(operation) == "" {
		// A route without an operation name is a programming error: deny, as
		// the Node SDK does, before anything is recorded.
		return nil, ErrSupportPolicy
	}
	effectiveRead, reason := g.supportDecision(c, operation, read)
	ev := SupportEvent{GrantID: c.ImpersonationGrantID, Actor: c.Actor.Subject, Subject: c.Subject, OrgID: c.OrgID, Operation: operation,
		Read: effectiveRead, Allowed: reason == "", DenyReason: reason, At: time.Now().UTC()}
	if err := g.Auditor.RecordSupportAccess(ctx, ev); err != nil {
		return nil, ErrUnavailable
	}
	if reason != "" {
		return nil, ErrSupportPolicy
	}
	return c, nil
}
