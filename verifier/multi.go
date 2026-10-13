package verifier

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// IssuerRegistration is one explicitly trusted issuer of a multi-issuer
// application (INT-009) and the application tenant it maps to.
type IssuerRegistration struct {
	Verifier *Verifier
	// Tenant is the application's own tenant for tokens of this issuer.
	Tenant string
}

// MultiIssuer verifies tokens from several explicitly registered issuers,
// for example one realm per customer (INT-009). The token's iss selects the
// registration and that issuer's verifier then checks everything, iss
// included; a token from any other issuer is refused even when it is validly
// signed and its subject or email matches a known user. Subjects are only
// unique per issuer: key application records by (Tenant, Subject).
type MultiIssuer struct {
	issuers map[string]IssuerRegistration
}

// TenantClaims are verified claims with the tenant of their issuer.
type TenantClaims struct {
	*Claims
	Tenant string
}

// NewMultiIssuer builds a multi-issuer verifier from registrations keyed by
// exact issuer URL.
func NewMultiIssuer(regs map[string]IssuerRegistration) (*MultiIssuer, error) {
	m := &MultiIssuer{issuers: map[string]IssuerRegistration{}}
	for iss, r := range regs {
		if iss == "" || r.Verifier == nil || r.Tenant == "" || r.Verifier.cfg.Issuer != iss {
			return nil, errors.New("verifier: each registration needs a tenant and a verifier configured for exactly that issuer")
		}
		m.issuers[iss] = r
	}
	if len(m.issuers) == 0 {
		return nil, ErrMisconfigured
	}
	return m, nil
}

// VerifyTenant verifies a token and returns its claims with the tenant.
func (m *MultiIssuer) VerifyTenant(ctx context.Context, raw string) (*TenantClaims, error) {
	iss, err := unverifiedIssuer(raw)
	if err != nil {
		return nil, err
	}
	r, ok := m.issuers[iss]
	if !ok {
		return nil, ErrIssuer
	}
	c, err := r.Verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	return &TenantClaims{Claims: c, Tenant: r.Tenant}, nil
}

// Authenticate implements Authenticator; the tenant is lost, so prefer
// VerifyTenant where the application maps tenants.
func (m *MultiIssuer) Authenticate(ctx context.Context, raw string) (*Claims, error) {
	tc, err := m.VerifyTenant(ctx, raw)
	if err != nil {
		return nil, err
	}
	return tc.Claims, nil
}

// unverifiedIssuer reads iss only to choose a verifier; nothing else in the
// unverified payload is used.
func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 16<<10 {
		return "", ErrMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrMalformed
	}
	var c struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.Issuer == "" {
		return "", ErrMalformed
	}
	return c.Issuer, nil
}
