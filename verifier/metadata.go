package verifier

import (
	"context"
	"strings"
)

// AuthenticateMetadata authenticates a request whose credentials travel as
// metadata rather than HTTP headers: gRPC metadata, message-queue headers or
// a WebSocket upgrade's headers (SDK-011, INT-003, INT-004). It accepts only
// a single "authorization: Bearer <token>" entry, keys matched without case,
// so a gRPC unary or stream interceptor is a few lines around it:
//
//	md, _ := metadata.FromIncomingContext(ctx)
//	claims, err := verifier.AuthenticateMetadata(ctx, v, md)
//	if err != nil {
//		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
//	}
//	return handler(verifier.WithClaims(ctx, claims), req)
//
// The security decision stays in the Authenticator; this only extracts the
// token. Long-lived streams must re-check claims before expiry (INT-005).
func AuthenticateMetadata(ctx context.Context, a Authenticator, md map[string][]string) (*Claims, error) {
	var values []string
	for k, v := range md {
		if strings.EqualFold(k, "authorization") {
			values = append(values, v...)
		}
	}
	if len(values) == 0 {
		return nil, ErrMissingToken
	}
	if len(values) != 1 {
		return nil, ErrMalformed
	}
	h := values[0]
	if len(h) <= 7 || !strings.EqualFold(h[:7], "bearer ") || strings.TrimSpace(h[7:]) == "" {
		return nil, ErrMissingToken
	}
	return a.Authenticate(ctx, strings.TrimSpace(h[7:]))
}
