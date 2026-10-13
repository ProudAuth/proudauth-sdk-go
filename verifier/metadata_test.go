package verifier

import (
	"context"
	"errors"
	"testing"
)

type stubAuth struct{ got string }

func (s *stubAuth) Authenticate(_ context.Context, raw string) (*Claims, error) {
	s.got = raw
	return &Claims{Subject: "usr_1"}, nil
}

// TestAuthenticateMetadata covers INT-003 and INT-004 for the SDK: gRPC
// metadata or a WebSocket upgrade's headers are authenticated from exactly one
// "authorization: Bearer" entry, never from other keys or duplicates.
func TestAuthenticateMetadata(t *testing.T) {
	a := &stubAuth{}
	c, err := AuthenticateMetadata(context.Background(), a, map[string][]string{"Authorization": {"Bearer abc.def"}})
	if err != nil || c.Subject != "usr_1" || a.got != "abc.def" {
		t.Fatalf("valid metadata: %v %v %q", c, err, a.got)
	}
	for name, md := range map[string]map[string][]string{
		"missing":    {},
		"not bearer": {"authorization": {"Basic eDp5"}},
		"duplicate":  {"authorization": {"Bearer a", "Bearer b"}},
		"two keys":   {"authorization": {"Bearer a"}, "Authorization": {"Bearer b"}},
	} {
		if _, err := AuthenticateMetadata(context.Background(), a, md); !errors.Is(err, ErrMissingToken) && !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
