package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// Secret holds a one-time secret returned by the API: a client secret, API
// key, webhook signing secret, setup or handoff code, download token or
// recovery code (SDK-007, SDK-008). It never prints, logs or serializes its
// value; Reveal returns it for the one place that must store it.
type Secret struct{ v string }

// NewSecret wraps a value.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the secret value.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.v == "" }

func (s Secret) redacted() string {
	if s.v == "" {
		return ""
	}
	return "[REDACTED]"
}

// String, Format, GoString, LogValue and MarshalJSON all redact.
func (s Secret) String() string                { return s.redacted() }
func (s Secret) GoString() string              { return "admin.Secret(" + s.redacted() + ")" }
func (s Secret) Format(f fmt.State, verb rune) { _, _ = fmt.Fprint(f, s.redacted()) }
func (s Secret) LogValue() slog.Value          { return slog.StringValue(s.redacted()) }
func (s Secret) MarshalJSON() ([]byte, error)  { return json.Marshal(s.redacted()) }
func (s *Secret) UnmarshalJSON(b []byte) error { return json.Unmarshal(b, &s.v) }

// secretMembers are response members that carry one-time secrets; the same
// list the server uses to keep such responses out of its idempotency store.
var secretMembers = map[string]bool{"client_secret": true, "client_secrets": true, "api_key": true, "signing_secret": true,
	"setup_token": true, "recovery_codes": true, "invitation_secret": true, "access_token": true, "refresh_token": true, "id_token": true,
	"handoff_code": true, "download_token": true, "token": true, "secret": true, "webhook_secrets": true}

// wrapSecrets replaces secret-bearing string values in a decoded JSON object
// with Secret values, recursively.
func wrapSecrets(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretMembers[k] {
				x[k] = sealValue(val)
				continue
			}
			x[k] = wrapSecrets(val)
		}
		return x
	case []any:
		for i := range x {
			x[i] = wrapSecrets(x[i])
		}
		return x
	}
	return v
}

func sealValue(v any) any {
	switch x := v.(type) {
	case string:
		return NewSecret(x)
	case []any:
		for i := range x {
			x[i] = sealValue(x[i])
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = sealValue(x[k])
		}
		return x
	}
	return v
}
