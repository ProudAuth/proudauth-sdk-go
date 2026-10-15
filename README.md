<p align="center">
  <a href="https://proudauth.com"><img src="https://raw.githubusercontent.com/ProudAuth/.github/main/assets/banner-proudauth-sdk-go.png" alt="ProudAuth SDK for Go" width="100%"></a>
</p>

<p align="center">
  <a href="https://github.com/ProudAuth/proudauth-sdk-go"><img alt="Go" src="https://img.shields.io/badge/Go-SDK-3ee6b0?logo=go&logoColor=3ee6b0&style=for-the-badge&labelColor=06120e"></a>
  <a href="https://github.com/ProudAuth/proudauth-sdk-go/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/ProudAuth/proudauth-sdk-go/ci.yml?branch=main&label=ci&style=for-the-badge&labelColor=06120e"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-3ee6b0?style=for-the-badge&labelColor=06120e"></a>
  <a href="https://proudauth.com/docs/sdks/go-reference/"><img alt="Documentation" src="https://img.shields.io/badge/docs-proudauth.com-3ee6b0?style=for-the-badge&labelColor=06120e"></a>
</p>

# ProudAuth SDK for Go

First-party backend SDK for ProudAuth: verify access tokens, apply live
revocation and support-access rules, integrate an OIDC backend-for-frontend,
and automate the administration API.

**Version 0.2.0, development snapshot.** No release tag exists yet.
Minimum Go: **1.27.1**.
Apache-2.0. The only third-party module is `go-jose/v4` 4.1.5.

[Documentation](https://proudauth.com/docs/) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

The identity service is maintained separately in
[`proudauth/proudauth`](https://github.com/proudauth/proudauth).
You deploy it on your own infrastructure; `proudauth.com` hosts the project
website and documentation. Configure the SDK with your instance's exact issuer.

## Quick start

Clone the source and run its checks from the repository root:

```sh
git clone https://github.com/proudauth/proudauth-sdk-go.git
cd proudauth-sdk-go
python3 scripts/check-contracts.py
go test -race ./...
```

Install the development revision into your application:

```sh
go get github.com/proudauth/proudauth-sdk-go@main
```

Go records the resolved immutable revision in your `go.mod` and `go.sum`.
Use a reviewed release tag when tagged releases become available. For local
development, a Go workspace can include your application and this module.

Imports use `github.com/proudauth/proudauth-sdk-go/verifier`, `/oidcclient`
and `/admin`. They no longer use the monorepo's `github.com/proudauth/sdk/go`.

## Packages

| Package | Purpose |
| --- | --- |
| `verifier` | Offline asymmetric JWT verification, HTTP middleware, exact multi-issuer registration, strict-online introspection, audited support access, bounded revocation state and request-level DPoP/mTLS verification |
| `oidcclient` | Backend-for-frontend authorization code + PKCE, ID-token validation, coordinated refresh and logout |
| `admin` | Administration API, RFC 9457 problems, cursor pagination, idempotency, optimistic concurrency, deadlines and one-time secret wrappers |

Supported signature algorithms: RS256, PS256, ES256 and EdDSA. Unsigned and
HMAC tokens are refused. Issuer and audience come from trusted configuration;
tokens never choose a discovery or key-set URL.

## Protect a Go API

```go
package main

import (
    "log"
    "net/http"

    "github.com/proudauth/proudauth-sdk-go/verifier"
)

func main() {
    auth, err := verifier.New(verifier.Config{
        Issuer: "https://identity.example.com/realms/main", // your instance
        Audience: "https://orders.example.com",
    })
    if err != nil {
        log.Fatal(err)
    }
    orders := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims := verifier.FromContext(r.Context())
        if err := claims.RequireScope("orders:read"); err != nil {
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }
        // Before reading an organization-owned row, compare its organization
        // from your database with claims.RequireOrganization(row.OrgID).
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"authenticated":true}`))
    })
    log.Fatal(http.ListenAndServe("127.0.0.1:8080", verifier.Middleware(auth, orders)))
}
```

Register the real API audience and choose a validation profile for each
operation before deploying this example. Identity-provider credentials are
needed only for profiles which make authenticated online calls.

## Pick a validation profile

| Profile | Appropriate use | Revocation exposure |
| --- | --- | --- |
| Offline `Verifier` | Ordinary operations on short-lived access tokens | Token expiry plus configured clock skew; it does not consult current state |
| `Introspector` | Security changes, payments and other operations needing current server state | One live request per check; unavailable identity provider denies access |
| `SupportGuard` | Administrator impersonation/support sessions | Strict-online with actor preservation, protected-operation denial, explicit write allowlisting and audit-before-access |
| `BoundedState` + `BoundedVerifier` | Local JWT checks with a chosen maximum revocation delay | At most `MaxStaleness`; stale state fails closed |
| `SenderVerifier` | DPoP or mutual-TLS-bound tokens | Checks the token plus this request's proof or certificate; shared replay state is required across replicas |

Do not use the ordinary verifier to accept support tokens. Token-only checks
reject sender-constrained tokens; a request-level sender verifier must validate
the bound proof. Key records by issuer/tenant and subject, not email. Compare
organization claims with stored resource ownership, never request-supplied IDs.

[Resource-server contract](https://proudauth.com/docs/integrations/resource-servers/) ·
[SDK compatibility policy](https://proudauth.com/docs/integrations/sdk-compatibility/)

## Testing and provenance

```sh
python3 scripts/check-contracts.py
go mod verify
go vet ./...
go test -race -count=1 ./...
go test ./verifier -run '^$' -fuzz '^FuzzVerify$' -fuzztime 30s
go test ./verifier -run '^$' -fuzz '^FuzzSenderURLNormalization$' -fuzztime 30s
```

The suite uses synthetic shared fixtures and loopback mock servers. It does not
call a live identity instance. `testdata/contracts/` contains the same 22 accepted
and rejected access-token cases used by the other SDKs, plus support-operation
classification rules. Keys in test data are test-only. `testdata/manifest.json`
pins their bytes; `SOURCE-MANIFEST.json` records the source checkout HEAD and
working-tree input hashes. Standalone check results are recorded in [VALIDATION.md](VALIDATION.md).

## License and security

Apache-2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE). Report vulnerabilities
privately using [SECURITY.md](SECURITY.md). Contributions require regression
coverage and a DCO sign-off as described in [CONTRIBUTING.md](CONTRIBUTING.md).
