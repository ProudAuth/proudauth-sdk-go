# Security policy

The current release is `v0.2.0`. During 0.x the API may change between minor
versions, and only the latest release receives security fixes; there is no
long-term support window yet. Security corrections must preserve the
access-token, support-access and revocation contracts.

Report suspected vulnerabilities privately through [GitHub private vulnerability
reporting](https://github.com/proudauth/proudauth-sdk-go/security/advisories/new).
If that channel is unavailable, request a private reporting channel from the
ProudAuth organization maintainers; do not put exploit details, credentials or
customer data in a public issue.

Please include the affected SDK and runtime versions, validation profile, minimal
reproduction and expected behavior. Use synthetic tokens and test-only data.
Never report a bearer token, client secret or private production signing key.

A confirmed issue affecting shared protocol behavior is coordinated with the
[service maintainers](https://github.com/proudauth/proudauth) and the other SDKs.
Published security advisories identify affected versions and the fixed release;
compatibility and breaking changes belong in CHANGELOG.md.
