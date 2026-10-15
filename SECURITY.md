# Security policy

This repository is a standalone, unpublished 0.2.0 development snapshot. It does
not yet promise a stable release or long-term support window. Security corrections
must preserve the access-token, support-access and revocation contracts.

Report suspected vulnerabilities privately through [GitHub private vulnerability
reporting](https://github.com/proudauth/proudauth-sdk-go/security/advisories/new).
Maintainers must enable that channel before public launch. If it is unavailable,
request a private reporting channel from the ProudAuth organization maintainers;
do not put exploit details, credentials or customer data in a public issue.

Please include the affected SDK and runtime versions, validation profile, minimal
reproduction and expected behavior. Use synthetic tokens and test-only data.
Never report a bearer token, client secret or private production signing key.

A confirmed issue affecting shared protocol behavior is coordinated with the
[service maintainers](https://github.com/proudauth/proudauth) and the other SDKs.
Published security advisories identify affected versions and the fixed release;
compatibility and breaking changes belong in CHANGELOG.md.
