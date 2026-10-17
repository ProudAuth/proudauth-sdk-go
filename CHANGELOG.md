# Changelog

All changes, including breaking changes, are documented here. Package releases
will use semantic versioning; the initial 0.x API may change between minor versions.

## Unreleased — 0.2.0 standalone extraction

### Known limitations

- A running verifier keeps a retired or compromised signing key trusted until
  the process restarts: the JWKS cache has no expiry, no refresh or rejection
  method, and `BoundedState` ignores `signing_key.rotated`. Restart resource
  servers after an emergency rotation; 0.3.0 adds key expiry, refresh and
  rejection.

### Changed

- The module requires Go 1.25 instead of Go 1.27.1, and CI tests Go 1.25,
  1.26 and 1.27.

### Added

- Independent repository layout, root-level package metadata and CI.
- Vendored shared access-token and support-operation fixtures, with source HEAD
  and SHA-256 provenance, and an offline integrity check.
- Standalone contribution and private vulnerability reporting policies.

### Changed

- Monorepo-relative test inputs and documentation links now work from this checkout.

This is source preparation. No registry package or release tag has been published.
The existing SDK behavior and 0.2.0 version identifiers are retained.
