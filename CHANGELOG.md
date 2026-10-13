# Changelog

All changes, including breaking changes, are documented here. Package releases
will use semantic versioning; the initial 0.x API may change between minor versions.

## Unreleased — 0.2.0 standalone extraction

### Added

- Independent repository layout, root-level package metadata and CI.
- Vendored shared access-token and support-operation fixtures, with source HEAD
  and SHA-256 provenance, and an offline integrity check.
- Standalone contribution and private vulnerability reporting policies.

### Changed

- Monorepo-relative test inputs and documentation links now work from this checkout.

This is source preparation. No registry package or release tag has been published.
The existing SDK behavior and 0.2.0 version identifiers are retained.
