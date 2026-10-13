# Standalone validation — 2026-10-13

Source checkout HEAD: `5ff6ddb852b572a05d4b1b5e6afdf2ecc1350a11`.
The source is a pre-migration working-tree snapshot, including unpublished changes,
not an asserted byte-identical export of that commit. Input hashes are recorded
in SOURCE-MANIFEST.json; local synthetic contract hashes are checked separately.

Runtime: Go 1.27.1, darwin/arm64. No server, database, Docker or live deployment
was used. Network module downloads were disabled with `GOPROXY=off`,
`GOSUMDB=off` and `GOTOOLCHAIN=local`.

| Check | Result |
| --- | --- |
| `python3 scripts/check-contracts.py` | Pass: 4 pinned contract/provenance files |
| `go mod verify` | Pass |
| `go vet ./...` | Pass |
| `go test -race -count=1 ./...` | Pass: admin, internal/httpclient, oidcclient, verifier |
| README example in a separate consumer module | Pass: offline module resolution and compilation; temporary consumer removed |
| Publication audit | Pass: no installation secrets, token/private-key markers, personal paths or private state in the source snapshot |

The verifier includes shared accepted/rejected access-token fixtures, support
operation cases and existing fuzz seeds. CI adds timed fuzz smoke runs; those
extra timed fuzz runs were not executed during this bounded local phase.

Go module: `github.com/proudbase/proudauth-sdk-go`; runtime dependency:
`github.com/go-jose/go-jose/v4` 4.1.5. No registry release or tag was published
by this staging work. The subsequent [public-source CI](https://github.com/proudbase/proudauth-sdk-go/actions/runs/38452064468)
passed at `116f9fa19d0b0174a0c270763e2ef6abf872233b`, including the race
suite and both 30-second fuzz smoke checks. README links and issuer examples now
use the canonical project documentation and an operator-owned identity domain;
runtime, module and contract bytes are unchanged.

Excluded: original .git history, local credentials, deployment state, SDK caches,
compiled outputs, node_modules, database/image archives and benchmark seed files.
