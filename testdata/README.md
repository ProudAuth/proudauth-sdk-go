# Pinned cross-language contracts

`contracts/` contains the shared access-token and support-operation cases from
the pre-migration ProudAuth working tree. These are synthetic fixtures, with
**test-only keys** and no customer data. Do not configure these keys in a real
issuer or resource server. The imported `contracts/README.md` describes the
canonical monorepo source and historical generation procedure; those historical
SDK paths are provenance, not standalone build dependencies.

The standalone tests read only local files. `manifest.json` identifies the
source checkout HEAD, labels the input as a working-tree snapshot and pins every
vendored file with SHA-256. `.NET` additionally carries independent Go signature
vectors in `vectors/`.

Run `python3 scripts/check-contracts.py` to verify this snapshot without network
access. Import contract changes from the service repository as a reviewed change;
do not independently redefine expected outcomes in one SDK.
