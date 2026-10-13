# Contributing

Changes must preserve exact issuer/audience checks, fail-closed revocation,
strict-online support access, redirect safety and secret redaction. Include a
regression test for a behavior change and describe the supported runtime impact.

Run the checks documented in README.md and `python3 scripts/check-contracts.py`
before submitting a pull request. Use synthetic fixtures and loopback mock
servers; unit tests must not depend on the public ProudAuth deployment.

The files under testdata/ are pinned copies of shared contracts. Change their
canonical source in the service repository first, then import the reviewed
snapshot and update testdata/manifest.json. Do not change expected outcomes only
to make one language implementation pass. SOURCE-MANIFEST.json is extraction
provenance, not a promise that the working-tree bytes equal the recorded HEAD.

Contributions are licensed under Apache-2.0. Sign off your commits with
`git commit -s` under the Developer Certificate of Origin
(https://developercertificate.org/). Do not include private keys, bearer tokens,
client secrets, local environment files, customer data or generated build output.

Report vulnerabilities using SECURITY.md. Ordinary bug reports should include
runtime and SDK versions, a minimal reproduction and the validation profile.
