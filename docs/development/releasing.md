# Release process

Every release follows this sequence:

SOURCE MERGE
-> VERSION PREPARATION
-> TAG
-> GITHUB ACTIONS
-> TEST
-> BUILD
-> PACKAGE
-> CHECKSUM
-> ATTESTATION
-> GITHUB RELEASE

Release binaries are built on GitHub-hosted Linux runners. They must never be
uploaded from a maintainer workstation. Tags with a prerelease suffix, such as
`v0.2.0-beta.1`, are published as GitHub prereleases.

The workflow checks out the exact tag and verifies that the tag, Cargo.toml, and
Cargo.lock versions match. It runs formatting, compilation, Clippy, tests, package
inspection, and dependency-tree checks. It then builds the release executable twice
into clean target directories on the same runner and records whether the hashes
match. This is a per-run check, not a general reproducibility guarantee.

The workflow packages the Linux x86_64 executable with the README, licenses, and
build information. It creates SHA-256 checksums and GitHub artifact attestations
for the archive, checksum file, and executable. It uploads the archive and
`SHA256SUMS`, downloads them again, checks the digest, and verifies provenance
before completing the release.

Manual dispatch is limited to `main` and is intended for a controlled repair of
an existing release. It builds from the supplied exact tag. Before replacing the
archive or checksum asset, it checks their current download counts, uploads and
verifies staged replacements, then checks the counts again. GitHub does not provide
an atomic operation that combines download-count inspection and asset replacement,
so a concurrent download during that short interval cannot be excluded. If an
existing target asset has a nonzero count, the workflow refuses replacement. If a
retry finds both assets already matching the built SHA-256 digests, it verifies them
without replacing them, even though the verification downloads have incremented
their counts. Historical backfills run the workflow from `main`; their attestation
identifies that workflow run and ref. The archive's `BUILDINFO.txt` records the
release tag and commit, which the workflow resolves and verifies before building.
A tag-triggered release instead attests the workflow run with the release tag as
its source ref. During replacement, the old assets are kept under temporary backup
names until the new canonical assets pass checksum and attestation verification.
The workflow attempts to restore the old names if the swap fails.

The release workflow publishes the Linux x86_64 GNU target only. Other platforms
require their own tested build and packaging work.
