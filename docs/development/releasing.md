# Release process

Release binaries are built on GitHub-hosted Linux runners. They must never be
uploaded from a maintainer workstation.

For a release, merge the version update, create and push the matching `vX.Y.Z`
tag, then let the Release workflow test the tag, build the executable, package
the archive, generate SHA-256 checksums, create GitHub artifact attestations,
and publish the assets. The workflow checks the tag against both Cargo version
files, records the source commit and toolchain, runs the release binary smoke
tests, and verifies the published archive and its provenance.

The workflow builds twice into clean target directories on the same runner and
records whether the executable hashes match. This is a per-run check, not a
general reproducibility guarantee.

Manual dispatch is limited to `main` and is intended for a controlled repair of
an existing release. It builds from the supplied exact tag. Before replacing
the archive or checksum asset, it checks their current download counts, uploads
and verifies staged replacements, then checks the counts again. GitHub does not
provide an atomic operation that combines download-count inspection and asset
replacement, so a concurrent download during that short interval cannot be
excluded. If an existing target asset has a nonzero count, the workflow refuses
replacement. If a retry finds both assets already matching the built SHA-256
digests, it verifies them without replacing them, even though the verification
downloads have incremented their counts. Historical backfills run the workflow from `main`; their
attestation identifies that workflow run and ref. The archive's `BUILDINFO.txt`
records the release tag and commit, which the workflow resolves and verifies
before building. A tag-triggered release instead attests the workflow run with
the release tag as its source ref. During replacement, the old assets are kept
under temporary backup names until the new canonical assets pass checksum and
attestation verification. The workflow attempts to restore the old names if the
swap fails.

The release workflow publishes the Linux x86_64 GNU target only. Other
platforms require their own tested build and packaging work.
