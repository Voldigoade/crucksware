# Contributing

Crucksware is experimental. Keep changes within the extracted root filesystem comparison
scope in [the v0.1.0 design](docs/design/v0.1.md).

For behavior changes, add a test that demonstrates the expected result before changing
the implementation. Use synthetic, redistributable inputs. Do not add proprietary
firmware, credentials, private keys, or large generated files.

Keep input trees read-only. Explain new dependencies and review their current
maintenance, API, licenses, and dependency graph. Run the verification commands in the
README before submitting a pull request. Use a concise change summary with observed test
results and known limitations.

Contributions are accepted under the project's MIT OR Apache-2.0 license.
