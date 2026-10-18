# Crucksware

Semantic firmware diff and triage in Rust.

**Experimental and under active development.** The Linux comparison core for two
extracted root filesystem directories is implemented behind an experimental Rust API.
The command-line interface, text report, and JSON output are not implemented yet. There
are no releases.

The core compares filesystem paths and metadata, and reads equal-sized regular files
when their contents must be distinguished. Input trees must remain stable during a
comparison. Path-based checks do not provide an atomic snapshot or containment against
concurrent replacement. Reads may update filesystem-managed access times.

Crucksware is a focused, local tool for firmware analysts, embedded engineers, reverse
engineers, and defensive security researchers. It does not extract firmware images,
interpret binary formats, or execute input files. Direct SquashFS input and semantic
file classification are outside the initial milestone.

## Design

The [v0.1 design](docs/design/v0.1.md) defines the comparison and report contract. The
[implementation plan](docs/development/v0.1-plan.md) tracks the remaining work.

## Development

Install stable Rust with rustfmt and Clippy. The comparison core has no third-party
runtime dependencies. Tests use `tempfile`. The lockfile is committed, and CI uses
stable Rust on Linux.

```sh
cargo fmt --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

## License

Licensed under either the MIT License or Apache License, Version 2.0, at your option.
See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
