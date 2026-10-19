# Crucksware

Semantic firmware diff and triage in Rust.

**Experimental and under active development.** Linux comparison of two extracted root
filesystem directories is implemented, including exact bounded regular-file comparison
and filesystem metadata. The direct CLI provides deterministic text and JSON schema v1
reports, plus bounded single-file inspection. ELF inputs receive static structural facts;
unknown files receive only basic type, size, and text/binary facts.
The interactive shell adds session summaries and text, JSON, Markdown, and offline HTML
exports with live progress.

The comparison reads equal-sized regular files when their contents must be distinguished.
Input trees must remain stable during a comparison. Path-based checks do not provide an
atomic snapshot or containment against concurrent replacement. Reads may update
filesystem-managed access times.

Crucksware is a focused, local tool for firmware analysts, embedded engineers, reverse
engineers, and defensive security researchers. It does not extract firmware images or
semantically compare binary formats. Input files are never executed. Direct SquashFS
input and semantic file classification are not implemented.

## Design

The [v0.1 design](docs/design/v0.1.md) defines the comparison and report contract,
including the [JSON schema](docs/json/schema-1.json). The
[implementation plan](docs/development/v0.1-plan.md) tracks the remaining work.
The [binary analysis design](docs/design/binary-analysis.md) describes current ELF
inspection and future format support.

```sh
crucksware compare old-rootfs/ new-rootfs/
crucksware compare --format json old-rootfs/ new-rootfs/
crucksware inspect ./program.bin
```

The command exits with status 0 when the trees have no differences, 1 when they do,
and 2 when comparison or output fails. See `crucksware compare --help` for limits.
`inspect` parses validated ELF structure without executing the input. ELF files are
limited to 64 MiB by default, with a 100,000-record limit. Unknown files still receive
only the bounded sample classification. PE signatures are identified as candidates but
are not parsed yet. Use `crucksware inspect --help` to adjust the byte and record limits.

## Interactive shell

Run `crucksware` without arguments to start the shell. Use `anal` or `analyze` to choose
between inspecting one input and comparing two extracted rootfs directories, and `last`
to review the most recent successful result.
`report text [OUTPUT]`, `report json [OUTPUT]`, `report markdown [OUTPUT]`, and
`report html [OUTPUT]` export the latest directory comparison. Single-file inspections
can be reviewed with `last` but cannot yet be exported. The shell prompts for an output
path when omitted and asks before replacing an existing file. It does not save analysis
history automatically. Report destinations inside either compared rootfs, symbolic-link
destinations, and existing files with multiple hard links are refused.
Replacing any existing report is also refused on non-Unix platforms because stable
standard APIs do not expose the hard-link count there. Reports are rendered to a temporary
file in the destination directory before publication. A failed render or write leaves an
existing report unchanged and does not publish a new destination. New destinations use
no-clobber publication. The temporary-file library does not guarantee atomic publication
on every platform or filesystem; it generally is atomic on modern Linux filesystems. A
process interruption may leave a temporary file behind. Keep the compared trees and
report directory stable while a command runs; path-based operations do not contain hostile
concurrent directory replacement.

## Development

Install stable Rust with rustfmt and Clippy. The CLI uses clap; JSON output uses Serde
and serde_json. Report files are published through `tempfile`. The lockfile is committed,
and CI uses stable Rust on Linux.

```sh
cargo fmt --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

## License

Licensed under either the MIT License or Apache License, Version 2.0, at your option.
See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
