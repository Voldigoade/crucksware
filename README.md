# Crucksware

Semantic firmware diff and triage in Rust.

**Experimental and under active development.** Linux comparison of two extracted root
filesystem directories is implemented, including exact bounded regular-file comparison
and filesystem metadata. The direct CLI provides deterministic text and JSON schema v1
reports for directory comparisons, plus bounded single-file inspection and file
comparison. ELF and PE file pairs receive normalized structural comparisons and separate
byte-level results. Source-aware directory comparison adds bounded text diffs and
structural facts for Rust, C, C++, and Python files. Other regular files receive exact
byte comparison without semantic claims.
The interactive shell adds session summaries and text, JSON, Markdown, and offline HTML
exports with live progress.

The comparison reads equal-sized regular files when their contents must be distinguished.
Input trees must remain stable during a comparison. Path-based checks do not provide an
atomic snapshot or containment against concurrent replacement. Reads may update
filesystem-managed access times.

Crucksware is a focused, local tool for firmware analysts, embedded engineers, reverse
engineers, and defensive security researchers. It does not extract firmware images.
Input files are never executed. Direct SquashFS input is not implemented.

## Design

The [v0.1 design](docs/design/v0.1.md) defines the comparison and report contract,
including the [JSON schema](docs/json/schema-1.json). File comparisons use
[JSON schema version 2](docs/json/schema-2.json). The
[implementation plan](docs/development/v0.1-plan.md) tracks the remaining work.
The [binary analysis design](docs/design/binary-analysis.md) describes current ELF and
PE inspection and future format support. The [semantic analysis design](docs/design/semantic-analysis.md)
documents source-aware and mixed-directory comparison and their limits.

```sh
crucksware compare old-rootfs/ new-rootfs/
crucksware compare --format json old-rootfs/ new-rootfs/
crucksware compare --source-aware project-v1/ project-v2/
crucksware compare old-program new-program
crucksware inspect ./program.bin
```

`compare` accepts either two directories or two regular files. Directory reports use
JSON schema v1. File reports use schema v2 and show exact byte-level changes separately
from normalized ELF or PE facts. If the detected formats differ, the report identifies
the mismatch. Unknown files receive exact byte comparison only. The command exits with
status 0 when no change is found, 1 when a change is found, and 2 when comparison or
output fails. See `crucksware compare --help` for limits.
`inspect` parses bounded ELF and PE structure without executing the input. Both formats
are limited to 64 MiB and 100,000 reported records by default. PE output includes
sections, imports, exports, resource metadata, CodeView PDB identity where present, and
certificate-table location. It does not verify Authenticode signatures. Unknown files
receive only a bounded text/binary classification. File comparison's byte-read limit
is shared across inspection and exact comparison of both inputs, and its entry limit is
shared across semantic parsing of both files. Directory-only depth and path-byte options
do not apply to file comparisons. Use
`crucksware inspect --help` to adjust inspection limits.
`compare --source-aware` is a separate directory mode. It reports bounded line changes
for changed text files and extracts definitions and imports from Rust, C, C++, and Python
files when parsing succeeds. Changed ELF and PE files are inspected with the same static
analyzers used by file comparison. Changed unknown binary files are identified without
invented semantics. File extensions select source parser hints only. Unsupported text
still receives a line diff, and syntax errors do not suppress that diff. [JSON schema v4](docs/json/schema-4.json)
embeds the existing filesystem schema v1 report and carries source and binary results.
Each changed source text file is limited to 8 MiB by default, with a 64 MiB maximum; the
directory entry and total byte-read limits also apply. Unchanged files are not analyzed,
and the report does not infer behavioral equivalence.

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
and serde_json. Tree-sitter grammars provide structural facts for the initial source
languages, and `similar` provides line-diff output. Report files are published through
`tempfile`. The lockfile is committed, and CI uses stable Rust on Linux.

```sh
cargo fmt --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

## License

Licensed under either the MIT License or Apache License, Version 2.0, at your option.
See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
