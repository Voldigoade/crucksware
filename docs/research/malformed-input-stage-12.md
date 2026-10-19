# Stage 12 malformed-input evidence

ELF and PE inspection treats file bytes as untrusted data. Parsing is read-only and does
not load or execute an input. Existing size, record, field, copied-name, and resource-depth
limits remain in force.

## Persistent test coverage

The integration tests cover truncated ELF and PE candidates, invalid ELF section and
program offsets, invalid dynamic string-table ranges, inconsistent header sizes, invalid
section data, invalid PE section and certificate ranges, invalid import RVAs, cyclic PE
resources, declared record limits, per-file size limits, and malformed unknown inputs.
Deterministic mutation tests now exercise four ELF seeds, three PE seeds, and 256
unrecognized binary samples. Separate ELF and PE cases cover overlapping section data
ranges. Mutations preserve format signatures where parser behavior is under test.

The mutation tests accept either a complete inspection or a typed input error. A parser
panic fails the test. They add no runtime dependency and do not rely on external corpus
files.

## Deterministic release mutation campaign

A deterministic mutation runner exercised the release CLI with 10,443 generated inputs:

- 4,096 mutations of a valid minimal ELF header
- 4,096 mutations of a valid PE32+ image
- 2,048 deterministic random byte sequences
- every prefix of the ELF seed and PE prefixes at 8-byte intervals
- 11 targeted extreme counts, offsets, raw ranges, and data-directory RVAs

Each input was passed to `inspect --format json` with a two-second per-input timeout.
There were 6,371 successful inspections and 4,072 input errors. No process crashed or
timed out, no panic text appeared, and input errors emitted no partial stdout. The full
campaign took 12.70 seconds on the measurement machine.

## Coverage-guided fuzz campaigns

Two `cargo-fuzz` targets call the public file-inspection and binary-comparison APIs.
Both use `libfuzzer-sys` with AddressSanitizer and sanitizer coverage. Inputs are written
to temporary files, capped at 1 MiB, and processed with a 4,096-entry limit. Seed corpora
contain minimal ELF and PE files, truncated format candidates, and unknown binary data.
Generated corpus entries were kept under `/tmp`; only the initial synthetic seeds are
tracked.

Campaigns ran on Ubuntu 26.04.1 LTS, x86_64, Linux 7.0.0-38-generic, with
`rustc 1.101.0-nightly (b6eeb93c9 2026-10-18)`, `cargo-fuzz 0.13.2`, and
`libfuzzer-sys 0.4.13`. Each target ran for 60 seconds with a two-second per-input
timeout and a 1 MiB maximum input length.

| Target | Executions | Average executions/s | New corpus units | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| `inspect_file` | 1,722,802 | 28,242 | 1,634 | 494 MiB |
| `compare_files` | 743,827 | 12,193 | 1,469 | 463 MiB |

Neither campaign reported a crash, timeout, sanitizer finding, or crash artifact. The
earlier deterministic release mutation campaign and the persistent malformed-input tests
remain in place. These bounded runs provide evidence for the tested build and seeds; they
do not prove parser safety or replace longer campaigns and testing on other architectures.
