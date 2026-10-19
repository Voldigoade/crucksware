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

The `inspect_file` and `compare_files` targets call the public file-inspection and
binary-comparison APIs. Both use `libfuzzer-sys` with AddressSanitizer and sanitizer
coverage. Inputs are written to temporary files, capped at 1 MiB, and processed with a
4,096-entry limit. Seed corpora contain minimal ELF and PE files, truncated format
candidates, and unknown binary data. Generated corpus entries were kept under `/tmp`; only
the initial synthetic seeds are tracked.

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

## Tree-sitter source-analysis campaign

The `source_analysis` target maps bounded arbitrary bytes to valid UTF-8 Rust source and
compares it against a synthetic baseline using the public source-aware directory API. It
does not execute the generated source. A 60-second AddressSanitizer campaign used two
tracked seed inputs, a 2-second per-input timeout, and a 256 KiB maximum fuzz input. It
completed 4,529 executions at an average 74 executions per second with a peak RSS of
383 MiB. No crash, timeout, or AddressSanitizer finding occurred.

The run used Ubuntu 26.04.1 LTS, x86_64, Linux 7.0.0-38-generic, `rustc
1.101.0-nightly (b6eeb93c9 2026-10-18)`, `cargo-fuzz 0.13.2`, and Clang 21.1.8. An
initial run completed its input loop but LeakSanitizer failed during shutdown because the
container does not permit its required ptrace access. The successful retry set
`ASAN_OPTIONS=detect_leaks=0`; AddressSanitizer remained enabled, but this campaign does
not provide leak-detection evidence. This bounded run does not prove parser safety or
replace longer campaigns and testing on other architectures.

## Requalification after parser work bounds

The three targets were rerun on 2026-10-19 against commit `718923cec724c67e149ebed4d835d04acbcbe30a`,
which includes the bounded Tree-sitter parser and query callbacks. Each run used the
tracked synthetic corpus copied to `/tmp`, a 60-second campaign, a two-second per-input
timeout, and AddressSanitizer with leak detection disabled for the container limitation
described above. No crash, timeout, sanitizer finding, or crash artifact occurred.

| Target | Executions | Average executions/s | New corpus units | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| `inspect_file` | 1,743,990 | not recorded | not recorded | 498 MiB |
| `compare_files` | 853,725 | 13,995 | 1,690 | 465 MiB |
| `source_analysis` | 4,569 | 74 | 223 | 384 MiB |

The inspection counter came from libFuzzer's final `Done` line. Final statistics were
enabled for the comparison and source-analysis runs. The runs tested this build and seed
corpus only; they do not prove parser safety or establish a universal resource bound.

## PE resource-name fix requalification

After strict UTF-16 validation was added for PE resource names, the `inspect_file` and
`compare_files` targets were rerun against commit `bd94f78`. Each campaign ran for 60
seconds with the tracked synthetic seeds copied to `/tmp`, a two-second per-input timeout,
a 1 MiB maximum input size, and AddressSanitizer. Leak detection remained disabled because
the container does not permit LeakSanitizer's required ptrace access.

| Target | Executions | Average executions/s | New corpus units | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| `inspect_file` | 1,245,914 | 20,424 | 1,490 | 508 MiB |
| `compare_files` | 597,945 | 9,802 | 1,502 | 460 MiB |

Neither campaign reported a crash, timeout, AddressSanitizer finding, or crash artifact.
These runs cover the tested build and seeds only and do not prove parser safety.

## Source-fact matching requalification

After replacing repeated signature searches with a sorted multiset merge, the
`source_analysis` target was rerun against commit
`f48ef394d1451b529ee3f767f1a2a8529044714a`. It used the two tracked synthetic seeds,
a 60-second campaign, a two-second per-input timeout, a 256 KiB maximum input, and
AddressSanitizer with leak detection disabled for the container limitation described
above.

The campaign completed 4,380 executions in 61 seconds, averaging 71 executions per
second. The corpus grew from two seed files to 164 files and peak RSS was 384 MiB. No
crash, timeout, AddressSanitizer finding, or crash artifact occurred. The run used
Ubuntu 26.04.1 LTS, x86_64, Linux 7.0.0-38-generic, `rustc 1.101.0-nightly
(b6eeb93c9 2026-10-18)`, `cargo-fuzz 0.13.2`, and Clang 21.1.8. This bounded run
provides evidence for the tested build and corpus; it does not prove parser safety.
