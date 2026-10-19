# Stage 11 performance measurements

Measurements were collected on 2026-10-19 using release builds from the current
`main` base and the semantic-analysis branch.

## Environment and method

- Machine: AMD Ryzen 7 5700X, x86_64, 16 logical CPUs
- OS: Ubuntu 26.04.1 LTS, Linux 7.0.0-38-generic
- Rust: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`
- Base for the initial broad measurements: `8293cb35feb2d427d1a04557c1b19a2dff7279e4`
- Initial feature snapshot: `9ff2c2107b35635b5ae136653e6b12c05876b129`
- Build: `cargo build --release --locked`

The initial broad-measurement base descends from the v0.1.0 baseline. The final direct
comparison spot-check below uses current main at `a36fa3880e9e370c23dd36cebfe5f9dd309dfe79`.

Fixtures were generated deterministically with Python's standard library. Each command
received one warm-up run followed by five measured runs, interleaved between base and
feature binaries. Filesystem cache was warm. Wall time was measured around each process;
GNU `time` recorded maximum resident memory. Comparison output went to `/dev/null`.
Times below are medians in milliseconds with the five-sample range in parentheses.
Memory is median maximum RSS in MiB, with KiB converted by dividing by 1024.

The base and feature `compare` commands used ordinary filesystem comparison. The
source-aware column uses `--source-aware` on the feature binary only, since that mode is
not present in the base. Exit codes were checked for all 22 baseline and feature fixture
comparisons.

## Comparison results

| Fixture | Base `compare` | Feature `compare` | Feature source-aware | RSS base / feature / source-aware |
| --- | ---: | ---: | ---: | ---: |
| 10,000 files per tree, 100 changed | 479.4 (478.2-482.0) | 484.0 (477.6-489.0) | n/a | 8.3 / 9.4 / n/a |
| 10,000 identical files per tree | 479.4 (475.6-487.6) | 478.8 (473.2-482.0) | n/a | 8.5 / 9.6 / n/a |
| 1,000 Rust files, 20 changed | 49.8 (48.3-50.2) | 49.1 (48.4-49.6) | 62.1 (61.6-64.6) | 4.1 / 5.5 / 9.0 |
| 1,000 Rust files, all changed | 48.9 (48.5-49.7) | 49.6 (48.8-50.1) | 123.0 (119.2-129.5) | 4.3 / 5.5 / 9.1 |
| 5.46 MB text file, one changed byte | 2.9 (2.8-3.1) | 3.3 (3.1-3.4) | 77.4 (75.8-78.2) | 3.6 / 4.9 / 34.5 |
| 8 MiB synthetic ELF with one overlay byte changed | 3.6 (3.4-4.0) | 3.8 (3.6-4.0) | 14.8 (14.3-16.3) | 3.7 / 4.9 / 13.0 |
| 8 MiB synthetic PE with one overlay byte changed | 3.5 (3.2-3.6) | 3.8 (3.4-4.1) | 14.9 (14.6-15.1) | 3.6 / 4.8 / 13.0 |
| Mixed tree, 752 files | 40.9 (40.1-41.2) | 41.8 (40.4-43.3) | 66.1 (65.5-67.2) | 4.0 / 5.3 / 15.0 |

The synthetic ELF contains a minimal valid ELF64 header. The PE contains a minimal valid
PE32+ header and one executable section. Each binary is padded to 8 MiB and differs only
in its final overlay byte. Neither input was executed. The mixed tree contains Rust
source, configuration files, binary assets, and one ELF and PE file.

Additional feature-only measurements used one warm-up and five measured runs:

| Operation | Median time (range) | Median maximum RSS |
| --- | ---: | ---: |
| Inspect 8 MiB ELF as JSON | 9.2 ms (8.7-9.3) | 12.4 MiB |
| Inspect 8 MiB PE as JSON | 8.6 ms (8.3-8.7) | 12.7 MiB |
| Compare two 8 MiB ELF files | 15.7 ms (15.1-16.1) | 12.9 MiB |
| Compare two 8 MiB PE files | 15.5 ms (15.2-16.1) | 12.7 MiB |

A malformed-input smoke corpus contained 50 truncated ELF candidates, 50 truncated PE
candidates, and 50 deterministic unknown binaries. Five batches analyzed all 150 inputs
through `inspect`; each malformed candidate returned the input-error status, unknown
binaries returned success, and no panic text was reported. Batch times were 178.5, 176.4,
178.0, 173.8, and 175.8 ms. This is a timing smoke test, not fuzzing evidence.

## Final post-review direct-comparison spot-check

On 2026-10-19, release binaries from main (`a36fa3880e9e370c23dd36cebfe5f9dd309dfe79`)
and PR code snapshot (`7a4e124fefb71fc456eee0a83586e35244fe53fe`) were tested on the
machine and Rust toolchain listed above. Fixtures were deterministic: 10,000 256-byte
files per tree with 100 changed files, 10,000 identical 256-byte files per tree, and one
8 MiB file differing at its final byte. Each binary received one warm-up and five
measured runs per fixture. Run order alternated, output was discarded, and the filesystem
cache was warm. Process elapsed time was measured with Python's `perf_counter`; expected
comparison exit codes were checked.

| Fixture | Main median (range) | PR median (range) |
| --- | ---: | ---: |
| 10,000 files, 100 changed | 461.58 ms (448.51-463.93) | 449.50 ms (441.32-473.85) |
| 10,000 identical files | 453.42 ms (449.00-468.57) | 451.38 ms (445.37-502.75) |
| One 8 MiB file, final byte changed | 3.19 ms (3.01-3.28) | 3.45 ms (3.25-3.57) |

The sampled ranges overlap for all three fixtures. This spot-check did not measure a
material direct-comparison slowdown. It measured elapsed process time only and did not
measure memory. The unstripped release executables measured 2,029,528 bytes on main and
11,983,592 bytes on the PR code snapshot, a 9,954,064-byte increase. `size -B` reported
text/data/bss sizes of 1,501,785/47,304/1,643 bytes on main and
10,273,141/313,184/3,768 bytes on the PR snapshot. These results apply only to this
machine, these fixtures, and warm-cache runs.

## Binary size and observations

The final measured unstripped release executable was 11,983,592 bytes, 9,954,064 bytes
larger than main. The feature dependency tree includes the object parser, Tree-sitter,
and the selected language grammars. No section-level attribution or stripped-binary
comparison was performed.

Across the latest direct-comparison fixtures, sampled ranges overlap and do not show a
material elapsed-time regression. Earlier broad measurements found feature direct-mode
peak RSS about 1.0 to 1.5 MiB higher in the tested cases. In those synthetic source-aware
measurements, analysis took about 13 ms for 20 changed Rust files, 73 ms for 1,000
changed Rust files, and 11 ms for 8 MiB ELF or PE overlay changes. The 5.46 MB text diff
used 34.5 MiB peak RSS and took 77 ms in that fixture.

These results describe this machine, these synthetic fixtures, warm filesystem cache,
and this build. They are not general performance guarantees. No code optimization was
made from these measurements.
