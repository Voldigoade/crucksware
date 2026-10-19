# Readable report measurements

These measurements cover the deterministic readable-report implementation. They
describe one synthetic workload on one machine and are not general performance claims.

## Environment

- Baseline commit: `99dbf2f` (`docs: define deterministic readable reports`)
- Feature commit: `a1aca3c8040a534542e1ab737b34960d61b7853e`
- OS: Ubuntu Linux, kernel `7.0.0-38-generic`, x86_64
- CPU: AMD Ryzen 7 5700X, 8 cores, 16 logical CPUs
- Rust: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`
- Build: `cargo build --release --locked`

The same locked dependencies and release profile were used for both commits. The
synthetic fixtures were deterministic and stored on the workspace's local ext4 volume
(`/dev/nvme1n1p3`). CLI stdout was sent to `/dev/null`; stderr was required to remain
empty. Each CLI case had one warm-up followed by 11 runs in alternating binary order.
The operating-system file cache was warm for the timed runs, so these are not cold-device
measurements. Peak RSS is the maximum reported by `/usr/bin/time -f %M` for one run of
each case, in KiB.

## Release executable size

| Commit | Bytes |
|:--|--:|
| Baseline | 11,978,480 |
| Feature | 12,136,040 |
| Difference | 157,560 (1.32%) |

## Direct comparison

All cases used the release `compare --format text OLD NEW` command.

| Fixture | Baseline median (range) | Feature median (range) | Median difference | Peak RSS baseline / feature |
|:--|--:|--:|--:|--:|
| 10,000 files per tree, 9,800 unchanged, 100 modified, 100 removed, 100 added | 601.424 ms (588.223 to 622.909) | 601.769 ms (579.623 to 639.980) | +0.345 ms (+0.06%) | 10,192 / 9,956 KiB |
| Identical trees, 10,000 unchanged files each | 585.509 ms (572.536 to 606.799) | 584.272 ms (578.363 to 601.677) | -1.237 ms (-0.21%) | 9,884 / 10,176 KiB |
| One 64 MiB file per input, differing at the last byte | 12.901 ms (12.189 to 15.127) | 13.174 ms (11.964 to 14.575) | +0.274 ms (+2.12%) | 4,720 / 5,104 KiB |

The observed CLI ranges overlap. Median changes are within the variation seen across
repeated runs, including the 0.274 ms difference on the large-file case. This run did
not show a consistent material regression in the direct comparison path. It does not
measure cold-cache storage, other filesystems, or other machines.

## Evidence reduction and rendering

A temporary release driver constructed synthetic `Diff` values before timing and
called the evidence selector directly. Input construction was outside the timed
region. Each case had one warm-up and nine measured selections; packet serialization
was measured afterward.

| Synthetic added entries | Selector median (range) | Encoded packet size |
|--:|--:|--:|
| 10,000 | 0.649 ms (0.578 to 0.738) | 2,037 bytes |
| 100,000 | 5.685 ms (5.365 to 6.533) | 2,042 bytes |

The selector retained at most 64 records and the report's display used at most eight.
The packet size stayed well below its 32 KiB cap for these fixtures.

With a selected packet already available, summary rendering to `io::sink()` had a
median of 3.46 microseconds for 10,000 entries and 3.56 microseconds for 100,000
entries. Rendering one evidence explanation by ID took 0.63 and 0.61 microseconds,
respectively. These figures measure renderer work only. They exclude comparison,
terminal output, and selection.

## Local model measurements

No model met the research phase's combined factuality and latency requirements, so no
inference runtime or model is integrated. Model download size, cold load, first-token
latency, generation throughput, warm generation, and multilingual generation are not
applicable to this implementation. The product does not bundle a model or download one
automatically. The temporary model files used during research are described in
`readable-reports-models.md`.
