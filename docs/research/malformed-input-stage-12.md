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

## Release mutation campaign

`cargo fuzz` is not installed in the available environment, and only the stable Rust
toolchain is installed. A temporary deterministic mutation runner therefore exercised the
release CLI without adding fuzzing dependencies or repository tooling.

The campaign analyzed 10,443 generated inputs:

- 4,096 mutations of a valid minimal ELF header
- 4,096 mutations of a valid PE32+ image
- 2,048 deterministic random byte sequences
- every prefix of the ELF seed and PE prefixes at 8-byte intervals
- 11 targeted extreme counts, offsets, raw ranges, and data-directory RVAs

Each input was passed to `inspect --format json` with a two-second per-input timeout.
There were 6,371 successful inspections and 4,072 input errors. No process crashed or
timed out, no panic text appeared, and input errors emitted no partial stdout. The full
campaign took 12.70 seconds on the measurement machine. This is deterministic mutation
testing, not coverage-guided fuzzing.

The campaign found no reproducible parser defect. It does not prove parser safety and
does not replace future coverage-guided fuzzing under sanitizers.
