# Parser fuzzing

The coverage-guided targets exercise file inspection and binary comparison through
Crucksware's public Rust APIs. They write fuzz bytes to temporary files and treat
typed input errors as expected results.

The `compare_files` target reads a little-endian 32-bit split offset from the first
four bytes, then divides the remaining bytes into old and new file contents at that
offset. The offset is reduced modulo the payload length plus one, so each value selects
a valid split point.

Install a nightly toolchain with LLVM tools and `cargo-fuzz`, then run each target
with a copy of its seed corpus so generated inputs remain outside the repository:

```sh
rustup toolchain install nightly --component llvm-tools-preview
cargo install cargo-fuzz --locked
cp -R fuzz/corpus/inspect_file /tmp/crucksware-inspect-corpus
cargo +nightly fuzz run inspect_file /tmp/crucksware-inspect-corpus -- -max_total_time=60 -timeout=2 -max_len=1048576
cp -R fuzz/corpus/compare_files /tmp/crucksware-compare-corpus
cargo +nightly fuzz run compare_files /tmp/crucksware-compare-corpus -- -max_total_time=60 -timeout=2 -max_len=1048576
```

Both targets cap each fuzz input at 1 MiB and use a 4,096-entry limit. The comparison
target has a 2 MiB read budget so a maximum-sized pair can be parsed and byte-compared.
The separate manifest and lockfile keep `libfuzzer-sys` out of the product dependency
graph. Fuzzing does not execute the input files. A completed campaign provides evidence
for the tested builds and corpus, not proof that malformed inputs are safe.
