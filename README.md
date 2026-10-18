# Crucksware

Semantic firmware diff and triage in Rust.

**Experimental and under active development.** The initial milestone targets
comparison of two extracted root filesystem directories. The comparison command
is not available yet, and there are no releases.

Crucksware is intended to answer: what actually changed between firmware
versions A and B? It is a focused, local tool for firmware analysts, embedded
engineers, reverse engineers, and defensive security researchers.

The first milestone is Linux-first and read-only. It does not extract firmware
images or interpret binary formats. SquashFS input and semantic file
classification are outside the initial milestone.

## License

Licensed under either the MIT License or Apache License, Version 2.0, at your
option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
