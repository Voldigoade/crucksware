# Semantic analysis architecture

Crucksware keeps its existing Linux directory comparator as the source of truth for
filesystem inventory, exact file comparison, metadata classification, and mutation
checks. New analysis capabilities are layered around that engine.

## Boundaries

- Input detection identifies a directory, ELF, PE, text sample, or unknown binary.
- Format inspection extracts facts from one supported input without executing it.
- Comparison combines exact byte-level results with format-specific semantic facts.
- Reporting renders the resulting models and does not perform detection or parsing.
- The CLI and interactive shell select workflows and present progress; they do not
  duplicate comparison or parsing logic.

These boundaries use focused modules and enums. They do not require a plugin registry.
The current filesystem comparison contract and JSON schema v1 remain unchanged until a
separate schema update is designed and tested.

## Detection contract

Directories are identified from filesystem metadata. ELF candidates are identified by
the ELF magic bytes and must still pass the ELF parser before inspection succeeds. PE
candidates require an `MZ` DOS header, a bounded `e_lfanew` value, and the `PE\0\0`
signature at that offset. A matching extension is never sufficient evidence.

Generic text classification validates a sample of at most 8 KiB as UTF-8 and accepts
ordinary text whitespace while rejecting control characters. This is a bounded heuristic
over the sample, not a claim that every byte in a large file is text. Unsupported regular
files are classified as unknown binary. Detection never executes or loads the input.

The Linux detector uses a nonblocking read-only open so a path replaced with a FIFO after
the metadata check cannot block at open. Path resolution is not an atomic snapshot; inputs
must remain stable during detection, and behavior for a concurrently substituted device
is not guaranteed.

The detector reports a broad kind only. It does not validate full ELF or PE structures;
the format-specific inspector owns that validation and must reject malformed input
cleanly.

## Current implementation

The `input` module implements the detection contract. The existing `compare` and `scan`
modules continue to handle extracted Linux root filesystem directories. Inspection,
format parsers, semantic comparison, and source-language analysis are future layers and
are not implied by detection alone.
