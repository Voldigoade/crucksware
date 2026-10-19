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
The filesystem comparison contract and JSON schema v1 remain unchanged. File comparison
uses JSON schema v2. Semantic-tree comparison uses schema v4; schema v3 remains the
documented source-only report shape.

## Detection contract

Directories are identified from filesystem metadata. ELF candidates are identified by
the ELF magic bytes. PE candidates require an `MZ` DOS header, a bounded `e_lfanew`
value, and the `PE\0\0` signature at that offset. A matching extension is never
sufficient evidence. These checks identify candidates only; they do not validate a full
format structure.

Generic text classification validates a sample of at most 8 KiB as UTF-8 and accepts
ordinary text whitespace while rejecting control characters. This is a bounded heuristic
over the sample, not a claim that every byte in a large file is text. Unsupported regular
files are classified as unknown binary. Detection never executes or loads the input.

The Linux detector uses a nonblocking read-only open so a path replaced with a FIFO after
the metadata check cannot block at open. Path resolution is not an atomic snapshot; inputs
must remain stable during detection, and behavior for a concurrently substituted device
is not guaranteed.

Single-file inspection validates ELF and PE structures and reports selected static
facts. ELF output includes header, section, segment, interpreter, dependency, import,
export, symbol, build ID, GNU stack, and GNU RELRO metadata where present. PE output
includes image width, architecture, machine, entry point, subsystem, sections, imports,
delay imports, exports, resource identifiers and ranges, CodeView PDB identity, and
certificate-table location where present. Neither format receives a security verdict.
Both have a 64 MiB file limit, a 100,000-record default, a 4 KiB per-name limit, and a
16 MiB aggregate copied-name limit. PE resource traversal has a depth limit of 16.
Malformed ELF or PE input returns an error without a partial report. Unknown files
receive only the bounded sample classification. The result is not an atomic filesystem
snapshot; inputs should remain stable during inspection.

## File comparison

`compare OLD NEW` accepts two regular files as well as two directories. It inspects both
files, then compares equal-sized inputs byte-for-byte. Different sizes establish a
byte-level change without reading file bodies a second time. The shared byte-read limit
covers detection, structural inspection, and exact comparison across both inputs. The
entry limit is shared across structural inspection of both files.

Matching ELF inputs compare normalized header, section, segment, interpreter, dependency,
import, export, symbol, build-ID, GNU stack, and GNU RELRO facts. Matching PE inputs
compare normalized header, section, import, delay-import, export, resource, CodeView, and
certificate-table facts. Record ordering does not affect the result. A different detected
input kind is reported as a format mismatch. Text and unknown-binary pairs receive exact
byte comparison only. Byte-level change is independent of semantic fact changes, and
semantic fact equality does not establish behavioral equivalence.

File-comparison reports use JSON schema v2. Directory comparison remains on schema v1;
the two schemas have distinct `analysis_type` values and are not interchangeable.

## Source-aware and mixed directory comparison

`compare --source-aware OLD NEW` runs the existing directory inventory, exact content
comparison, metadata classification, and revalidation before analyzing changed files. It
does not add another tree walker. Unchanged files and metadata-only changes are not
analyzed. The ordinary `compare OLD NEW` behavior is unchanged.

The source pass reads each changed regular file through a no-follow, nonblocking open and
checks it against the inventory stamp before and after reading. It shares the directory
comparison byte budget. A text file is bounded to 8 MiB by default and 64 MiB maximum;
each side also contributes to the existing total byte-read limit. Text diffs are limited
to 200,000 lines per side. Structural parsing traverses at most 500,000 syntax nodes and
retains at most 50,000 facts per file. Exceeding a limit fails the comparison before any
report is written.

The initial structural languages are Rust, C, C++, and Python. Extensions are parser
hints only. Changed text with an unsupported extension still receives a deterministic
line diff. A supported file with syntax errors also keeps its line diff, while structural
changes are omitted and marked `syntax_errors`. Binary files are not parsed as source;
a transition between text and binary content is reported without an invented line diff.
Structural facts include definitions, normalized function or method signatures, and
imports. Ordering is normalized for deterministic output. These facts do not describe
control flow, runtime behavior, intent, or behavioral equivalence.

Changed files that classify as text receive the bounded line and structural analysis
described above. Changed ELF and PE files use the same inspection and normalized-fact
comparison as single-file comparison. Other binary files are identified as unknown
binary and receive no invented semantic facts. These analyses run only for file content
changes; unchanged and metadata-only paths are skipped. Analysis uses the same total
byte-read budget and entry limit as the directory comparison. `byte_level_changed` is
true when both file versions exist and the exact directory diff found different content;
it is null for a one-sided addition or removal, where there is no byte pair to compare.

Source-aware text output appends source-change, structural, and binary rows to the
filesystem report. JSON output uses schema v4, whose `filesystem` member retains schema
v1 and whose `source_changes` and `binary_changes` members carry the additional results.
Schema v3 remains the contract for the earlier source-only report shape. Schema versions
identify report shapes and are independent of the tool's semantic version.

The `similar` crate supplies the line-diff algorithm. Tree-sitter and its Rust, C, C++,
and Python grammars provide one parser interface for the selected languages. The existing
ELF and PE parsers provide static format facts for changed binaries. These analyses run
only on changed files and are not general source-code or binary understanding systems.

## Current implementation

The `input` module implements detection and bounded read accounting. The `inspection`
module validates supported ELF and PE candidates and builds static facts. The
`binary_compare` module combines exact file-byte comparison with normalized facts. The
existing `compare` and `scan` modules handle extracted Linux root filesystem directories.
The `source` module layers bounded text diffs and selected syntax facts over the existing
directory result. The `semantic_tree` module adds changed ELF and PE inspections and
unknown-binary classifications, while `report::semantic_tree` renders the combined
schema-v4 output.
