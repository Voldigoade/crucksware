# Binary Analysis Design

This is a future design, not a description of current Crucksware behavior. Format-specific
binary inspection and semantic comparison are not implemented. The current generic file
inspection reports only bounded type, size, and text/binary facts. Inputs remain read-only
and are never executed, loaded by the operating-system loader, or mounted.

## Model

Single-input inspection and before/after comparison should share one bounded parsing
path. Inspection returns a deterministic set of format facts. Comparison inspects each
input with that same path, then compares the normalized facts and reports byte-level
change separately where useful. A format mismatch is explicit; it is not interpreted
as a set of matching ELF or PE fields. Unsupported or malformed input must produce a
clear result, never a partial successful report.

Detect containers before their inner executable format. A Type 2 AppImage is also an
ELF file, so identify it as an AppImage only when its marker and appended filesystem
structure validate. File extensions are hints, not format evidence.

Keep a small format dispatcher and focused readers for ELF, PE, and AppImage. Use a
common representation for facts that have the same meaning, while keeping format-only
facts typed and identifiable. Sort facts by stable keys, preserve undecodable names as
bytes internally, and render them with an explicit deterministic escape in reports.
Avoid treating offsets or parser iteration order as semantic identity. Keep
implementation focused on the formats Crucksware actually supports.

The existing filesystem comparison remains the source of truth for tree changes.
AppImage payload comparison should adapt a validated embedded filesystem to that same
inventory and comparison path instead of adding another filesystem comparator.

## ELF

Report facts that can be read directly and consistently: class, byte order, machine,
file type, entry point, sections and segments, program interpreter when present,
dynamic library dependencies, and available imports, exports, symbols, and build ID.
Keep section and symbol names as bytes until rendering. A missing section table must
not prevent facts available through program headers or dynamic metadata from being
reported. ELF program headers describe loadable segments and `PT_INTERP`; the dynamic
section supplies entries such as `DT_NEEDED` ([ELF program headers](https://gabi.xinuos.com/elf/07-pheader.html),
[ELF dynamic section](https://gabi.xinuos.com/elf/08-dynamic.html)).

Security-relevant output should be limited to directly observed metadata such as
segment permissions, GNU stack/RELRO indicators, and recognized notes. Describe the
fact, not a verdict: a flag alone does not establish that an executable is safe or
secure. Do not infer loader behavior or dependency resolution from static fields.

## PE

For Windows PE executables, including `.exe` files, report machine and image width,
sections and their recorded flags, entry point, subsystem, imports, delay-load imports,
exports, and resource identifiers and sizes where they can be parsed within limits.
Microsoft’s PE format uses a resource directory tree and treats the Certificate Table
address as a file offset rather than an RVA.
[PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

Certificate-table presence and parseable signer metadata may be reported as file facts.
They do not establish signature validity, trusted identity, or policy acceptance.
Authenticode verification and trust-chain evaluation are outside this design. Do not
read resources or metadata beyond configured byte, entry, and nesting limits.

## AppImage

Detect an AppImage from validated format markers and structure, never from its file
extension alone. The current specification describes Type 1 as ISO 9660 with Rock Ridge
and Type 2 as an ELF executable with an appended filesystem; both use a marker at byte
offset 8. Type 1 SHOULD carry marker `0x414901` there; Type 2 MUST carry `0x414902`.
The published specification remains a working draft, so implementation must validate
against the current specification and reference tools ([AppImage specification](https://github.com/AppImage/AppImageSpec/blob/master/draft.md)).

For Type 2, report runtime ELF facts separately from payload filesystem facts. Current
AppImage documentation identifies SquashFS as the Type 2 filesystem and describes a
runtime that mounts it and launches `AppRun` ([AppImage architecture](https://docs.appimage.org/reference/architecture.html)).
Crucksware must not run that runtime or mount the image. It should locate and validate
the embedded filesystem as data, then use a read-only SquashFS reader and the existing
filesystem comparison model. Do not assume a fixed payload offset or search for a
magic byte sequence without validating the runtime’s framing rules. Type 1 ISO support
is a separate future decision.

## Unknown binary files

Report the byte length and, if it proves useful to users, a fingerprint with its
algorithm named. For a pair, use bounded exact byte comparison to establish whether
contents differ. Unknown files remain unknown; Crucksware should not imply that it has
understood their internal structure. Do not extract strings or calculate entropy by
default. Add either only when a concrete use case justifies its cost, output contract,
and limits.

## Parser choice and input limits

The current leading candidate is [`object`](https://docs.rs/object/0.40.0/object/).
Its unified read API covers ELF and PE/COFF and exposes common sections, symbols,
imports, exports, and entry-point facts; format-specific read APIs can fill gaps. Its
current release is dual-licensed MIT or Apache-2.0. The project’s open discussion about
an exhaustive validation pass and bounded work on untrusted input is directly relevant:
adoption is conditional on a documented input-risk review and tests that demonstrate
acceptable limits. A wrapper that limits file bytes alone is not enough if parser work
or allocation is unbounded. The project has an [open discussion about exhaustive
validation and bounded work](https://github.com/gimli-rs/object/issues/874).

[`goblin`](https://docs.rs/goblin/0.10.7/goblin/) is an alternative with
format-specific ELF and PE APIs; its PE API includes resources and certificate-table
data. It is MIT-licensed. Prefer `object` for the shared read model only if the required
facts and hostile-input behavior qualify. If PE resource or certificate coverage is a
release requirement and the `object` API is insufficient, evaluate `goblin` directly
before adding a second parser. Do not combine parser outputs without tests that define
which parser owns each fact.

No binary parser dependency is added by this design task.

Parser implementation must enforce checked offsets and lengths, and explicit bounds on
file size, records, nesting, name bytes, and any decompressed data. Do not materialize
whole files or decompressed sections without a bounded reason. A parser error, an
unsupported structure, a resource-limit error, and an unknown format are distinct
outcomes. Build a malformed-input corpus and fuzz each reader before claiming robust
handling. These measures reduce exposure; they do not prove the absence of parser bugs.

## References

- [ELF Object File Format, System V ABI](https://gabi.xinuos.com/elf/)
- [Microsoft PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [AppImage specification repository](https://github.com/AppImage/AppImageSpec)
- [AppImage architecture](https://docs.appimage.org/reference/architecture.html)
- [`object` 0.40.0 documentation](https://docs.rs/object/0.40.0/object/)
- [`object` crate manifest](https://github.com/gimli-rs/object/blob/master/Cargo.toml)
- [`goblin` 0.10.7 documentation](https://docs.rs/goblin/0.10.7/goblin/)
- [`goblin` crate manifest](https://docs.rs/crate/goblin/0.10.7/source/Cargo.toml)
