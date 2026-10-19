# Readable report design

## Goal

Add a concise explanation layer to Crucksware's existing deterministic analysis.
The explanation is a presentation of observed report facts. It does not infer intent,
behavior, vulnerability, or risk, and it never replaces the detailed report.

Local model evaluation did not produce a candidate that met the factuality bar. The
first implementation is deterministic and uses no inference runtime, model download,
network access, or model-specific dependency. The model research and its limitations
are recorded in `docs/research/readable-reports-models.md`.

## Data flow

For comparisons, the summary reads only the existing `Diff`, `SemanticTreeDiff`, and
`FileComparison` facts. It does not reopen inputs or include raw file content. A bounded
evidence selector produces aggregate counts and a small ordered set of typed evidence
records. The renderer turns those records into short English sentences. Detailed text,
JSON, Markdown, and offline HTML data remain available as the canonical technical
record.

Each selected fact receives a stable report-local identifier such as `E0001`. The
identifier is derived from its position after deterministic ordering, not from a hash
or an input-controlled value. Paths use Crucksware's existing byte-safe encoding.
Identifiers, symbols, paths, library names, and values are preserved as data and
escaped only at the output boundary.

## Selection and bounds

Selection uses explicit categories rather than a numeric importance score. Binary
semantic field changes and source structural changes are considered first, followed by
binary byte changes and added or removed executable files, filesystem type, mode,
device ID, or symlink-target changes, source content-kind changes, bounded text line
summaries, and ordinary additions or removals. Ties use raw path byte order and stable
fact values. The selector does not read files, change the source analysis, or depend on
hash-map iteration order.

The evidence packet is capped at 64 records and 32 KiB of encoded fields. A single
record that does not fit is omitted whole; names, paths, and signatures are never
truncated into misleading identifiers. The packet retains aggregate counts from the
complete analysis and reports how many eligible records were omitted. Human-facing
summaries show at most eight evidence records, while technical reports retain every
existing bounded fact.

## Rendering and compatibility

Text, Markdown, and HTML reports place the concise summary before the detailed report.
HTML remains a self-contained offline document. Interactive `last` shows the same
summary, and `explain` accepts an evidence identifier, encoded path, or `--all` to
display selected facts from that session without re-running analysis. A path selector
shows all selected facts for that path; `path:` forces path matching when a path
resembles an evidence identifier. Direct comparison remains scriptable and emits no
progress or inference diagnostics on JSON stdout.

The JSON schemas continue to represent canonical structured facts. The summary is
derived from those facts and is not serialized as an additional field in this
milestone, so existing schema meanings do not change. A future change that serializes
summary-specific data must introduce and document a schema version explicitly.

Only English deterministic wording is included initially. The evaluated models did not
qualify English, French, Spanish, and Simplified Chinese output for this evidence task,
so the product does not claim those languages are supported. Localization can be added
after its own factual and terminology review.

## Failure behavior

Evidence selection is an in-memory, read-only operation over an already completed
analysis. It uses checked counters and fixed output bounds. It does not modify session
state or input paths. If a future optional model or explanation path fails validation,
the canonical report and deterministic summary remain available; unvalidated generated
content is never published.
