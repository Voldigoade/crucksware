# Changelog

Crucksware follows Semantic Versioning.

## 0.2.0-beta.1

- Add bounded inspection and semantic comparison for ELF and PE files while keeping
  exact byte changes separate from normalized format facts.
- Add source-aware directory comparison for Rust, C, C++, and Python, with bounded text
  diffs for changed text files and static analysis for changed ELF and PE files.
- Add single-file inspection and combined semantic reports. Directory comparison keeps
  JSON schema v1; file comparison, source-aware comparison, and inspection use schemas
  v6, v7, and v5 respectively.
- Bound source parser and query work with deterministic cancellation limits.
- Add deterministic readable summaries in English, French, Spanish, and Simplified
  Chinese. Technical report details remain in English.

## 0.1.0

- Compare two extracted Linux root filesystem trees using bounded inventory, exact
  regular-file comparison, metadata classification, and mutation checks.
- Provide a direct CLI with deterministic text output, JSON schema version 1, and
  explicit resource limits and exit statuses.
- Provide an interactive shell with session summaries, live progress, and text, JSON,
  Markdown, and offline HTML report export.
- Keep input trees read-only and report filesystem, resource, mutation, and output errors
  without emitting partial successful results.
