# Localized readable reports

## Scope

Localization applies to the short readable summary in text, Markdown, and offline
HTML reports. The detailed technical report and JSON schemas remain canonical and
English. Paths, symbols, signatures, library names, numeric values, addresses, and
other technical identifiers are data, not translation input.

The initial language codes are `en`, `fr`, `es`, and `zh-CN`. English remains the
default. No system-locale detection or network access is used.

## Architecture decision

Use deterministic localization of Crucksware's own summary templates. The existing
summary has a finite input model: aggregate filesystem counts and a bounded set of
typed evidence facts for filesystem changes, source structure and text changes, and
binary metadata. Each language needs wording for those template families, not an
open-ended translation engine.

The renderer consumes the same selected evidence packet for every language. It does
not perform analysis, select different facts, or translate values. Exact paths and
identifiers pass through the existing encoding and output escaping. Counts and
numeric facts retain their original values. The detailed report remains unchanged.

A local translation model would add model files, runtime cost, model-loading failure
modes, and a new boundary for preserving identifiers. That cost is not justified for
this finite summary grammar. Dedicated translation models are therefore deferred;
this decision does not claim that a translation-model benchmark was performed.

## Language selection

Interactive sessions default to English. `language` displays the current setting and
accepts `en`, `fr`, `es`, or `zh-CN`; it changes comparison summaries, `last`, and
`explain` for that session only. It does not persist the preference. Inspection reports
remain in English.

The direct comparison command accepts `--language` for text and Markdown summaries and
for a single-language HTML report. HTML accepts `--languages en,fr,...` to embed an
explicit set of summaries. Interactive Markdown accepts `report markdown --language fr`;
interactive HTML accepts `report html --languages en,fr,es`. A report with one requested
HTML language has no selector. JSON remains language-neutral, and technical report details
remain canonical English.

The HTML selector changes only the visible summary. The technical details below it
remain in their stable form. A report with one requested language has no selector.

## Validation

Tests cover the summary template families in all four languages, singular and plural
counts, empty reports, identifiers and encoded paths, HTML switching, CLI and shell
selection, and unchanged technical report data. The template strings should remain short
and use consistent terminology.
Translation quality has not been reviewed by native speakers; that remains a
limitation until such review is available.

Terminology and concise interface wording should follow the relevant language
conventions in Microsoft's [localization style guides](https://learn.microsoft.com/en-us/globalization/reference/microsoft-style-guides)
and [localization guidance](https://learn.microsoft.com/globalization/localization/localization).
