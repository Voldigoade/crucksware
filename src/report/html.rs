use std::io::{self, Write};

use super::shared::{category_name, changed_field_name, validate_diff_summary};
use crate::{
    model::{Category, ChangedField, Diff, Entry},
    path::encode_bytes,
    semantic_tree::{BinaryFileChange, SemanticTreeDiff},
    source::{SourceFileChange, StructuralChange},
};

pub(super) const STYLE: &str = r#"
:root { color-scheme: light; font-family: system-ui, sans-serif; line-height: 1.5; }
body { margin: 0; background: #f6f8fa; color: #1f2328; }
main { max-width: 84rem; margin: 0 auto; padding: 2rem; }
h1 { margin: 0 0 1.5rem; font-size: 1.8rem; }
h2 { margin: 2rem 0 0.75rem; font-size: 1.25rem; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #d0d7de; padding: 0.5rem 0.65rem; text-align: left; vertical-align: top; }
th { background: #eaeef2; }
.summary { max-width: 32rem; }
.summary td { text-align: right; font-variant-numeric: tabular-nums; }
.filters { display: flex; flex-wrap: wrap; gap: 1rem; margin: 1rem 0; }
.filters label { display: grid; gap: 0.25rem; font-weight: 600; }
input, select { min-height: 2.4rem; padding: 0.35rem 0.5rem; font: inherit; }
input { width: min(26rem, 80vw); }
.change-group { margin: 0.75rem 0; border: 1px solid #d0d7de; border-radius: 0.4rem; background: #fff; }
.change-group summary { padding: 0.65rem 0.8rem; cursor: pointer; font-weight: 700; }
.table-wrap { overflow-x: auto; padding: 0 0.5rem 0.5rem; }
.changes { min-width: 54rem; }
code { overflow-wrap: anywhere; }
pre { overflow-wrap: anywhere; white-space: pre-wrap; }
[hidden] { display: none !important; }
@media (max-width: 40rem) { main { padding: 1rem; } }
"#;

const FILTER_SCRIPT: &str = r#"
const pathFilter = document.getElementById("path-filter");
const categoryFilter = document.getElementById("category-filter");
const groups = Array.from(document.querySelectorAll("details.change-group"));
function updateFilters() {
  const query = pathFilter.value.toLowerCase();
  const category = categoryFilter.value;
  for (const group of groups) {
    let hasVisibleRows = false;
    for (const row of group.querySelectorAll("tr[data-path]")) {
      const matchesPath = row.dataset.path.toLowerCase().includes(query);
      const matchesCategory = category === "" || row.dataset.category === category;
      row.hidden = !(matchesPath && matchesCategory);
      if (!row.hidden) hasVisibleRows = true;
    }
    group.hidden = !hasVisibleRows;
  }
}
pathFilter.addEventListener("input", updateFilters);
categoryFilter.addEventListener("change", updateFilters);
"#;

#[cfg(test)]
mod tests;

pub fn write_html(diff: &Diff, output: &mut impl Write) -> io::Result<()> {
    let total_changes = validate_diff_summary(diff)?;

    output.write_all(
        b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Crucksware report</title>\n<style>",
    )?;
    output.write_all(STYLE.as_bytes())?;
    output.write_all(
        b"</style>\n</head>\n<body>\n<main>\n<header><h1>Crucksware report</h1></header>\n",
    )?;
    write_summary(diff, total_changes, output)?;
    output.write_all(
        b"<section aria-labelledby=\"changes-heading\">\n<h2 id=\"changes-heading\">Changes</h2>\n",
    )?;

    if diff.changes.is_empty() {
        output.write_all(b"<p>No changes.</p>\n")?;
    } else {
        write_filters(output, false)?;
        write_groups(diff, output)?;
    }

    output.write_all(b"</section>\n</main>\n")?;
    if !diff.changes.is_empty() {
        output.write_all(b"<script>")?;
        output.write_all(FILTER_SCRIPT.as_bytes())?;
        output.write_all(b"</script>\n")?;
    }
    output.write_all(b"</body>\n</html>\n")
}

pub fn write_semantic_tree_html(
    diff: &SemanticTreeDiff,
    output: &mut impl Write,
) -> io::Result<()> {
    let total_changes = validate_diff_summary(&diff.filesystem)?;
    let has_changes = !diff.filesystem.changes.is_empty()
        || !diff.source_changes.is_empty()
        || !diff.binary_changes.is_empty();

    output.write_all(
        b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Crucksware report</title>\n<style>",
    )?;
    output.write_all(STYLE.as_bytes())?;
    output.write_all(
        b"</style>\n</head>\n<body>\n<main>\n<header><h1>Crucksware report</h1></header>\n",
    )?;
    write_summary_with_total_label(
        &diff.filesystem,
        total_changes,
        "Total filesystem changes",
        output,
    )?;
    output.write_all(b"<section aria-labelledby=\"analysis-heading\">\n<h2 id=\"analysis-heading\">Analysis</h2>\n<table class=\"summary\">\n<tbody>\n")?;
    write_summary_row(output, "Source files analyzed", diff.source_changes.len())?;
    write_summary_row(output, "Binary files analyzed", diff.binary_changes.len())?;
    output.write_all(b"</tbody>\n</table>\n</section>\n")?;
    output.write_all(
        b"<section aria-labelledby=\"changes-heading\">\n<h2 id=\"changes-heading\">Changes</h2>\n",
    )?;

    if !has_changes {
        output.write_all(b"<p>No changes.</p>\n")?;
    } else {
        write_filters(output, true)?;
        write_groups(&diff.filesystem, output)?;
        write_source_group(&diff.source_changes, output)?;
        write_binary_group(&diff.binary_changes, output)?;
    }

    output.write_all(b"</section>\n</main>\n")?;
    if has_changes {
        output.write_all(b"<script>")?;
        output.write_all(FILTER_SCRIPT.as_bytes())?;
        output.write_all(b"</script>\n")?;
    }
    output.write_all(b"</body>\n</html>\n")
}

fn write_summary(diff: &Diff, total_changes: u64, output: &mut impl Write) -> io::Result<()> {
    write_summary_with_total_label(diff, total_changes, "Total changes", output)
}

fn write_summary_with_total_label(
    diff: &Diff,
    total_changes: u64,
    total_label: &str,
    output: &mut impl Write,
) -> io::Result<()> {
    output.write_all(b"<section aria-labelledby=\"summary-heading\">\n<h2 id=\"summary-heading\">Summary</h2>\n<table class=\"summary\">\n<tbody>\n")?;
    write_summary_row(output, "Added", diff.summary.added)?;
    write_summary_row(output, "Removed", diff.summary.removed)?;
    write_summary_row(output, "Modified", diff.summary.modified)?;
    write_summary_row(output, "Type changed", diff.summary.type_changed)?;
    write_summary_row(output, "Metadata changed", diff.summary.metadata_changed)?;
    write_summary_row(output, total_label, total_changes)?;
    write_summary_row(output, "Unchanged", diff.summary.unchanged)?;
    output.write_all(b"</tbody>\n</table>\n</section>\n")
}

fn write_summary_row(
    output: &mut impl Write,
    label: &str,
    count: impl std::fmt::Display,
) -> io::Result<()> {
    writeln!(
        output,
        "<tr><th scope=\"row\">{label}</th><td>{count}</td></tr>"
    )
}

fn write_filters(output: &mut impl Write, include_semantic_categories: bool) -> io::Result<()> {
    output.write_all(
        b"<div class=\"filters\">\n<label for=\"path-filter\">Search path</label>\n<input id=\"path-filter\" type=\"search\" autocomplete=\"off\" placeholder=\"Encoded path\">\n<label for=\"category-filter\">Category</label>\n<select id=\"category-filter\">\n<option value=\"\">All categories</option>\n",
    )?;
    for category in categories() {
        let name = category_name(category);
        writeln!(output, "<option value=\"{name}\">{name}</option>")?;
    }
    if include_semantic_categories {
        output.write_all(
            b"<option value=\"SOURCE\">SOURCE</option>\n<option value=\"BINARY\">BINARY</option>\n",
        )?;
    }
    output.write_all(b"</select>\n</div>\n")
}

fn write_groups(diff: &Diff, output: &mut impl Write) -> io::Result<()> {
    for (category, count) in [
        (Category::Added, diff.summary.added),
        (Category::Removed, diff.summary.removed),
        (Category::Modified, diff.summary.modified),
        (Category::TypeChanged, diff.summary.type_changed),
        (Category::MetadataChanged, diff.summary.metadata_changed),
    ] {
        if count == 0 {
            continue;
        }
        let name = category_name(category);
        writeln!(
            output,
            "<details class=\"change-group\" open data-group=\"{name}\">\n<summary>{name} ({count})</summary>\n<div class=\"table-wrap\">\n<table class=\"changes\">\n<thead><tr><th>Path</th><th>Category</th><th>Changed fields</th><th>Before</th><th>After</th></tr></thead>\n<tbody>"
        )?;
        for change in diff
            .changes
            .iter()
            .filter(|change| change.category == category)
        {
            write_change(change, output)?;
        }
        output.write_all(b"</tbody>\n</table>\n</div>\n</details>\n")?;
    }
    Ok(())
}

fn write_source_group(changes: &[SourceFileChange], output: &mut impl Write) -> io::Result<()> {
    if changes.is_empty() {
        return Ok(());
    }
    output.write_all(b"<details class=\"change-group\" open data-group=\"SOURCE\">\n")?;
    writeln!(output, "<summary>SOURCE ({})</summary>", changes.len())?;
    output.write_all(b"<div class=\"table-wrap\">\n<table class=\"changes\">\n<thead><tr><th>Path</th><th>Category</th><th>Status</th><th>Language</th><th>Lines added</th><th>Lines removed</th><th>Hunks</th><th>Structural status</th><th>Structural changes</th></tr></thead>\n<tbody>\n")?;
    for change in changes {
        let path = encode_bytes(change.path.as_bytes());
        writeln!(
            output,
            "<tr data-category=\"SOURCE\" data-path=\"{}\">",
            escape_html(&path)
        )?;
        output.write_all(b"<td><code>")?;
        write_escaped(output, &path)?;
        output.write_all(b"</code></td><td>SOURCE</td><td>")?;
        write_escaped(output, source_status_name(change.analysis_status))?;
        output.write_all(b"</td><td>")?;
        write_escaped(
            output,
            change.language.map_or("none", |language| language.as_str()),
        )?;
        write!(
            output,
            "</td><td>{}</td><td>{}</td><td>{}</td><td>",
            display_optional(change.lines_added),
            display_optional(change.lines_removed),
            display_optional(change.hunk_count)
        )?;
        write_escaped(output, structural_status_name(change.structural_status))?;
        output.write_all(b"</td><td>")?;
        write_structural_changes(&change.structural_changes, output)?;
        output.write_all(b"</td></tr>\n")?;
    }
    output.write_all(b"</tbody>\n</table>\n</div>\n</details>\n")
}

fn write_structural_changes(
    changes: &[StructuralChange],
    output: &mut impl Write,
) -> io::Result<()> {
    if changes.is_empty() {
        return output.write_all(b"none");
    }
    output.write_all(b"<ul>\n")?;
    for change in changes {
        output.write_all(b"<li><code>")?;
        write_escaped(output, change.action.as_str())?;
        output.write_all(b" ")?;
        write_escaped(output, change.kind.as_str())?;
        output.write_all(b"</code> ")?;
        write_escaped(output, &change.name)?;
        if let Some(signature) = &change.before_signature {
            output.write_all(b"<br>Before: <code>")?;
            write_escaped(output, signature)?;
            output.write_all(b"</code>")?;
        }
        if let Some(signature) = &change.after_signature {
            output.write_all(b"<br>After: <code>")?;
            write_escaped(output, signature)?;
            output.write_all(b"</code>")?;
        }
        output.write_all(b"</li>\n")?;
    }
    output.write_all(b"</ul>")
}

fn write_binary_group(changes: &[BinaryFileChange], output: &mut impl Write) -> io::Result<()> {
    if changes.is_empty() {
        return Ok(());
    }
    output.write_all(b"<details class=\"change-group\" open data-group=\"BINARY\">\n")?;
    writeln!(output, "<summary>BINARY ({})</summary>", changes.len())?;
    output.write_all(b"<div class=\"table-wrap\">\n<table class=\"changes\">\n<thead><tr><th>Path</th><th>Category</th><th>Old kind</th><th>New kind</th><th>Old size bytes</th><th>New size bytes</th><th>Byte-level changed</th><th>Semantic status</th><th>Semantic changes</th></tr></thead>\n<tbody>\n")?;
    for change in changes {
        let path = encode_bytes(change.path.as_bytes());
        writeln!(
            output,
            "<tr data-category=\"BINARY\" data-path=\"{}\">",
            escape_html(&path)
        )?;
        output.write_all(b"<td><code>")?;
        write_escaped(output, &path)?;
        output.write_all(b"</code></td><td>BINARY</td><td>")?;
        write_optional_kind(output, change.old_kind)?;
        output.write_all(b"</td><td>")?;
        write_optional_kind(output, change.new_kind)?;
        write!(
            output,
            "</td><td>{}</td><td>{}</td><td>{}</td><td>",
            display_optional(change.old_size_bytes),
            display_optional(change.new_size_bytes),
            change
                .byte_level_changed
                .map_or("unknown", |changed| if changed { "yes" } else { "no" })
        )?;
        write_escaped(output, change.semantic_status.as_str())?;
        output.write_all(b"</td><td>")?;
        write_binary_semantic_changes(change, output)?;
        output.write_all(b"</td></tr>\n")?;
    }
    output.write_all(b"</tbody>\n</table>\n</div>\n</details>\n")
}

fn write_binary_semantic_changes(
    change: &BinaryFileChange,
    output: &mut impl Write,
) -> io::Result<()> {
    if change.semantic_changes.is_empty() {
        return output.write_all(b"none");
    }
    output.write_all(b"<ul>\n")?;
    for fact in &change.semantic_changes {
        output.write_all(b"<li><code>")?;
        write_escaped(output, &fact.field)?;
        output.write_all(b"</code><br>Before: <code>")?;
        write_escaped(output, &fact.before.to_string())?;
        output.write_all(b"</code><br>After: <code>")?;
        write_escaped(output, &fact.after.to_string())?;
        output.write_all(b"</code></li>\n")?;
    }
    output.write_all(b"</ul>")
}

fn write_optional_kind(
    output: &mut impl Write,
    kind: Option<crate::input::InputKind>,
) -> io::Result<()> {
    match kind {
        Some(kind) => write_escaped(output, kind.as_str()),
        None => output.write_all(b"none"),
    }
}

fn display_optional(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn source_status_name(status: crate::source::SourceAnalysisStatus) -> &'static str {
    match status {
        crate::source::SourceAnalysisStatus::Compared => "compared",
        crate::source::SourceAnalysisStatus::ContentKindChanged => "content_kind_changed",
    }
}

fn structural_status_name(status: crate::source::StructuralStatus) -> &'static str {
    match status {
        crate::source::StructuralStatus::Complete => "complete",
        crate::source::StructuralStatus::SyntaxErrors => "syntax_errors",
        crate::source::StructuralStatus::Unsupported => "unsupported",
        crate::source::StructuralStatus::NotApplicable => "not_applicable",
    }
}

fn write_change(change: &crate::model::Change, output: &mut impl Write) -> io::Result<()> {
    let category = category_name(change.category);
    let path = encode_bytes(change.path.as_bytes());
    writeln!(
        output,
        "<tr data-category=\"{category}\" data-path=\"{}\">",
        escape_html(&path)
    )?;
    output.write_all(b"<td><code>")?;
    write_escaped(output, &path)?;
    output.write_all(b"</code></td><td><code>")?;
    write_escaped(output, category)?;
    output.write_all(b"</code></td><td>")?;
    write_changed_fields(&change.changed_fields, output)?;
    output.write_all(b"</td><td>")?;
    write_entry(change.before.as_ref(), output)?;
    output.write_all(b"</td><td>")?;
    write_entry(change.after.as_ref(), output)?;
    output.write_all(b"</td></tr>\n")
}

fn write_changed_fields(fields: &[ChangedField], output: &mut impl Write) -> io::Result<()> {
    if fields.is_empty() {
        return output.write_all(b"none");
    }
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            output.write_all(b", ")?;
        }
        output.write_all(b"<code>")?;
        write_escaped(output, changed_field_name(*field))?;
        output.write_all(b"</code>")?;
    }
    Ok(())
}

fn write_entry(entry: Option<&Entry>, output: &mut impl Write) -> io::Result<()> {
    let Some(entry) = entry else {
        return output.write_all(b"none");
    };
    match entry {
        Entry::File { size, mode } => write!(
            output,
            "<code>file; size_bytes={size}; mode={:04o}</code>",
            mode & 0o7777
        ),
        Entry::Directory { mode } => {
            write!(output, "<code>directory; mode={:04o}</code>", mode & 0o7777)
        }
        Entry::Symlink { target } => {
            output.write_all(b"<code>symlink; target=")?;
            write_escaped(output, &encode_bytes(target))?;
            output.write_all(b"</code>")
        }
        Entry::Fifo { mode } => write!(output, "<code>fifo; mode={:04o}</code>", mode & 0o7777),
        Entry::Socket { mode } => {
            write!(output, "<code>socket; mode={:04o}</code>", mode & 0o7777)
        }
        Entry::CharDevice { mode, device_id } => write!(
            output,
            "<code>char_device; mode={:04o}; device_id={device_id}</code>",
            mode & 0o7777
        ),
        Entry::BlockDevice { mode, device_id } => write!(
            output,
            "<code>block_device; mode={:04o}; device_id={device_id}</code>",
            mode & 0o7777
        ),
    }
}

fn categories() -> [Category; 5] {
    [
        Category::Added,
        Category::Removed,
        Category::Modified,
        Category::TypeChanged,
        Category::MetadataChanged,
    ]
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        if character.is_control() {
            use std::fmt::Write as _;
            let _ = write!(escaped, "\\u{{{:x}}}", character as u32);
            continue;
        }
        escaped.push_str(match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#39;",
            _ => {
                escaped.push(character);
                continue;
            }
        });
    }
    escaped
}

pub(super) fn write_escaped(output: &mut impl Write, input: &str) -> io::Result<()> {
    output.write_all(escape_html(input).as_bytes())
}
