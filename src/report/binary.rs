use std::io::{self, Write};

use serde_json::{Map, Value, json};

use crate::{
    binary_compare::{FileComparison, SemanticComparisonStatus},
    input::InputKind,
    readable::select_file_comparison,
    report::{html, semantic_tree::write_markdown_cell},
};

pub fn write_text(comparison: &FileComparison, output: &mut impl Write) -> io::Result<()> {
    let packet = select_file_comparison(comparison).map_err(super::readable::selection_error)?;
    super::readable::write_text(&packet, output)?;
    output.write_all(b"\n")?;
    writeln!(output, "Binary comparison")?;
    writeln!(
        output,
        "Old: {} ({} bytes)",
        comparison.old_kind, comparison.old_size_bytes
    )?;
    writeln!(
        output,
        "New: {} ({} bytes)",
        comparison.new_kind, comparison.new_size_bytes
    )?;
    writeln!(
        output,
        "Byte-level changed: {}",
        yes_no(comparison.bytes_changed)
    )?;
    writeln!(
        output,
        "Semantic comparison: {}",
        status_name(comparison.semantic_status)
    )?;
    writeln!(
        output,
        "Semantic fields changed: {}",
        comparison.semantic_changes.len()
    )?;
    for change in &comparison.semantic_changes {
        writeln!(
            output,
            "{}\t{}\t{}",
            change.field,
            value_text(&change.before),
            value_text(&change.after)
        )?;
    }
    Ok(())
}

pub fn write_json(comparison: &FileComparison, output: &mut impl Write) -> io::Result<()> {
    let changes: Vec<_> = comparison
        .semantic_changes
        .iter()
        .map(|change| {
            json!({
                "field": change.field,
                "before": change.before,
                "after": change.after,
            })
        })
        .collect();
    let mut report = Map::new();
    report.insert("schema_version".to_owned(), json!(6));
    report.insert("analysis_type".to_owned(), json!("file_comparison"));
    report.insert(
        "old_kind".to_owned(),
        json!(comparison.old_kind.to_string()),
    );
    report.insert(
        "new_kind".to_owned(),
        json!(comparison.new_kind.to_string()),
    );
    report.insert(
        "old_size_bytes".to_owned(),
        json!(comparison.old_size_bytes.to_string()),
    );
    report.insert(
        "new_size_bytes".to_owned(),
        json!(comparison.new_size_bytes.to_string()),
    );
    report.insert(
        "byte_level_changed".to_owned(),
        json!(comparison.bytes_changed),
    );
    report.insert(
        "semantic_status".to_owned(),
        json!(status_name(comparison.semantic_status)),
    );
    report.insert("semantic_changes".to_owned(), json!(changes));

    serde_json::to_writer_pretty(&mut *output, &Value::Object(report))?;
    output.write_all(b"\n")
}

pub fn write_markdown(comparison: &FileComparison, output: &mut impl Write) -> io::Result<()> {
    let packet = select_file_comparison(comparison).map_err(super::readable::selection_error)?;
    output.write_all(b"# Crucksware report\n\n")?;
    super::readable::write_markdown(&packet, output)?;
    output.write_all(b"\n## Summary\n\n| Field | Value |\n|:--|:--|\n")?;
    writeln!(output, "| Old kind | {} |", comparison.old_kind)?;
    writeln!(output, "| New kind | {} |", comparison.new_kind)?;
    writeln!(output, "| Old size bytes | {} |", comparison.old_size_bytes)?;
    writeln!(output, "| New size bytes | {} |", comparison.new_size_bytes)?;
    writeln!(
        output,
        "| Byte-level changed | {} |",
        yes_no(comparison.bytes_changed)
    )?;
    writeln!(
        output,
        "| Semantic status | {} |",
        status_name(comparison.semantic_status)
    )?;
    writeln!(
        output,
        "| Semantic fields changed | {} |\n",
        comparison.semantic_changes.len()
    )?;

    output.write_all(b"## Semantic changes\n\n")?;
    if comparison.semantic_changes.is_empty() {
        return output.write_all(b"No semantic field changes.\n");
    }
    output.write_all(b"| Field | Before | After |\n|:--|:--|:--|\n")?;
    for change in &comparison.semantic_changes {
        output.write_all(b"| ")?;
        write_markdown_cell(output, &change.field)?;
        output.write_all(b" | ")?;
        write_markdown_cell(output, &value_text(&change.before))?;
        output.write_all(b" | ")?;
        write_markdown_cell(output, &value_text(&change.after))?;
        output.write_all(b" |\n")?;
    }
    Ok(())
}

pub fn write_html(comparison: &FileComparison, output: &mut impl Write) -> io::Result<()> {
    let packet = select_file_comparison(comparison).map_err(super::readable::selection_error)?;
    output.write_all(
        b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Crucksware report</title>\n<style>",
    )?;
    output.write_all(html::STYLE.as_bytes())?;
    output.write_all(
        b"</style>\n</head>\n<body>\n<main>\n<header><h1>Crucksware report</h1></header>\n",
    )?;
    super::readable::write_html(&packet, output)?;
    output.write_all(
        b"<section aria-labelledby=\"summary-heading\">\n<h2 id=\"summary-heading\">Binary comparison</h2>\n<table class=\"summary\">\n<tbody>\n",
    )?;
    write_html_row(output, "Old kind", kind_name(comparison.old_kind))?;
    write_html_row(output, "New kind", kind_name(comparison.new_kind))?;
    write_html_row(
        output,
        "Old size bytes",
        &comparison.old_size_bytes.to_string(),
    )?;
    write_html_row(
        output,
        "New size bytes",
        &comparison.new_size_bytes.to_string(),
    )?;
    write_html_row(
        output,
        "Byte-level changed",
        yes_no(comparison.bytes_changed),
    )?;
    write_html_row(
        output,
        "Semantic status",
        status_name(comparison.semantic_status),
    )?;
    write_html_row(
        output,
        "Semantic fields changed",
        &comparison.semantic_changes.len().to_string(),
    )?;
    output.write_all(b"</tbody>\n</table>\n</section>\n<section aria-labelledby=\"changes-heading\">\n<h2 id=\"changes-heading\">Semantic changes</h2>\n")?;
    if comparison.semantic_changes.is_empty() {
        output.write_all(b"<p>No semantic field changes.</p>\n")?;
    } else {
        output.write_all(b"<div class=\"table-wrap\">\n<table class=\"changes\">\n<thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>\n<tbody>\n")?;
        for change in &comparison.semantic_changes {
            output.write_all(b"<tr><td><code>")?;
            html::write_escaped(output, &change.field)?;
            output.write_all(b"</code></td><td><code>")?;
            html::write_escaped(output, &value_text(&change.before))?;
            output.write_all(b"</code></td><td><code>")?;
            html::write_escaped(output, &value_text(&change.after))?;
            output.write_all(b"</code></td></tr>\n")?;
        }
        output.write_all(b"</tbody>\n</table>\n</div>\n")?;
    }
    output.write_all(b"</section>\n</main>\n</body>\n</html>\n")
}

fn write_html_row(output: &mut impl Write, label: &str, value: &str) -> io::Result<()> {
    output.write_all(b"<tr><th scope=\"row\">")?;
    html::write_escaped(output, label)?;
    output.write_all(b"</th><td>")?;
    html::write_escaped(output, value)?;
    output.write_all(b"</td></tr>\n")
}

fn kind_name(kind: InputKind) -> &'static str {
    match kind {
        InputKind::Directory => "directory",
        InputKind::Elf => "ELF",
        InputKind::Pe => "PE",
        InputKind::Text => "text",
        InputKind::UnknownBinary => "unknown binary",
    }
}

fn status_name(status: SemanticComparisonStatus) -> &'static str {
    match status {
        SemanticComparisonStatus::Compared => "compared",
        SemanticComparisonStatus::FormatMismatch => "format_mismatch",
        SemanticComparisonStatus::Unsupported => "unsupported",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn value_text(value: &Value) -> String {
    value.to_string()
}

#[cfg(test)]
mod tests;
