use std::io::{self, Write};

use serde_json::{Map, Value, json};

use crate::binary_compare::{FileComparison, SemanticComparisonStatus};

pub fn write_text(comparison: &FileComparison, output: &mut impl Write) -> io::Result<()> {
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
    report.insert("schema_version".to_owned(), json!(2));
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
