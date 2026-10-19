use std::io::{self, Write};

use serde::Serialize;

use crate::{
    binary_compare::SemanticChange,
    path::encode_bytes,
    report::{json, text},
    semantic_tree::{BinaryAnalysisStatus, BinaryFileChange, SemanticTreeDiff},
    source::{SourceAnalysisStatus, SourceFileChange, StructuralChange, StructuralStatus},
};

#[cfg(test)]
mod tests;

pub fn write_text(diff: &SemanticTreeDiff, output: &mut impl Write) -> io::Result<()> {
    text::write_text(&diff.filesystem, output)?;
    for change in &diff.source_changes {
        write!(output, "SOURCE\t{}\t", encode_bytes(change.path.as_bytes()))?;
        match (change.lines_added, change.lines_removed, change.hunk_count) {
            (Some(added), Some(removed), Some(hunks)) => {
                write!(
                    output,
                    "lines_added={added},lines_removed={removed},hunks={hunks}"
                )?;
            }
            _ => output.write_all(b"content_kind_changed")?,
        }
        if let Some(language) = change.language {
            write!(output, "\tlanguage={}", language.as_str())?;
        }
        writeln!(
            output,
            "\tstructural_status={}",
            structural_status_name(change.structural_status)
        )?;
        for structural in &change.structural_changes {
            write_structural_change(structural, output)?;
        }
    }
    for change in &diff.binary_changes {
        writeln!(
            output,
            "BINARY\t{}\told_kind={}\tnew_kind={}\told_size_bytes={}\tnew_size_bytes={}\tbyte_level_changed={}\tsemantic_status={}",
            encode_bytes(change.path.as_bytes()),
            optional_kind(change.old_kind),
            optional_kind(change.new_kind),
            optional_size(change.old_size_bytes),
            optional_size(change.new_size_bytes),
            optional_bool(change.byte_level_changed),
            change.semantic_status.as_str(),
        )?;
        for semantic in &change.semantic_changes {
            writeln!(
                output,
                "BINARY_SEMANTIC\t{}\t{}\tbefore={}\tafter={}",
                encode_bytes(change.path.as_bytes()),
                serde_json::to_string(&semantic.field)?,
                serde_json::to_string(&semantic.before)?,
                serde_json::to_string(&semantic.after)?,
            )?;
        }
    }
    Ok(())
}

pub fn write_markdown(diff: &SemanticTreeDiff, output: &mut impl Write) -> io::Result<()> {
    super::markdown::write_markdown_with_labels(
        &diff.filesystem,
        output,
        "Total filesystem changes",
        "No filesystem changes.",
    )?;
    if !diff.source_changes.is_empty() {
        output.write_all(b"\n## Source analysis\n\n")?;
        output.write_all(
            b"| Path | Status | Language | Lines added | Lines removed | Hunks | Structural status |\n|:--|:--|:--|--:|--:|--:|:--|\n",
        )?;
        for change in &diff.source_changes {
            write!(
                output,
                "| `{}` | {} | ",
                encode_bytes(change.path.as_bytes()),
                source_status_name(change.analysis_status)
            )?;
            write_markdown_cell(
                output,
                change.language.map_or("none", |language| language.as_str()),
            )?;
            writeln!(
                output,
                " | {} | {} | {} | {} |",
                optional_count(change.lines_added),
                optional_count(change.lines_removed),
                optional_count(change.hunk_count),
                structural_status_name(change.structural_status)
            )?;
        }

        let has_structural_changes = diff
            .source_changes
            .iter()
            .any(|change| !change.structural_changes.is_empty());
        if has_structural_changes {
            output.write_all(
                b"\n### Structural changes\n\n| Path | Action | Kind | Name | Before signature | After signature |\n|:--|:--|:--|:--|:--|:--|\n",
            )?;
            for change in &diff.source_changes {
                for structural in &change.structural_changes {
                    write!(
                        output,
                        "| `{}` | {} | {} | ",
                        encode_bytes(change.path.as_bytes()),
                        structural.action.as_str(),
                        structural.kind.as_str()
                    )?;
                    write_markdown_cell(output, &structural.name)?;
                    output.write_all(b" | ")?;
                    write_optional_markdown_cell(output, structural.before_signature.as_deref())?;
                    output.write_all(b" | ")?;
                    write_optional_markdown_cell(output, structural.after_signature.as_deref())?;
                    output.write_all(b" |\n")?;
                }
            }
        }
    }

    if !diff.binary_changes.is_empty() {
        output.write_all(b"\n## Binary analysis\n\n")?;
        output.write_all(
            b"| Path | Old kind | New kind | Old size bytes | New size bytes | Byte-level changed | Semantic status |\n|:--|:--|:--|--:|--:|:--|:--|\n",
        )?;
        for change in &diff.binary_changes {
            writeln!(
                output,
                "| `{}` | {} | {} | {} | {} | {} | {} |",
                encode_bytes(change.path.as_bytes()),
                optional_kind(change.old_kind),
                optional_kind(change.new_kind),
                optional_count(change.old_size_bytes),
                optional_count(change.new_size_bytes),
                optional_bool(change.byte_level_changed),
                change.semantic_status.as_str()
            )?;
        }

        let has_semantic_changes = diff
            .binary_changes
            .iter()
            .any(|change| !change.semantic_changes.is_empty());
        if has_semantic_changes {
            output.write_all(
                b"\n### Binary semantic changes\n\n| Path | Field | Before | After |\n|:--|:--|:--|:--|\n",
            )?;
            for change in &diff.binary_changes {
                for semantic in &change.semantic_changes {
                    write!(output, "| `{}` | ", encode_bytes(change.path.as_bytes()))?;
                    write_markdown_cell(output, &semantic.field)?;
                    output.write_all(b" | ")?;
                    write_markdown_cell(output, &semantic.before.to_string())?;
                    output.write_all(b" | ")?;
                    write_markdown_cell(output, &semantic.after.to_string())?;
                    output.write_all(b" |\n")?;
                }
            }
        }
    }
    Ok(())
}

pub fn write_html(diff: &SemanticTreeDiff, output: &mut impl Write) -> io::Result<()> {
    super::html::write_semantic_tree_html(diff, output)
}

pub(super) fn write_markdown_cell(output: &mut impl Write, value: &str) -> io::Result<()> {
    for character in value.chars() {
        match character {
            '\\' => output.write_all(b"\\\\")?,
            '|' => output.write_all(b"\\|")?,
            '`' => output.write_all(b"&#96;")?,
            '&' => output.write_all(b"&amp;")?,
            '<' => output.write_all(b"&lt;")?,
            '>' => output.write_all(b"&gt;")?,
            '"' => output.write_all(b"&quot;")?,
            '\'' => output.write_all(b"&#39;")?,
            '\n' => output.write_all(b"<br>")?,
            '\r' => output.write_all(b"\\r")?,
            '\t' => output.write_all(b"\\t")?,
            control if control.is_control() => write!(output, "\\u{{{:x}}}", control as u32)?,
            character => write!(output, "{character}")?,
        }
    }
    Ok(())
}

fn write_optional_markdown_cell(output: &mut impl Write, value: Option<&str>) -> io::Result<()> {
    match value {
        Some(value) => write_markdown_cell(output, value),
        None => output.write_all(b"none"),
    }
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn source_status_name(status: SourceAnalysisStatus) -> &'static str {
    match status {
        SourceAnalysisStatus::Compared => "compared",
        SourceAnalysisStatus::ContentKindChanged => "content_kind_changed",
    }
}

fn write_structural_change(change: &StructuralChange, output: &mut impl Write) -> io::Result<()> {
    write!(
        output,
        "STRUCTURE\t{}\t{}\t{}",
        change.action.as_str(),
        change.kind.as_str(),
        serde_json::to_string(&change.name)?
    )?;
    if let Some(signature) = &change.before_signature {
        write!(output, "\tbefore={}", serde_json::to_string(signature)?)?;
    }
    if let Some(signature) = &change.after_signature {
        write!(output, "\tafter={}", serde_json::to_string(signature)?)?;
    }
    output.write_all(b"\n")
}

pub fn write_json(diff: &SemanticTreeDiff, output: &mut impl Write) -> io::Result<()> {
    let report = JsonSemanticTreeReport {
        schema_version: 4,
        analysis_type: "semantic_tree_comparison",
        filesystem: json::json_report(&diff.filesystem),
        source_changes: diff
            .source_changes
            .iter()
            .map(JsonSourceChange::from)
            .collect(),
        binary_changes: diff
            .binary_changes
            .iter()
            .map(JsonBinaryChange::from)
            .collect(),
    };
    serde_json::to_writer_pretty(&mut *output, &report).map_err(io::Error::from)?;
    output.write_all(b"\n")
}

#[derive(Serialize)]
struct JsonSemanticTreeReport<'a> {
    schema_version: u8,
    analysis_type: &'static str,
    filesystem: json::JsonReport<'a>,
    source_changes: Vec<JsonSourceChange<'a>>,
    binary_changes: Vec<JsonBinaryChange<'a>>,
}

#[derive(Serialize)]
struct JsonBinaryChange<'a> {
    path: String,
    old_kind: Option<&'static str>,
    new_kind: Option<&'static str>,
    old_size_bytes: Option<String>,
    new_size_bytes: Option<String>,
    byte_level_changed: Option<bool>,
    semantic_status: &'static str,
    semantic_changes: Vec<JsonSemanticChange<'a>>,
}

impl<'a> From<&'a BinaryFileChange> for JsonBinaryChange<'a> {
    fn from(change: &'a BinaryFileChange) -> Self {
        Self {
            path: encode_bytes(change.path.as_bytes()),
            old_kind: change.old_kind.map(|kind| kind.as_str()),
            new_kind: change.new_kind.map(|kind| kind.as_str()),
            old_size_bytes: change.old_size_bytes.map(|size| size.to_string()),
            new_size_bytes: change.new_size_bytes.map(|size| size.to_string()),
            byte_level_changed: change.byte_level_changed,
            semantic_status: match change.semantic_status {
                BinaryAnalysisStatus::SingleInput => "single_input",
                BinaryAnalysisStatus::Compared => "compared",
                BinaryAnalysisStatus::FormatMismatch => "format_mismatch",
                BinaryAnalysisStatus::Unsupported => "unsupported",
            },
            semantic_changes: change
                .semantic_changes
                .iter()
                .map(JsonSemanticChange::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct JsonSemanticChange<'a> {
    field: &'a str,
    before: &'a serde_json::Value,
    after: &'a serde_json::Value,
}

impl<'a> From<&'a SemanticChange> for JsonSemanticChange<'a> {
    fn from(change: &'a SemanticChange) -> Self {
        Self {
            field: &change.field,
            before: &change.before,
            after: &change.after,
        }
    }
}

#[derive(Serialize)]
struct JsonSourceChange<'a> {
    path: String,
    analysis_status: &'static str,
    language: Option<&'static str>,
    lines_added: Option<u64>,
    lines_removed: Option<u64>,
    hunk_count: Option<u64>,
    structural_status: &'static str,
    structural_changes: Vec<JsonStructuralChange<'a>>,
}

impl<'a> From<&'a SourceFileChange> for JsonSourceChange<'a> {
    fn from(change: &'a SourceFileChange) -> Self {
        Self {
            path: encode_bytes(change.path.as_bytes()),
            analysis_status: match change.analysis_status {
                SourceAnalysisStatus::Compared => "compared",
                SourceAnalysisStatus::ContentKindChanged => "content_kind_changed",
            },
            language: change.language.map(|language| language.as_str()),
            lines_added: change.lines_added,
            lines_removed: change.lines_removed,
            hunk_count: change.hunk_count,
            structural_status: structural_status_name(change.structural_status),
            structural_changes: change
                .structural_changes
                .iter()
                .map(JsonStructuralChange::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct JsonStructuralChange<'a> {
    action: &'static str,
    kind: &'static str,
    name: &'a str,
    before_signature: Option<&'a str>,
    after_signature: Option<&'a str>,
}

impl<'a> From<&'a StructuralChange> for JsonStructuralChange<'a> {
    fn from(change: &'a StructuralChange) -> Self {
        Self {
            action: change.action.as_str(),
            kind: change.kind.as_str(),
            name: &change.name,
            before_signature: change.before_signature.as_deref(),
            after_signature: change.after_signature.as_deref(),
        }
    }
}

fn structural_status_name(status: StructuralStatus) -> &'static str {
    match status {
        StructuralStatus::Complete => "complete",
        StructuralStatus::SyntaxErrors => "syntax_errors",
        StructuralStatus::Unsupported => "unsupported",
        StructuralStatus::NotApplicable => "not_applicable",
    }
}

fn optional_kind(kind: Option<crate::input::InputKind>) -> &'static str {
    kind.map(crate::input::InputKind::as_str).unwrap_or("none")
}

fn optional_size(size: Option<u64>) -> String {
    size.map(|size| size.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn optional_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "none",
    }
}
