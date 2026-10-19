use std::io::{self, Write};

use serde::Serialize;

use crate::{
    path::encode_bytes,
    report::{json, text},
    source::{
        SourceAnalysisStatus, SourceDiff, SourceFileChange, StructuralChange, StructuralStatus,
    },
};

#[cfg(test)]
mod tests;

pub fn write_text(diff: &SourceDiff, output: &mut impl Write) -> io::Result<()> {
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
    Ok(())
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

pub fn write_json(diff: &SourceDiff, output: &mut impl Write) -> io::Result<()> {
    let report = JsonSourceReport {
        schema_version: 3,
        analysis_type: "source_tree_comparison",
        filesystem: json::json_report(&diff.filesystem),
        source_changes: diff
            .source_changes
            .iter()
            .map(JsonSourceChange::from)
            .collect(),
    };
    serde_json::to_writer_pretty(&mut *output, &report).map_err(io::Error::from)?;
    output.write_all(b"\n")
}

#[derive(Serialize)]
struct JsonSourceReport<'a> {
    schema_version: u8,
    analysis_type: &'static str,
    filesystem: json::JsonReport<'a>,
    source_changes: Vec<JsonSourceChange<'a>>,
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
