use std::io::{self, Write};

use crate::readable::{
    EvidenceError, EvidenceFact, EvidencePacket, EvidenceRecord, EvidenceTotals,
    MAX_SUMMARY_RECORDS,
};

#[cfg(test)]
mod tests;

pub(super) fn selection_error(error: EvidenceError) -> io::Error {
    io::Error::other(error)
}

pub(super) fn write_text(packet: &EvidencePacket, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "Readable summary")?;
    if is_empty(&packet.totals) {
        return output.write_all(b"No changes were found.\n");
    }
    for line in overview_lines(&packet.totals) {
        writeln!(output, "{line}")?;
    }
    write_text_highlights(packet, output)?;
    write_omission_note(packet, output, "text")
}

pub(super) fn write_markdown(packet: &EvidencePacket, output: &mut impl Write) -> io::Result<()> {
    output.write_all(b"## Readable summary\n\n")?;
    if is_empty(&packet.totals) {
        return output.write_all(b"No changes were found.\n");
    }
    for line in overview_lines(&packet.totals) {
        write_markdown_text(output, &line)?;
        output.write_all(b"\n\n")?;
    }
    write_markdown_highlights(packet, output)?;
    write_omission_note(packet, output, "markdown")
}

pub(super) fn write_html(packet: &EvidencePacket, output: &mut impl Write) -> io::Result<()> {
    output.write_all(b"<section class=\"readable-summary\" aria-labelledby=\"readable-summary-heading\">\n<h2 id=\"readable-summary-heading\">Readable summary</h2>\n")?;
    if is_empty(&packet.totals) {
        output.write_all(b"<p>No changes were found.</p>\n</section>\n")?;
        return Ok(());
    }
    for line in overview_lines(&packet.totals) {
        output.write_all(b"<p>")?;
        super::html::write_escaped(output, &line)?;
        output.write_all(b"</p>\n")?;
    }
    write_html_highlights(packet, output)?;
    write_omission_note(packet, output, "html")?;
    output.write_all(b"</section>\n")
}

pub(super) fn write_explanation(
    record: &EvidenceRecord,
    output: &mut impl Write,
) -> io::Result<()> {
    writeln!(output, "Evidence {}", record.id)?;
    if let Some(path) = &record.path {
        writeln!(output, "Path: `{path}`")?;
    } else {
        writeln!(output, "Path: file comparison")?;
    }
    writeln!(output, "Fact: {}", describe(&record.fact))
}

fn overview_lines(totals: &EvidenceTotals) -> Vec<String> {
    let mut lines = Vec::with_capacity(3);
    let filesystem = [
        (totals.filesystem.added, "added"),
        (totals.filesystem.removed, "removed"),
        (totals.filesystem.modified, "modified"),
        (totals.filesystem.type_changed, "type changed"),
        (totals.filesystem.metadata_changed, "metadata changed"),
        (totals.filesystem.unchanged, "unchanged"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, label)| format!("{count} {label}"))
    .collect::<Vec<_>>();
    if totals.filesystem_entries > 0 {
        lines.push(format!(
            "Filesystem: {} across {} ({}).",
            count_phrase(totals.filesystem_changes, "change", "changes"),
            count_phrase(totals.filesystem_entries, "entry", "entries"),
            filesystem.join(", ")
        ));
    }
    if totals.source_files > 0 {
        lines.push(format!(
            "Source analysis: {} changed {}, {} structural {}.",
            totals.source_files,
            plural(totals.source_files, "file", "files"),
            totals.structural_changes,
            plural(totals.structural_changes, "change", "changes")
        ));
    }
    if totals.file_comparison_inputs > 0 {
        lines.push(format!(
            "File comparison: {} {}, {} semantic {}.",
            totals.file_comparison_inputs,
            plural(totals.file_comparison_inputs, "input", "inputs"),
            totals.binary_semantic_changes,
            plural(
                totals.binary_semantic_changes,
                "field change",
                "field changes"
            )
        ));
    }
    if totals.binary_files > 0 {
        lines.push(format!(
            "Binary analysis: {} {}, {} semantic {}.",
            totals.binary_files,
            plural(totals.binary_files, "input", "inputs"),
            totals.binary_semantic_changes,
            plural(
                totals.binary_semantic_changes,
                "field change",
                "field changes"
            )
        ));
    }
    lines
}

fn count_phrase(count: u64, singular: &str, plural_word: &str) -> String {
    format!("{count} {}", plural(count, singular, plural_word))
}

fn is_empty(totals: &EvidenceTotals) -> bool {
    totals.filesystem_entries == 0
        && totals.source_files == 0
        && totals.binary_semantic_changes == 0
        && totals.file_comparison_inputs == 0
        && totals.eligible_records == 0
}

fn plural<'a>(count: u64, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn write_text_highlights(packet: &EvidencePacket, output: &mut impl Write) -> io::Result<()> {
    let shown = packet.records.len().min(MAX_SUMMARY_RECORDS);
    if shown == 0 {
        return Ok(());
    }
    output.write_all(b"Notable changes:\n")?;
    let mut index = 0;
    while index < shown {
        let path = packet.records[index].path.as_deref();
        writeln!(output, "- {}", path_label(path))?;
        while index < shown && packet.records[index].path.as_deref() == path {
            let record = &packet.records[index];
            writeln!(output, "  - {}: {}.", record.id, describe(&record.fact))?;
            index += 1;
        }
    }
    Ok(())
}

fn write_markdown_highlights(packet: &EvidencePacket, output: &mut impl Write) -> io::Result<()> {
    let shown = packet.records.len().min(MAX_SUMMARY_RECORDS);
    if shown == 0 {
        return Ok(());
    }
    output.write_all(b"### Notable changes\n\n")?;
    let mut index = 0;
    while index < shown {
        let path = packet.records[index].path.as_deref();
        output.write_all(b"- ")?;
        if let Some(path) = path {
            writeln!(output, "`{path}`")?;
        } else {
            output.write_all(b"File comparison\n")?;
        }
        while index < shown && packet.records[index].path.as_deref() == path {
            let record = &packet.records[index];
            output.write_all(b"  - **")?;
            write!(output, "{}**: ", record.id)?;
            write_markdown_text(output, &describe(&record.fact))?;
            output.write_all(b".\n")?;
            index += 1;
        }
    }
    Ok(())
}

fn write_html_highlights(packet: &EvidencePacket, output: &mut impl Write) -> io::Result<()> {
    let shown = packet.records.len().min(MAX_SUMMARY_RECORDS);
    if shown == 0 {
        return Ok(());
    }
    output.write_all(b"<h3>Notable changes</h3>\n<ul>\n")?;
    let mut index = 0;
    while index < shown {
        let path = packet.records[index].path.as_deref();
        output.write_all(b"<li>")?;
        if let Some(path) = path {
            output.write_all(b" <code>")?;
            super::html::write_escaped(output, path)?;
            output.write_all(b"</code>\n")?;
        } else {
            output.write_all(b"File comparison\n")?;
        }
        output.write_all(b"<ul>\n")?;
        while index < shown && packet.records[index].path.as_deref() == path {
            write_html_record(&packet.records[index], output)?;
            index += 1;
        }
        output.write_all(b"</ul>\n</li>\n")?;
    }
    output.write_all(b"</ul>\n")
}

fn write_html_record(record: &EvidenceRecord, output: &mut impl Write) -> io::Result<()> {
    write!(output, "<li><strong>{}</strong>: ", record.id)?;
    super::html::write_escaped(output, &describe(&record.fact))?;
    output.write_all(b".</li>\n")
}

fn path_label(path: Option<&str>) -> String {
    path.map_or_else(|| "File comparison".to_owned(), |path| format!("`{path}`"))
}

fn write_omission_note(
    packet: &EvidencePacket,
    output: &mut impl Write,
    format: &str,
) -> io::Result<()> {
    let shown = packet.records.len().min(MAX_SUMMARY_RECORDS);
    let omitted = packet.totals.eligible_records.saturating_sub(shown as u64);
    if omitted == 0 {
        return Ok(());
    }
    let note = format!(
        "{omitted} evidence {} not shown; see technical details.",
        plural(omitted, "record is", "records are")
    );
    match format {
        "text" => writeln!(output, "{note}"),
        "markdown" => {
            write_markdown_text(output, &note)?;
            output.write_all(b"\n")
        }
        "html" => {
            output.write_all(b"<p>")?;
            super::html::write_escaped(output, &note)?;
            output.write_all(b"</p>\n")
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown summary format",
        )),
    }
}

fn describe(fact: &EvidenceFact) -> String {
    match fact {
        EvidenceFact::FilesystemChange {
            category,
            changed_fields,
            before,
            after,
        } => describe_filesystem(category, changed_fields, before.as_ref(), after.as_ref()),
        EvidenceFact::SourceStructuralChange {
            action,
            symbol_kind,
            name,
            before_signature,
            after_signature,
        } => {
            let name = display_safe(name);
            match action.as_str() {
                "added" => format!("{symbol_kind} \"{name}\" added"),
                "removed" => format!("{symbol_kind} \"{name}\" removed"),
                "signature_changed" => format!(
                    "{symbol_kind} \"{name}\" signature changed from {} to {}",
                    quoted(before_signature.as_deref()),
                    quoted(after_signature.as_deref())
                ),
                _ => format!("{symbol_kind} \"{name}\" changed"),
            }
        }
        EvidenceFact::SourceTextChange {
            lines_added,
            lines_removed,
            hunk_count,
        } => {
            let hunks = hunk_count.map_or_else(
                || "an unknown number of hunks".to_owned(),
                |count| format!("{count} {}", plural(count, "hunk", "hunks")),
            );
            format!(
                "text changed (+{} lines, -{} lines across {hunks})",
                optional_number(*lines_added),
                optional_number(*lines_removed)
            )
        }
        EvidenceFact::SourceContentKindChanged => "file content kind changed".to_owned(),
        EvidenceFact::BinarySemanticChange {
            field,
            before,
            after,
        } => format!(
            "binary field \"{}\" changed from {} to {}",
            display_safe(field),
            display_safe(&before.to_string()),
            display_safe(&after.to_string())
        ),
        EvidenceFact::BinaryBytesChanged {
            old_kind,
            new_kind,
            old_size_bytes,
            new_size_bytes,
            byte_level_changed,
            semantic_status,
        } => format!(
            "byte-level comparison {}; {} ({} bytes) to {} ({} bytes); semantic comparison: {}",
            byte_change_text(*byte_level_changed),
            old_kind.as_deref().unwrap_or("unknown format"),
            optional_count(*old_size_bytes),
            new_kind.as_deref().unwrap_or("unknown format"),
            optional_count(*new_size_bytes),
            semantic_status.replace('_', " ")
        ),
    }
}

fn describe_filesystem(
    category: &str,
    changed_fields: &[String],
    before: Option<&crate::readable::EntryEvidence>,
    after: Option<&crate::readable::EntryEvidence>,
) -> String {
    match category {
        "added" => format!("added {}", describe_entry(after)),
        "removed" => format!("removed {}", describe_entry(before)),
        "type_changed" => format!(
            "type changed from {} to {}",
            before.map_or("unknown type", |entry| entry.kind.as_str()),
            after.map_or("unknown type", |entry| entry.kind.as_str())
        ),
        "modified" | "metadata_changed" => {
            let details = changed_fields
                .iter()
                .filter_map(|field| describe_field(field, before, after))
                .collect::<Vec<_>>();
            if details.is_empty() {
                "filesystem metadata changed".to_owned()
            } else {
                details.join(", ")
            }
        }
        _ => "filesystem entry changed".to_owned(),
    }
}

fn describe_entry(entry: Option<&crate::readable::EntryEvidence>) -> String {
    let Some(entry) = entry else {
        return "an entry with unavailable metadata".to_owned();
    };
    let mut details = vec![entry.kind.clone()];
    if let Some(size) = entry.size_bytes {
        details.push(format!("{size} bytes"));
    }
    if let Some(mode) = entry.mode {
        details.push(format!("mode {:04o}", mode & 0o7777));
    }
    if let Some(device_id) = entry.device_id {
        details.push(format!("device ID {device_id}"));
    }
    if let Some(target) = &entry.symlink_target {
        details.push(format!("target {target}"));
    }
    details.join("; ")
}

fn describe_field(
    field: &str,
    before: Option<&crate::readable::EntryEvidence>,
    after: Option<&crate::readable::EntryEvidence>,
) -> Option<String> {
    match field {
        "content" => Some("file content changed".to_owned()),
        "type" => Some(format!(
            "type changed from {} to {}",
            before.map_or("unknown type", |entry| entry.kind.as_str()),
            after.map_or("unknown type", |entry| entry.kind.as_str())
        )),
        "mode" => Some(format!(
            "mode {} to {}",
            before.and_then(|entry| entry.mode).map_or_else(
                || "unknown".to_owned(),
                |mode| format!("{:04o}", mode & 0o7777)
            ),
            after.and_then(|entry| entry.mode).map_or_else(
                || "unknown".to_owned(),
                |mode| format!("{:04o}", mode & 0o7777)
            )
        )),
        "device_id" => Some(format!(
            "device ID {} to {}",
            before
                .and_then(|entry| entry.device_id)
                .map_or_else(|| "unknown".to_owned(), |id| id.to_string()),
            after
                .and_then(|entry| entry.device_id)
                .map_or_else(|| "unknown".to_owned(), |id| id.to_string())
        )),
        "symlink_target" => Some(format!(
            "symlink target {} to {}",
            before
                .and_then(|entry| entry.symlink_target.as_deref())
                .map_or("unknown", |target| target),
            after
                .and_then(|entry| entry.symlink_target.as_deref())
                .map_or("unknown", |target| target)
        )),
        _ => None,
    }
}

fn quoted(value: Option<&str>) -> String {
    value.map_or_else(
        || "an unavailable signature".to_owned(),
        |value| format!("\"{}\"", display_safe(value)),
    )
}

fn display_safe(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            output.push_str(&format!("\\u{{{:X}}}", character as u32));
        } else {
            output.push(character);
        }
    }
    output
}

fn byte_change_text(changed: Option<bool>) -> &'static str {
    match changed {
        Some(true) => "changed",
        Some(false) => "unchanged",
        None => "not established",
    }
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown size".to_owned(), |size| format!("{size}"))
}

fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |number| number.to_string())
}

fn write_markdown_text(output: &mut impl Write, value: &str) -> io::Result<()> {
    for character in value.chars() {
        if matches!(
            character,
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '<' | '>' | '|'
        ) {
            output.write_all(b"\\")?;
        }
        write!(output, "{character}")?;
    }
    Ok(())
}
