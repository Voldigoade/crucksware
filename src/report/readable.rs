use std::io::{self, Write};

use crate::readable::{
    EvidenceError, EvidenceFact, EvidencePacket, EvidenceRecord, EvidenceTotals, Language,
    MAX_SUMMARY_RECORDS,
};

mod language;

#[cfg(test)]
mod tests;

pub(super) fn selection_error(error: EvidenceError) -> io::Error {
    io::Error::other(error)
}

pub(super) fn write_text(packet: &EvidencePacket, output: &mut impl Write) -> io::Result<()> {
    write_text_in_language(packet, Language::English, output)
}

pub(super) fn write_text_in_language(
    packet: &EvidencePacket,
    language: Language,
    output: &mut impl Write,
) -> io::Result<()> {
    writeln!(output, "{}", language::heading(language))?;
    if is_empty(&packet.totals) {
        writeln!(output, "{}", language::empty_message(language))?;
        return Ok(());
    }
    for line in language::overview_lines(&packet.totals, language) {
        writeln!(output, "{line}")?;
    }
    write_text_highlights(packet, language, output)?;
    write_omission_note(packet, language, output, "text")
}

pub(super) fn write_markdown_in_language(
    packet: &EvidencePacket,
    language: Language,
    output: &mut impl Write,
) -> io::Result<()> {
    output.write_all(b"## ")?;
    write_markdown_text(output, language::heading(language))?;
    output.write_all(b"\n\n")?;
    if is_empty(&packet.totals) {
        write_markdown_text(output, language::empty_message(language))?;
        return output.write_all(b"\n");
    }
    for line in language::overview_lines(&packet.totals, language) {
        write_markdown_text(output, &line)?;
        output.write_all(b"\n\n")?;
    }
    write_markdown_highlights(packet, language, output)?;
    write_omission_note(packet, language, output, "markdown")
}

pub(super) fn write_html_languages(
    packet: &EvidencePacket,
    languages: &[Language],
    output: &mut impl Write,
) -> io::Result<()> {
    validate_languages(languages)?;
    if languages.len() > 1 {
        write_html_language_selector(languages, output)?;
    }
    for (index, &language) in languages.iter().enumerate() {
        write_html_language(packet, language, index, languages.len(), output)?;
    }
    if languages.len() > 1 {
        output.write_all(b"<script>")?;
        output.write_all(SUMMARY_LANGUAGE_SCRIPT.as_bytes())?;
        output.write_all(b"</script>\n")?;
    }
    Ok(())
}

const SUMMARY_LANGUAGE_SCRIPT: &str = r#"
const summaryLanguage = document.getElementById("summary-language");
const readableSummaries = Array.from(document.querySelectorAll(".readable-summary[data-readable-summary-language]"));
summaryLanguage.addEventListener("change", () => {
  for (const summary of readableSummaries) {
    summary.hidden = summary.dataset.readableSummaryLanguage !== summaryLanguage.value;
  }
});
"#;

pub(super) fn validate_languages(languages: &[Language]) -> io::Result<()> {
    if languages.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one readable-summary language is required",
        ));
    }
    for (index, language) in languages.iter().enumerate() {
        if languages[..index].contains(language) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "readable-summary languages must be unique",
            ));
        }
    }
    Ok(())
}

fn write_html_language_selector(languages: &[Language], output: &mut impl Write) -> io::Result<()> {
    let label = match languages[0] {
        Language::English => "Summary language",
        Language::French => "Langue du résumé",
        Language::Spanish => "Idioma del resumen",
        Language::SimplifiedChinese => "摘要语言",
    };
    writeln!(
        output,
        "<div class=\"summary-language-picker\"><label for=\"summary-language\">{label}</label><select id=\"summary-language\">"
    )?;
    for (index, language) in languages.iter().enumerate() {
        writeln!(
            output,
            "<option value=\"{}\"{}>{}</option>",
            language.code(),
            if index == 0 { " selected" } else { "" },
            language.display_name()
        )?;
    }
    output.write_all(b"</select></div>\n")
}

fn write_html_language(
    packet: &EvidencePacket,
    language: Language,
    index: usize,
    total: usize,
    output: &mut impl Write,
) -> io::Result<()> {
    let heading_id = if total == 1 {
        "readable-summary-heading".to_owned()
    } else {
        format!("readable-summary-heading-{}", language.code())
    };
    write!(
        output,
        "<section class=\"readable-summary\" lang=\"{}\" data-readable-summary-language=\"{}\" aria-labelledby=\"{}\"{}>\n<h2 id=\"{}\">",
        language.code(),
        language.code(),
        heading_id,
        if index == 0 { "" } else { " hidden" },
        heading_id
    )?;
    super::html::write_escaped(output, language::heading(language))?;
    output.write_all(b"</h2>\n")?;
    if is_empty(&packet.totals) {
        output.write_all(b"<p>")?;
        super::html::write_escaped(output, language::empty_message(language))?;
        output.write_all(b"</p>\n</section>\n")?;
        return Ok(());
    }
    for line in language::overview_lines(&packet.totals, language) {
        output.write_all(b"<p>")?;
        super::html::write_escaped(output, &line)?;
        output.write_all(b"</p>\n")?;
    }
    write_html_highlights(packet, language, output)?;
    write_omission_note(packet, language, output, "html")?;
    output.write_all(b"</section>\n")
}

pub(super) fn write_explanation_in_language(
    record: &EvidenceRecord,
    language: Language,
    output: &mut impl Write,
) -> io::Result<()> {
    let (evidence_label, path_label, fact_label) = language::explanation_labels(language);
    writeln!(output, "{evidence_label} {}", record.id)?;
    if let Some(path) = &record.path {
        writeln!(output, "{path_label}: `{path}`")?;
    } else {
        writeln!(
            output,
            "{path_label}: {}",
            language::file_comparison_path(language)
        )?;
    }
    writeln!(
        output,
        "{fact_label}: {}",
        language::describe(&record.fact, language)
    )
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

fn write_text_highlights(
    packet: &EvidencePacket,
    language: Language,
    output: &mut impl Write,
) -> io::Result<()> {
    let shown = packet.records.len().min(MAX_SUMMARY_RECORDS);
    if shown == 0 {
        return Ok(());
    }
    writeln!(output, "{}:", language::notable_changes(language))?;
    let mut index = 0;
    while index < shown {
        let path = packet.records[index].path.as_deref();
        writeln!(output, "- {}", path_label(path, language))?;
        while index < shown && packet.records[index].path.as_deref() == path {
            let record = &packet.records[index];
            writeln!(
                output,
                "  - {}: {}.",
                record.id,
                language::describe(&record.fact, language)
            )?;
            index += 1;
        }
    }
    Ok(())
}

fn write_markdown_highlights(
    packet: &EvidencePacket,
    language: Language,
    output: &mut impl Write,
) -> io::Result<()> {
    let shown = packet.records.len().min(MAX_SUMMARY_RECORDS);
    if shown == 0 {
        return Ok(());
    }
    output.write_all(b"### ")?;
    write_markdown_text(output, language::notable_changes(language))?;
    output.write_all(b"\n\n")?;
    let mut index = 0;
    while index < shown {
        let path = packet.records[index].path.as_deref();
        output.write_all(b"- ")?;
        if let Some(path) = path {
            writeln!(output, "`{path}`")?;
        } else {
            write_markdown_text(output, &path_label(path, language))?;
            output.write_all(b"\n")?;
        }
        while index < shown && packet.records[index].path.as_deref() == path {
            let record = &packet.records[index];
            output.write_all(b"  - **")?;
            write!(output, "{}**: ", record.id)?;
            write_markdown_text(output, &language::describe(&record.fact, language))?;
            output.write_all(b".\n")?;
            index += 1;
        }
    }
    Ok(())
}

fn write_html_highlights(
    packet: &EvidencePacket,
    language: Language,
    output: &mut impl Write,
) -> io::Result<()> {
    let shown = packet.records.len().min(MAX_SUMMARY_RECORDS);
    if shown == 0 {
        return Ok(());
    }
    output.write_all(b"<h3>")?;
    super::html::write_escaped(output, language::notable_changes(language))?;
    output.write_all(b"</h3>\n<ul>\n")?;
    let mut index = 0;
    while index < shown {
        let path = packet.records[index].path.as_deref();
        output.write_all(b"<li>")?;
        if let Some(path) = path {
            output.write_all(b" <code>")?;
            super::html::write_escaped(output, path)?;
            output.write_all(b"</code>\n")?;
        } else {
            super::html::write_escaped(output, &path_label(path, language))?;
            output.write_all(b"\n")?;
        }
        output.write_all(b"<ul>\n")?;
        while index < shown && packet.records[index].path.as_deref() == path {
            write_html_record(&packet.records[index], language, output)?;
            index += 1;
        }
        output.write_all(b"</ul>\n</li>\n")?;
    }
    output.write_all(b"</ul>\n")
}

fn write_html_record(
    record: &EvidenceRecord,
    language: Language,
    output: &mut impl Write,
) -> io::Result<()> {
    write!(output, "<li><strong>{}</strong>: ", record.id)?;
    super::html::write_escaped(output, &language::describe(&record.fact, language))?;
    output.write_all(b".</li>\n")
}

fn path_label(path: Option<&str>, language: Language) -> String {
    path.map_or_else(
        || {
            if language == Language::English {
                "File comparison".to_owned()
            } else {
                language::file_comparison_path(language).to_owned()
            }
        },
        |path| format!("`{path}`"),
    )
}

fn write_omission_note(
    packet: &EvidencePacket,
    language: Language,
    output: &mut impl Write,
    format: &str,
) -> io::Result<()> {
    let shown = packet.records.len().min(MAX_SUMMARY_RECORDS);
    let omitted = packet.totals.eligible_records.saturating_sub(shown as u64);
    if omitted == 0 {
        return Ok(());
    }
    let note = language::omission_note(language, omitted);
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
        if character.is_control() || is_bidi_formatting(character) {
            output.push_str(&format!("\\u{{{:X}}}", character as u32));
        } else {
            output.push(character);
        }
    }
    output
}

fn is_bidi_formatting(character: char) -> bool {
    matches!(
        character,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{206F}'
    )
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
