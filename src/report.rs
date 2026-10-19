pub mod binary;
pub mod html;
pub mod inspection;
pub mod json;
pub mod markdown;
mod readable;
pub mod semantic_tree;
mod shared;
pub mod text;

pub fn write_readable_summary_text(
    packet: &crate::readable::EvidencePacket,
    output: &mut impl std::io::Write,
) -> std::io::Result<()> {
    readable::write_text(packet, output)
}

pub fn write_evidence_explanation(
    packet: &crate::readable::EvidencePacket,
    selector: &str,
    output: &mut impl std::io::Write,
) -> std::io::Result<usize> {
    let mut written = 0;
    let explicit_path = selector.strip_prefix("path:");
    let id_selector = explicit_path.is_none() && is_evidence_id(selector);
    for record in &packet.records {
        let matches = selector == "--all"
            || explicit_path.is_some_and(|path| record.path.as_deref() == Some(path))
            || (id_selector && record.id.to_string() == selector)
            || (!id_selector
                && explicit_path.is_none()
                && record.path.as_deref() == Some(selector));
        if matches {
            readable::write_explanation(record, output)?;
            written += 1;
        }
    }
    Ok(written)
}

fn is_evidence_id(selector: &str) -> bool {
    selector.len() == 5
        && selector.starts_with('E')
        && selector.as_bytes()[1..].iter().all(u8::is_ascii_digit)
}
