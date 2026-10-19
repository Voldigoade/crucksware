use std::{
    cmp::Ordering,
    io::{self, Write},
};

use serde::Serialize;
use serde_json::Value;

use crate::{
    binary_compare::{FileComparison, SemanticChange, SemanticComparisonStatus},
    input::InputKind,
    model::{Category, Change, ChangedField, Entry, Summary},
    path::{RelPath, encode_bytes},
    readable::{
        ChangeCounts, EntryEvidence, EvidenceError, EvidenceFact, EvidenceId, EvidencePacket,
        EvidenceRecord, EvidenceTotals, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_PATHS,
        MAX_EVIDENCE_PER_PATH, MAX_EVIDENCE_RECORDS,
    },
    semantic_tree::{BinaryAnalysisStatus, BinaryFileChange},
    source::{SourceAnalysisStatus, SourceFileChange, StructuralChange},
};

const RECORD_OVERHEAD_BOUND: usize = 256;
const PACKET_ENVELOPE_RESERVE: usize = super::PACKET_ENVELOPE_RESERVE;

#[derive(Clone, Copy)]
enum EvidenceCandidate<'a> {
    Filesystem(&'a Change),
    SourceStructural(&'a StructuralChange),
    SourceText(&'a SourceFileChange),
    SourceContentKindChanged,
    BinarySemantic(&'a SemanticChange),
    BinaryBytes(&'a BinaryFileChange),
    FileComparisonSemantic(&'a SemanticChange),
    FileComparisonBytes(&'a FileComparison),
}

impl EvidenceCandidate<'_> {
    fn priority(self) -> u8 {
        match self {
            Self::BinarySemantic(_) | Self::FileComparisonSemantic(_) => 0,
            Self::SourceStructural(_) => 1,
            Self::BinaryBytes(_) | Self::FileComparisonBytes(_) => 2,
            Self::Filesystem(change) if executable_added_or_removed(change) => 2,
            Self::Filesystem(change) if filesystem_metadata_change(change) => 3,
            Self::SourceContentKindChanged => 4,
            Self::SourceText(_) => 5,
            Self::Filesystem(_) => 6,
        }
    }
}

#[derive(Clone, Copy)]
struct PathCandidate<'a> {
    path: &'a RelPath,
    facts: [Option<EvidenceCandidate<'a>>; MAX_EVIDENCE_PER_PATH],
    fact_count: usize,
}

impl<'a> PathCandidate<'a> {
    fn new(path: &'a RelPath) -> Self {
        Self {
            path,
            facts: [None; MAX_EVIDENCE_PER_PATH],
            fact_count: 0,
        }
    }

    fn add(&mut self, fact: EvidenceCandidate<'a>) {
        let position = self.facts[..self.fact_count]
            .iter()
            .position(|existing| existing.is_some_and(|old| candidate_precedes(fact, old)))
            .unwrap_or(self.fact_count);
        if self.fact_count < MAX_EVIDENCE_PER_PATH {
            for index in (position..self.fact_count).rev() {
                self.facts[index + 1] = self.facts[index];
            }
            self.facts[position] = Some(fact);
            self.fact_count += 1;
        } else if position < MAX_EVIDENCE_PER_PATH {
            for index in (position..MAX_EVIDENCE_PER_PATH - 1).rev() {
                self.facts[index + 1] = self.facts[index];
            }
            self.facts[position] = Some(fact);
        }
    }

    fn priority(self) -> u8 {
        self.facts[0].map_or(u8::MAX, EvidenceCandidate::priority)
    }
}

pub(super) fn select(
    filesystem_changes: &[Change],
    source_changes: &[SourceFileChange],
    binary_changes: &[BinaryFileChange],
    summary: &Summary,
) -> Result<EvidencePacket, EvidenceError> {
    let mut filesystem_changes: Vec<_> = filesystem_changes.iter().collect();
    let mut source_changes: Vec<_> = source_changes.iter().collect();
    let mut binary_changes: Vec<_> = binary_changes.iter().collect();
    filesystem_changes.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    source_changes.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    binary_changes.sort_unstable_by(|left, right| left.path.cmp(&right.path));

    let mut totals = EvidenceTotals {
        filesystem: summary.into(),
        filesystem_entries: checked_sum(&[
            summary.added,
            summary.removed,
            summary.modified,
            summary.type_changed,
            summary.metadata_changed,
            summary.unchanged,
        ])?,
        filesystem_changes: checked_sum(&[
            summary.added,
            summary.removed,
            summary.modified,
            summary.type_changed,
            summary.metadata_changed,
        ])?,
        source_files: checked_count(source_changes.len())?,
        binary_files: checked_count(binary_changes.len())?,
        ..EvidenceTotals::default()
    };
    let mut candidates = Vec::with_capacity(MAX_EVIDENCE_PATHS);
    let mut filesystem_index = 0;
    let mut source_index = 0;
    let mut binary_index = 0;

    while filesystem_index < filesystem_changes.len()
        || source_index < source_changes.len()
        || binary_index < binary_changes.len()
    {
        let Some(path) = next_path(
            filesystem_changes
                .get(filesystem_index)
                .map(|change| &change.path),
            source_changes.get(source_index).map(|change| &change.path),
            binary_changes.get(binary_index).map(|change| &change.path),
        ) else {
            break;
        };
        let mut candidate = PathCandidate::new(path);

        while filesystem_changes
            .get(filesystem_index)
            .is_some_and(|change| change.path == *path)
        {
            let change = filesystem_changes[filesystem_index];
            checked_increment(&mut totals.eligible_records)?;
            candidate.add(EvidenceCandidate::Filesystem(change));
            filesystem_index += 1;
        }

        while source_changes
            .get(source_index)
            .is_some_and(|change| change.path == *path)
        {
            let change = source_changes[source_index];
            totals.structural_changes = totals
                .structural_changes
                .checked_add(checked_count(change.structural_changes.len())?)
                .ok_or(EvidenceError::CountOverflow)?;
            for structural in &change.structural_changes {
                checked_increment(&mut totals.eligible_records)?;
                candidate.add(EvidenceCandidate::SourceStructural(structural));
            }
            if change.analysis_status == SourceAnalysisStatus::ContentKindChanged {
                checked_increment(&mut totals.eligible_records)?;
                candidate.add(EvidenceCandidate::SourceContentKindChanged);
            } else if has_line_changes(change) {
                checked_increment(&mut totals.eligible_records)?;
                candidate.add(EvidenceCandidate::SourceText(change));
            }
            source_index += 1;
        }

        while binary_changes
            .get(binary_index)
            .is_some_and(|change| change.path == *path)
        {
            let change = binary_changes[binary_index];
            totals.binary_semantic_changes = totals
                .binary_semantic_changes
                .checked_add(checked_count(change.semantic_changes.len())?)
                .ok_or(EvidenceError::CountOverflow)?;
            for semantic in &change.semantic_changes {
                checked_increment(&mut totals.eligible_records)?;
                candidate.add(EvidenceCandidate::BinarySemantic(semantic));
            }
            if change.byte_level_changed == Some(true) {
                checked_increment(&mut totals.eligible_records)?;
                candidate.add(EvidenceCandidate::BinaryBytes(change));
            }
            binary_index += 1;
        }

        if candidate.fact_count > 0 {
            insert_path_candidate(&mut candidates, candidate);
        }
    }

    let mut packet = EvidencePacket {
        totals,
        records: Vec::with_capacity(MAX_EVIDENCE_RECORDS),
    };
    let mut encoded_record_bytes = 0_usize;
    for candidate in candidates {
        let path = encode_bytes(candidate.path.as_bytes());
        for fact in candidate.facts[..candidate.fact_count]
            .iter()
            .flatten()
            .copied()
        {
            if packet.records.len() >= MAX_EVIDENCE_RECORDS {
                break;
            }
            let id = EvidenceId(checked_count(packet.records.len())? + 1);
            let id_text = id.to_string();
            let remaining = record_budget().saturating_sub(encoded_record_bytes);
            if estimated_size(fact, &id_text, &path, remaining).is_none() {
                continue;
            }
            let record = make_record(fact, id, Some(path.clone()));
            let Some(size) = serialized_size(&record, remaining) else {
                continue;
            };
            encoded_record_bytes = encoded_record_bytes
                .checked_add(size)
                .and_then(|bytes| bytes.checked_add(usize::from(!packet.records.is_empty())))
                .ok_or(EvidenceError::CountOverflow)?;
            packet.records.push(record);
        }
    }
    packet.totals.omitted_records = packet
        .totals
        .eligible_records
        .checked_sub(checked_count(packet.records.len())?)
        .ok_or(EvidenceError::CountOverflow)?;
    Ok(packet)
}

pub(super) fn select_file_comparison(
    comparison: &FileComparison,
) -> Result<EvidencePacket, EvidenceError> {
    let has_bytes_record = comparison.bytes_changed
        || comparison.semantic_status != SemanticComparisonStatus::Compared
        || !comparison.semantic_changes.is_empty();
    let bytes_record_count = usize::from(has_bytes_record);
    let eligible_records = comparison
        .semantic_changes
        .len()
        .checked_add(bytes_record_count)
        .ok_or(EvidenceError::CountOverflow)?;

    let mut packet = EvidencePacket {
        totals: EvidenceTotals {
            file_comparison_inputs: 2,
            binary_semantic_changes: checked_count(comparison.semantic_changes.len())?,
            eligible_records: checked_count(eligible_records)?,
            ..EvidenceTotals::default()
        },
        records: Vec::with_capacity(eligible_records.min(MAX_EVIDENCE_RECORDS)),
    };
    let mut encoded_record_bytes = 0_usize;
    let mut semantic_changes: Vec<_> = comparison.semantic_changes.iter().collect();
    semantic_changes.sort_unstable_by(|left, right| {
        left.field
            .cmp(&right.field)
            .then_with(|| compare_json_values(&left.before, &right.before))
            .then_with(|| compare_json_values(&left.after, &right.after))
    });
    for candidate in semantic_changes
        .into_iter()
        .map(EvidenceCandidate::FileComparisonSemantic)
        .chain(has_bytes_record.then_some(EvidenceCandidate::FileComparisonBytes(comparison)))
    {
        if packet.records.len() >= MAX_EVIDENCE_RECORDS {
            continue;
        }
        let id = EvidenceId(checked_count(packet.records.len())? + 1);
        let id_text = id.to_string();
        let remaining = record_budget().saturating_sub(encoded_record_bytes);
        if estimated_size(candidate, &id_text, "", remaining).is_none() {
            continue;
        }
        let record = make_record(candidate, id, None);
        let Some(size) = serialized_size(&record, remaining) else {
            continue;
        };
        encoded_record_bytes = encoded_record_bytes
            .checked_add(size)
            .and_then(|bytes| bytes.checked_add(usize::from(!packet.records.is_empty())))
            .ok_or(EvidenceError::CountOverflow)?;
        packet.records.push(record);
    }
    packet.totals.omitted_records = packet
        .totals
        .eligible_records
        .checked_sub(checked_count(packet.records.len())?)
        .ok_or(EvidenceError::CountOverflow)?;
    Ok(packet)
}

fn next_path<'a>(
    filesystem: Option<&'a RelPath>,
    source: Option<&'a RelPath>,
    binary: Option<&'a RelPath>,
) -> Option<&'a RelPath> {
    [filesystem, source, binary].into_iter().flatten().min()
}

fn insert_path_candidate<'a>(selected: &mut Vec<PathCandidate<'a>>, candidate: PathCandidate<'a>) {
    let position = selected
        .iter()
        .position(|old| path_candidate_precedes(candidate, *old))
        .unwrap_or(selected.len());
    if selected.len() < MAX_EVIDENCE_PATHS {
        selected.insert(position, candidate);
    } else if position < MAX_EVIDENCE_PATHS {
        selected.insert(position, candidate);
        selected.pop();
    }
}

fn path_candidate_precedes(left: PathCandidate<'_>, right: PathCandidate<'_>) -> bool {
    (left.priority(), left.path.as_bytes()) < (right.priority(), right.path.as_bytes())
}

fn candidate_precedes(left: EvidenceCandidate<'_>, right: EvidenceCandidate<'_>) -> bool {
    left.priority()
        .cmp(&right.priority())
        .then_with(|| candidate_kind(left).cmp(&candidate_kind(right)))
        .then_with(|| compare_candidate_values(left, right))
        == Ordering::Less
}

fn candidate_kind(candidate: EvidenceCandidate<'_>) -> u8 {
    match candidate {
        EvidenceCandidate::BinarySemantic(_) | EvidenceCandidate::FileComparisonSemantic(_) => 0,
        EvidenceCandidate::SourceStructural(_) => 1,
        EvidenceCandidate::BinaryBytes(_) | EvidenceCandidate::FileComparisonBytes(_) => 2,
        EvidenceCandidate::Filesystem(_) => 3,
        EvidenceCandidate::SourceContentKindChanged => 4,
        EvidenceCandidate::SourceText(_) => 5,
    }
}

fn compare_candidate_values(left: EvidenceCandidate<'_>, right: EvidenceCandidate<'_>) -> Ordering {
    match (left, right) {
        (EvidenceCandidate::SourceStructural(left), EvidenceCandidate::SourceStructural(right)) => {
            (
                left.action.as_str(),
                left.kind.as_str(),
                left.name.as_str(),
                left.before_signature.as_deref(),
                left.after_signature.as_deref(),
            )
                .cmp(&(
                    right.action.as_str(),
                    right.kind.as_str(),
                    right.name.as_str(),
                    right.before_signature.as_deref(),
                    right.after_signature.as_deref(),
                ))
        }
        (
            EvidenceCandidate::BinarySemantic(left)
            | EvidenceCandidate::FileComparisonSemantic(left),
            EvidenceCandidate::BinarySemantic(right)
            | EvidenceCandidate::FileComparisonSemantic(right),
        ) => left
            .field
            .cmp(&right.field)
            .then_with(|| compare_json_values(&left.before, &right.before))
            .then_with(|| compare_json_values(&left.after, &right.after)),
        (EvidenceCandidate::Filesystem(left), EvidenceCandidate::Filesystem(right)) => {
            category_name(left.category)
                .cmp(category_name(right.category))
                .then_with(|| {
                    left.changed_fields
                        .iter()
                        .map(|field| changed_field_name(*field))
                        .cmp(
                            right
                                .changed_fields
                                .iter()
                                .map(|field| changed_field_name(*field)),
                        )
                })
                .then_with(|| compare_optional_entries(left.before.as_ref(), right.before.as_ref()))
                .then_with(|| compare_optional_entries(left.after.as_ref(), right.after.as_ref()))
        }
        (EvidenceCandidate::SourceText(left), EvidenceCandidate::SourceText(right)) => (
            left.lines_added,
            left.lines_removed,
            left.hunk_count,
        )
            .cmp(&(right.lines_added, right.lines_removed, right.hunk_count)),
        (EvidenceCandidate::BinaryBytes(left), EvidenceCandidate::BinaryBytes(right)) => (
            left.old_kind.map(InputKind::as_str),
            left.new_kind.map(InputKind::as_str),
            left.old_size_bytes,
            left.new_size_bytes,
            left.semantic_status.as_str(),
        )
            .cmp(&(
                right.old_kind.map(InputKind::as_str),
                right.new_kind.map(InputKind::as_str),
                right.old_size_bytes,
                right.new_size_bytes,
                right.semantic_status.as_str(),
            )),
        (
            EvidenceCandidate::FileComparisonBytes(left),
            EvidenceCandidate::FileComparisonBytes(right),
        ) => (
            left.old_kind.as_str(),
            left.new_kind.as_str(),
            left.old_size_bytes,
            left.new_size_bytes,
            file_status_name(left.semantic_status),
        )
            .cmp(&(
                right.old_kind.as_str(),
                right.new_kind.as_str(),
                right.old_size_bytes,
                right.new_size_bytes,
                file_status_name(right.semantic_status),
            )),
        _ => Ordering::Equal,
    }
}

fn compare_optional_entries(left: Option<&Entry>, right: Option<&Entry>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_entries(left, right),
    }
}

fn compare_json_values(left: &Value, right: &Value) -> Ordering {
    left.to_string().cmp(&right.to_string())
}

fn compare_entries(left: &Entry, right: &Entry) -> Ordering {
    match (left, right) {
        (
            Entry::File {
                size: left_size,
                mode: left_mode,
            },
            Entry::File {
                size: right_size,
                mode: right_mode,
            },
        ) => (left_size, left_mode).cmp(&(right_size, right_mode)),
        (Entry::Directory { mode: left }, Entry::Directory { mode: right })
        | (Entry::Fifo { mode: left }, Entry::Fifo { mode: right })
        | (Entry::Socket { mode: left }, Entry::Socket { mode: right }) => left.cmp(right),
        (Entry::Symlink { target: left }, Entry::Symlink { target: right }) => left.cmp(right),
        (
            Entry::CharDevice {
                mode: left_mode,
                device_id: left_id,
            },
            Entry::CharDevice {
                mode: right_mode,
                device_id: right_id,
            },
        )
        | (
            Entry::BlockDevice {
                mode: left_mode,
                device_id: left_id,
            },
            Entry::BlockDevice {
                mode: right_mode,
                device_id: right_id,
            },
        ) => (left_mode, left_id).cmp(&(right_mode, right_id)),
        _ => entry_kind_name(left.kind()).cmp(entry_kind_name(right.kind())),
    }
}

fn filesystem_metadata_change(change: &Change) -> bool {
    matches!(
        change.category,
        Category::TypeChanged | Category::MetadataChanged
    ) || change.changed_fields.contains(&ChangedField::Mode)
        || change.changed_fields.contains(&ChangedField::DeviceId)
        || change.changed_fields.contains(&ChangedField::SymlinkTarget)
}

fn executable_added_or_removed(change: &Change) -> bool {
    let entry = match change.category {
        Category::Added => change.after.as_ref(),
        Category::Removed => change.before.as_ref(),
        Category::Modified | Category::TypeChanged | Category::MetadataChanged => None,
    };
    entry.is_some_and(|entry| match entry {
        Entry::File { mode, .. } => mode & 0o111 != 0,
        _ => false,
    })
}

fn has_line_changes(change: &SourceFileChange) -> bool {
    change.lines_added.is_some_and(|lines| lines != 0)
        || change.lines_removed.is_some_and(|lines| lines != 0)
}

fn record_budget() -> usize {
    MAX_EVIDENCE_BYTES - PACKET_ENVELOPE_RESERVE
}

fn estimated_size(
    candidate: EvidenceCandidate<'_>,
    id: &str,
    path: &str,
    limit: usize,
) -> Option<usize> {
    let mut size = RECORD_OVERHEAD_BOUND;
    size = add_size(size, json_string_size(id, limit)?, limit)?;
    size = add_size(size, json_string_size(path, limit)?, limit)?;
    match candidate {
        EvidenceCandidate::Filesystem(change) => {
            size = add_size(size, 64, limit)?;
            for field in &change.changed_fields {
                size = add_size(
                    size,
                    json_string_size(changed_field_name(*field), limit)?,
                    limit,
                )?;
            }
            for entry in [change.before.as_ref(), change.after.as_ref()]
                .into_iter()
                .flatten()
            {
                size = add_size(size, entry_evidence_size(entry, limit)?, limit)?;
            }
        }
        EvidenceCandidate::SourceStructural(change) => {
            for value in [
                change.action.as_str(),
                change.kind.as_str(),
                change.name.as_str(),
            ] {
                size = add_size(size, json_string_size(value, limit)?, limit)?;
            }
            for value in [
                change.before_signature.as_deref(),
                change.after_signature.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                size = add_size(size, json_string_size(value, limit)?, limit)?;
            }
        }
        EvidenceCandidate::SourceText(_) | EvidenceCandidate::SourceContentKindChanged => {
            size = add_size(size, 64, limit)?;
        }
        EvidenceCandidate::BinarySemantic(change)
        | EvidenceCandidate::FileComparisonSemantic(change) => {
            size = add_size(size, json_string_size(&change.field, limit)?, limit)?;
            size = add_size(size, json_value_size(&change.before, limit)?, limit)?;
            size = add_size(size, json_value_size(&change.after, limit)?, limit)?;
        }
        EvidenceCandidate::BinaryBytes(change) => {
            size = add_size(size, 128, limit)?;
            for value in [change.old_kind, change.new_kind].into_iter().flatten() {
                size = add_size(size, json_string_size(value.as_str(), limit)?, limit)?;
            }
        }
        EvidenceCandidate::FileComparisonBytes(comparison) => {
            size = add_size(size, 128, limit)?;
            size = add_size(
                size,
                json_string_size(&comparison.old_kind.to_string(), limit)?,
                limit,
            )?;
            size = add_size(
                size,
                json_string_size(&comparison.new_kind.to_string(), limit)?,
                limit,
            )?;
        }
    }
    (size <= limit).then_some(size)
}

fn make_record(
    candidate: EvidenceCandidate<'_>,
    id: EvidenceId,
    path: Option<String>,
) -> EvidenceRecord {
    EvidenceRecord {
        id,
        path,
        fact: match candidate {
            EvidenceCandidate::Filesystem(change) => EvidenceFact::FilesystemChange {
                category: category_name(change.category).to_owned(),
                changed_fields: change
                    .changed_fields
                    .iter()
                    .map(|field| changed_field_name(*field).to_owned())
                    .collect(),
                before: change.before.as_ref().map(entry_evidence),
                after: change.after.as_ref().map(entry_evidence),
            },
            EvidenceCandidate::SourceStructural(change) => EvidenceFact::SourceStructuralChange {
                action: change.action.as_str().to_owned(),
                symbol_kind: change.kind.as_str().to_owned(),
                name: change.name.clone(),
                before_signature: change.before_signature.clone(),
                after_signature: change.after_signature.clone(),
            },
            EvidenceCandidate::SourceText(change) => EvidenceFact::SourceTextChange {
                lines_added: change.lines_added,
                lines_removed: change.lines_removed,
                hunk_count: change.hunk_count,
            },
            EvidenceCandidate::SourceContentKindChanged => EvidenceFact::SourceContentKindChanged,
            EvidenceCandidate::BinarySemantic(change)
            | EvidenceCandidate::FileComparisonSemantic(change) => {
                EvidenceFact::BinarySemanticChange {
                    field: change.field.clone(),
                    before: change.before.clone(),
                    after: change.after.clone(),
                }
            }
            EvidenceCandidate::BinaryBytes(change) => EvidenceFact::BinaryBytesChanged {
                old_kind: change.old_kind.map(|kind| kind.as_str().to_owned()),
                new_kind: change.new_kind.map(|kind| kind.as_str().to_owned()),
                old_size_bytes: change.old_size_bytes,
                new_size_bytes: change.new_size_bytes,
                byte_level_changed: change.byte_level_changed,
                semantic_status: binary_status_name(change.semantic_status).to_owned(),
            },
            EvidenceCandidate::FileComparisonBytes(comparison) => {
                EvidenceFact::BinaryBytesChanged {
                    old_kind: Some(comparison.old_kind.as_str().to_owned()),
                    new_kind: Some(comparison.new_kind.as_str().to_owned()),
                    old_size_bytes: Some(comparison.old_size_bytes),
                    new_size_bytes: Some(comparison.new_size_bytes),
                    byte_level_changed: Some(comparison.bytes_changed),
                    semantic_status: file_status_name(comparison.semantic_status).to_owned(),
                }
            }
        },
    }
}

fn entry_evidence(entry: &Entry) -> EntryEvidence {
    let (size_bytes, mode, device_id, symlink_target) = match entry {
        Entry::File { size, mode } => (Some(*size), Some(*mode & 0o7777), None, None),
        Entry::Directory { mode } | Entry::Fifo { mode } | Entry::Socket { mode } => {
            (None, Some(*mode & 0o7777), None, None)
        }
        Entry::Symlink { target } => (None, None, None, Some(encode_bytes(target))),
        Entry::CharDevice { mode, device_id } | Entry::BlockDevice { mode, device_id } => {
            (None, Some(*mode & 0o7777), Some(*device_id), None)
        }
    };
    EntryEvidence {
        kind: entry_kind_name(entry.kind()).to_owned(),
        size_bytes,
        mode,
        device_id,
        symlink_target,
    }
}

fn entry_kind_name(kind: crate::model::EntryKind) -> &'static str {
    match kind {
        crate::model::EntryKind::File => "file",
        crate::model::EntryKind::Directory => "directory",
        crate::model::EntryKind::Symlink => "symlink",
        crate::model::EntryKind::Fifo => "fifo",
        crate::model::EntryKind::Socket => "socket",
        crate::model::EntryKind::CharDevice => "char_device",
        crate::model::EntryKind::BlockDevice => "block_device",
    }
}

fn serialized_size<T: Serialize + ?Sized>(value: &T, limit: usize) -> Option<usize> {
    let mut writer = LimitedCounter::new(limit);
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(writer.count)
}

fn json_string_size(value: &str, limit: usize) -> Option<usize> {
    serialized_size(value, limit)
}

fn json_value_size(value: &Value, limit: usize) -> Option<usize> {
    serialized_size(value, limit)
}

fn add_size(current: usize, amount: usize, limit: usize) -> Option<usize> {
    current.checked_add(amount).filter(|size| *size <= limit)
}

fn entry_evidence_size(entry: &Entry, limit: usize) -> Option<usize> {
    let mut size = add_size(
        128,
        json_string_size(entry_kind_name(entry.kind()), limit)?,
        limit,
    )?;
    if let Entry::Symlink { target } = entry {
        let encoded_len = target.iter().try_fold(0_usize, |length, byte| {
            length.checked_add(
                if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
                    1
                } else {
                    3
                },
            )
        })?;
        size = add_size(size, encoded_len.checked_add(2)?, limit)?;
    }
    Some(size)
}

fn checked_increment(value: &mut u64) -> Result<(), EvidenceError> {
    *value = value.checked_add(1).ok_or(EvidenceError::CountOverflow)?;
    Ok(())
}

fn checked_count(value: usize) -> Result<u64, EvidenceError> {
    u64::try_from(value).map_err(|_| EvidenceError::CountOverflow)
}

fn checked_sum(values: &[u64]) -> Result<u64, EvidenceError> {
    values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(*value).ok_or(EvidenceError::CountOverflow)
    })
}

struct LimitedCounter {
    count: usize,
    limit: usize,
}

impl LimitedCounter {
    fn new(limit: usize) -> Self {
        Self { count: 0, limit }
    }
}

impl Write for LimitedCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .filter(|count| *count <= self.limit)
            .ok_or_else(|| io::Error::other("evidence record exceeds the packet budget"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn category_name(category: Category) -> &'static str {
    match category {
        Category::Added => "added",
        Category::Removed => "removed",
        Category::Modified => "modified",
        Category::TypeChanged => "type_changed",
        Category::MetadataChanged => "metadata_changed",
    }
}

fn changed_field_name(field: ChangedField) -> &'static str {
    match field {
        ChangedField::Type => "type",
        ChangedField::Content => "content",
        ChangedField::SymlinkTarget => "symlink_target",
        ChangedField::Mode => "mode",
        ChangedField::DeviceId => "device_id",
    }
}

fn binary_status_name(status: BinaryAnalysisStatus) -> &'static str {
    match status {
        BinaryAnalysisStatus::SingleInput => "single_input",
        BinaryAnalysisStatus::Compared => "compared",
        BinaryAnalysisStatus::FormatMismatch => "format_mismatch",
        BinaryAnalysisStatus::Unsupported => "unsupported",
    }
}

fn file_status_name(status: SemanticComparisonStatus) -> &'static str {
    match status {
        SemanticComparisonStatus::Compared => "compared",
        SemanticComparisonStatus::FormatMismatch => "format_mismatch",
        SemanticComparisonStatus::Unsupported => "unsupported",
    }
}

impl From<&Summary> for ChangeCounts {
    fn from(summary: &Summary) -> Self {
        Self {
            added: summary.added,
            removed: summary.removed,
            modified: summary.modified,
            type_changed: summary.type_changed,
            metadata_changed: summary.metadata_changed,
            unchanged: summary.unchanged,
        }
    }
}
