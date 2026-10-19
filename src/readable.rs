use std::fmt;

use serde::Serialize;
use serde_json::Value;

use crate::{binary_compare::FileComparison, model::Diff, semantic_tree::SemanticTreeDiff};

mod select;

#[cfg(test)]
mod tests;

pub(crate) const MAX_EVIDENCE_RECORDS: usize = 64;
pub(crate) const MAX_EVIDENCE_PATHS: usize = 8;
pub(crate) const MAX_EVIDENCE_PER_PATH: usize = 8;
pub(crate) const MAX_EVIDENCE_BYTES: usize = 32 * 1024;
pub(crate) const MAX_SUMMARY_RECORDS: usize = 8;

const PACKET_ENVELOPE_RESERVE: usize = 512;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EvidencePacket {
    pub(crate) totals: EvidenceTotals,
    pub(crate) records: Vec<EvidenceRecord>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct EvidenceTotals {
    pub(crate) filesystem: ChangeCounts,
    pub(crate) filesystem_entries: u64,
    pub(crate) filesystem_changes: u64,
    pub(crate) source_files: u64,
    pub(crate) binary_files: u64,
    pub(crate) file_comparison_inputs: u64,
    pub(crate) structural_changes: u64,
    pub(crate) binary_semantic_changes: u64,
    pub(crate) eligible_records: u64,
    pub(crate) omitted_records: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct ChangeCounts {
    pub(crate) added: u64,
    pub(crate) removed: u64,
    pub(crate) modified: u64,
    pub(crate) type_changed: u64,
    pub(crate) metadata_changed: u64,
    pub(crate) unchanged: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct EvidenceRecord {
    pub(crate) id: EvidenceId,
    pub(crate) path: Option<String>,
    pub(crate) fact: EvidenceFact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct EvidenceId(u64);

impl fmt::Display for EvidenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "E{:04}", self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum EvidenceFact {
    FilesystemChange {
        category: String,
        changed_fields: Vec<String>,
        before: Option<EntryEvidence>,
        after: Option<EntryEvidence>,
    },
    SourceStructuralChange {
        action: String,
        symbol_kind: String,
        name: String,
        before_signature: Option<String>,
        after_signature: Option<String>,
    },
    SourceTextChange {
        lines_added: Option<u64>,
        lines_removed: Option<u64>,
        hunk_count: Option<u64>,
    },
    SourceContentKindChanged,
    BinarySemanticChange {
        field: String,
        before: Value,
        after: Value,
    },
    BinaryBytesChanged {
        old_kind: Option<String>,
        new_kind: Option<String>,
        old_size_bytes: Option<u64>,
        new_size_bytes: Option<u64>,
        byte_level_changed: Option<bool>,
        semantic_status: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct EntryEvidence {
    pub(crate) kind: String,
    pub(crate) size_bytes: Option<u64>,
    pub(crate) mode: Option<u32>,
    pub(crate) device_id: Option<u64>,
    pub(crate) symlink_target: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    CountOverflow,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountOverflow => formatter.write_str("readable evidence count overflowed"),
        }
    }
}

impl std::error::Error for EvidenceError {}

pub fn select_filesystem(diff: &Diff) -> Result<EvidencePacket, EvidenceError> {
    select::select(&diff.changes, &[], &[], &diff.summary)
}

pub fn select_semantic_tree(diff: &SemanticTreeDiff) -> Result<EvidencePacket, EvidenceError> {
    select::select(
        &diff.filesystem.changes,
        &diff.source_changes,
        &diff.binary_changes,
        &diff.filesystem.summary,
    )
}

pub fn select_file_comparison(
    comparison: &FileComparison,
) -> Result<EvidencePacket, EvidenceError> {
    select::select_file_comparison(comparison)
}
