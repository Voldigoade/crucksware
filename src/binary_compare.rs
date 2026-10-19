use std::path::Path;

use serde_json::Value;

use crate::{
    input::{InputError, InputKind},
    inspection::{FileInspection, inspect_file_with_limits},
};

mod bytes;
mod facts;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticComparisonStatus {
    Compared,
    FormatMismatch,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticChange {
    pub field: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileComparison {
    pub old_kind: InputKind,
    pub new_kind: InputKind,
    pub old_size_bytes: u64,
    pub new_size_bytes: u64,
    pub bytes_changed: bool,
    pub semantic_status: SemanticComparisonStatus,
    pub semantic_changes: Vec<SemanticChange>,
}

pub fn compare_files(
    old_path: &Path,
    new_path: &Path,
    max_bytes_read: u64,
    max_entries: u64,
) -> Result<FileComparison, InputError> {
    let old = inspect_file_with_limits(old_path, max_bytes_read, max_entries)?;
    let remaining_bytes =
        max_bytes_read
            .checked_sub(old.bytes_read)
            .ok_or(InputError::LimitExceeded {
                resource: "bytes read",
                limit: max_bytes_read,
            })?;
    let remaining_entries =
        max_entries
            .checked_sub(old.semantic_entries)
            .ok_or(InputError::LimitExceeded {
                resource: "semantic entries",
                limit: max_entries,
            })?;
    let new = inspect_file_with_limits(new_path, remaining_bytes, remaining_entries)?;
    let bytes_before_comparison =
        old.bytes_read
            .checked_add(new.bytes_read)
            .ok_or(InputError::LimitExceeded {
                resource: "bytes read",
                limit: max_bytes_read,
            })?;
    let old_stamp = old
        .input_stamp
        .as_ref()
        .ok_or_else(|| InputError::Changed {
            path: old_path.to_path_buf(),
        })?;
    let new_stamp = new
        .input_stamp
        .as_ref()
        .ok_or_else(|| InputError::Changed {
            path: new_path.to_path_buf(),
        })?;
    let bytes_changed = !bytes::equal_file_bytes(bytes::FileBytesComparison {
        old_path,
        new_path,
        old_size: old.size_bytes,
        new_size: new.size_bytes,
        old_stamp,
        new_stamp,
        bytes_read: bytes_before_comparison,
        max_bytes_read,
    })?;
    Ok(compare_inspections(&old, &new, bytes_changed))
}

pub fn compare_inspections(
    old: &FileInspection,
    new: &FileInspection,
    bytes_changed: bool,
) -> FileComparison {
    facts::compare_inspections(old, new, bytes_changed)
}

#[cfg(test)]
mod tests;
