use std::path::Path;

use serde_json::Value;

use crate::{
    input::{InputError, InputKind},
    inspection::{FileInspection, inspect_file_inner},
    progress::{ProgressEvent, ProgressPhase, emit},
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
    pub bytes_read: u64,
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
    compare_files_inner(
        old_path,
        new_path,
        max_bytes_read,
        max_entries,
        None::<fn(ProgressEvent)>,
    )
}

pub fn compare_files_with_progress(
    old_path: &Path,
    new_path: &Path,
    max_bytes_read: u64,
    max_entries: u64,
    progress: impl FnMut(ProgressEvent),
) -> Result<FileComparison, InputError> {
    compare_files_inner(
        old_path,
        new_path,
        max_bytes_read,
        max_entries,
        Some(progress),
    )
}

fn compare_files_inner<F>(
    old_path: &Path,
    new_path: &Path,
    max_bytes_read: u64,
    max_entries: u64,
    mut progress: Option<F>,
) -> Result<FileComparison, InputError>
where
    F: FnMut(ProgressEvent),
{
    let phase = ProgressPhase::FileComparison;
    emit(
        &mut progress,
        ProgressEvent::PhaseStarted { phase, total: None },
    );
    let old =
        inspect_file_with_progress_offset(old_path, max_bytes_read, max_entries, 0, &mut progress)?;
    emit(
        &mut progress,
        ProgressEvent::BytesRead {
            total_bytes_read: old.bytes_read,
        },
    );
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
    let new = inspect_file_with_progress_offset(
        new_path,
        remaining_bytes,
        remaining_entries,
        old.bytes_read,
        &mut progress,
    )?;
    let bytes_before_comparison =
        old.bytes_read
            .checked_add(new.bytes_read)
            .ok_or(InputError::LimitExceeded {
                resource: "bytes read",
                limit: max_bytes_read,
            })?;
    emit(
        &mut progress,
        ProgressEvent::BytesRead {
            total_bytes_read: bytes_before_comparison,
        },
    );
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
    let (bytes_equal, bytes_read) = bytes::equal_file_bytes(
        bytes::FileBytesComparison {
            old_path,
            new_path,
            old_size: old.size_bytes,
            new_size: new.size_bytes,
            old_stamp,
            new_stamp,
            bytes_read: bytes_before_comparison,
            max_bytes_read,
        },
        &mut progress,
    )?;
    let mut comparison = compare_inspections(&old, &new, !bytes_equal);
    comparison.bytes_read = bytes_read;
    emit(&mut progress, ProgressEvent::PhaseCompleted { phase });
    Ok(comparison)
}

fn inspect_file_with_progress_offset<F>(
    path: &Path,
    max_bytes_read: u64,
    max_entries: u64,
    byte_offset: u64,
    progress: &mut Option<F>,
) -> Result<FileInspection, InputError>
where
    F: FnMut(ProgressEvent),
{
    if progress.is_none() {
        return inspect_file_inner(path, max_bytes_read, max_entries, progress);
    }

    let mut forward = |event| {
        let event = match event {
            ProgressEvent::BytesRead { total_bytes_read } => ProgressEvent::BytesRead {
                total_bytes_read: byte_offset.saturating_add(total_bytes_read),
            },
            event => event,
        };
        if let Some(progress) = progress.as_mut() {
            progress(event);
        }
    };
    let mut adjusted_progress = Some(&mut forward);
    inspect_file_inner(path, max_bytes_read, max_entries, &mut adjusted_progress)
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
