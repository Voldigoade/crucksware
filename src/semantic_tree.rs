use crate::{
    binary_compare::{SemanticChange, SemanticComparisonStatus},
    input::InputKind,
    model::Diff,
    path::RelPath,
    source::SourceFileChange,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticTreeDiff {
    pub filesystem: Diff,
    pub source_changes: Vec<SourceFileChange>,
    pub binary_changes: Vec<BinaryFileChange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryAnalysisStatus {
    SingleInput,
    Compared,
    FormatMismatch,
    Unsupported,
}

impl BinaryAnalysisStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleInput => "single_input",
            Self::Compared => "compared",
            Self::FormatMismatch => "format_mismatch",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryFileChange {
    pub path: RelPath,
    pub old_kind: Option<InputKind>,
    pub new_kind: Option<InputKind>,
    pub old_size_bytes: Option<u64>,
    pub new_size_bytes: Option<u64>,
    pub byte_level_changed: Option<bool>,
    pub semantic_status: BinaryAnalysisStatus,
    pub semantic_changes: Vec<SemanticChange>,
}

#[cfg(target_os = "linux")]
pub(crate) fn analyze_binary_changes(
    diff: &Diff,
    old: &crate::model::Snapshot,
    new: &crate::model::Snapshot,
    source_changes: &[crate::source::SourceFileChange],
    budget: &mut crate::limits::Budget,
    max_entries: u64,
    progress: &mut Option<impl FnMut(crate::progress::ProgressEvent)>,
) -> Result<Vec<BinaryFileChange>, crate::error::DiffError> {
    use crate::{
        binary_compare::compare_inspections,
        error::{DiffError, Resource, Side},
        inspection::FileInspection,
        model::Entry,
        progress::{ProgressEvent, ProgressPhase, emit},
        scan::{absolute_path, changed, io_error, stamp, verify_stamp},
    };
    use std::{fs::OpenOptions, io, os::unix::fs::OpenOptionsExt, path::Path};

    let report_progress = progress.is_some();
    let phase = ProgressPhase::BinaryAnalysis;
    if report_progress {
        emit(progress, ProgressEvent::PhaseStarted { phase, total: None });
    }
    let total = if report_progress {
        binary_analysis_candidate_count(diff, old, new, source_changes)?
    } else {
        0
    };
    if report_progress {
        emit(progress, ProgressEvent::PhaseTotalKnown { phase, total });
    }
    let mut completed = 0_u64;
    let mut semantic_entries = 0_u64;
    let mut changes = Vec::new();
    let mut source_index = 0;
    for change in &diff.changes {
        while source_changes
            .get(source_index)
            .is_some_and(|source| source.path < change.path)
        {
            source_index += 1;
        }
        let old_entry = old.entries.get(&change.path);
        let new_entry = new.entries.get(&change.path);
        if !crate::source::is_changed_regular_file(change, old_entry, new_entry) {
            continue;
        }
        if source_changes.get(source_index).is_some_and(|source| {
            source.path == change.path
                && source.analysis_status == crate::source::SourceAnalysisStatus::Compared
        }) {
            continue;
        }

        let old_inspection = inspect_side(
            &old.root,
            Side::Old,
            &change.path,
            old_entry,
            budget,
            max_entries.saturating_sub(semantic_entries),
        )?;
        if let Some(inspection) = &old_inspection {
            semantic_entries = charge_semantic_entries(
                semantic_entries,
                inspection.semantic_entries,
                max_entries,
            )?;
        }

        let new_inspection = inspect_side(
            &new.root,
            Side::New,
            &change.path,
            new_entry,
            budget,
            max_entries.saturating_sub(semantic_entries),
        )?;
        if let Some(inspection) = &new_inspection {
            semantic_entries = charge_semantic_entries(
                semantic_entries,
                inspection.semantic_entries,
                max_entries,
            )?;
        }

        let old_kind = old_inspection.as_ref().map(|inspection| inspection.kind);
        let new_kind = new_inspection.as_ref().map(|inspection| inspection.kind);
        if !old_kind.is_none_or(|kind| kind == InputKind::Text)
            || !new_kind.is_none_or(|kind| kind == InputKind::Text)
        {
            let (semantic_status, semantic_changes) = match (&old_inspection, &new_inspection) {
                (Some(old), Some(new)) => {
                    let comparison = compare_inspections(old, new, true);
                    let status = match comparison.semantic_status {
                        SemanticComparisonStatus::Compared => BinaryAnalysisStatus::Compared,
                        SemanticComparisonStatus::FormatMismatch => {
                            BinaryAnalysisStatus::FormatMismatch
                        }
                        SemanticComparisonStatus::Unsupported => BinaryAnalysisStatus::Unsupported,
                    };
                    (status, comparison.semantic_changes)
                }
                _ => (BinaryAnalysisStatus::SingleInput, Vec::new()),
            };

            changes.push(BinaryFileChange {
                path: change.path.clone(),
                old_kind,
                new_kind,
                old_size_bytes: old_inspection
                    .as_ref()
                    .map(|inspection| inspection.size_bytes),
                new_size_bytes: new_inspection
                    .as_ref()
                    .map(|inspection| inspection.size_bytes),
                byte_level_changed: (old_inspection.is_some() && new_inspection.is_some())
                    .then_some(true),
                semantic_status,
                semantic_changes,
            });
        }
        if report_progress {
            completed = completed.checked_add(1).ok_or(DiffError::LimitExceeded {
                resource: Resource::Entries,
                limit: total,
            })?;
            emit(
                progress,
                ProgressEvent::BytesRead {
                    total_bytes_read: budget.bytes_read(),
                },
            );
            emit(
                progress,
                ProgressEvent::PhaseProgress {
                    phase,
                    completed,
                    total,
                },
            );
        }
    }
    if report_progress {
        emit(progress, ProgressEvent::PhaseCompleted { phase });
    }
    fn inspect_side(
        root: &Path,
        side: Side,
        path: &RelPath,
        observed: Option<&crate::model::ObservedEntry>,
        budget: &mut crate::limits::Budget,
        max_entries: u64,
    ) -> Result<Option<FileInspection>, DiffError> {
        let Some(observed) = observed else {
            return Ok(None);
        };
        if !matches!(&observed.entry, Entry::File { .. }) {
            return Ok(None);
        }
        let full_path = absolute_path(root, path);
        verify_stamp(&full_path, &observed.stamp, side)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options
            .open(&full_path)
            .map_err(|source| match source.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => changed(side, &full_path),
                _ => io_error("open file for semantic analysis", side, &full_path, source),
            })?;
        let metadata = file.metadata().map_err(|source| {
            io_error(
                "inspect file for semantic analysis",
                side,
                &full_path,
                source,
            )
        })?;
        if !metadata.is_file() || stamp(&metadata) != observed.stamp {
            return Err(changed(side, &full_path));
        }
        let inspection = crate::inspection::inspect_open_file_with_limits(
            &full_path,
            file,
            budget.remaining_read_bytes(),
            max_entries,
        )
        .map_err(|source| DiffError::InputInspection { side, source })?;
        budget.charge_read(inspection.bytes_read)?;
        verify_stamp(&full_path, &observed.stamp, side)?;
        Ok(Some(inspection))
    }

    fn charge_semantic_entries(current: u64, amount: u64, limit: u64) -> Result<u64, DiffError> {
        current
            .checked_add(amount)
            .filter(|total| *total <= limit)
            .ok_or(DiffError::LimitExceeded {
                resource: Resource::Entries,
                limit,
            })
    }

    Ok(changes)
}

#[cfg(target_os = "linux")]
fn binary_analysis_candidate_count(
    diff: &Diff,
    old: &crate::model::Snapshot,
    new: &crate::model::Snapshot,
    source_changes: &[crate::source::SourceFileChange],
) -> Result<u64, crate::error::DiffError> {
    use crate::{
        error::{DiffError, Resource},
        source::SourceAnalysisStatus,
    };

    let mut source_index = 0;
    diff.changes.iter().try_fold(0_u64, |count, change| {
        while source_changes
            .get(source_index)
            .is_some_and(|source| source.path < change.path)
        {
            source_index += 1;
        }
        let old_entry = old.entries.get(&change.path);
        let new_entry = new.entries.get(&change.path);
        let compared_as_text = source_changes.get(source_index).is_some_and(|source| {
            source.path == change.path && source.analysis_status == SourceAnalysisStatus::Compared
        });
        if crate::source::is_changed_regular_file(change, old_entry, new_entry) && !compared_as_text
        {
            count.checked_add(1).ok_or(DiffError::LimitExceeded {
                resource: Resource::Entries,
                limit: u64::MAX,
            })
        } else {
            Ok(count)
        }
    })
}
