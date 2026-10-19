use crate::{model::Diff, path::RelPath};

pub const DEFAULT_MAX_SOURCE_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_SOURCE_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_SOURCE_RECORDS: u64 = 50_000;
pub(crate) const MAX_SOURCE_FACT_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(target_os = "linux")]
mod parser;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SourceLanguage {
    C,
    Cpp,
    Python,
    Rust,
}

impl SourceLanguage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Python => "python",
            Self::Rust => "rust",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceAnalysisStatus {
    Compared,
    ContentKindChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuralStatus {
    Complete,
    SyntaxErrors,
    Unsupported,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StructuralKind {
    Function,
    Method,
    Struct,
    Union,
    Enum,
    Class,
    Interface,
    Type,
    Constant,
    Module,
    Macro,
    Import,
}

impl StructuralKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Method => "method",
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
            Self::Class => "class",
            Self::Interface => "interface",
            Self::Type => "type",
            Self::Constant => "constant",
            Self::Module => "module",
            Self::Macro => "macro",
            Self::Import => "import",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StructuralAction {
    Added,
    Removed,
    SignatureChanged,
}

impl StructuralAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::SignatureChanged => "signature_changed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralChange {
    pub action: StructuralAction,
    pub kind: StructuralKind,
    pub name: String,
    pub before_signature: Option<String>,
    pub after_signature: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceFileChange {
    pub path: RelPath,
    pub analysis_status: SourceAnalysisStatus,
    pub language: Option<SourceLanguage>,
    pub lines_added: Option<u64>,
    pub lines_removed: Option<u64>,
    pub hunk_count: Option<u64>,
    pub structural_status: StructuralStatus,
    pub structural_changes: Vec<StructuralChange>,
}

#[cfg(target_os = "linux")]
pub(crate) fn analyze_changes(
    diff: &Diff,
    old: &crate::model::Snapshot,
    new: &crate::model::Snapshot,
    budget: &mut crate::limits::Budget,
    max_source_file_bytes: u64,
    progress: &mut Option<impl FnMut(crate::progress::ProgressEvent)>,
) -> Result<Vec<SourceFileChange>, crate::error::DiffError> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

    use crate::{
        error::{DiffError, Resource, Side},
        progress::{ProgressEvent, ProgressPhase, emit},
    };

    if max_source_file_bytes == 0 || max_source_file_bytes > MAX_SOURCE_FILE_BYTES {
        return Err(DiffError::LimitExceeded {
            resource: Resource::SourceFileBytes,
            limit: MAX_SOURCE_FILE_BYTES,
        });
    }

    let report_progress = progress.is_some();
    let phase = ProgressPhase::SourceAnalysis;
    if report_progress {
        emit(progress, ProgressEvent::PhaseStarted { phase, total: None });
    }
    let total = if report_progress {
        changed_regular_file_count(diff, old, new)?
    } else {
        0
    };
    if report_progress {
        emit(progress, ProgressEvent::PhaseTotalKnown { phase, total });
    }
    let mut completed = 0_u64;
    let mut analyzer = parser::Analyzer::new();
    let mut changes = Vec::new();
    let mut source_records = 0_u64;
    let mut report_fact_bytes = 0_u64;
    for change in &diff.changes {
        let old_entry = old.entries.get(&change.path);
        let new_entry = new.entries.get(&change.path);
        if !is_changed_regular_file(change, old_entry, new_entry) {
            continue;
        }
        let old_text = read_source_side(
            &old.root,
            Side::Old,
            &change.path,
            old_entry,
            budget,
            max_source_file_bytes,
        )?;
        let new_text = read_source_side(
            &new.root,
            Side::New,
            &change.path,
            new_entry,
            budget,
            max_source_file_bytes,
        )?;

        let language =
            parser::language_for_path(Path::new(OsStr::from_bytes(change.path.as_bytes())));
        let file_change = match (old_text, new_text) {
            (SourceSide::Text(old_text), SourceSide::Text(new_text)) => Some(build_text_change(
                change.path.clone(),
                language,
                &old_text,
                &new_text,
                &mut analyzer,
            )?),
            (SourceSide::Missing, SourceSide::Text(new_text)) => Some(build_text_change(
                change.path.clone(),
                language,
                "",
                &new_text,
                &mut analyzer,
            )?),
            (SourceSide::Text(old_text), SourceSide::Missing) => Some(build_text_change(
                change.path.clone(),
                language,
                &old_text,
                "",
                &mut analyzer,
            )?),
            (SourceSide::Text(_), SourceSide::NonText)
            | (SourceSide::NonText, SourceSide::Text(_)) => Some(SourceFileChange {
                path: change.path.clone(),
                analysis_status: SourceAnalysisStatus::ContentKindChanged,
                language,
                lines_added: None,
                lines_removed: None,
                hunk_count: None,
                structural_status: StructuralStatus::NotApplicable,
                structural_changes: Vec::new(),
            }),
            (SourceSide::NotRegular, _) | (_, SourceSide::NotRegular) => None,
            (
                SourceSide::Missing | SourceSide::NonText,
                SourceSide::Missing | SourceSide::NonText,
            ) => None,
        };
        if let Some(file_change) = file_change {
            let record_count = u64::try_from(file_change.structural_changes.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or(DiffError::LimitExceeded {
                    resource: Resource::SourceRecords,
                    limit: MAX_SOURCE_RECORDS,
                })?;
            let fact_bytes = file_change
                .structural_changes
                .iter()
                .try_fold(0_u64, |total, change| {
                    total.checked_add(structural_fact_bytes(change)?)
                })
                .ok_or(DiffError::LimitExceeded {
                    resource: Resource::SourceFactBytes,
                    limit: MAX_SOURCE_FACT_BYTES,
                })?;
            report_fact_bytes = report_fact_bytes
                .checked_add(fact_bytes)
                .filter(|bytes| *bytes <= MAX_SOURCE_FACT_BYTES)
                .ok_or(DiffError::LimitExceeded {
                    resource: Resource::SourceFactBytes,
                    limit: MAX_SOURCE_FACT_BYTES,
                })?;
            source_records = source_records
                .checked_add(record_count)
                .filter(|count| *count <= MAX_SOURCE_RECORDS)
                .ok_or(DiffError::LimitExceeded {
                    resource: Resource::SourceRecords,
                    limit: MAX_SOURCE_RECORDS,
                })?;
            changes.push(file_change);
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
    Ok(changes)
}

#[cfg(target_os = "linux")]
fn structural_fact_bytes(change: &StructuralChange) -> Option<u64> {
    let mut bytes = u64::try_from(change.name.len()).ok()?;
    for signature in [
        change.before_signature.as_ref(),
        change.after_signature.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        bytes = bytes.checked_add(u64::try_from(signature.len()).ok()?)?;
    }
    Some(bytes)
}

#[cfg(target_os = "linux")]
pub(crate) fn is_changed_regular_file(
    change: &crate::model::Change,
    old_entry: Option<&crate::model::ObservedEntry>,
    new_entry: Option<&crate::model::ObservedEntry>,
) -> bool {
    use crate::model::{Category, ChangedField, Entry};

    if change.category == Category::MetadataChanged
        || (change.category == Category::Modified
            && !change.changed_fields.contains(&ChangedField::Content))
    {
        return false;
    }
    !old_entry.is_some_and(|entry| !matches!(&entry.entry, Entry::File { .. }))
        && !new_entry.is_some_and(|entry| !matches!(&entry.entry, Entry::File { .. }))
}

#[cfg(target_os = "linux")]
pub(crate) fn changed_regular_file_count(
    diff: &Diff,
    old: &crate::model::Snapshot,
    new: &crate::model::Snapshot,
) -> Result<u64, crate::error::DiffError> {
    use crate::error::{DiffError, Resource};

    diff.changes.iter().try_fold(0_u64, |count, change| {
        let old_entry = old.entries.get(&change.path);
        let new_entry = new.entries.get(&change.path);
        if is_changed_regular_file(change, old_entry, new_entry) {
            count.checked_add(1).ok_or(DiffError::LimitExceeded {
                resource: Resource::Entries,
                limit: u64::MAX,
            })
        } else {
            Ok(count)
        }
    })
}

#[cfg(target_os = "linux")]
enum SourceSide {
    Missing,
    NotRegular,
    NonText,
    Text(String),
}

#[cfg(target_os = "linux")]
fn read_source_side(
    root: &std::path::Path,
    side: crate::error::Side,
    path: &RelPath,
    observed: Option<&crate::model::ObservedEntry>,
    budget: &mut crate::limits::Budget,
    max_source_file_bytes: u64,
) -> Result<SourceSide, crate::error::DiffError> {
    use std::{fs::OpenOptions, io, os::unix::fs::OpenOptionsExt};

    use crate::{
        error::{DiffError, Resource},
        input::looks_like_text,
        model::Entry,
        scan::{absolute_path, changed, io_error, stamp, verify_stamp},
    };

    const SAMPLE_BYTES: usize = 8_192;

    let Some(observed) = observed else {
        return Ok(SourceSide::Missing);
    };
    let Entry::File { size, .. } = &observed.entry else {
        return Ok(SourceSide::NotRegular);
    };
    let full_path = absolute_path(root, path);
    verify_stamp(&full_path, &observed.stamp, side)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options
        .open(&full_path)
        .map_err(|source| match source.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => changed(side, &full_path),
            _ => io_error("open source file", side, &full_path, source),
        })?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect source file", side, &full_path, source))?;
    if !metadata.is_file() || stamp(&metadata) != observed.stamp {
        return Err(changed(side, &full_path));
    }

    let sample_len = (*size).min(SAMPLE_BYTES as u64) as usize;
    budget.charge_read(sample_len as u64)?;
    let mut sample = vec![0; sample_len];
    read_source_exact(&mut file, &mut sample, side, &full_path)?;
    let truncated = *size > sample_len as u64;
    if !looks_like_text(&sample, truncated) {
        revalidate_source_file(&file, &full_path, &observed.stamp, side)?;
        return Ok(SourceSide::NonText);
    }
    if *size > max_source_file_bytes {
        return Err(DiffError::LimitExceeded {
            resource: Resource::SourceFileBytes,
            limit: max_source_file_bytes,
        });
    }

    let size_usize = usize::try_from(*size).map_err(|_| DiffError::LimitExceeded {
        resource: Resource::SourceFileBytes,
        limit: max_source_file_bytes,
    })?;
    let remaining = size_usize.saturating_sub(sample.len());
    budget.check_read(remaining as u64)?;
    let mut bytes = sample;
    bytes
        .try_reserve_exact(remaining)
        .map_err(|_| DiffError::LimitExceeded {
            resource: Resource::SourceFileBytes,
            limit: max_source_file_bytes,
        })?;
    bytes.resize(size_usize, 0);
    budget.charge_read(remaining as u64)?;
    read_source_exact(
        &mut file,
        &mut bytes[size_usize - remaining..],
        side,
        &full_path,
    )?;
    revalidate_source_file(&file, &full_path, &observed.stamp, side)?;

    let text = match String::from_utf8(bytes) {
        Ok(text)
            if text.chars().all(|character| {
                !character.is_control() || matches!(character, '\t' | '\n' | '\r')
            }) =>
        {
            text
        }
        _ => return Ok(SourceSide::NonText),
    };
    Ok(SourceSide::Text(text))
}

#[cfg(target_os = "linux")]
fn read_source_exact(
    file: &mut std::fs::File,
    bytes: &mut [u8],
    side: crate::error::Side,
    path: &std::path::Path,
) -> Result<(), crate::error::DiffError> {
    use std::io::{self, Read as _};

    use crate::scan::{changed, io_error};

    match file.read_exact(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(changed(side, path)),
        Err(source) => Err(io_error("read source file", side, path, source)),
    }
}

#[cfg(target_os = "linux")]
fn revalidate_source_file(
    file: &std::fs::File,
    path: &std::path::Path,
    expected: &crate::model::Stamp,
    side: crate::error::Side,
) -> Result<(), crate::error::DiffError> {
    use crate::scan::{changed, io_error, stamp, verify_stamp};

    let metadata = file
        .metadata()
        .map_err(|source| io_error("revalidate source file", side, path, source))?;
    if !metadata.is_file() || stamp(&metadata) != *expected {
        return Err(changed(side, path));
    }
    verify_stamp(path, expected, side)
}

#[cfg(target_os = "linux")]
fn build_text_change(
    path: RelPath,
    language: Option<SourceLanguage>,
    old: &str,
    new: &str,
    analyzer: &mut parser::Analyzer,
) -> Result<SourceFileChange, crate::error::DiffError> {
    use similar::{Algorithm, ChangeTag, TextDiff};

    use crate::error::{DiffError, Resource};

    const MAX_SOURCE_LINES: usize = 200_000;

    let old_lines = old.lines().count();
    let new_lines = new.lines().count();
    if old_lines > MAX_SOURCE_LINES || new_lines > MAX_SOURCE_LINES {
        return Err(DiffError::LimitExceeded {
            resource: Resource::SourceLines,
            limit: MAX_SOURCE_LINES as u64,
        });
    }

    let diff = TextDiff::configure()
        .algorithm(Algorithm::Patience)
        .diff_lines(old, new);
    let mut lines_added = 0_u64;
    let mut lines_removed = 0_u64;
    for change in diff.iter_all_changes() {
        let counter = match change.tag() {
            ChangeTag::Insert => &mut lines_added,
            ChangeTag::Delete => &mut lines_removed,
            ChangeTag::Equal => continue,
        };
        *counter = counter.checked_add(1).ok_or(DiffError::LimitExceeded {
            resource: Resource::SourceLines,
            limit: MAX_SOURCE_LINES as u64,
        })?;
    }
    let hunk_count =
        u64::try_from(diff.grouped_ops(3).len()).map_err(|_| DiffError::LimitExceeded {
            resource: Resource::SourceLines,
            limit: MAX_SOURCE_LINES as u64,
        })?;

    let (structural_status, structural_changes) = match language {
        Some(language) => analyzer.compare(language, old, new, &path)?,
        None => (StructuralStatus::Unsupported, Vec::new()),
    };

    Ok(SourceFileChange {
        path,
        analysis_status: SourceAnalysisStatus::Compared,
        language,
        lines_added: Some(lines_added),
        lines_removed: Some(lines_removed),
        hunk_count: Some(hunk_count),
        structural_status,
        structural_changes,
    })
}
