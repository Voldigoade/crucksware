use std::path::Path;

use crate::{
    content::equal_files_with_progress,
    error::{DiffError, Resource, Side},
    limits::{Budget, Limits},
    model::{Category, Change, ChangedField, Diff, Entry, Snapshot},
    progress::{ProgressEvent, ProgressPhase, emit},
    scan::{revalidate_with_progress, scan_with_progress},
    semantic_tree::{SemanticTreeDiff, analyze_binary_changes},
    source::analyze_changes,
};

/// Compares extracted Linux trees that remain stable for the entire operation.
/// Path-based traversal cannot contain hostile concurrent path replacement.
/// Reads can cause filesystem-managed atime updates.
pub fn compare(old: &Path, new: &Path, limits: Limits) -> Result<Diff, DiffError> {
    compare_inner(old, new, limits, None::<fn(ProgressEvent)>)
}

pub fn compare_with_progress(
    old: &Path,
    new: &Path,
    limits: Limits,
    progress: impl FnMut(ProgressEvent),
) -> Result<Diff, DiffError> {
    compare_inner(old, new, limits, Some(progress))
}

fn compare_inner<F>(
    old: &Path,
    new: &Path,
    limits: Limits,
    progress: Option<F>,
) -> Result<Diff, DiffError>
where
    F: FnMut(ProgressEvent),
{
    Ok(run_comparison(old, new, limits, progress)?.diff)
}

struct ComparisonRun {
    diff: Diff,
    old: Snapshot,
    new: Snapshot,
    budget: Budget,
}

fn run_comparison<F>(
    old: &Path,
    new: &Path,
    limits: Limits,
    mut progress: Option<F>,
) -> Result<ComparisonRun, DiffError>
where
    F: FnMut(ProgressEvent),
{
    let mut budget = Budget::new(limits);
    let old = scan_with_progress(old, Side::Old, &mut budget, &mut progress)?;
    let new = scan_with_progress(new, Side::New, &mut budget, &mut progress)?;
    let diff = compare_snapshots_with_progress(&old, &new, &mut budget, &mut progress)?;
    Ok(ComparisonRun {
        diff,
        old,
        new,
        budget,
    })
}

pub fn compare_semantic_tree(
    old: &Path,
    new: &Path,
    limits: Limits,
    max_source_file_bytes: u64,
) -> Result<SemanticTreeDiff, DiffError> {
    let max_entries = limits.max_entries;
    let mut run = run_comparison(old, new, limits, None::<fn(ProgressEvent)>)?;
    let source_changes = analyze_changes(
        &run.diff,
        &run.old,
        &run.new,
        &mut run.budget,
        max_source_file_bytes,
    )?;
    let binary_changes = analyze_binary_changes(
        &run.diff,
        &run.old,
        &run.new,
        &source_changes,
        &mut run.budget,
        max_entries,
    )?;
    let mut no_progress = None::<fn(ProgressEvent)>;
    revalidate_with_progress(&run.old, Side::Old, &mut no_progress)?;
    revalidate_with_progress(&run.new, Side::New, &mut no_progress)?;
    Ok(SemanticTreeDiff {
        filesystem: run.diff,
        source_changes,
        binary_changes,
    })
}

#[cfg(test)]
fn compare_snapshots(
    old: &Snapshot,
    new: &Snapshot,
    budget: &mut Budget,
) -> Result<Diff, DiffError> {
    compare_snapshots_with_progress(old, new, budget, &mut None::<fn(ProgressEvent)>)
}

fn compare_snapshots_with_progress<F>(
    old: &Snapshot,
    new: &Snapshot,
    budget: &mut Budget,
    progress: &mut Option<F>,
) -> Result<Diff, DiffError>
where
    F: FnMut(ProgressEvent),
{
    let mut diff = Diff::default();
    let phase = ProgressPhase::Comparing;
    let total = if progress.is_some() {
        emit(progress, ProgressEvent::PhaseStarted { phase, total: None });
        let total = union_entry_count(old, new)?;
        emit(progress, ProgressEvent::PhaseTotalKnown { phase, total });
        Some(total)
    } else {
        None
    };
    let mut completed = 0;
    for (path, before) in &old.entries {
        if let Some(after) = new.entries.get(path) {
            let content_equal = if matches!(
                (&before.entry, &after.entry),
                (Entry::File { .. }, Entry::File { .. })
            ) {
                equal_files_with_progress(
                    &old.root, &new.root, path, before, after, budget, progress,
                )?
            } else {
                true
            };
            if let Some((category, changed_fields)) =
                classify(&before.entry, &after.entry, content_equal)
            {
                push_change_with_progress(
                    &mut diff,
                    Change {
                        path: path.clone(),
                        category,
                        changed_fields,
                        before: Some(before.entry.clone()),
                        after: Some(after.entry.clone()),
                    },
                    progress,
                )?;
            } else {
                increment(&mut diff.summary.unchanged)?;
            }
        } else {
            push_change_with_progress(
                &mut diff,
                Change {
                    path: path.clone(),
                    category: Category::Removed,
                    changed_fields: Vec::new(),
                    before: Some(before.entry.clone()),
                    after: None,
                },
                progress,
            )?;
        }
        if let Some(total) = total {
            increment(&mut completed)?;
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
    for (path, after) in &new.entries {
        if !old.entries.contains_key(path) {
            push_change_with_progress(
                &mut diff,
                Change {
                    path: path.clone(),
                    category: Category::Added,
                    changed_fields: Vec::new(),
                    before: None,
                    after: Some(after.entry.clone()),
                },
                progress,
            )?;
            if let Some(total) = total {
                increment(&mut completed)?;
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
    }
    if total.is_some() {
        emit(progress, ProgressEvent::PhaseCompleted { phase });
    }
    diff.changes.sort_by(|a, b| a.path.cmp(&b.path));
    revalidate_with_progress(old, Side::Old, progress)?;
    revalidate_with_progress(new, Side::New, progress)?;
    Ok(diff)
}

fn union_entry_count(old: &Snapshot, new: &Snapshot) -> Result<u64, DiffError> {
    let mut old_paths = old.entries.keys().peekable();
    let mut new_paths = new.entries.keys().peekable();
    let mut count = 0;
    while old_paths.peek().is_some() || new_paths.peek().is_some() {
        match (old_paths.peek(), new_paths.peek()) {
            (Some(old), Some(new)) if old == new => {
                old_paths.next();
                new_paths.next();
            }
            (Some(old), Some(new)) if old < new => {
                old_paths.next();
            }
            (Some(_), Some(_)) | (None, Some(_)) => {
                new_paths.next();
            }
            (Some(_), None) => {
                old_paths.next();
            }
            (None, None) => break,
        }
        increment(&mut count)?;
    }
    Ok(count)
}

fn classify(
    before: &Entry,
    after: &Entry,
    content_equal: bool,
) -> Option<(Category, Vec<ChangedField>)> {
    if before.kind() != after.kind() {
        return Some((Category::TypeChanged, vec![ChangedField::Type]));
    }
    let mut fields = Vec::new();
    if let (Entry::File { size: old, .. }, Entry::File { size: new, .. }) = (before, after)
        && (old != new || !content_equal)
    {
        fields.push(ChangedField::Content);
    }
    if let (Entry::Symlink { target: old }, Entry::Symlink { target: new }) = (before, after)
        && old != new
    {
        fields.push(ChangedField::SymlinkTarget);
    }
    if mode(before) != mode(after) {
        fields.push(ChangedField::Mode);
    }
    if device_id(before) != device_id(after) {
        fields.push(ChangedField::DeviceId);
    }
    if fields.is_empty() {
        return None;
    }
    let category = if fields.contains(&ChangedField::Content)
        || fields.contains(&ChangedField::SymlinkTarget)
    {
        Category::Modified
    } else {
        Category::MetadataChanged
    };
    Some((category, fields))
}

fn mode(entry: &Entry) -> Option<u32> {
    match entry {
        Entry::File { mode, .. }
        | Entry::Directory { mode }
        | Entry::Fifo { mode }
        | Entry::Socket { mode }
        | Entry::CharDevice { mode, .. }
        | Entry::BlockDevice { mode, .. } => Some(*mode),
        Entry::Symlink { .. } => None,
    }
}

fn device_id(entry: &Entry) -> Option<u64> {
    match entry {
        Entry::CharDevice { device_id, .. } | Entry::BlockDevice { device_id, .. } => {
            Some(*device_id)
        }
        _ => None,
    }
}

fn push_change(diff: &mut Diff, change: Change) -> Result<(), DiffError> {
    let counter = match change.category {
        Category::Added => &mut diff.summary.added,
        Category::Removed => &mut diff.summary.removed,
        Category::Modified => &mut diff.summary.modified,
        Category::TypeChanged => &mut diff.summary.type_changed,
        Category::MetadataChanged => &mut diff.summary.metadata_changed,
    };
    increment(counter)?;
    diff.changes.push(change);
    Ok(())
}

fn push_change_with_progress<F>(
    diff: &mut Diff,
    change: Change,
    progress: &mut Option<F>,
) -> Result<(), DiffError>
where
    F: FnMut(ProgressEvent),
{
    let category = change.category;
    push_change(diff, change)?;
    emit(progress, ProgressEvent::ChangeDiscovered { category });
    Ok(())
}

fn increment(counter: &mut u64) -> Result<(), DiffError> {
    *counter = counter.checked_add(1).ok_or(DiffError::LimitExceeded {
        resource: Resource::Entries,
        limit: u64::MAX,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
