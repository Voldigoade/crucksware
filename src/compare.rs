use std::path::Path;

use crate::{
    content::equal_files,
    error::{DiffError, Resource, Side},
    limits::{Budget, Limits},
    model::{Category, Change, ChangedField, Diff, Entry, Snapshot},
    scan::{revalidate, scan},
};

/// Compares extracted Linux trees that remain stable for the entire operation.
/// Path-based traversal cannot contain hostile concurrent path replacement.
/// Reads can cause filesystem-managed atime updates.
pub fn compare(old: &Path, new: &Path, limits: Limits) -> Result<Diff, DiffError> {
    let mut budget = Budget::new(limits);
    let old = scan(old, Side::Old, &mut budget)?;
    let new = scan(new, Side::New, &mut budget)?;
    compare_snapshots(&old, &new, &mut budget)
}

fn compare_snapshots(
    old: &Snapshot,
    new: &Snapshot,
    budget: &mut Budget,
) -> Result<Diff, DiffError> {
    let mut diff = Diff::default();
    for (path, before) in &old.entries {
        if let Some(after) = new.entries.get(path) {
            let content_equal = if matches!(
                (&before.entry, &after.entry),
                (Entry::File { .. }, Entry::File { .. })
            ) {
                equal_files(&old.root, &new.root, path, before, after, budget)?
            } else {
                true
            };
            if let Some((category, changed_fields)) =
                classify(&before.entry, &after.entry, content_equal)
            {
                push_change(
                    &mut diff,
                    Change {
                        path: path.clone(),
                        category,
                        changed_fields,
                        before: Some(before.entry.clone()),
                        after: Some(after.entry.clone()),
                    },
                )?;
            } else {
                increment(&mut diff.summary.unchanged)?;
            }
        } else {
            push_change(
                &mut diff,
                Change {
                    path: path.clone(),
                    category: Category::Removed,
                    changed_fields: Vec::new(),
                    before: Some(before.entry.clone()),
                    after: None,
                },
            )?;
        }
    }
    for (path, after) in &new.entries {
        if !old.entries.contains_key(path) {
            push_change(
                &mut diff,
                Change {
                    path: path.clone(),
                    category: Category::Added,
                    changed_fields: Vec::new(),
                    before: None,
                    after: Some(after.entry.clone()),
                },
            )?;
        }
    }
    diff.changes.sort_by(|a, b| a.path.cmp(&b.path));
    revalidate(old, Side::Old)?;
    revalidate(new, Side::New)?;
    Ok(diff)
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

fn increment(counter: &mut u64) -> Result<(), DiffError> {
    *counter = counter.checked_add(1).ok_or(DiffError::LimitExceeded {
        resource: Resource::Entries,
        limit: u64::MAX,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
