use crate::model::{Category, ChangedField, Entry, EntryKind};

pub(super) fn category_name(category: Category) -> &'static str {
    match category {
        Category::Added => "ADDED",
        Category::Removed => "REMOVED",
        Category::Modified => "MODIFIED",
        Category::TypeChanged => "TYPE_CHANGED",
        Category::MetadataChanged => "METADATA_CHANGED",
    }
}

pub(super) fn changed_field_name(field: ChangedField) -> &'static str {
    match field {
        ChangedField::Type => "type",
        ChangedField::Content => "content",
        ChangedField::SymlinkTarget => "symlink_target",
        ChangedField::Mode => "mode",
        ChangedField::DeviceId => "device_id",
    }
}

pub(super) fn kind_name(entry: &Entry) -> &'static str {
    match entry.kind() {
        EntryKind::File => "file",
        EntryKind::Directory => "directory",
        EntryKind::Symlink => "symlink",
        EntryKind::Fifo => "fifo",
        EntryKind::Socket => "socket",
        EntryKind::CharDevice => "char_device",
        EntryKind::BlockDevice => "block_device",
    }
}

pub(super) fn file_size(entry: &Entry) -> Option<u64> {
    match entry {
        Entry::File { size, .. } => Some(*size),
        _ => None,
    }
}

pub(super) fn mode(entry: &Entry) -> Option<u32> {
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

pub(super) fn format_mode(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

pub(super) fn symlink_target(entry: &Entry) -> Option<&[u8]> {
    match entry {
        Entry::Symlink { target } => Some(target),
        _ => None,
    }
}

pub(super) fn device_id(entry: &Entry) -> Option<u64> {
    match entry {
        Entry::CharDevice { device_id, .. } | Entry::BlockDevice { device_id, .. } => {
            Some(*device_id)
        }
        _ => None,
    }
}
