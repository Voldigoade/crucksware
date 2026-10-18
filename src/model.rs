use std::{collections::BTreeMap, path::PathBuf};

use crate::path::RelPath;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Entry {
    File { size: u64, mode: u32 },
    Directory { mode: u32 },
    Symlink { target: Vec<u8> },
    Fifo { mode: u32 },
    Socket { mode: u32 },
    CharDevice { mode: u32, device_id: u64 },
    BlockDevice { mode: u32, device_id: u64 },
}

impl Entry {
    pub fn kind(&self) -> EntryKind {
        match self {
            Self::File { .. } => EntryKind::File,
            Self::Directory { .. } => EntryKind::Directory,
            Self::Symlink { .. } => EntryKind::Symlink,
            Self::Fifo { .. } => EntryKind::Fifo,
            Self::Socket { .. } => EntryKind::Socket,
            Self::CharDevice { .. } => EntryKind::CharDevice,
            Self::BlockDevice { .. } => EntryKind::BlockDevice,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub len: u64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedEntry {
    pub entry: Entry,
    pub stamp: Stamp,
}

#[derive(Debug)]
pub(crate) struct Snapshot {
    pub root: PathBuf,
    pub root_stamp: Stamp,
    pub entries: BTreeMap<RelPath, ObservedEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Category {
    Added,
    Removed,
    Modified,
    TypeChanged,
    MetadataChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangedField {
    Type,
    Content,
    SymlinkTarget,
    Mode,
    DeviceId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub path: RelPath,
    pub category: Category,
    pub changed_fields: Vec<ChangedField>,
    pub before: Option<Entry>,
    pub after: Option<Entry>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    pub added: u64,
    pub removed: u64,
    pub modified: u64,
    pub type_changed: u64,
    pub metadata_changed: u64,
    pub unchanged: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Diff {
    pub changes: Vec<Change>,
    pub summary: Summary,
}
