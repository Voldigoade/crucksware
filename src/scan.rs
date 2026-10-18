use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs, io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
};

use crate::{
    error::{DiffError, Side},
    limits::Budget,
    model::{Entry, EntryKind, ObservedEntry, Snapshot, Stamp},
    path::RelPath,
};

pub(crate) fn scan(root: &Path, side: Side, budget: &mut Budget) -> Result<Snapshot, DiffError> {
    let root =
        fs::canonicalize(root).map_err(|source| io_error("resolve root", side, root, source))?;
    let metadata = fs::symlink_metadata(&root)
        .map_err(|source| io_error("inspect root", side, &root, source))?;
    if !metadata.is_dir() {
        return Err(io_error(
            "inspect root",
            side,
            &root,
            io::ErrorKind::NotADirectory.into(),
        ));
    }
    let root_stamp = stamp(&metadata);
    let mut entries = BTreeMap::new();
    let mut stack = vec![(None, root_stamp.clone())];
    while let Some((parent, expected)) = stack.pop() {
        let directory = parent
            .as_ref()
            .map_or_else(|| root.clone(), |path| absolute_path(&root, path));
        verify_stamp(&directory, &expected, side)?;
        let iterator = fs::read_dir(&directory)
            .map_err(|source| io_error("read directory", side, &directory, source))?;
        let names = collect_names(
            iterator.map(|item| item.map(|entry| entry.file_name())),
            parent.as_ref(),
            side,
            &root,
            budget,
        )?;
        verify_stamp(&directory, &expected, side)?;
        for path in names {
            let full = absolute_path(&root, &path);
            let metadata = metadata_at(&full, side)?;
            let facts = NodeFacts::from_metadata(&metadata);
            check_device(root_stamp.dev, facts.dev, side, &full)?;
            let observed_stamp = stamp(&metadata);
            let target = if facts.kind == Some(EntryKind::Symlink) {
                let target = fs::read_link(&full)
                    .map_err(|source| io_error("read link", side, &full, source))?
                    .as_os_str()
                    .as_bytes()
                    .to_vec();
                budget.charge_target(target.len() as u64)?;
                verify_stamp(&full, &observed_stamp, side)?;
                Some(target)
            } else {
                None
            };
            let entry = entry_from_facts(&facts, target, side, &full)?;
            if facts.kind == Some(EntryKind::Directory) {
                stack.push((Some(path.clone()), observed_stamp.clone()));
            }
            if entries
                .insert(
                    path,
                    ObservedEntry {
                        entry,
                        stamp: observed_stamp,
                    },
                )
                .is_some()
            {
                return Err(changed(side, &full));
            }
        }
    }
    Ok(Snapshot {
        root,
        root_stamp,
        entries,
    })
}

pub(crate) fn revalidate(snapshot: &Snapshot, side: Side) -> Result<(), DiffError> {
    verify_stamp(&snapshot.root, &snapshot.root_stamp, side)?;
    for (path, observed) in &snapshot.entries {
        let full = absolute_path(&snapshot.root, path);
        verify_stamp(&full, &observed.stamp, side)?;
        if let Entry::Symlink { target } = &observed.entry {
            let actual = fs::read_link(&full)
                .map_err(|source| io_error("revalidate link", side, &full, source))?;
            if actual.as_os_str().as_bytes() != target {
                return Err(changed(side, &full));
            }
            verify_stamp(&full, &observed.stamp, side)?;
        }
    }
    Ok(())
}

pub(crate) fn stamp(metadata: &fs::Metadata) -> Stamp {
    Stamp {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        len: metadata.len(),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

pub(crate) fn absolute_path(root: &Path, path: &RelPath) -> PathBuf {
    root.join(OsStr::from_bytes(path.as_bytes()))
}

pub(crate) fn verify_stamp(path: &Path, expected: &Stamp, side: Side) -> Result<(), DiffError> {
    if stamp(&metadata_at(path, side)?) != *expected {
        return Err(changed(side, path));
    }
    Ok(())
}

fn metadata_at(path: &Path, side: Side) -> Result<fs::Metadata, DiffError> {
    fs::symlink_metadata(path).map_err(|source| match source.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => changed(side, path),
        _ => io_error("inspect entry", side, path, source),
    })
}

pub(crate) fn io_error(
    operation: &'static str,
    side: Side,
    path: &Path,
    source: io::Error,
) -> DiffError {
    DiffError::Io {
        operation,
        side,
        path: path.to_path_buf(),
        source,
    }
}

pub(crate) fn changed(side: Side, path: &Path) -> DiffError {
    DiffError::TreeChanged {
        side,
        path: path.to_path_buf(),
    }
}

struct NodeFacts {
    kind: Option<EntryKind>,
    mode: u32,
    len: u64,
    device_id: u64,
    dev: u64,
}

impl NodeFacts {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        let ty = metadata.file_type();
        let kind = if ty.is_file() {
            Some(EntryKind::File)
        } else if ty.is_dir() {
            Some(EntryKind::Directory)
        } else if ty.is_symlink() {
            Some(EntryKind::Symlink)
        } else if ty.is_fifo() {
            Some(EntryKind::Fifo)
        } else if ty.is_socket() {
            Some(EntryKind::Socket)
        } else if ty.is_char_device() {
            Some(EntryKind::CharDevice)
        } else if ty.is_block_device() {
            Some(EntryKind::BlockDevice)
        } else {
            None
        };
        Self {
            kind,
            mode: metadata.mode(),
            len: metadata.len(),
            device_id: metadata.rdev(),
            dev: metadata.dev(),
        }
    }
}

fn entry_from_facts(
    facts: &NodeFacts,
    target: Option<Vec<u8>>,
    side: Side,
    path: &Path,
) -> Result<Entry, DiffError> {
    let mode = facts.mode & 0o7777;
    Ok(match facts.kind {
        Some(EntryKind::File) => Entry::File {
            size: facts.len,
            mode,
        },
        Some(EntryKind::Directory) => Entry::Directory { mode },
        Some(EntryKind::Symlink) => Entry::Symlink {
            target: target.ok_or_else(|| {
                io_error("read link", side, path, io::ErrorKind::InvalidData.into())
            })?,
        },
        Some(EntryKind::Fifo) => Entry::Fifo { mode },
        Some(EntryKind::Socket) => Entry::Socket { mode },
        Some(EntryKind::CharDevice) => Entry::CharDevice {
            mode,
            device_id: facts.device_id,
        },
        Some(EntryKind::BlockDevice) => Entry::BlockDevice {
            mode,
            device_id: facts.device_id,
        },
        None => {
            return Err(DiffError::UnsupportedType {
                side,
                path: path.to_path_buf(),
            });
        }
    })
}

fn check_device(root_dev: u64, node_dev: u64, side: Side, path: &Path) -> Result<(), DiffError> {
    if root_dev != node_dev {
        return Err(DiffError::FilesystemBoundary {
            side,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn collect_names(
    entries: impl Iterator<Item = io::Result<OsString>>,
    parent: Option<&RelPath>,
    side: Side,
    root: &Path,
    budget: &mut Budget,
) -> Result<Vec<RelPath>, DiffError> {
    let directory = parent.map_or_else(|| root.to_path_buf(), |path| absolute_path(root, path));
    let mut paths = Vec::new();
    for item in entries {
        let name =
            item.map_err(|source| io_error("read directory entry", side, &directory, source))?;
        let name = name.as_os_str().as_bytes();
        if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." {
            return Err(DiffError::InvalidRelativePath);
        }
        let mut raw = parent.map_or_else(Vec::new, |path| path.as_bytes().to_vec());
        if parent.is_some() {
            raw.push(b'/');
        }
        raw.extend_from_slice(name);
        let path = RelPath::new(raw)?;
        let depth = path.as_bytes().split(|&byte| byte == b'/').count() as u64;
        budget.charge_entry(depth, path.as_bytes().len() as u64)?;
        paths.push(path);
    }
    paths.sort();
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(changed(side, &directory));
    }
    Ok(paths)
}

#[cfg(test)]
mod tests;
