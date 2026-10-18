use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use crate::{
    error::{DiffError, Side},
    limits::Budget,
    model::{Entry, ObservedEntry, Stamp},
    path::RelPath,
    scan::{absolute_path, changed, io_error, stamp, verify_stamp},
};

pub(crate) fn equal_files(
    old_root: &Path,
    new_root: &Path,
    path: &RelPath,
    old: &ObservedEntry,
    new: &ObservedEntry,
    budget: &mut Budget,
) -> Result<bool, DiffError> {
    let old_path = absolute_path(old_root, path);
    let new_path = absolute_path(new_root, path);
    let old_size = regular_size(old, Side::Old, &old_path)?;
    let new_size = regular_size(new, Side::New, &new_path)?;
    verify_stamp(&old_path, &old.stamp, Side::Old)?;
    verify_stamp(&new_path, &new.stamp, Side::New)?;
    let equal = if old_size != new_size {
        false
    } else if old_size == 0 {
        true
    } else {
        let mut old_file = File::open(&old_path)
            .map_err(|source| io_error("open file", Side::Old, &old_path, source))?;
        let mut new_file = File::open(&new_path)
            .map_err(|source| io_error("open file", Side::New, &new_path, source))?;
        verify_handle(&old_file, &old.stamp, Side::Old, &old_path)?;
        verify_handle(&new_file, &new.stamp, Side::New, &new_path)?;
        let equal = equal_readers(
            &mut old_file,
            &mut new_file,
            old_size,
            (&old_path, &new_path),
            budget,
        )?;
        verify_handle(&old_file, &old.stamp, Side::Old, &old_path)?;
        verify_handle(&new_file, &new.stamp, Side::New, &new_path)?;
        equal
    };
    verify_stamp(&old_path, &old.stamp, Side::Old)?;
    verify_stamp(&new_path, &new.stamp, Side::New)?;
    Ok(equal)
}

fn regular_size(observed: &ObservedEntry, side: Side, path: &Path) -> Result<u64, DiffError> {
    match observed.entry {
        Entry::File { size, .. } => Ok(size),
        _ => Err(DiffError::UnsupportedType {
            side,
            path: path.to_path_buf(),
        }),
    }
}

fn verify_handle(file: &File, expected: &Stamp, side: Side, path: &Path) -> Result<(), DiffError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect open file", side, path, source))?;
    if !metadata.is_file() || stamp(&metadata) != *expected {
        return Err(changed(side, path));
    }
    Ok(())
}

fn equal_readers(
    old: &mut impl Read,
    new: &mut impl Read,
    expected_len: u64,
    paths: (&Path, &Path),
    budget: &mut Budget,
) -> Result<bool, DiffError> {
    let mut left = [0; 65_536];
    let mut right = [0; 65_536];
    let mut remaining = expected_len;
    while remaining > 0 {
        // Leave enough budget to compare every byte returned by the first read.
        budget.check_read(2)?;
        let count = remaining
            .min(left.len() as u64)
            .min(budget.remaining_read_bytes() / 2) as usize;
        let count = read_chunk(old, &mut left[..count], Side::Old, paths.0, budget)?;
        let mut compared = 0;
        while compared < count {
            let read = read_chunk(
                new,
                &mut right[..count - compared],
                Side::New,
                paths.1,
                budget,
            )?;
            if left[compared..compared + read] != right[..read] {
                return Ok(false);
            }
            compared += read;
        }
        remaining -= count as u64;
    }
    Ok(true)
}

fn read_chunk(
    reader: &mut impl Read,
    buffer: &mut [u8],
    side: Side,
    path: &Path,
    budget: &mut Budget,
) -> Result<usize, DiffError> {
    loop {
        match reader.read(buffer) {
            Ok(0) => return Err(changed(side, path)),
            Ok(count) => {
                budget.charge_read(count as u64)?;
                return Ok(count);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(io_error("read file", side, path, source)),
        }
    }
}

#[cfg(test)]
mod tests;
