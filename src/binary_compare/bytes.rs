use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use crate::input::{InputError, InputStamp, open_input_file, revalidate_input_file};

pub(super) struct FileBytesComparison<'a> {
    pub old_path: &'a Path,
    pub new_path: &'a Path,
    pub old_size: u64,
    pub new_size: u64,
    pub old_stamp: &'a InputStamp,
    pub new_stamp: &'a InputStamp,
    pub bytes_read: u64,
    pub max_bytes_read: u64,
}

pub(super) fn equal_file_bytes(comparison: FileBytesComparison<'_>) -> Result<bool, InputError> {
    let FileBytesComparison {
        old_path,
        new_path,
        old_size,
        new_size,
        old_stamp,
        new_stamp,
        mut bytes_read,
        max_bytes_read,
    } = comparison;
    let mut old = open_comparison_file(old_path, old_stamp)?;
    let mut new = open_comparison_file(new_path, new_stamp)?;
    if old_size != new_size {
        revalidate_comparison_file(&old, old_path, old_stamp)?;
        revalidate_comparison_file(&new, new_path, new_stamp)?;
        return Ok(false);
    }

    let mut old_buffer = [0; 64 * 1024];
    let mut new_buffer = [0; 64 * 1024];
    let mut remaining = old_size;
    while remaining > 0 {
        let available =
            max_bytes_read
                .checked_sub(bytes_read)
                .ok_or(InputError::LimitExceeded {
                    resource: "bytes read",
                    limit: max_bytes_read,
                })?;
        let count = remaining.min(old_buffer.len() as u64).min(available / 2) as usize;
        if count == 0 {
            return Err(InputError::LimitExceeded {
                resource: "bytes read",
                limit: max_bytes_read,
            });
        }
        read_exact_counted(
            &mut old,
            &mut old_buffer[..count],
            old_path,
            &mut bytes_read,
            max_bytes_read,
        )?;
        read_exact_counted(
            &mut new,
            &mut new_buffer[..count],
            new_path,
            &mut bytes_read,
            max_bytes_read,
        )?;
        if old_buffer[..count] != new_buffer[..count] {
            revalidate_comparison_file(&old, old_path, old_stamp)?;
            revalidate_comparison_file(&new, new_path, new_stamp)?;
            return Ok(false);
        }
        remaining -= count as u64;
    }

    revalidate_comparison_file(&old, old_path, old_stamp)?;
    revalidate_comparison_file(&new, new_path, new_stamp)?;
    Ok(true)
}

fn open_comparison_file(path: &Path, expected_stamp: &InputStamp) -> Result<File, InputError> {
    let file = open_input_file(path).map_err(|source| InputError::Io {
        operation: "open input",
        path: path.to_path_buf(),
        source,
    })?;
    revalidate_comparison_file(&file, path, expected_stamp)?;
    Ok(file)
}

fn revalidate_comparison_file(
    file: &File,
    path: &Path,
    expected_stamp: &InputStamp,
) -> Result<(), InputError> {
    revalidate_input_file(file, path, expected_stamp)
}

fn read_exact_counted(
    file: &mut File,
    buffer: &mut [u8],
    path: &Path,
    bytes_read: &mut u64,
    max_bytes_read: u64,
) -> Result<(), InputError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => {
                return Err(InputError::Changed {
                    path: path.to_path_buf(),
                });
            }
            Ok(count) => {
                *bytes_read =
                    bytes_read
                        .checked_add(count as u64)
                        .ok_or(InputError::LimitExceeded {
                            resource: "bytes read",
                            limit: max_bytes_read,
                        })?;
                if *bytes_read > max_bytes_read {
                    return Err(InputError::LimitExceeded {
                        resource: "bytes read",
                        limit: max_bytes_read,
                    });
                }
                filled += count;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(InputError::Io {
                    operation: "read input",
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    Ok(())
}
