use std::{
    error::Error,
    fmt, fs,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::path::encode_bytes;

const SAMPLE_SIZE: usize = 8_192;
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const PE_OFFSET_FIELD: std::ops::Range<usize> = 0x3c..0x40;
const DOS_HEADER_SIZE: u64 = 64;

/// A broad input category determined before format-specific inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputKind {
    Directory,
    Elf,
    Pe,
    Text,
    UnknownBinary,
}

impl fmt::Display for InputKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Directory => "directory",
            Self::Elf => "ELF",
            Self::Pe => "PE",
            Self::Text => "text",
            Self::UnknownBinary => "unknown binary",
        })
    }
}

/// An error encountered while identifying an input category.
#[derive(Debug)]
pub enum InputError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    UnsupportedType {
        path: PathBuf,
    },
    Changed {
        path: PathBuf,
    },
    Format {
        format: &'static str,
        path: PathBuf,
        message: String,
    },
    LimitExceeded {
        resource: &'static str,
        limit: u64,
    },
}

#[derive(Debug)]
pub(crate) struct InputDetection {
    pub kind: InputKind,
    pub size_bytes: Option<u64>,
    pub file: Option<File>,
    pub sample: Vec<u8>,
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "{operation} {}: {source}",
                encode_bytes(path.as_os_str().as_encoded_bytes())
            ),
            Self::UnsupportedType { path } => write!(
                formatter,
                "unsupported input type at {}",
                encode_bytes(path.as_os_str().as_encoded_bytes())
            ),
            Self::Changed { path } => write!(
                formatter,
                "input changed during inspection at {}",
                encode_bytes(path.as_os_str().as_encoded_bytes())
            ),
            Self::Format {
                format,
                path,
                message,
            } => write!(
                formatter,
                "invalid {format} input at {}: {message}",
                encode_bytes(path.as_os_str().as_encoded_bytes())
            ),
            Self::LimitExceeded { resource, limit } => {
                write!(formatter, "{resource} limit exceeded ({limit})")
            }
        }
    }
}

impl Error for InputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::UnsupportedType { .. }
            | Self::Changed { .. }
            | Self::Format { .. }
            | Self::LimitExceeded { .. } => None,
        }
    }
}

/// Identifies directories, ELF and PE files, text samples, and other regular files.
///
/// ELF detection uses its magic bytes. PE detection validates the DOS header offset and
/// PE signature. Text classification examines at most 8 KiB and is a heuristic, not a
/// guarantee about the whole file. File extensions do not affect the result.
pub fn detect_input(path: &Path) -> Result<InputKind, InputError> {
    detect_input_bounded(path, u64::MAX).map(|detection| detection.kind)
}

pub(crate) fn detect_input_bounded(
    path: &Path,
    max_bytes_read: u64,
) -> Result<InputDetection, InputError> {
    let metadata = fs::metadata(path).map_err(|source| input_io("inspect input", path, source))?;
    if metadata.is_dir() {
        return Ok(InputDetection {
            kind: InputKind::Directory,
            size_bytes: None,
            file: None,
            sample: Vec::new(),
        });
    }
    if !metadata.is_file() {
        return Err(InputError::UnsupportedType {
            path: path.to_path_buf(),
        });
    }

    let mut file = open_input_file(path).map_err(|source| input_io("open input", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| input_io("inspect open input", path, source))?;
    if !metadata.is_file() {
        return Err(InputError::UnsupportedType {
            path: path.to_path_buf(),
        });
    }

    let sample_capacity = if max_bytes_read < SAMPLE_SIZE as u64 {
        max_bytes_read as usize
    } else {
        SAMPLE_SIZE
    };
    let mut sample = [0; SAMPLE_SIZE];
    let sample_len = read_sample(&mut file, &mut sample[..sample_capacity])
        .map_err(|source| input_io("read input", path, source))?;
    let sample = &sample[..sample_len];

    if sample.starts_with(ELF_MAGIC) {
        return Ok(InputDetection {
            kind: InputKind::Elf,
            size_bytes: Some(metadata.len()),
            file: Some(file),
            sample: sample.to_vec(),
        });
    }

    let bytes_read = sample_len as u64;
    if let Some(offset) = pe_signature_offset(sample, metadata.len()) {
        let signature = if let Ok(start) = usize::try_from(offset)
            && let Some(end) = start.checked_add(PE_SIGNATURE.len())
            && let Some(signature) = sample.get(start..end)
        {
            signature == PE_SIGNATURE
        } else {
            let total = bytes_read.checked_add(PE_SIGNATURE.len() as u64).ok_or(
                InputError::LimitExceeded {
                    resource: "bytes read",
                    limit: max_bytes_read,
                },
            )?;
            if total > max_bytes_read {
                return Err(InputError::LimitExceeded {
                    resource: "bytes read",
                    limit: max_bytes_read,
                });
            }
            file.seek(SeekFrom::Start(offset))
                .map_err(|source| input_io("read PE signature", path, source))?;
            let mut signature = [0; PE_SIGNATURE.len()];
            file.read_exact(&mut signature)
                .map_err(|source| input_io("read PE signature", path, source))?;
            signature == *PE_SIGNATURE
        };
        if signature {
            return Ok(InputDetection {
                kind: InputKind::Pe,
                size_bytes: Some(metadata.len()),
                file: Some(file),
                sample: sample.to_vec(),
            });
        }
    }

    let expected_sample_len = metadata.len().min(SAMPLE_SIZE as u64);
    if (sample_len as u64) < expected_sample_len {
        if max_bytes_read >= expected_sample_len {
            return Err(InputError::Changed {
                path: path.to_path_buf(),
            });
        }
        return Err(InputError::LimitExceeded {
            resource: "bytes read",
            limit: max_bytes_read,
        });
    }

    let sample_is_truncated = sample_len == SAMPLE_SIZE && metadata.len() > SAMPLE_SIZE as u64;
    let kind = if looks_like_text(sample, sample_is_truncated) {
        InputKind::Text
    } else {
        InputKind::UnknownBinary
    };
    Ok(InputDetection {
        kind,
        size_bytes: Some(metadata.len()),
        file: Some(file),
        sample: sample.to_vec(),
    })
}

#[cfg(target_os = "linux")]
fn open_input_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_input_file(path: &Path) -> io::Result<File> {
    File::open(path)
}

fn input_io(operation: &'static str, path: &Path, source: io::Error) -> InputError {
    InputError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn read_sample(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut length = 0;
    while length < buffer.len() {
        match reader.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(length)
}

fn pe_signature_offset(sample: &[u8], file_len: u64) -> Option<u64> {
    if !sample.starts_with(b"MZ") || sample.len() < PE_OFFSET_FIELD.end {
        return None;
    }

    let offset_bytes = <[u8; 4]>::try_from(&sample[PE_OFFSET_FIELD]).ok()?;
    let offset = u64::from(u32::from_le_bytes(offset_bytes));
    let signature_end = offset.checked_add(PE_SIGNATURE.len() as u64)?;
    if offset < DOS_HEADER_SIZE || signature_end > file_len {
        return None;
    }

    Some(offset)
}

fn looks_like_text(sample: &[u8], sample_is_truncated: bool) -> bool {
    let text_len = match std::str::from_utf8(sample) {
        Ok(text) => return text.chars().all(allowed_text_character),
        Err(error) if sample_is_truncated && error.error_len().is_none() => error.valid_up_to(),
        Err(_) => return false,
    };
    std::str::from_utf8(&sample[..text_len])
        .is_ok_and(|text| text.chars().all(allowed_text_character))
}

fn allowed_text_character(character: char) -> bool {
    !character.is_control() || matches!(character, '\t' | '\n' | '\r')
}
