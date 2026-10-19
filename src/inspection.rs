use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use crate::input::{InputDetection, InputError, InputKind, detect_input_bounded};

mod elf;

pub const MAX_ELF_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_BYTES_READ: u64 = MAX_ELF_FILE_BYTES + 8 * 1024 + 4;
pub const DEFAULT_MAX_ENTRIES: u64 = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentKind {
    Text,
    Binary,
}

impl std::fmt::Display for ContentKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Text => "text",
            Self::Binary => "binary",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfSection {
    pub index: u64,
    pub name: Vec<u8>,
    pub section_type: String,
    pub flags: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfSegment {
    pub index: u64,
    pub segment_type: String,
    pub flags: String,
    pub offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfSymbol {
    pub name: Vec<u8>,
    pub binding: String,
    pub symbol_type: String,
    pub value: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfImport {
    pub library: Vec<u8>,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElfInspection {
    pub class: &'static str,
    pub byte_order: &'static str,
    pub architecture: String,
    pub machine: String,
    pub elf_type: String,
    pub entry_point: u64,
    pub sections: Vec<ElfSection>,
    pub segments: Vec<ElfSegment>,
    pub interpreters: Vec<Vec<u8>>,
    pub dependencies: Vec<Vec<u8>>,
    pub imports: Vec<ElfImport>,
    pub exports: Vec<Vec<u8>>,
    pub symbols: Vec<ElfSymbol>,
    pub build_id: Option<Vec<u8>>,
    pub gnu_stack_executable: Vec<bool>,
    pub gnu_relro_segments: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileInspection {
    pub kind: InputKind,
    pub size_bytes: u64,
    pub content: ContentKind,
    pub elf: Option<ElfInspection>,
}

pub fn inspect_file(path: &Path, max_bytes_read: u64) -> Result<FileInspection, InputError> {
    inspect_file_with_limits(path, max_bytes_read, DEFAULT_MAX_ENTRIES)
}

pub fn inspect_file_with_limits(
    path: &Path,
    max_bytes_read: u64,
    max_entries: u64,
) -> Result<FileInspection, InputError> {
    let InputDetection {
        kind,
        size_bytes,
        file,
        sample,
    } = detect_input_bounded(path, max_bytes_read)?;
    let Some(size_bytes) = size_bytes else {
        return Err(InputError::UnsupportedType {
            path: path.to_path_buf(),
        });
    };
    let content = match kind {
        InputKind::Text => ContentKind::Text,
        InputKind::Directory | InputKind::Elf | InputKind::Pe | InputKind::UnknownBinary => {
            ContentKind::Binary
        }
    };

    let elf = if kind == InputKind::Elf {
        let file = file.ok_or_else(|| InputError::Changed {
            path: path.to_path_buf(),
        })?;
        Some(inspect_elf_file(
            file,
            sample,
            size_bytes,
            max_bytes_read,
            max_entries,
            path,
        )?)
    } else {
        None
    };

    Ok(FileInspection {
        kind,
        size_bytes,
        content,
        elf,
    })
}

fn inspect_elf_file(
    mut file: File,
    sample: Vec<u8>,
    size_bytes: u64,
    max_bytes_read: u64,
    max_entries: u64,
    path: &Path,
) -> Result<ElfInspection, InputError> {
    if size_bytes > MAX_ELF_FILE_BYTES {
        return Err(InputError::LimitExceeded {
            resource: "ELF file size",
            limit: MAX_ELF_FILE_BYTES,
        });
    }
    if size_bytes > max_bytes_read {
        return Err(InputError::LimitExceeded {
            resource: "bytes read",
            limit: max_bytes_read,
        });
    }
    if sample.len() as u64 > size_bytes {
        return Err(InputError::Changed {
            path: path.to_path_buf(),
        });
    }
    if (sample.len() as u64) < size_bytes.min(8 * 1024) {
        return Err(InputError::Changed {
            path: path.to_path_buf(),
        });
    }
    let data_len = usize::try_from(size_bytes).map_err(|_| InputError::LimitExceeded {
        resource: "ELF file size",
        limit: MAX_ELF_FILE_BYTES,
    })?;
    let mut data = sample;
    let sample_len = data.len();
    data.try_reserve_exact(data_len.saturating_sub(data.len()))
        .map_err(|_| InputError::LimitExceeded {
            resource: "ELF memory",
            limit: MAX_ELF_FILE_BYTES,
        })?;
    data.resize(data_len, 0);
    if let Err(source) = file.read_exact(&mut data[sample_len..]) {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            return Err(InputError::Changed {
                path: path.to_path_buf(),
            });
        }
        return Err(InputError::Io {
            operation: "read input",
            path: path.to_path_buf(),
            source,
        });
    }

    let metadata = file.metadata().map_err(|source| InputError::Io {
        operation: "revalidate input",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() != size_bytes {
        return Err(InputError::Changed {
            path: path.to_path_buf(),
        });
    }

    elf::inspect(&data, max_entries, path)
}
