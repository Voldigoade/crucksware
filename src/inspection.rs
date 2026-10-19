use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

use crate::input::{
    InputDetection, InputError, InputKind, InputStamp, detect_input_bounded_with_progress,
    detect_open_file_bounded, revalidate_input_file,
};
use crate::progress::{ProgressEvent, ProgressPhase, emit};

mod elf;
mod pe;

pub const MAX_ELF_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_PE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FORMAT_FILE_BYTES: u64 = if MAX_ELF_FILE_BYTES > MAX_PE_FILE_BYTES {
    MAX_ELF_FILE_BYTES
} else {
    MAX_PE_FILE_BYTES
};
pub const DEFAULT_MAX_BYTES_READ: u64 = MAX_FORMAT_FILE_BYTES + 8 * 1024 + 4;
pub const DEFAULT_MAX_ENTRIES: u64 = 100_000;

const ELF_FILE_LIMIT: FormatFileLimit = FormatFileLimit {
    max_bytes: MAX_ELF_FILE_BYTES,
    resource: "ELF file size",
};
const PE_FILE_LIMIT: FormatFileLimit = FormatFileLimit {
    max_bytes: MAX_PE_FILE_BYTES,
    resource: "PE file size",
};

#[derive(Clone, Copy)]
struct FormatFileLimit {
    max_bytes: u64,
    resource: &'static str,
}

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
    pub(crate) entries_read: u64,
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
pub struct PeSection {
    pub name: Vec<u8>,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeCertificateTable {
    pub file_offset: u32,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PeImportName {
    Name(Vec<u8>),
    Ordinal(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeImport {
    pub library: Vec<u8>,
    pub name: PeImportName,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeExport {
    pub ordinal: u16,
    pub name: Option<Vec<u8>>,
    pub target: PeExportTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeExportTarget {
    Address(u32),
    ForwardedName { library: Vec<u8>, name: Vec<u8> },
    ForwardedOrdinal { library: Vec<u8>, ordinal: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PeResourceId {
    Name(Vec<u8>),
    Id(u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeResource {
    pub path: Vec<PeResourceId>,
    pub data_rva: u32,
    pub size: u32,
    pub code_page: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PePdbInfo {
    pub path: Vec<u8>,
    pub guid: [u8; 16],
    pub age: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeInspection {
    pub(crate) entries_read: u64,
    pub format: &'static str,
    pub architecture: String,
    pub machine: u16,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub subsystem: u16,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub delay_imports: Vec<PeImport>,
    pub exports: Vec<PeExport>,
    pub resources: Vec<PeResource>,
    pub pdb_info: Option<PePdbInfo>,
    pub certificate_table: Option<PeCertificateTable>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileInspection {
    pub kind: InputKind,
    pub size_bytes: u64,
    pub bytes_read: u64,
    pub(crate) semantic_entries: u64,
    pub(crate) input_stamp: Option<InputStamp>,
    pub content: ContentKind,
    pub elf: Option<ElfInspection>,
    pub pe: Option<PeInspection>,
}

pub fn inspect_file(path: &Path, max_bytes_read: u64) -> Result<FileInspection, InputError> {
    inspect_file_with_limits(path, max_bytes_read, DEFAULT_MAX_ENTRIES)
}

pub fn inspect_file_with_limits(
    path: &Path,
    max_bytes_read: u64,
    max_entries: u64,
) -> Result<FileInspection, InputError> {
    inspect_file_inner(
        path,
        max_bytes_read,
        max_entries,
        &mut None::<fn(ProgressEvent)>,
    )
}

pub fn inspect_file_with_progress(
    path: &Path,
    max_bytes_read: u64,
    max_entries: u64,
    progress: impl FnMut(ProgressEvent),
) -> Result<FileInspection, InputError> {
    let mut progress = Some(progress);
    let phase = ProgressPhase::Inspection;
    emit(
        &mut progress,
        ProgressEvent::PhaseStarted { phase, total: None },
    );
    let inspection = inspect_file_inner(path, max_bytes_read, max_entries, &mut progress)?;
    emit(
        &mut progress,
        ProgressEvent::BytesRead {
            total_bytes_read: inspection.bytes_read,
        },
    );
    emit(&mut progress, ProgressEvent::PhaseCompleted { phase });
    Ok(inspection)
}

pub(crate) fn inspect_open_file_with_limits(
    path: &Path,
    file: File,
    max_bytes_read: u64,
    max_entries: u64,
) -> Result<FileInspection, InputError> {
    let detection = detect_open_file_bounded(path, file, max_bytes_read)?;
    inspect_detection(
        path,
        detection,
        max_bytes_read,
        max_entries,
        &mut None::<fn(ProgressEvent)>,
    )
}

pub(crate) fn inspect_file_inner<F>(
    path: &Path,
    max_bytes_read: u64,
    max_entries: u64,
    progress: &mut Option<F>,
) -> Result<FileInspection, InputError>
where
    F: FnMut(ProgressEvent),
{
    let detection = detect_input_bounded_with_progress(path, max_bytes_read, progress)?;
    inspect_detection(path, detection, max_bytes_read, max_entries, progress)
}

fn inspect_detection<F>(
    path: &Path,
    detection: InputDetection,
    max_bytes_read: u64,
    max_entries: u64,
    progress: &mut Option<F>,
) -> Result<FileInspection, InputError>
where
    F: FnMut(ProgressEvent),
{
    let InputDetection {
        kind,
        size_bytes,
        bytes_read,
        file,
        sample,
        pe_signature_probe,
        stamp,
    } = detection;
    let Some(size_bytes) = size_bytes else {
        return Err(InputError::UnsupportedType {
            path: path.to_path_buf(),
        });
    };
    let Some(stamp) = stamp else {
        return Err(InputError::Changed {
            path: path.to_path_buf(),
        });
    };
    let content = match kind {
        InputKind::Text => ContentKind::Text,
        InputKind::Directory | InputKind::Elf | InputKind::Pe | InputKind::UnknownBinary => {
            ContentKind::Binary
        }
    };

    let (elf, pe, bytes_read) = match kind {
        InputKind::Elf => {
            let file = file.ok_or_else(|| InputError::Changed {
                path: path.to_path_buf(),
            })?;
            let read = read_format_file(
                FormatFileRead {
                    file,
                    sample,
                    bytes_already_read: bytes_read,
                    size_bytes,
                    signature_probe: None,
                    stamp: stamp.clone(),
                },
                max_bytes_read,
                ELF_FILE_LIMIT,
                path,
                progress,
            )?;
            (
                Some(elf::inspect(&read.data, max_entries, path)?),
                None,
                read.bytes_read,
            )
        }
        InputKind::Pe => {
            let file = file.ok_or_else(|| InputError::Changed {
                path: path.to_path_buf(),
            })?;
            let read = read_format_file(
                FormatFileRead {
                    file,
                    sample,
                    bytes_already_read: bytes_read,
                    size_bytes,
                    signature_probe: pe_signature_probe,
                    stamp: stamp.clone(),
                },
                max_bytes_read,
                PE_FILE_LIMIT,
                path,
                progress,
            )?;
            (
                None,
                Some(pe::inspect(&read.data, max_entries, path)?),
                read.bytes_read,
            )
        }
        _ => {
            let file = file.as_ref().ok_or_else(|| InputError::Changed {
                path: path.to_path_buf(),
            })?;
            revalidate_input_file(file, path, &stamp)?;
            (None, None, bytes_read)
        }
    };
    let semantic_entries = elf
        .as_ref()
        .map_or(0, |inspection| inspection.entries_read)
        .checked_add(pe.as_ref().map_or(0, |inspection| inspection.entries_read))
        .ok_or(InputError::LimitExceeded {
            resource: "semantic entries",
            limit: max_entries,
        })?;

    Ok(FileInspection {
        kind,
        size_bytes,
        bytes_read,
        semantic_entries,
        input_stamp: Some(stamp),
        content,
        elf,
        pe,
    })
}

struct FormatFileRead {
    file: File,
    sample: Vec<u8>,
    bytes_already_read: u64,
    size_bytes: u64,
    signature_probe: Option<crate::input::PeSignatureProbe>,
    stamp: InputStamp,
}

struct FormatFileContent {
    data: Vec<u8>,
    bytes_read: u64,
}

struct ProgressRead<'a, F> {
    events: &'a mut Option<F>,
    bytes_already_read: u64,
    max_bytes_read: u64,
    additional_bytes_read: &'a mut u64,
}

fn read_format_file<F>(
    input: FormatFileRead,
    max_bytes_read: u64,
    file_limit: FormatFileLimit,
    path: &Path,
    progress: &mut Option<F>,
) -> Result<FormatFileContent, InputError>
where
    F: FnMut(ProgressEvent),
{
    let FormatFileRead {
        mut file,
        sample,
        bytes_already_read,
        size_bytes,
        signature_probe,
        stamp,
    } = input;
    if size_bytes > file_limit.max_bytes {
        return Err(InputError::LimitExceeded {
            resource: file_limit.resource,
            limit: file_limit.max_bytes,
        });
    }
    if sample.len() as u64 > size_bytes {
        return Err(InputError::Changed {
            path: path.to_path_buf(),
        });
    }
    let sample_len = sample.len() as u64;
    let probe_end = signature_probe
        .map(|probe| {
            probe
                .offset
                .checked_add(probe.bytes.len() as u64)
                .ok_or_else(|| InputError::Changed {
                    path: path.to_path_buf(),
                })
        })
        .transpose()?;
    if probe_end.is_some_and(|end| end > size_bytes) {
        return Err(InputError::Changed {
            path: path.to_path_buf(),
        });
    }
    let probe_bytes_after_sample = signature_probe
        .zip(probe_end)
        .map(|(probe, end)| end.saturating_sub(probe.offset.max(sample_len)))
        .unwrap_or(0);
    let additional_bytes = size_bytes
        .checked_sub(sample_len)
        .and_then(|remaining| remaining.checked_sub(probe_bytes_after_sample))
        .ok_or_else(|| InputError::Changed {
            path: path.to_path_buf(),
        })?;
    let total_bytes_read =
        bytes_already_read
            .checked_add(additional_bytes)
            .ok_or(InputError::LimitExceeded {
                resource: "bytes read",
                limit: max_bytes_read,
            })?;
    if total_bytes_read > max_bytes_read {
        return Err(InputError::LimitExceeded {
            resource: "bytes read",
            limit: max_bytes_read,
        });
    }
    let data_len = usize::try_from(size_bytes).map_err(|_| InputError::LimitExceeded {
        resource: file_limit.resource,
        limit: file_limit.max_bytes,
    })?;
    let mut data = sample;
    let sample_len = data.len();
    data.try_reserve_exact(data_len.saturating_sub(data.len()))
        .map_err(|_| InputError::LimitExceeded {
            resource: "input memory",
            limit: file_limit.max_bytes,
        })?;
    data.resize(data_len, 0);
    let mut additional_bytes_read = 0_u64;
    let mut progress_read = ProgressRead {
        events: progress,
        bytes_already_read,
        max_bytes_read,
        additional_bytes_read: &mut additional_bytes_read,
    };
    if let Some(probe) = signature_probe {
        let start = usize::try_from(probe.offset).map_err(|_| InputError::Changed {
            path: path.to_path_buf(),
        })?;
        let end = start
            .checked_add(probe.bytes.len())
            .ok_or_else(|| InputError::Changed {
                path: path.to_path_buf(),
            })?;
        if end > data.len() {
            return Err(InputError::Changed {
                path: path.to_path_buf(),
            });
        }
        let copy_end = end.max(sample_len);
        read_file_range(
            &mut file,
            &mut data,
            sample_len..start.max(sample_len),
            path,
            &mut progress_read,
        )?;
        data[start..end].copy_from_slice(&probe.bytes);
        let data_len = data.len();
        read_file_range(
            &mut file,
            &mut data,
            copy_end..data_len,
            path,
            &mut progress_read,
        )?;
    } else {
        let data_len = data.len();
        read_file_range(
            &mut file,
            &mut data,
            sample_len..data_len,
            path,
            &mut progress_read,
        )?;
    }

    revalidate_input_file(&file, path, &stamp)?;

    Ok(FormatFileContent {
        data,
        bytes_read: total_bytes_read,
    })
}

fn read_file_range<F>(
    file: &mut File,
    data: &mut [u8],
    mut range: std::ops::Range<usize>,
    path: &Path,
    progress: &mut ProgressRead<'_, F>,
) -> Result<(), InputError>
where
    F: FnMut(ProgressEvent),
{
    if range.is_empty() {
        return Ok(());
    }
    file.seek(SeekFrom::Start(range.start as u64))
        .map_err(|source| InputError::Io {
            operation: "read input",
            path: path.to_path_buf(),
            source,
        })?;
    if progress.events.is_none() {
        read_exact_input(file, &mut data[range], path)?;
        return Ok(());
    }

    const PROGRESS_CHUNK_BYTES: usize = 64 * 1024;
    while !range.is_empty() {
        let end = range.start + range.len().min(PROGRESS_CHUNK_BYTES);
        read_exact_input(file, &mut data[range.start..end], path)?;
        let chunk_bytes = (end - range.start) as u64;
        *progress.additional_bytes_read = progress
            .additional_bytes_read
            .checked_add(chunk_bytes)
            .ok_or(InputError::LimitExceeded {
            resource: "bytes read",
            limit: progress.max_bytes_read,
        })?;
        let total_bytes_read = progress
            .bytes_already_read
            .checked_add(*progress.additional_bytes_read)
            .filter(|total| *total <= progress.max_bytes_read)
            .ok_or(InputError::LimitExceeded {
                resource: "bytes read",
                limit: progress.max_bytes_read,
            })?;
        emit(
            progress.events,
            ProgressEvent::BytesRead { total_bytes_read },
        );
        range.start = end;
    }
    Ok(())
}

fn read_exact_input(file: &mut File, buffer: &mut [u8], path: &Path) -> Result<(), InputError> {
    if let Err(source) = file.read_exact(buffer) {
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
    Ok(())
}
