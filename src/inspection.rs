use std::path::Path;

use crate::input::{InputDetection, InputError, InputKind, detect_input_bounded};

pub const DEFAULT_MAX_BYTES_READ: u64 = 8 * 1024 + 4;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileInspection {
    pub kind: InputKind,
    pub size_bytes: u64,
    pub content: ContentKind,
}

pub fn inspect_file(path: &Path, max_bytes_read: u64) -> Result<FileInspection, InputError> {
    let InputDetection { kind, size_bytes } = detect_input_bounded(path, max_bytes_read)?;
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

    Ok(FileInspection {
        kind,
        size_bytes,
        content,
    })
}
