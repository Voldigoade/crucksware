use std::{fmt, io, path::PathBuf};

use crate::{input::InputError, path::encode_bytes};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Old,
    New,
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Old => "old",
            Self::New => "new",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resource {
    Entries,
    Depth,
    PathBytes,
    BytesRead,
    SourceFileBytes,
    SourceFactBytes,
    SourceLines,
    SourceNodes,
    SourceParseWork,
    SourceQueryWork,
    SourceRecords,
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Entries => "entries",
            Self::Depth => "depth",
            Self::PathBytes => "path bytes",
            Self::BytesRead => "bytes read",
            Self::SourceFileBytes => "source file byte",
            Self::SourceFactBytes => "source fact byte",
            Self::SourceLines => "source line",
            Self::SourceNodes => "source syntax node",
            Self::SourceParseWork => "source parse work",
            Self::SourceQueryWork => "source query work",
            Self::SourceRecords => "source record",
        })
    }
}

#[derive(Debug)]
pub enum DiffError {
    Io {
        operation: &'static str,
        side: Side,
        path: PathBuf,
        source: io::Error,
    },
    InvalidRelativePath,
    UnsupportedType {
        side: Side,
        path: PathBuf,
    },
    FilesystemBoundary {
        side: Side,
        path: PathBuf,
    },
    TreeChanged {
        side: Side,
        path: PathBuf,
    },
    LimitExceeded {
        resource: Resource,
        limit: u64,
    },
    SourceAnalysis {
        path: PathBuf,
        message: String,
    },
    InputInspection {
        side: Side,
        source: InputError,
    },
    UnsupportedPlatform,
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path_text = |path: &std::path::Path| encode_bytes(path.as_os_str().as_encoded_bytes());
        match self {
            Self::Io {
                operation,
                side,
                path,
                source,
            } => write!(f, "{side}: {operation} {}: {source}", path_text(path)),
            Self::InvalidRelativePath => f.write_str("invalid relative path"),
            Self::UnsupportedType { side, path } => {
                write!(f, "{side}: unsupported file type at {}", path_text(path))
            }
            Self::FilesystemBoundary { side, path } => {
                write!(f, "{side}: filesystem boundary at {}", path_text(path))
            }
            Self::TreeChanged { side, path } => {
                write!(f, "{side}: tree changed at {}", path_text(path))
            }
            Self::LimitExceeded { resource, limit } => {
                write!(f, "{resource} limit exceeded ({limit})")
            }
            Self::SourceAnalysis { path, message } => write!(
                f,
                "source analysis failed at {}: {message}",
                path_text(path)
            ),
            Self::InputInspection { side, source } => write!(f, "{side}: {source}"),
            Self::UnsupportedPlatform => f.write_str("comparison is supported only on Linux"),
        }
    }
}

impl std::error::Error for DiffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InputInspection { source, .. } => Some(source),
            _ => None,
        }
    }
}
