use std::{fmt, io, path::PathBuf};

use crate::path::encode_bytes;

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
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Entries => "entries",
            Self::Depth => "depth",
            Self::PathBytes => "path bytes",
            Self::BytesRead => "bytes read",
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
            Self::UnsupportedPlatform => f.write_str("comparison is supported only on Linux"),
        }
    }
}

impl std::error::Error for DiffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
