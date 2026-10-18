//! Experimental filesystem comparison core. The Rust API is not stable.

pub mod error;
pub mod limits;
pub mod model;
pub mod path;

#[cfg(target_os = "linux")]
mod scan;

#[cfg(target_os = "linux")]
mod content;

#[cfg(target_os = "linux")]
mod compare;

#[cfg(target_os = "linux")]
pub use compare::compare;

#[cfg(not(target_os = "linux"))]
pub fn compare(
    _old: &std::path::Path,
    _new: &std::path::Path,
    _limits: limits::Limits,
) -> Result<model::Diff, error::DiffError> {
    Err(error::DiffError::UnsupportedPlatform)
}

pub mod report;
