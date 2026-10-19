//! Experimental filesystem comparison core. The Rust API is not stable.

pub mod binary_compare;
pub mod error;
pub mod input;
pub mod inspection;
pub mod limits;
pub mod model;
pub mod path;
pub mod progress;

#[cfg(target_os = "linux")]
mod scan;

#[cfg(target_os = "linux")]
mod content;

#[cfg(target_os = "linux")]
mod compare;

#[cfg(target_os = "linux")]
pub use compare::{
    compare, compare_semantic_tree, compare_semantic_tree_with_progress, compare_with_progress,
};

#[cfg(not(target_os = "linux"))]
pub fn compare(
    _old: &std::path::Path,
    _new: &std::path::Path,
    _limits: limits::Limits,
) -> Result<model::Diff, error::DiffError> {
    Err(error::DiffError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub fn compare_with_progress<F>(
    _old: &std::path::Path,
    _new: &std::path::Path,
    _limits: limits::Limits,
    _progress: F,
) -> Result<model::Diff, error::DiffError>
where
    F: FnMut(progress::ProgressEvent),
{
    Err(error::DiffError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub fn compare_semantic_tree(
    _old: &std::path::Path,
    _new: &std::path::Path,
    _limits: limits::Limits,
    _max_source_file_bytes: u64,
) -> Result<semantic_tree::SemanticTreeDiff, error::DiffError> {
    Err(error::DiffError::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
pub fn compare_semantic_tree_with_progress<F>(
    _old: &std::path::Path,
    _new: &std::path::Path,
    _limits: limits::Limits,
    _max_source_file_bytes: u64,
    _progress: F,
) -> Result<semantic_tree::SemanticTreeDiff, error::DiffError>
where
    F: FnMut(progress::ProgressEvent),
{
    Err(error::DiffError::UnsupportedPlatform)
}

pub mod report;
pub mod semantic_tree;
pub mod source;
