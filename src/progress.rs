use crate::{error::Side, model::Category};

/// A comparison phase whose work can be observed through [`ProgressEvent`].
///
/// Inventory counts exclude the root directory. Revalidation counts include it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressPhase {
    /// Inspection of a single input.
    Inspection,
    /// Comparison of two regular files.
    FileComparison,
    /// Discovery of entries on one side of the comparison.
    Inventory(Side),
    /// Comparison of the unique paths found in either tree.
    Comparing,
    /// Final mutation checks for one side, including its root directory.
    Revalidation(Side),
    /// Text and source analysis of changed regular files.
    SourceAnalysis,
    /// Format analysis of changed files not classified as text source.
    BinaryAnalysis,
}

/// A path-free observation emitted by analysis and comparison operations.
///
/// Events remain valid partial observations if a later operation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressEvent {
    /// A phase has started. Inventory and comparison initially have no total.
    PhaseStarted {
        phase: ProgressPhase,
        /// A known work-unit count, when available at phase start.
        total: Option<u64>,
    },
    /// The comparison has calculated the phase's exact work-unit count.
    PhaseTotalKnown {
        phase: ProgressPhase,
        /// For comparison, the number of unique paths in either tree.
        total: u64,
    },
    /// Inventory found another non-root entry on this side.
    EntryDiscovered {
        side: Side,
        /// Cumulative number of entries found on this side.
        entries: u64,
    },
    /// A successful file read increased the shared comparison read total.
    BytesRead {
        /// Cumulative actual bytes read from both trees.
        total_bytes_read: u64,
    },
    /// The comparison classified and recorded another change.
    ///
    /// A later comparison or revalidation error can still fail the operation.
    ChangeDiscovered { category: Category },
    /// A bounded phase completed another work unit.
    ///
    /// Comparison units are unique paths. Revalidation units include the root.
    PhaseProgress {
        phase: ProgressPhase,
        completed: u64,
        total: u64,
    },
    /// A phase completed successfully.
    PhaseCompleted { phase: ProgressPhase },
}

pub(crate) fn emit<F>(progress: &mut Option<F>, event: ProgressEvent)
where
    F: FnMut(ProgressEvent),
{
    if let Some(progress) = progress.as_mut() {
        progress(event);
    }
}
