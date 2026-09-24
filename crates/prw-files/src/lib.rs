//! Typed file-management domain model.

use prw_core::TransferId;

/// File operation requested through the managed file API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileOperation {
    /// List a directory.
    List { path: String },
    /// Read metadata for a path.
    Stat { path: String },
    /// Read file bytes.
    Read { path: String },
    /// Write file bytes.
    Write { path: String },
    /// Copy a path.
    Copy { source: String, destination: String },
    /// Move a path on the same managed filesystem.
    Move { source: String, destination: String },
    /// Rename a path.
    Rename { source: String, destination: String },
    /// Create a directory.
    CreateDirectory { path: String },
    /// Delete a path.
    Delete { path: String },
}

/// Transfer lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Transfer has been accepted but has not started.
    Queued,
    /// Transfer is actively moving data.
    Running,
    /// Transfer is intentionally paused.
    Paused,
    /// Destination integrity is being verified.
    Verifying,
    /// Transfer and finalization succeeded.
    Completed,
    /// Transfer failed.
    Failed,
    /// Transfer was cancelled.
    Cancelled,
}

/// Minimal transfer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// Stable transfer identifier.
    pub id: TransferId,
    /// Current transfer lifecycle state.
    pub state: TransferState,
    /// Number of bytes successfully persisted so far.
    pub bytes_completed: u64,
    /// Expected total byte count when known.
    pub bytes_total: Option<u64>,
}

impl Transfer {
    /// Returns progress as a floating-point ratio when total size is known.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn progress_ratio(&self) -> Option<f64> {
        let total = self.bytes_total?;
        if total == 0 {
            return Some(1.0);
        }

        let bounded = self.bytes_completed.min(total);
        Some(bounded as f64 / total as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::{Transfer, TransferState};
    use prw_core::TransferId;

    #[test]
    fn progress_is_bounded_to_one() {
        let transfer = Transfer {
            id: TransferId::new("transfer-1").expect("valid transfer id"),
            state: TransferState::Running,
            bytes_completed: 150,
            bytes_total: Some(100),
        };

        assert_eq!(transfer.progress_ratio(), Some(1.0));
    }
}
