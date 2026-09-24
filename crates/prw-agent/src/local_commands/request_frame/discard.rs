//! Provider-neutral disposition of outstanding Requests on connection discard.
//!
//! Phase 035 does not close a transport. It only extracts bounded correlation
//! state so outstanding Requests are surfaced as abandoned rather than silently
//! completed or retried.

use crate::LocalIpcRequestId;

use super::send_state::LocalConnectionSendState;
use crate::local_commands::request_tracker::LocalRequestTracker;

/// Result of discarding one future local IPC connection's Request state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalConnectionDiscardDisposition {
    was_write_poisoned: bool,
    abandoned_request_ids: Vec<LocalIpcRequestId>,
}

impl LocalConnectionDiscardDisposition {
    /// Returns whether the discarded connection state had been write-poisoned.
    #[must_use]
    pub const fn was_write_poisoned(&self) -> bool {
        self.was_write_poisoned
    }

    /// Returns all Requests abandoned by connection discard in registration order.
    #[must_use]
    pub fn abandoned_request_ids(&self) -> &[LocalIpcRequestId] {
        &self.abandoned_request_ids
    }

    /// Returns the number of abandoned Requests.
    #[must_use]
    pub const fn abandoned_count(&self) -> usize {
        self.abandoned_request_ids.len()
    }

    /// Returns whether no outstanding Requests were abandoned.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.abandoned_request_ids.is_empty()
    }
}

/// Extracts all outstanding Request IDs as abandoned connection-discard state.
///
/// The tracker is left empty. This function does not classify any Request as a
/// successful terminal completion and does not retry any Request.
#[must_use]
pub fn discard_local_connection_request_state(
    send_state: LocalConnectionSendState,
    tracker: &mut LocalRequestTracker,
) -> LocalConnectionDiscardDisposition {
    LocalConnectionDiscardDisposition {
        was_write_poisoned: send_state.is_write_poisoned(),
        abandoned_request_ids: tracker.abandon_all(),
    }
}

#[cfg(test)]
mod tests {
    use super::discard_local_connection_request_state;
    use crate::LocalIpcRequestId;
    use crate::local_commands::request_frame::send_state::LocalConnectionSendState;
    use crate::local_commands::request_tracker::{LocalRequestTracker, LocalRequestTrackerError};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    #[test]
    fn healthy_discard_surfaces_outstanding_ids_in_registration_order() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(170)).expect("first request registered");
        tracker
            .register(id(171))
            .expect("second request registered");

        let disposition =
            discard_local_connection_request_state(LocalConnectionSendState::Healthy, &mut tracker);

        assert!(!disposition.was_write_poisoned());
        assert_eq!(disposition.abandoned_request_ids(), &[id(170), id(171)]);
        assert_eq!(disposition.abandoned_count(), 2);
        assert!(!disposition.is_empty());
        assert!(tracker.is_empty());
    }

    #[test]
    fn poisoned_discard_reports_poison_and_preserves_ambiguous_id_for_caller() {
        let mut tracker = LocalRequestTracker::new();
        tracker
            .register(id(172))
            .expect("ambiguous request registered");

        let disposition = discard_local_connection_request_state(
            LocalConnectionSendState::WritePoisoned,
            &mut tracker,
        );

        assert!(disposition.was_write_poisoned());
        assert_eq!(disposition.abandoned_request_ids(), &[id(172)]);
        assert!(tracker.is_empty());
    }

    #[test]
    fn empty_discard_is_explicit_and_stable() {
        let mut tracker = LocalRequestTracker::new();

        let disposition =
            discard_local_connection_request_state(LocalConnectionSendState::Healthy, &mut tracker);

        assert!(disposition.is_empty());
        assert_eq!(disposition.abandoned_count(), 0);
        assert!(tracker.is_empty());
    }

    #[test]
    fn abandoned_id_is_not_recorded_as_completed() {
        let mut tracker = LocalRequestTracker::new();
        tracker.register(id(173)).expect("request registered");
        let disposition =
            discard_local_connection_request_state(LocalConnectionSendState::Healthy, &mut tracker);

        assert_eq!(disposition.abandoned_request_ids(), &[id(173)]);
        assert_eq!(
            tracker.complete(id(173)),
            Err(LocalRequestTrackerError::UnknownRequestId)
        );
    }
}
