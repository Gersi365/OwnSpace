//! Pure bridge-owned PRWC request-ID custody for one live connection context.
//!
//! This module owns only the bounded in-memory lifecycle selected by Phase 152 C03e-BY.
//! It performs no I/O, authentication, routing, timeout, retry, persistence, or runtime work.

use std::fmt;

/// Maximum simultaneously outstanding locally originated PRWC requests on one connection.
pub const PRWC_MAX_OUTSTANDING_REQUESTS: usize = 64;

/// Connection-local custody for locally originated PRWC request identifiers.
///
/// Allocated identifiers are monotonic, non-zero `u64` values and are never reused during
/// the lifetime of this custody instance, even after completion or abandonment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrwcRequestIdLifecycle {
    next_request_id: Option<u64>,
    outstanding: Vec<u64>,
}

impl PrwcRequestIdLifecycle {
    /// Creates a fresh connection-local request-ID namespace beginning at `1`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_request_id: Some(1),
            outstanding: Vec::new(),
        }
    }

    /// Allocates and atomically registers one locally originated request identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PrwcRequestIdLifecycleError::OutstandingBoundReached`] when 64 requests are
    /// already outstanding, [`PrwcRequestIdLifecycleError::RequestIdSpaceExhausted`] after the
    /// final `u64` identifier has been allocated, or
    /// [`PrwcRequestIdLifecycleError::InternalRequestIdCollision`] if the monotonic allocator
    /// ever observes an identifier that is already outstanding.
    pub fn allocate(&mut self) -> Result<u64, PrwcRequestIdLifecycleError> {
        if self.outstanding.len() >= PRWC_MAX_OUTSTANDING_REQUESTS {
            return Err(PrwcRequestIdLifecycleError::OutstandingBoundReached);
        }

        let request_id = self
            .next_request_id
            .ok_or(PrwcRequestIdLifecycleError::RequestIdSpaceExhausted)?;
        if self.outstanding.contains(&request_id) {
            return Err(PrwcRequestIdLifecycleError::InternalRequestIdCollision);
        }

        self.outstanding.push(request_id);
        self.next_request_id = request_id.checked_add(1);
        Ok(request_id)
    }

    /// Completes one outstanding locally originated request exactly once.
    ///
    /// Completion removes the identifier from the outstanding set but never makes it reusable
    /// on the same connection-local lifecycle instance.
    ///
    /// # Errors
    ///
    /// Returns [`PrwcRequestIdLifecycleError::UnknownRequestId`] when the identifier is not
    /// currently outstanding, including duplicate terminal completion.
    pub fn complete(&mut self, request_id: u64) -> Result<(), PrwcRequestIdLifecycleError> {
        let position = self
            .outstanding
            .iter()
            .position(|candidate| *candidate == request_id)
            .ok_or(PrwcRequestIdLifecycleError::UnknownRequestId)?;
        self.outstanding.remove(position);
        Ok(())
    }

    /// Abandons every still-outstanding request identifier in allocation order.
    ///
    /// This is connection-discard/shutdown cleanup, not successful terminal completion. The
    /// returned identifiers remain available to a later runtime layer for explicit disposition.
    #[must_use]
    pub fn abandon_all(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.outstanding)
    }

    /// Returns whether one identifier is currently outstanding.
    #[must_use]
    pub fn contains(&self, request_id: u64) -> bool {
        self.outstanding.contains(&request_id)
    }

    /// Returns the number of currently outstanding identifiers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.outstanding.len()
    }

    /// Returns whether no identifiers are currently outstanding.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }
}

impl Default for PrwcRequestIdLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

/// Fail-closed PRWC request-ID lifecycle transition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrwcRequestIdLifecycleError {
    /// The per-connection bound of outstanding locally originated requests is already reached.
    OutstandingBoundReached,
    /// Every non-zero `u64` identifier in this connection-local namespace has been consumed.
    RequestIdSpaceExhausted,
    /// A terminal response/error references an identifier that is not currently outstanding.
    UnknownRequestId,
    /// The monotonic allocator detected an impossible outstanding-ID collision.
    InternalRequestIdCollision,
}

impl fmt::Display for PrwcRequestIdLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::OutstandingBoundReached => "PRWC outstanding request bound reached",
            Self::RequestIdSpaceExhausted => "PRWC request id space exhausted",
            Self::UnknownRequestId => "PRWC terminal frame references an unknown request id",
            Self::InternalRequestIdCollision => "PRWC request id allocator detected a collision",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PrwcRequestIdLifecycleError {}

#[cfg(test)]
mod tests {
    use super::{
        PRWC_MAX_OUTSTANDING_REQUESTS, PrwcRequestIdLifecycle, PrwcRequestIdLifecycleError,
    };

    #[test]
    fn fresh_lifecycle_allocates_monotonic_non_zero_ids() {
        let mut lifecycle = PrwcRequestIdLifecycle::new();

        assert_eq!(lifecycle.allocate(), Ok(1));
        assert_eq!(lifecycle.allocate(), Ok(2));
        assert_eq!(lifecycle.allocate(), Ok(3));
        assert_eq!(lifecycle.len(), 3);
        assert!(lifecycle.contains(1));
        assert!(lifecycle.contains(2));
        assert!(lifecycle.contains(3));
    }

    #[test]
    fn completion_is_terminal_and_does_not_reuse_id() {
        let mut lifecycle = PrwcRequestIdLifecycle::new();
        assert_eq!(lifecycle.allocate(), Ok(1));
        assert_eq!(lifecycle.complete(1), Ok(()));
        assert!(lifecycle.is_empty());

        assert_eq!(lifecycle.allocate(), Ok(2));
        assert_eq!(
            lifecycle.complete(1),
            Err(PrwcRequestIdLifecycleError::UnknownRequestId)
        );
    }

    #[test]
    fn outstanding_bound_fails_before_mutating_state() {
        let mut lifecycle = PrwcRequestIdLifecycle::new();
        for expected in 1_u64..=PRWC_MAX_OUTSTANDING_REQUESTS as u64 {
            assert_eq!(lifecycle.allocate(), Ok(expected));
        }

        assert_eq!(
            lifecycle.allocate(),
            Err(PrwcRequestIdLifecycleError::OutstandingBoundReached)
        );
        assert_eq!(lifecycle.len(), PRWC_MAX_OUTSTANDING_REQUESTS);
        assert!(!lifecycle.contains(65));
    }

    #[test]
    fn completed_slots_allow_more_allocations_without_reuse() {
        let mut lifecycle = PrwcRequestIdLifecycle::new();
        for expected in 1_u64..=PRWC_MAX_OUTSTANDING_REQUESTS as u64 {
            assert_eq!(lifecycle.allocate(), Ok(expected));
        }
        lifecycle.complete(1).expect("known request completes");

        assert_eq!(lifecycle.allocate(), Ok(65));
        assert!(!lifecycle.contains(1));
        assert!(lifecycle.contains(65));
    }

    #[test]
    fn unknown_and_duplicate_completion_fail_closed() {
        let mut lifecycle = PrwcRequestIdLifecycle::new();
        assert_eq!(
            lifecycle.complete(7),
            Err(PrwcRequestIdLifecycleError::UnknownRequestId)
        );

        assert_eq!(lifecycle.allocate(), Ok(1));
        assert_eq!(lifecycle.complete(1), Ok(()));
        assert_eq!(
            lifecycle.complete(1),
            Err(PrwcRequestIdLifecycleError::UnknownRequestId)
        );
    }

    #[test]
    fn abandon_all_returns_all_outstanding_ids_and_preserves_no_reuse() {
        let mut lifecycle = PrwcRequestIdLifecycle::new();
        assert_eq!(lifecycle.allocate(), Ok(1));
        assert_eq!(lifecycle.allocate(), Ok(2));
        assert_eq!(lifecycle.allocate(), Ok(3));
        lifecycle.complete(2).expect("known request completes");

        assert_eq!(lifecycle.abandon_all(), vec![1, 3]);
        assert!(lifecycle.is_empty());
        assert_eq!(lifecycle.allocate(), Ok(4));
    }

    #[test]
    fn final_u64_id_is_allocated_once_then_space_is_exhausted() {
        let mut lifecycle = PrwcRequestIdLifecycle {
            next_request_id: Some(u64::MAX),
            outstanding: Vec::new(),
        };

        assert_eq!(lifecycle.allocate(), Ok(u64::MAX));
        lifecycle
            .complete(u64::MAX)
            .expect("final allocated id can complete");
        assert_eq!(
            lifecycle.allocate(),
            Err(PrwcRequestIdLifecycleError::RequestIdSpaceExhausted)
        );
    }

    #[test]
    fn internal_collision_fails_without_mutation() {
        let mut lifecycle = PrwcRequestIdLifecycle {
            next_request_id: Some(9),
            outstanding: vec![9],
        };

        assert_eq!(
            lifecycle.allocate(),
            Err(PrwcRequestIdLifecycleError::InternalRequestIdCollision)
        );
        assert_eq!(lifecycle.outstanding, vec![9]);
        assert_eq!(lifecycle.next_request_id, Some(9));
    }
}
