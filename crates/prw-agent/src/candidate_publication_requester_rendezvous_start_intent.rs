//! Agent-internal non-authoritative requester/rendezvous start-intent carrier.
//!
//! C03e-DD materializes only the C03e-DC-selected semantic envelope. The requester session must
//! come from already-authenticated server-held operation state, while `target_device_id` remains
//! requester-nominated intent until separately gated registry/workspace/policy validation succeeds.
//! This module performs no validation, authorization, provider mutation, wire handling, I/O,
//! synchronization, task/listener activation, networking, readiness publication, or deployment.

#[allow(
    dead_code,
    reason = "C03e-DF materializes current-registry validation before separately gated consumers"
)]
#[path = "candidate_publication_requester_rendezvous_start_intent_registry_validation.rs"]
pub mod registry_validation;

#[allow(
    dead_code,
    reason = "C03e-DK materializes policy admission before separately gated provider composition"
)]
#[path = "candidate_publication_requester_rendezvous_start_intent_policy_admission.rs"]
pub mod policy_admission;

#[allow(
    dead_code,
    reason = "C03e-DP materializes requester-aware policy source before separately gated caller composition"
)]
#[path = "candidate_publication_requester_rendezvous_start_intent_policy_source.rs"]
pub mod policy_source;

#[allow(
    dead_code,
    reason = "C03e-DR materializes caller composition before separately gated runtime activation"
)]
#[path = "candidate_publication_requester_rendezvous_start_intent_composition.rs"]
pub mod composition;

use prw_core::DeviceId;
use prw_session::AuthenticatedDeviceSession;

/// One unvalidated requester-nominated logical rendezvous target.
///
/// This crate-private value carries no requester identity and confers no authorization or current
/// registration fact. A later separately gated authenticated-session adaptation may consume it
/// without reinterpreting the exact logical `DeviceId`.
pub struct RequesterRendezvousTargetIntent {
    target_device_id: DeviceId,
}

impl RequesterRendezvousTargetIntent {
    /// Retains exactly one explicit logical target without validation, authorization, or I/O.
    #[must_use]
    pub const fn new(target_device_id: DeviceId) -> Self {
        Self { target_device_id }
    }

    /// Returns the exact caller-nominated logical target without deriving any authority from it.
    #[must_use]
    pub const fn target_device_id(&self) -> &DeviceId {
        &self.target_device_id
    }

    /// Transfers ownership of the exact caller-nominated logical target without reinterpretation.
    #[must_use]
    pub fn into_target_device_id(self) -> DeviceId {
        self.target_device_id
    }
}

/// One unvalidated requester-side intent to begin rendezvous toward one logical target device.
///
/// This value is deliberately neither `Copy` nor `Clone`. Possession is not authorization or a
/// current-registration fact; later composition must separately establish requester currentness,
/// target eligibility, workspace relationship, and the exact policy decision before provider
/// mutation can be considered.
pub struct RequesterRendezvousStartIntent {
    requester_session: AuthenticatedDeviceSession,
    target_device_id: DeviceId,
}

impl RequesterRendezvousStartIntent {
    /// Packages already-authenticated server-held requester identity with nominated target intent.
    ///
    /// Construction performs ownership composition only. It does not validate registry state,
    /// evaluate policy, mutate requester/rendezvous authority, inspect transport identity, or
    /// perform I/O.
    #[must_use]
    pub const fn new(
        requester_session: AuthenticatedDeviceSession,
        target_device_id: DeviceId,
    ) -> Self {
        Self {
            requester_session,
            target_device_id,
        }
    }

    /// Returns the already-authenticated requester session carried by this unvalidated intent.
    #[must_use]
    pub const fn requester_session(&self) -> &AuthenticatedDeviceSession {
        &self.requester_session
    }

    /// Returns the requester-nominated logical target, which is not yet registration authority.
    #[must_use]
    pub const fn target_device_id(&self) -> &DeviceId {
        &self.target_device_id
    }
}
