//! Agent-internal policy admission for a registry-validated requester/rendezvous start.
//!
//! C03e-DK materializes only the C03e-DJ-selected dedicated policy gate after C03e-DI
//! current-registry validation. It does not select a runtime policy source, authenticate a new
//! principal, mutate requester/rendezvous provider state, handle wire commands, inspect transport
//! readiness, perform I/O, activate networking, or deploy anything.

use std::fmt;

use prw_policy::{Capability, Decision, PolicyEvaluator};

use super::registry_validation::RegistryValidatedRequesterRendezvousStart;

/// One registry-validated requester/rendezvous start that passed the dedicated policy capability.
///
/// This owned value deliberately contains the already-validated provenance carrier as one private
/// nested value. It is neither `Copy` nor `Clone`, has no constructor from raw identity values, and
/// is not requester/rendezvous provider registration authority, transport readiness, live-owner
/// authority, candidate-publication authority, a lease/currentness guarantee, or network reachability.
pub struct PolicyAuthorizedRequesterRendezvousStart {
    registry_validated: RegistryValidatedRequesterRendezvousStart,
}

impl PolicyAuthorizedRequesterRendezvousStart {
    /// Returns borrowed access to the exact registry-validated provenance admitted by policy.
    #[must_use]
    pub const fn registry_validated(&self) -> &RegistryValidatedRequesterRendezvousStart {
        &self.registry_validated
    }
}

/// Stable failure for the dedicated requester/rendezvous-start policy gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousStartPolicyAuthorizationError {
    /// The evaluator denied the exact dedicated requester/rendezvous-start capability.
    Denied,
}

impl fmt::Display for RequesterRendezvousStartPolicyAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied => formatter.write_str("requester rendezvous start policy denied"),
        }
    }
}

impl std::error::Error for RequesterRendezvousStartPolicyAuthorizationError {}

fn requester_rendezvous_start_policy_decision<E: PolicyEvaluator + ?Sized>(
    evaluator: &E,
) -> Decision {
    evaluator.evaluate(Capability::RequesterRendezvousStart)
}

/// Applies the dedicated requester/rendezvous-start policy gate to validated provenance.
///
/// The evaluator must already be selected and bound by the caller to the same authenticated
/// requester principal represented by `registry_validated`. This function does not perform that
/// binding. It evaluates exactly one capability and performs no provider mutation or I/O.
///
/// # Errors
///
/// Returns [`RequesterRendezvousStartPolicyAuthorizationError::Denied`] when the exact dedicated
/// capability is not allowed. Denial produces no policy-authorized carrier.
pub fn policy_authorize_requester_rendezvous_start<E: PolicyEvaluator + ?Sized>(
    registry_validated: RegistryValidatedRequesterRendezvousStart,
    evaluator: &E,
) -> Result<
    PolicyAuthorizedRequesterRendezvousStart,
    RequesterRendezvousStartPolicyAuthorizationError,
> {
    match requester_rendezvous_start_policy_decision(evaluator) {
        Decision::Allow => Ok(PolicyAuthorizedRequesterRendezvousStart { registry_validated }),
        Decision::Deny => Err(RequesterRendezvousStartPolicyAuthorizationError::Denied),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use prw_policy::{Capability, Decision, PolicyEvaluator};

    use super::{
        PolicyAuthorizedRequesterRendezvousStart, RequesterRendezvousStartPolicyAuthorizationError,
        policy_authorize_requester_rendezvous_start, requester_rendezvous_start_policy_decision,
    };
    use crate::candidate_publication_requester_rendezvous_start_intent::registry_validation::RegistryValidatedRequesterRendezvousStart;

    struct ExactCapabilityPolicy {
        decision: Decision,
        calls: Cell<usize>,
    }

    impl ExactCapabilityPolicy {
        const fn new(decision: Decision) -> Self {
            Self {
                decision,
                calls: Cell::new(0),
            }
        }
    }

    impl PolicyEvaluator for ExactCapabilityPolicy {
        fn evaluate(&self, capability: Capability) -> Decision {
            assert_eq!(capability, Capability::RequesterRendezvousStart);
            self.calls.set(self.calls.get() + 1);
            self.decision
        }
    }

    fn assert_admission_signature(
        admission: fn(
            RegistryValidatedRequesterRendezvousStart,
            &ExactCapabilityPolicy,
        ) -> Result<
            PolicyAuthorizedRequesterRendezvousStart,
            RequesterRendezvousStartPolicyAuthorizationError,
        >,
    ) {
        let _ = admission;
    }

    #[test]
    fn admission_surface_has_selected_consuming_typed_shape() {
        assert_admission_signature(
            policy_authorize_requester_rendezvous_start::<ExactCapabilityPolicy>,
        );
    }

    #[test]
    fn policy_decision_uses_exact_dedicated_capability_once() {
        let allow = ExactCapabilityPolicy::new(Decision::Allow);
        assert_eq!(
            requester_rendezvous_start_policy_decision(&allow),
            Decision::Allow
        );
        assert_eq!(allow.calls.get(), 1);

        let deny = ExactCapabilityPolicy::new(Decision::Deny);
        assert_eq!(
            requester_rendezvous_start_policy_decision(&deny),
            Decision::Deny
        );
        assert_eq!(deny.calls.get(), 1);
    }

    #[test]
    fn denial_error_is_bounded_and_non_authoritative() {
        assert_eq!(
            RequesterRendezvousStartPolicyAuthorizationError::Denied.to_string(),
            "requester rendezvous start policy denied"
        );
    }
}
