//! Agent-internal requester/rendezvous start validation-policy-registration composition.
//!
//! C03e-DR materializes only the C03e-DQ-selected synchronous composition across the existing DI
//! current-registry validator, DP requester-aware policy source, DK dedicated policy admission, and
//! DN private registration mutation owner. It does not materialize a concrete policy store, runtime
//! caller, wire handler, listener/task, networking, readiness publication, deployment, or merge.

use std::fmt;

use prw_registry::WorkspaceDeviceRegistry;
use prw_remote_bridge::requester_rendezvous_in_memory_provider::RequesterRendezvousLifecycleError;

use super::{
    RequesterRendezvousStartIntent,
    policy_admission::{
        RequesterRendezvousStartPolicyAuthorizationError,
        policy_authorize_requester_rendezvous_start,
    },
    policy_source::{
        RequesterRendezvousStartPolicySource, RequesterRendezvousStartPolicySourceError,
    },
    registry_validation::{
        RequesterRendezvousStartRegistryValidationError,
        validate_current_requester_rendezvous_start_intent,
    },
};
use crate::candidate_publication_requester_rendezvous_runtime::CandidatePublicationRequesterRendezvousRuntimeOwner;

/// Stable fail-closed failure across the requester/rendezvous start composition stages.
#[derive(Debug)]
#[non_exhaustive]
pub enum RequesterRendezvousStartCompositionError {
    /// DI current-registry validation failed before policy-source resolution.
    RegistryValidation(RequesterRendezvousStartRegistryValidationError),
    /// DP could not resolve authoritative policy for the exact validated requester.
    PolicySource(RequesterRendezvousStartPolicySourceError),
    /// DK denied the exact dedicated requester/rendezvous-start capability.
    PolicyAuthorization(RequesterRendezvousStartPolicyAuthorizationError),
    /// DN could not register the exact policy-authorized requester/rendezvous start.
    Registration(RequesterRendezvousLifecycleError),
}

impl fmt::Display for RequesterRendezvousStartCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryValidation(error) => write!(
                formatter,
                "requester rendezvous start composition registry validation failed: {error}"
            ),
            Self::PolicySource(error) => write!(
                formatter,
                "requester rendezvous start composition policy source failed: {error}"
            ),
            Self::PolicyAuthorization(error) => write!(
                formatter,
                "requester rendezvous start composition policy authorization failed: {error}"
            ),
            Self::Registration(error) => write!(
                formatter,
                "requester rendezvous start composition registration failed: {error}"
            ),
        }
    }
}

impl std::error::Error for RequesterRendezvousStartCompositionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RegistryValidation(error) => Some(error),
            Self::PolicySource(error) => Some(error),
            Self::PolicyAuthorization(error) => Some(error),
            Self::Registration(error) => Some(error),
        }
    }
}

/// Validates, requester-binds policy, authorizes, and registers one requester/rendezvous start.
///
/// Execution order is fixed and fail-closed:
///
/// 1. DI validates the raw intent against current registry state.
/// 2. DP resolves the evaluator using only the exact DI-held authenticated requester session.
/// 3. DK consumes the unchanged DI carrier and evaluates the dedicated capability.
/// 4. DN consumes the exact DK carrier and performs the existing private registration mutation.
///
/// The evaluator borrow is source-owned, so the temporary requester-session borrow can end before
/// the validated carrier moves by value into DK. This function introduces no provenance
/// decomposition, fallback evaluator, direct provider access, retry, replacement, or second
/// registration path. DI currentness remains point-in-time only.
///
/// # Errors
///
/// Returns the exact stage class that failed. Every error short-circuits before later stages run.
pub fn validate_authorize_and_register_requester_rendezvous_start<
    S: RequesterRendezvousStartPolicySource + ?Sized,
>(
    registry: &WorkspaceDeviceRegistry,
    policy_source: &S,
    runtime_owner: &mut CandidatePublicationRequesterRendezvousRuntimeOwner,
    intent: RequesterRendezvousStartIntent,
) -> Result<(), RequesterRendezvousStartCompositionError> {
    let validated = validate_current_requester_rendezvous_start_intent(registry, intent)
        .map_err(RequesterRendezvousStartCompositionError::RegistryValidation)?;

    let evaluator = policy_source
        .evaluator_for_requester(validated.requester_session())
        .map_err(RequesterRendezvousStartCompositionError::PolicySource)?;

    let authorized = policy_authorize_requester_rendezvous_start(validated, evaluator)
        .map_err(RequesterRendezvousStartCompositionError::PolicyAuthorization)?;

    runtime_owner
        .register_policy_authorized_requester_rendezvous_start(authorized)
        .map_err(RequesterRendezvousStartCompositionError::Registration)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use prw_policy::{Capability, Decision, PolicyEvaluator};
    use prw_registry::WorkspaceDeviceRegistry;
    use prw_remote_bridge::requester_rendezvous_in_memory_provider::RequesterRendezvousLifecycleError;
    use prw_session::AuthenticatedDeviceSession;

    use super::{
        RequesterRendezvousStartCompositionError,
        validate_authorize_and_register_requester_rendezvous_start,
    };
    use crate::{
        candidate_publication_requester_rendezvous_runtime::CandidatePublicationRequesterRendezvousRuntimeOwner,
        candidate_publication_requester_rendezvous_start_intent::{
            RequesterRendezvousStartIntent,
            policy_admission::RequesterRendezvousStartPolicyAuthorizationError,
            policy_source::{
                RequesterRendezvousStartPolicySource, RequesterRendezvousStartPolicySourceError,
            },
            registry_validation::RequesterRendezvousStartRegistryValidationError,
        },
    };

    struct SignatureOnlyEvaluator;

    impl PolicyEvaluator for SignatureOnlyEvaluator {
        fn evaluate(&self, _capability: Capability) -> Decision {
            Decision::Deny
        }
    }

    struct SignatureOnlyPolicySource;

    impl RequesterRendezvousStartPolicySource for SignatureOnlyPolicySource {
        type Evaluator = SignatureOnlyEvaluator;

        fn evaluator_for_requester<'a>(
            &'a self,
            _requester: &AuthenticatedDeviceSession,
        ) -> Result<&'a Self::Evaluator, RequesterRendezvousStartPolicySourceError> {
            static EVALUATOR: SignatureOnlyEvaluator = SignatureOnlyEvaluator;
            Ok(&EVALUATOR)
        }
    }

    #[test]
    fn composition_surface_has_selected_consuming_shape() {
        let composition: fn(
            &WorkspaceDeviceRegistry,
            &SignatureOnlyPolicySource,
            &mut CandidatePublicationRequesterRendezvousRuntimeOwner,
            RequesterRendezvousStartIntent,
        ) -> Result<(), RequesterRendezvousStartCompositionError> =
            validate_authorize_and_register_requester_rendezvous_start::<SignatureOnlyPolicySource>;

        let _ = composition;
    }

    #[test]
    fn composition_errors_preserve_distinct_stage_sources() {
        let errors = [
            RequesterRendezvousStartCompositionError::RegistryValidation(
                RequesterRendezvousStartRegistryValidationError::WorkspaceMismatch,
            ),
            RequesterRendezvousStartCompositionError::PolicySource(
                RequesterRendezvousStartPolicySourceError::Unavailable,
            ),
            RequesterRendezvousStartCompositionError::PolicyAuthorization(
                RequesterRendezvousStartPolicyAuthorizationError::Denied,
            ),
            RequesterRendezvousStartCompositionError::Registration(
                RequesterRendezvousLifecycleError::CapacityExhausted,
            ),
        ];

        assert!(errors.iter().all(|error| error.source().is_some()));
        assert!(errors[0].to_string().contains("registry validation"));
        assert!(errors[1].to_string().contains("policy source"));
        assert!(errors[2].to_string().contains("policy authorization"));
        assert!(errors[3].to_string().contains("registration"));
    }
}
