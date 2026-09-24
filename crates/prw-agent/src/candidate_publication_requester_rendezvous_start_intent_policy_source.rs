//! Agent-internal requester-aware policy source for requester/rendezvous start.
//!
//! C03e-DP materialized the requester-aware source interface. C03e-DX adds only the
//! C03e-DW-selected bounded in-memory concrete backing and dedicated operation-specific evaluator.
//! It does not wire production custody or population, invoke requester/rendezvous start, mutate the
//! provider, expose wire handling, perform I/O, activate a runtime/listener/network, persist policy,
//! deploy, restart, recover, or merge.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
};

use prw_core::{DeviceId, UserId, WorkspaceId};
use prw_policy::{Capability, Decision, PolicyEvaluator};
use prw_registry::MAX_REGISTERED_DEVICES;
use prw_session::AuthenticatedDeviceSession;

/// Maximum concrete requester/rendezvous-start policy bindings held by one C03e-DX source.
pub const MAX_REQUESTER_RENDEZVOUS_START_POLICY_BINDINGS: usize = MAX_REGISTERED_DEVICES;

/// Stable fail-closed failure while resolving the policy evaluator for one exact requester.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousStartPolicySourceError {
    /// No authoritative requester policy is currently available.
    Unavailable,
    /// The authoritative requester policy cannot be resolved deterministically.
    Indeterminate,
}

impl fmt::Display for RequesterRendezvousStartPolicySourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "requester rendezvous start policy source unavailable",
            Self::Indeterminate => "requester rendezvous start policy source indeterminate",
        })
    }
}

impl std::error::Error for RequesterRendezvousStartPolicySourceError {}

/// Stable bounded failure while constructing one concrete requester-policy backing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousStartPolicyBackingError {
    /// The selected bounded source capacity would be exceeded.
    Capacity,
    /// More than one policy binding was supplied for the same logical requester device.
    DuplicateDevicePolicyBinding,
}

impl fmt::Display for RequesterRendezvousStartPolicyBackingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Capacity => "requester rendezvous start policy backing capacity reached",
            Self::DuplicateDevicePolicyBinding => {
                "duplicate requester rendezvous start logical device policy binding"
            }
        })
    }
}

impl std::error::Error for RequesterRendezvousStartPolicyBackingError {}

/// Dedicated configuration policy for the requester/rendezvous-start capability only.
///
/// Every capability other than [`Capability::RequesterRendezvousStart`] is denied fail-closed.
/// Constructing this value does not authenticate a principal or create authorization/provider
/// provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequesterRendezvousStartPolicy {
    requester_rendezvous_start: Decision,
}

impl RequesterRendezvousStartPolicy {
    /// Creates one explicit requester/rendezvous-start decision.
    #[must_use]
    pub const fn new(requester_rendezvous_start: Decision) -> Self {
        Self {
            requester_rendezvous_start,
        }
    }

    /// Creates the fail-closed requester/rendezvous-start policy.
    #[must_use]
    pub const fn deny() -> Self {
        Self::new(Decision::Deny)
    }
}

impl PolicyEvaluator for RequesterRendezvousStartPolicy {
    fn evaluate(&self, capability: Capability) -> Decision {
        if capability == Capability::RequesterRendezvousStart {
            self.requester_rendezvous_start
        } else {
            Decision::Deny
        }
    }
}

/// One owned logical-principal binding used only to construct the bounded concrete source.
///
/// The request-time selector does not accept this type or any raw logical-identity tuple. It
/// accepts only the exact authenticated requester session through
/// [`RequesterRendezvousStartPolicySource::evaluator_for_requester`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterRendezvousStartPolicyBinding {
    device_id: DeviceId,
    workspace_id: WorkspaceId,
    user_id: UserId,
    policy: RequesterRendezvousStartPolicy,
}

impl RequesterRendezvousStartPolicyBinding {
    /// Creates one construction-time logical requester policy binding.
    #[must_use]
    pub const fn new(
        workspace_id: WorkspaceId,
        user_id: UserId,
        device_id: DeviceId,
        policy: RequesterRendezvousStartPolicy,
    ) -> Self {
        Self {
            device_id,
            workspace_id,
            user_id,
            policy,
        }
    }
}

/// Resolves the existing policy evaluator authoritative for one exact authenticated requester.
///
/// The requester must be the exact server-held [`AuthenticatedDeviceSession`] that survived the
/// separately materialized C03e-DI current-registry validation. Implementations must fail closed
/// rather than substitute a process-global/default evaluator or another requester's evaluator.
///
/// The returned evaluator borrow is tied to `self`, not to the requester borrow. This permits a
/// later caller to end its temporary requester-session borrow and then move the unchanged C03e-DI
/// provenance carrier by value into the existing C03e-DK admission function.
///
/// This trait selects policy source only. It does not evaluate a capability, create
/// `PolicyAuthorizedRequesterRendezvousStart`, mutate requester/rendezvous provider state, or grant
/// reusable registration authority.
pub trait RequesterRendezvousStartPolicySource {
    /// Existing policy evaluator type resolved by this source.
    type Evaluator: PolicyEvaluator + ?Sized;

    /// Resolves the evaluator authoritative for the exact authenticated requester.
    ///
    /// # Errors
    ///
    /// Returns a bounded fail-closed source error when authoritative policy is unavailable or
    /// cannot be resolved deterministically. Failure must not select a fallback evaluator.
    fn evaluator_for_requester<'a>(
        &'a self,
        requester: &AuthenticatedDeviceSession,
    ) -> Result<&'a Self::Evaluator, RequesterRendezvousStartPolicySourceError>;
}

/// Bounded immutable requester-principal-indexed policy backing selected by C03e-DW.
///
/// Population is one-shot through [`Self::try_from_bindings`]. C03e-DX exposes no live
/// insert/update/remove/replace operation and selects no persistence, refresh, watch, lock, or
/// distributed-coherence semantics.
#[derive(Debug, Default)]
pub struct BoundedRequesterRendezvousStartPolicySource {
    policies_by_device: HashMap<DeviceId, RequesterRendezvousStartPolicyBinding>,
}

impl BoundedRequesterRendezvousStartPolicySource {
    /// Creates one fully populated bounded source from owned logical-principal bindings.
    ///
    /// # Errors
    ///
    /// Rejects duplicate logical requester device bindings and capacity overflow. Failure returns
    /// no partially authoritative source and performs no fallback policy selection.
    pub fn try_from_bindings(
        bindings: impl IntoIterator<Item = RequesterRendezvousStartPolicyBinding>,
    ) -> Result<Self, RequesterRendezvousStartPolicyBackingError> {
        let mut source = Self::default();

        for binding in bindings {
            let at_capacity =
                source.policies_by_device.len() >= MAX_REQUESTER_RENDEZVOUS_START_POLICY_BINDINGS;
            let device_id = binding.device_id.clone();
            match source.policies_by_device.entry(device_id) {
                Entry::Occupied(_) => {
                    return Err(
                        RequesterRendezvousStartPolicyBackingError::DuplicateDevicePolicyBinding,
                    );
                }
                Entry::Vacant(entry) => {
                    if at_capacity {
                        return Err(RequesterRendezvousStartPolicyBackingError::Capacity);
                    }
                    entry.insert(binding);
                }
            }
        }

        Ok(source)
    }

    fn evaluator_for_authenticated_dimensions(
        &self,
        device_id: &DeviceId,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<&RequesterRendezvousStartPolicy, RequesterRendezvousStartPolicySourceError> {
        let binding = self
            .policies_by_device
            .get(device_id)
            .ok_or(RequesterRendezvousStartPolicySourceError::Unavailable)?;

        if &binding.workspace_id != workspace_id || &binding.user_id != user_id {
            return Err(RequesterRendezvousStartPolicySourceError::Indeterminate);
        }

        Ok(&binding.policy)
    }
}

impl RequesterRendezvousStartPolicySource for BoundedRequesterRendezvousStartPolicySource {
    type Evaluator = RequesterRendezvousStartPolicy;

    fn evaluator_for_requester<'a>(
        &'a self,
        requester: &AuthenticatedDeviceSession,
    ) -> Result<&'a Self::Evaluator, RequesterRendezvousStartPolicySourceError> {
        self.evaluator_for_authenticated_dimensions(
            requester.device_id(),
            requester.workspace_id(),
            requester.user_id(),
        )
    }
}

#[cfg(test)]
mod tests {
    use prw_core::{DeviceId, UserId, WorkspaceId};
    use prw_policy::{Capability, Decision, PolicyEvaluator};
    use prw_session::AuthenticatedDeviceSession;

    use super::{
        BoundedRequesterRendezvousStartPolicySource,
        MAX_REQUESTER_RENDEZVOUS_START_POLICY_BINDINGS, RequesterRendezvousStartPolicy,
        RequesterRendezvousStartPolicyBackingError, RequesterRendezvousStartPolicyBinding,
        RequesterRendezvousStartPolicySource, RequesterRendezvousStartPolicySourceError,
    };

    struct SignatureOnlyEvaluator;

    impl PolicyEvaluator for SignatureOnlyEvaluator {
        fn evaluate(&self, _capability: Capability) -> Decision {
            Decision::Deny
        }
    }

    struct SignatureOnlySource {
        evaluator: SignatureOnlyEvaluator,
    }

    impl RequesterRendezvousStartPolicySource for SignatureOnlySource {
        type Evaluator = SignatureOnlyEvaluator;

        fn evaluator_for_requester<'a>(
            &'a self,
            _requester: &AuthenticatedDeviceSession,
        ) -> Result<&'a Self::Evaluator, RequesterRendezvousStartPolicySourceError> {
            Ok(&self.evaluator)
        }
    }

    fn binding(
        device_id: &str,
        workspace_id: &str,
        user_id: &str,
        decision: Decision,
    ) -> RequesterRendezvousStartPolicyBinding {
        RequesterRendezvousStartPolicyBinding::new(
            WorkspaceId::new(workspace_id).expect("workspace id"),
            UserId::new(user_id).expect("user id"),
            DeviceId::new(device_id).expect("device id"),
            RequesterRendezvousStartPolicy::new(decision),
        )
    }

    #[test]
    fn source_method_keeps_evaluator_borrow_owned_by_source_not_requester_borrow() {
        let method: for<'source, 'requester> fn(
            &'source SignatureOnlySource,
            &'requester AuthenticatedDeviceSession,
        ) -> Result<
            &'source SignatureOnlyEvaluator,
            RequesterRendezvousStartPolicySourceError,
        > = <SignatureOnlySource as RequesterRendezvousStartPolicySource>::evaluator_for_requester;

        let _ = method;
    }

    #[test]
    fn source_failures_are_stable_and_distinct() {
        assert_eq!(
            RequesterRendezvousStartPolicySourceError::Unavailable.to_string(),
            "requester rendezvous start policy source unavailable"
        );
        assert_eq!(
            RequesterRendezvousStartPolicySourceError::Indeterminate.to_string(),
            "requester rendezvous start policy source indeterminate"
        );
        assert_ne!(
            RequesterRendezvousStartPolicySourceError::Unavailable,
            RequesterRendezvousStartPolicySourceError::Indeterminate
        );
    }

    #[test]
    fn dedicated_policy_configures_only_requester_rendezvous_start() {
        let policy = RequesterRendezvousStartPolicy::new(Decision::Allow);
        assert_eq!(
            policy.evaluate(Capability::RequesterRendezvousStart),
            Decision::Allow
        );

        for capability in [
            Capability::AgentStatusRead,
            Capability::PrivateDnsConfigRead,
            Capability::TerminalOpen,
            Capability::TerminalExec,
            Capability::FilesRead,
            Capability::FilesWrite,
            Capability::FilesDelete,
            Capability::ForwardingCreate,
            Capability::DeviceManage,
            Capability::PolicyManage,
        ] {
            assert_eq!(policy.evaluate(capability), Decision::Deny);
        }

        assert_eq!(
            RequesterRendezvousStartPolicy::deny().evaluate(Capability::RequesterRendezvousStart),
            Decision::Deny
        );
    }

    #[test]
    fn bounded_source_resolves_only_exact_logical_requester_dimensions() {
        let source = BoundedRequesterRendezvousStartPolicySource::try_from_bindings([binding(
            "device-1",
            "workspace-1",
            "user-1",
            Decision::Allow,
        )])
        .expect("bounded source");

        let device_id = DeviceId::new("device-1").expect("device id");
        let workspace_id = WorkspaceId::new("workspace-1").expect("workspace id");
        let user_id = UserId::new("user-1").expect("user id");
        let evaluator = source
            .evaluator_for_authenticated_dimensions(&device_id, &workspace_id, &user_id)
            .expect("exact requester policy");
        assert_eq!(
            evaluator.evaluate(Capability::RequesterRendezvousStart),
            Decision::Allow
        );

        let absent_device = DeviceId::new("device-absent").expect("device id");
        assert_eq!(
            source.evaluator_for_authenticated_dimensions(&absent_device, &workspace_id, &user_id),
            Err(RequesterRendezvousStartPolicySourceError::Unavailable)
        );

        let wrong_workspace = WorkspaceId::new("workspace-other").expect("workspace id");
        assert_eq!(
            source.evaluator_for_authenticated_dimensions(&device_id, &wrong_workspace, &user_id),
            Err(RequesterRendezvousStartPolicySourceError::Indeterminate)
        );

        let wrong_user = UserId::new("user-other").expect("user id");
        assert_eq!(
            source.evaluator_for_authenticated_dimensions(&device_id, &workspace_id, &wrong_user),
            Err(RequesterRendezvousStartPolicySourceError::Indeterminate)
        );
    }

    #[test]
    fn duplicate_logical_device_policy_binding_is_rejected_without_overwrite() {
        let result = BoundedRequesterRendezvousStartPolicySource::try_from_bindings([
            binding("device-1", "workspace-1", "user-1", Decision::Allow),
            binding("device-1", "workspace-2", "user-2", Decision::Deny),
        ]);

        assert!(matches!(
            result,
            Err(RequesterRendezvousStartPolicyBackingError::DuplicateDevicePolicyBinding)
        ));
    }

    #[test]
    fn capacity_overflow_is_rejected() {
        let bindings = (0..=MAX_REQUESTER_RENDEZVOUS_START_POLICY_BINDINGS).map(|index| {
            binding(
                &format!("device-{index}"),
                "workspace-1",
                "user-1",
                Decision::Deny,
            )
        });

        assert!(matches!(
            BoundedRequesterRendezvousStartPolicySource::try_from_bindings(bindings),
            Err(RequesterRendezvousStartPolicyBackingError::Capacity)
        ));
    }

    #[test]
    fn concrete_source_and_policy_are_send_sync_and_use_existing_source_trait() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn assert_source<T>()
        where
            T: RequesterRendezvousStartPolicySource<Evaluator = RequesterRendezvousStartPolicy>,
        {
        }

        assert_send_sync::<RequesterRendezvousStartPolicy>();
        assert_send_sync::<BoundedRequesterRendezvousStartPolicySource>();
        assert_source::<BoundedRequesterRendezvousStartPolicySource>();
    }
}
