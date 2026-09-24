//! Typed policy-admission boundary for local read-only commands.
//!
//! Phase 037 maps each admitted command to an explicit `prw-policy`
//! capability and produces a token that can be created only after an Allow
//! decision. This module does not authenticate a principal; runtime code must
//! supply a policy evaluator already selected/bound for an authenticated peer.

use prw_policy::{Capability, Decision, PolicyEvaluator};

use super::{LocalAgentCommand, LocalAgentRequestEnvelope};
use crate::LocalIpcRequestId;

/// Proof that one local Request passed the explicit policy capability check.
///
/// The wrapped raw request remains private so successful responder APIs can
/// require this type instead of accepting an unchecked request envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalPolicyAdmittedRequest {
    request: LocalAgentRequestEnvelope,
}

impl LocalPolicyAdmittedRequest {
    /// Returns the admitted Request correlation identifier.
    #[must_use]
    pub const fn request_id(self) -> LocalIpcRequestId {
        self.request.request_id()
    }

    /// Returns the admitted read-only command.
    #[must_use]
    pub const fn command(self) -> LocalAgentCommand {
        self.request.command()
    }
}

/// Returns the exact capability required by one current local read-only command.
#[must_use]
pub const fn required_capability(command: LocalAgentCommand) -> Capability {
    match command {
        LocalAgentCommand::GetAgentStatus => Capability::AgentStatusRead,
        LocalAgentCommand::GetPrivateDnsConfig => Capability::PrivateDnsConfigRead,
    }
}

/// Evaluates one decoded local Request and returns a typed admission token only
/// when the caller-supplied policy context explicitly allows its capability.
///
/// # Errors
///
/// Returns [`LocalRequestAdmissionError::Denied`] when the evaluator does not
/// grant the command's exact required capability. The raw request is not
/// converted into an admitted token on denial.
pub fn policy_admit_local_request<E: PolicyEvaluator + ?Sized>(
    request: LocalAgentRequestEnvelope,
    evaluator: &E,
) -> Result<LocalPolicyAdmittedRequest, LocalRequestAdmissionError> {
    let capability = required_capability(request.command());
    match evaluator.evaluate(capability) {
        Decision::Allow => Ok(LocalPolicyAdmittedRequest { request }),
        Decision::Deny => Err(LocalRequestAdmissionError::Denied),
    }
}

/// Phase 037 policy-admission failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRequestAdmissionError {
    /// The policy context denied the command's required capability.
    Denied,
}

#[cfg(test)]
mod tests {
    use super::{LocalRequestAdmissionError, policy_admit_local_request, required_capability};
    use crate::LocalIpcRequestId;
    use crate::local_commands::{LocalAgentCommand, LocalAgentRequestEnvelope};
    use prw_policy::{Capability, Decision, PolicyEvaluator};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    struct AllowOnly(Capability);

    impl PolicyEvaluator for AllowOnly {
        fn evaluate(&self, capability: Capability) -> Decision {
            if capability == self.0 {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
    }

    struct DenyAll;

    impl PolicyEvaluator for DenyAll {
        fn evaluate(&self, _capability: Capability) -> Decision {
            Decision::Deny
        }
    }

    #[test]
    fn current_commands_map_to_distinct_exact_capabilities() {
        assert_eq!(
            required_capability(LocalAgentCommand::GetAgentStatus),
            Capability::AgentStatusRead
        );
        assert_eq!(
            required_capability(LocalAgentCommand::GetPrivateDnsConfig),
            Capability::PrivateDnsConfigRead
        );
    }

    #[test]
    fn exact_allow_produces_token_with_preserved_request_metadata() {
        let request = LocalAgentRequestEnvelope::new(id(190), LocalAgentCommand::GetAgentStatus);
        let admitted = policy_admit_local_request(request, &AllowOnly(Capability::AgentStatusRead))
            .expect("matching capability admits request");

        assert_eq!(admitted.request_id(), id(190));
        assert_eq!(admitted.command(), LocalAgentCommand::GetAgentStatus);
    }

    #[test]
    fn allowing_status_does_not_allow_private_dns_read() {
        let request =
            LocalAgentRequestEnvelope::new(id(191), LocalAgentCommand::GetPrivateDnsConfig);

        assert_eq!(
            policy_admit_local_request(request, &AllowOnly(Capability::AgentStatusRead)),
            Err(LocalRequestAdmissionError::Denied)
        );
    }

    #[test]
    fn deny_all_never_produces_admission_token() {
        let request = LocalAgentRequestEnvelope::new(id(192), LocalAgentCommand::GetAgentStatus);

        assert_eq!(
            policy_admit_local_request(request, &DenyAll),
            Err(LocalRequestAdmissionError::Denied)
        );
    }
}
