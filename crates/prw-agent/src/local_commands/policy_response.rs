//! Pure policy-gated terminal response composition for local read-only commands.
//!
//! Phase 038 combines Phase 037 admission with existing successful/error frame
//! builders. The caller-supplied evaluator is assumed to belong to an already
//! authenticated policy context; this module does not authenticate a principal.

use prw_policy::PolicyEvaluator;

use crate::frame_object::LocalIpcFrame;

use super::admission::{LocalRequestAdmissionError, policy_admit_local_request};
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::responder::{LocalReadOnlyResponseBuildError, build_read_only_success_response};
use super::status_snapshot::LocalAgentStatusSnapshot;
use super::terminal_response::builder::{
    LocalTerminalResponseBuildError, build_terminal_response_frame,
};
use super::{LocalAgentRequestEnvelope, LocalAgentResponseStatus};

/// Applies policy admission and builds one correlated terminal response frame.
///
/// `Allow` delegates to the token-gated successful responder. `Deny` builds a
/// correlated terminal `Unauthorized` error frame with an empty command-specific
/// body. No live host state is read and no transport I/O occurs.
///
/// # Errors
///
/// Returns [`LocalPolicyResponseBuildError::Success`] if a policy-admitted
/// command's existing successful response builder fails defensively, or
/// [`LocalPolicyResponseBuildError::Unauthorized`] if construction of the
/// correlated `Unauthorized` terminal frame fails defensively.
pub fn build_policy_gated_read_only_response<E: PolicyEvaluator + ?Sized>(
    request: LocalAgentRequestEnvelope,
    evaluator: &E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<LocalIpcFrame, LocalPolicyResponseBuildError> {
    match policy_admit_local_request(request, evaluator) {
        Ok(admitted) => {
            build_read_only_success_response(admitted, status_snapshot, private_dns_snapshot)
                .map_err(LocalPolicyResponseBuildError::Success)
        }
        Err(LocalRequestAdmissionError::Denied) => build_terminal_response_frame(
            request.request_id(),
            LocalAgentResponseStatus::Unauthorized,
            &[],
        )
        .map_err(LocalPolicyResponseBuildError::Unauthorized),
    }
}

/// Defensive Phase 038 policy-gated response construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPolicyResponseBuildError {
    /// Policy admitted the Request but successful response construction failed.
    Success(LocalReadOnlyResponseBuildError),
    /// Policy denied the Request but the terminal Unauthorized frame failed to build.
    Unauthorized(LocalTerminalResponseBuildError),
}

#[cfg(test)]
mod tests {
    use super::build_policy_gated_read_only_response;
    use crate::LocalIpcMessageKind;
    use crate::LocalIpcRequestId;
    use crate::local_commands::private_dns_response::decode_success_private_dns_frame;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;
    use crate::local_commands::{
        LocalAgentCommand, LocalAgentRequestEnvelope, LocalAgentResponseStatus,
    };
    use prw_network::PrivateDnsConfig;
    use prw_policy::{Capability, Decision, PolicyEvaluator};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn dns_snapshot() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig {
            enabled: true,
            device_naming: true,
            resolvers: vec!["10.0.0.53".into()],
            split_domains: vec!["corp.example".into()],
        })
        .expect("bounded DNS snapshot")
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
    fn allowed_status_request_builds_existing_success_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let request = LocalAgentRequestEnvelope::new(id(200), LocalAgentCommand::GetAgentStatus);

        let frame = build_policy_gated_read_only_response(
            request,
            &AllowOnly(Capability::AgentStatusRead),
            status,
            &dns,
        )
        .expect("allowed status response builds");
        let decoded = decode_success_status_frame(&frame).expect("status response decodes");

        assert_eq!(decoded.request_id(), id(200));
        assert_eq!(decoded.snapshot(), status);
    }

    #[test]
    fn allowed_private_dns_request_builds_existing_success_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Degraded);
        let dns = dns_snapshot();
        let request =
            LocalAgentRequestEnvelope::new(id(201), LocalAgentCommand::GetPrivateDnsConfig);

        let frame = build_policy_gated_read_only_response(
            request,
            &AllowOnly(Capability::PrivateDnsConfigRead),
            status,
            &dns,
        )
        .expect("allowed DNS response builds");
        let decoded =
            decode_success_private_dns_frame(&frame).expect("private DNS response decodes");

        assert_eq!(decoded.request_id(), id(201));
        assert_eq!(decoded.snapshot(), &dns);
    }

    #[test]
    fn denied_request_builds_correlated_unauthorized_error() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let request =
            LocalAgentRequestEnvelope::new(id(202), LocalAgentCommand::GetPrivateDnsConfig);

        let frame = build_policy_gated_read_only_response(request, &DenyAll, status, &dns)
            .expect("denial response builds");
        let terminal = validate_terminal_response_frame(&frame).expect("terminal frame validates");

        assert_eq!(frame.header().kind(), LocalIpcMessageKind::Error);
        assert_eq!(terminal.request_id(), id(202));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Unauthorized);
        assert_eq!(frame.payload().as_bytes(), &[0, 2]);
    }

    #[test]
    fn granting_other_read_capability_still_denies_command() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let request = LocalAgentRequestEnvelope::new(id(203), LocalAgentCommand::GetAgentStatus);

        let frame = build_policy_gated_read_only_response(
            request,
            &AllowOnly(Capability::PrivateDnsConfigRead),
            status,
            &dns,
        )
        .expect("denial response builds");
        let terminal = validate_terminal_response_frame(&frame).expect("terminal frame validates");

        assert_eq!(terminal.request_id(), id(203));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Unauthorized);
    }
}
