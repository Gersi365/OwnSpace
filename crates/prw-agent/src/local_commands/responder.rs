//! Pure in-memory responder for policy-admitted read-only local commands.
//!
//! Phase 036 selects existing successful response-frame builders from typed
//! command metadata and caller-supplied snapshots. Phase 037 tightens this
//! boundary so successful response construction requires a policy-admitted
//! request token rather than an unchecked raw request envelope.

use crate::frame_object::LocalIpcFrame;

use super::LocalAgentCommand;
use super::admission::LocalPolicyAdmittedRequest;
use super::private_dns_response::{
    LocalPrivateDnsFrameBuildError, build_success_private_dns_frame,
};
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::status_snapshot::LocalAgentStatusSnapshot;
use super::status_snapshot::response_frame::build_success_status_frame;
use super::terminal_response::builder::LocalTerminalResponseBuildError;

/// Builds one successful terminal response for a policy-admitted read-only request.
///
/// The caller supplies both current read-only snapshots. This function only
/// selects the command-specific existing builder and preserves the request ID.
/// Policy admission must already have produced `request`; this responder does
/// not itself authenticate a principal or read live host state.
///
/// # Errors
///
/// Returns [`LocalReadOnlyResponseBuildError::Status`] if the existing status
/// response builder fails defensively, or
/// [`LocalReadOnlyResponseBuildError::PrivateDns`] if bounded private-DNS
/// encoding/frame construction fails defensively.
pub fn build_read_only_success_response(
    request: LocalPolicyAdmittedRequest,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<LocalIpcFrame, LocalReadOnlyResponseBuildError> {
    match request.command() {
        LocalAgentCommand::GetAgentStatus => {
            build_success_status_frame(request.request_id(), status_snapshot)
                .map_err(LocalReadOnlyResponseBuildError::Status)
        }
        LocalAgentCommand::GetPrivateDnsConfig => {
            build_success_private_dns_frame(request.request_id(), private_dns_snapshot)
                .map_err(LocalReadOnlyResponseBuildError::PrivateDns)
        }
    }
}

/// Defensive read-only response construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalReadOnlyResponseBuildError {
    /// Existing `GetAgentStatus` successful-frame construction failed.
    Status(LocalTerminalResponseBuildError),
    /// Existing `GetPrivateDnsConfig` successful-frame construction failed.
    PrivateDns(LocalPrivateDnsFrameBuildError),
}

#[cfg(test)]
mod tests {
    use super::build_read_only_success_response;
    use crate::LocalIpcRequestId;
    use crate::local_commands::admission::policy_admit_local_request;
    use crate::local_commands::private_dns_response::decode_success_private_dns_frame;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::{LocalAgentCommand, LocalAgentRequestEnvelope};
    use prw_network::PrivateDnsConfig;
    use prw_policy::{Capability, Decision, PolicyEvaluator};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    struct AllowAll;

    impl PolicyEvaluator for AllowAll {
        fn evaluate(&self, _capability: Capability) -> Decision {
            Decision::Allow
        }
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

    #[test]
    fn admitted_status_request_uses_existing_builder_and_preserves_correlation() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let raw_request =
            LocalAgentRequestEnvelope::new(id(180), LocalAgentCommand::GetAgentStatus);
        let request =
            policy_admit_local_request(raw_request, &AllowAll).expect("request is admitted");

        let frame = build_read_only_success_response(request, status, &dns)
            .expect("status response builds");
        let decoded = decode_success_status_frame(&frame).expect("status response decodes");

        assert_eq!(decoded.request_id(), id(180));
        assert_eq!(decoded.snapshot(), status);
    }

    #[test]
    fn admitted_private_dns_request_uses_existing_builder_and_preserves_correlation() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Degraded);
        let dns = dns_snapshot();
        let raw_request =
            LocalAgentRequestEnvelope::new(id(181), LocalAgentCommand::GetPrivateDnsConfig);
        let request =
            policy_admit_local_request(raw_request, &AllowAll).expect("request is admitted");

        let frame = build_read_only_success_response(request, status, &dns)
            .expect("private DNS response builds");
        let decoded =
            decode_success_private_dns_frame(&frame).expect("private DNS response decodes");

        assert_eq!(decoded.request_id(), id(181));
        assert_eq!(decoded.snapshot(), &dns);
    }
}
