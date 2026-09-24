//! Generic one-request read and policy-response composition.
//!
//! Phase 040 reads exactly one complete local Request from a generic `Read`,
//! decodes it before policy evaluation, and returns one terminal response frame
//! in memory. It performs no response write and owns no transport.

use std::io::Read;

use prw_policy::PolicyEvaluator;

use crate::frame_object::LocalIpcFrame;

use super::policy_response::{
    LocalPolicyResponseBuildError, build_policy_gated_read_only_response,
};
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::request_frame::stream::{LocalAgentRequestStreamReadError, read_local_command_request};
use super::status_snapshot::LocalAgentStatusSnapshot;

/// Reads one validated Request, applies the supplied policy context, and builds
/// one correlated terminal response frame in memory.
///
/// The Request must fully pass generic framing and command decoding before the
/// policy evaluator is invoked. This function writes no response bytes.
///
/// # Errors
///
/// Returns [`LocalRequestProcessorError::Request`] when the incoming frame or
/// command payload is invalid/truncated. In that case policy evaluation is not
/// reached. Returns [`LocalRequestProcessorError::Response`] if construction of
/// the policy-gated terminal response fails defensively.
pub fn read_and_build_policy_response<R: Read, E: PolicyEvaluator + ?Sized>(
    reader: &mut R,
    evaluator: &E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<LocalIpcFrame, LocalRequestProcessorError> {
    let request =
        read_local_command_request(reader).map_err(LocalRequestProcessorError::Request)?;
    build_policy_gated_read_only_response(request, evaluator, status_snapshot, private_dns_snapshot)
        .map_err(LocalRequestProcessorError::Response)
}

/// Phase 040 one-request processing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRequestProcessorError {
    /// Generic Request acquisition or command decoding failed.
    Request(LocalAgentRequestStreamReadError),
    /// Policy-gated terminal response construction failed defensively.
    Response(LocalPolicyResponseBuildError),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;

    use super::{LocalRequestProcessorError, read_and_build_policy_response};
    use crate::LocalIpcRequestId;
    use crate::frame_object::writer::write_frame;
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::local_commands::codec::LocalAgentRequestDecodeError;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::LocalAgentRequestFrameDecodeError;
    use crate::local_commands::request_frame::stream::{
        LocalAgentRequestStreamReadError, write_local_command_request,
    };
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;
    use crate::local_commands::{LocalAgentCommand, LocalAgentResponseStatus};
    use crate::{LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion};
    use prw_network::PrivateDnsConfig;
    use prw_policy::{Capability, Decision, PolicyEvaluator};

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn dns_snapshot() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS config is bounded")
    }

    struct CountingPolicy {
        allowed: Option<Capability>,
        calls: Cell<usize>,
    }

    impl CountingPolicy {
        const fn allow(capability: Capability) -> Self {
            Self {
                allowed: Some(capability),
                calls: Cell::new(0),
            }
        }

        const fn deny_all() -> Self {
            Self {
                allowed: None,
                calls: Cell::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl PolicyEvaluator for CountingPolicy {
        fn evaluate(&self, capability: Capability) -> Decision {
            self.calls.set(self.calls.get() + 1);
            if self.allowed == Some(capability) {
                Decision::Allow
            } else {
                Decision::Deny
            }
        }
    }

    #[test]
    fn valid_allowed_request_reads_then_builds_success_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut request_bytes = Vec::new();
        write_local_command_request(
            &mut request_bytes,
            id(210),
            LocalAgentCommand::GetAgentStatus,
        )
        .expect("memory Request write succeeds");

        let response =
            read_and_build_policy_response(&mut Cursor::new(request_bytes), &policy, status, &dns)
                .expect("policy-allowed response builds");
        let decoded = decode_success_status_frame(&response).expect("status response decodes");

        assert_eq!(policy.calls(), 1);
        assert_eq!(decoded.request_id(), id(210));
        assert_eq!(decoded.snapshot(), status);
    }

    #[test]
    fn valid_denied_request_reads_then_builds_unauthorized_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();
        let mut request_bytes = Vec::new();
        write_local_command_request(
            &mut request_bytes,
            id(211),
            LocalAgentCommand::GetPrivateDnsConfig,
        )
        .expect("memory Request write succeeds");

        let response =
            read_and_build_policy_response(&mut Cursor::new(request_bytes), &policy, status, &dns)
                .expect("policy denial response builds");
        let terminal =
            validate_terminal_response_frame(&response).expect("terminal response validates");

        assert_eq!(policy.calls(), 1);
        assert_eq!(terminal.request_id(), id(211));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Unauthorized);
    }

    #[test]
    fn unknown_command_is_rejected_before_policy_evaluation() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();
        let payload = LocalIpcPayload::new(vec![0, 3]).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            id(212),
            payload.len(),
        )
        .expect("valid header");
        let frame = LocalIpcFrame::new(header, payload).expect("matching frame");
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("memory frame write succeeds");

        assert_eq!(
            read_and_build_policy_response(&mut Cursor::new(bytes), &policy, status, &dns),
            Err(LocalRequestProcessorError::Request(
                LocalAgentRequestStreamReadError::Decode(
                    LocalAgentRequestFrameDecodeError::Command(
                        LocalAgentRequestDecodeError::UnknownCommand
                    )
                )
            ))
        );
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn truncated_request_is_rejected_before_policy_evaluation() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut request_bytes = Vec::new();
        write_local_command_request(
            &mut request_bytes,
            id(213),
            LocalAgentCommand::GetAgentStatus,
        )
        .expect("memory Request write succeeds");
        request_bytes.pop();

        assert!(
            read_and_build_policy_response(&mut Cursor::new(request_bytes), &policy, status, &dns,)
                .is_err()
        );
        assert_eq!(policy.calls(), 0);
    }
}
