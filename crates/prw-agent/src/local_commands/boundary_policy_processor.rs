//! Boundary-aware Request read and policy-response composition.
//!
//! Phase 048 carries the Phase 047 clean-EOF distinction through the existing
//! policy-gated response builder. It performs no response I/O and owns no transport.

use std::io::Read;

use prw_policy::PolicyEvaluator;

use crate::frame_object::LocalIpcFrame;

use super::policy_response::build_policy_gated_read_only_response;
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::request_frame::boundary_stream::{
    LocalAgentRequestBoundaryRead, read_local_command_request_at_boundary,
};
use super::request_processor::LocalRequestProcessorError;
use super::status_snapshot::LocalAgentStatusSnapshot;

/// Successful Phase 048 boundary-aware policy-processing outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalBoundaryPolicyResponse {
    /// The peer reached EOF before any byte of a new frame was acquired.
    CleanEof,
    /// A complete valid Request produced one correlated terminal response frame.
    Response(LocalIpcFrame),
}

/// Reads at a frame boundary and, only for a valid Request, builds a policy response.
///
/// Clean EOF returns without invoking the policy evaluator. Request acquisition
/// and decoding must succeed before policy evaluation occurs. This function
/// writes no response bytes.
///
/// # Errors
///
/// Preserves boundary/Request failures as [`LocalRequestProcessorError::Request`]
/// and defensive response-construction failures as
/// [`LocalRequestProcessorError::Response`].
pub fn read_and_build_policy_response_at_boundary<R: Read, E: PolicyEvaluator + ?Sized>(
    reader: &mut R,
    evaluator: &E,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<LocalBoundaryPolicyResponse, LocalRequestProcessorError> {
    match read_local_command_request_at_boundary(reader)
        .map_err(LocalRequestProcessorError::Request)?
    {
        LocalAgentRequestBoundaryRead::CleanEof => Ok(LocalBoundaryPolicyResponse::CleanEof),
        LocalAgentRequestBoundaryRead::Request(request) => build_policy_gated_read_only_response(
            request,
            evaluator,
            status_snapshot,
            private_dns_snapshot,
        )
        .map(LocalBoundaryPolicyResponse::Response)
        .map_err(LocalRequestProcessorError::Response),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;

    use super::{LocalBoundaryPolicyResponse, read_and_build_policy_response_at_boundary};
    use crate::LocalIpcRequestId;
    use crate::frame_object::reader::LocalIpcFrameReadError;
    use crate::frame_object::writer::write_frame;
    use crate::frame_object::{LocalIpcFrame, LocalIpcPayload};
    use crate::local_commands::codec::LocalAgentRequestDecodeError;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::LocalAgentRequestFrameDecodeError;
    use crate::local_commands::request_frame::stream::{
        LocalAgentRequestStreamReadError, write_local_command_request,
    };
    use crate::local_commands::request_processor::LocalRequestProcessorError;
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
    fn clean_eof_returns_without_policy_evaluation() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();

        assert_eq!(
            read_and_build_policy_response_at_boundary(
                &mut Cursor::new(Vec::<u8>::new()),
                &policy,
                status,
                &dns,
            ),
            Ok(LocalBoundaryPolicyResponse::CleanEof)
        );
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn allowed_request_builds_existing_correlated_success_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut bytes = Vec::new();
        write_local_command_request(&mut bytes, id(280), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");

        let outcome = read_and_build_policy_response_at_boundary(
            &mut Cursor::new(bytes),
            &policy,
            status,
            &dns,
        )
        .expect("allowed response builds");
        let LocalBoundaryPolicyResponse::Response(frame) = outcome else {
            panic!("expected response outcome");
        };
        let decoded = decode_success_status_frame(&frame).expect("status response decodes");

        assert_eq!(decoded.request_id(), id(280));
        assert_eq!(decoded.snapshot(), status);
        assert_eq!(policy.calls(), 1);
    }

    #[test]
    fn denied_request_builds_existing_correlated_unauthorized_response() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();
        let mut bytes = Vec::new();
        write_local_command_request(&mut bytes, id(281), LocalAgentCommand::GetPrivateDnsConfig)
            .expect("Request writes");

        let outcome = read_and_build_policy_response_at_boundary(
            &mut Cursor::new(bytes),
            &policy,
            status,
            &dns,
        )
        .expect("denial response builds");
        let LocalBoundaryPolicyResponse::Response(frame) = outcome else {
            panic!("expected response outcome");
        };
        let terminal =
            validate_terminal_response_frame(&frame).expect("terminal response validates");

        assert_eq!(terminal.request_id(), id(281));
        assert_eq!(terminal.status(), LocalAgentResponseStatus::Unauthorized);
        assert_eq!(policy.calls(), 1);
    }

    #[test]
    fn partial_header_stops_before_policy_evaluation() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::allow(Capability::AgentStatusRead);
        let mut bytes = Vec::new();
        write_local_command_request(&mut bytes, id(282), LocalAgentCommand::GetAgentStatus)
            .expect("Request writes");
        bytes.truncate(8);

        assert_eq!(
            read_and_build_policy_response_at_boundary(
                &mut Cursor::new(bytes),
                &policy,
                status,
                &dns,
            ),
            Err(LocalRequestProcessorError::Request(
                LocalAgentRequestStreamReadError::Read(LocalIpcFrameReadError::TruncatedHeader)
            ))
        );
        assert_eq!(policy.calls(), 0);
    }

    #[test]
    fn unknown_command_stops_before_policy_evaluation() {
        let status = LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready);
        let dns = dns_snapshot();
        let policy = CountingPolicy::deny_all();
        let payload = LocalIpcPayload::new(vec![0, 3]).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            id(283),
            payload.len(),
        )
        .expect("valid header");
        let frame = LocalIpcFrame::new(header, payload).expect("matching frame");
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("frame writes");

        assert_eq!(
            read_and_build_policy_response_at_boundary(
                &mut Cursor::new(bytes),
                &policy,
                status,
                &dns,
            ),
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
}
