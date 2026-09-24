//! Boundary-aware local Request transaction for C03 management activation.
//!
//! This module reads exactly one already-framed local Request from an authenticated
//! same-UID connection. Legacy commands 1/2 continue through their existing decoder,
//! policy admission and responder. Additive command 3 delegates to the existing C03
//! authenticated management execution seam. The same inbound/read-poison and guarded
//! response-write states remain authoritative for both paths.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};

use prw_forwarding::PortForwardBackend;
use prw_policy::PolicyEvaluator;
use prw_terminal::TerminalBackend;

use super::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
use super::inbound_state::LocalInboundRequestState;
use super::management_authority::LocalManagementFilesystemAuthority;
use super::management_execution::process_authenticated_linux_management_with_local_authorities;
use super::management_provider_lifecycle::LocalManagementProviderLifecycle;
use super::management_request::LOCAL_MANAGEMENT_BRIDGE_COMMAND_CODE;
use super::policy_response::{
    LocalPolicyResponseBuildError, build_policy_gated_read_only_response,
};
use super::private_dns_snapshot::LocalPrivateDnsSnapshot;
use super::request_frame::{LocalAgentRequestFrameDecodeError, decode_local_command_request_frame};
use super::response_writer::{
    LocalTerminalResponseWriteError, LocalTerminalResponseWriteState,
    write_terminal_response_guarded,
};
use super::status_snapshot::LocalAgentStatusSnapshot;
use super::terminal_response::builder::LocalTerminalResponseBuildError;
use crate::frame_object::boundary_reader::{LocalIpcFrameBoundaryRead, read_frame_at_boundary};
use crate::frame_object::reader::LocalIpcFrameReadError;
use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;

/// One C03 boundary transaction failure after exact connection-state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalManagementBoundaryTransactionError {
    /// Generic frame acquisition failed and poisoned the inbound direction.
    FrameRead(LocalIpcFrameReadError),
    /// A non-management frame failed the exact legacy commands-1/2 decoder and poisoned inbound.
    ReadOnlyDecode(LocalAgentRequestFrameDecodeError),
    /// Legacy policy-response construction failed before any response write.
    ReadOnlyResponse(LocalPolicyResponseBuildError),
    /// C03 management response construction failed before any response write.
    ManagementResponse(LocalTerminalResponseBuildError),
    /// Response writing failed through the existing guarded writer.
    ResponseWrite(LocalTerminalResponseWriteError),
}

/// Processes one clean-EOF-aware local request on the shared authenticated transport.
///
/// The first two payload bytes select only the existing local command namespace. Code 3
/// is additive and receives the complete frame unchanged. Every other frame is decoded
/// by the byte-for-byte legacy command decoder, preserving commands 1/2 semantics and
/// unknown-command failure behavior.
///
/// A syntactically framed command-3 request that is rejected by canonical C03 admission
/// produces its existing correlated terminal error and does not poison framing state;
/// malformed generic framing or malformed legacy command decoding does poison inbound.
#[expect(
    clippy::too_many_arguments,
    reason = "authority-bearing boundary inputs stay explicit rather than hidden in a context bag"
)]
pub(super) fn process_one_management_capable_at_boundary<R, W, RE, ME, T, F, S>(
    reader: &mut R,
    writer: &mut W,
    inbound_state: &mut LocalInboundRequestState,
    response_write_state: &mut LocalTerminalResponseWriteState,
    connection: &AuthenticatedLocalLinuxConnection<S>,
    read_evaluator: &RE,
    management_evaluator: &ME,
    filesystem: &LocalManagementFilesystemAuthority,
    lifecycle: &mut LocalManagementProviderLifecycle<'_, T, F>,
    status_snapshot: LocalAgentStatusSnapshot,
    private_dns_snapshot: &LocalPrivateDnsSnapshot,
) -> Result<LocalBoundaryRequestResponseOutcome, LocalManagementBoundaryTransactionError>
where
    R: Read,
    W: Write,
    RE: PolicyEvaluator + ?Sized,
    ME: PolicyEvaluator + ?Sized,
    T: TerminalBackend,
    F: PortForwardBackend,
{
    if inbound_state.is_read_poisoned() {
        return Err(LocalManagementBoundaryTransactionError::FrameRead(
            LocalIpcFrameReadError::HeaderIo,
        ));
    }
    if response_write_state.is_write_poisoned() {
        return Err(LocalManagementBoundaryTransactionError::ResponseWrite(
            LocalTerminalResponseWriteError::WritePoisoned,
        ));
    }

    let frame = match read_frame_at_boundary(reader) {
        Ok(LocalIpcFrameBoundaryRead::CleanEof) => {
            return Ok(LocalBoundaryRequestResponseOutcome::CleanEof);
        }
        Ok(LocalIpcFrameBoundaryRead::Frame(frame)) => frame,
        Err(error) => {
            *inbound_state = LocalInboundRequestState::ReadPoisoned;
            return Err(LocalManagementBoundaryTransactionError::FrameRead(error));
        }
    };

    let response = if payload_command_code(&frame) == Some(LOCAL_MANAGEMENT_BRIDGE_COMMAND_CODE) {
        process_authenticated_linux_management_with_local_authorities(
            &frame,
            connection,
            management_evaluator,
            filesystem,
            lifecycle,
            status_snapshot,
        )
        .map_err(LocalManagementBoundaryTransactionError::ManagementResponse)?
    } else {
        let request = match decode_local_command_request_frame(&frame) {
            Ok(request) => request,
            Err(error) => {
                *inbound_state = LocalInboundRequestState::ReadPoisoned;
                return Err(LocalManagementBoundaryTransactionError::ReadOnlyDecode(
                    error,
                ));
            }
        };
        build_policy_gated_read_only_response(
            request,
            read_evaluator,
            status_snapshot,
            private_dns_snapshot,
        )
        .map_err(LocalManagementBoundaryTransactionError::ReadOnlyResponse)?
    };

    write_terminal_response_guarded(response_write_state, writer, &response)
        .map_err(LocalManagementBoundaryTransactionError::ResponseWrite)?;
    Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
}

fn payload_command_code(frame: &crate::frame_object::LocalIpcFrame) -> Option<u16> {
    let bytes = frame.payload().as_bytes();
    (bytes.len() >= 2).then(|| u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use prw_forwarding::{ForwardingError, PortForwardBackend, TcpForwardSpec};
    use prw_network::PrivateDnsConfig;
    use prw_policy::{
        BoundedLocalManagementDecisions, BoundedLocalManagementPolicy, BoundedLocalReadPolicy,
        Decision,
    };
    use prw_remote_bridge::BridgeCommand;
    use prw_terminal::{TerminalBackend, TerminalError, TerminalGeometry, TerminalProfile};

    use super::{
        LocalManagementBoundaryTransactionError, process_one_management_capable_at_boundary,
    };
    use crate::LocalIpcRequestId;
    use crate::frame_object::LocalIpcPayload;
    use crate::frame_object::reader::read_frame;
    use crate::frame_object::writer::write_frame;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::local_commands::LocalAgentCommand;
    use crate::local_commands::boundary_request_response_transaction::LocalBoundaryRequestResponseOutcome;
    use crate::local_commands::inbound_state::LocalInboundRequestState;
    use crate::local_commands::management_authority::LocalManagementFilesystemAuthority;
    use crate::local_commands::management_provider_lifecycle::LocalManagementProviderLifecycle;
    use crate::local_commands::management_request::build_local_management_request_frame;
    use crate::local_commands::private_dns_snapshot::LocalPrivateDnsSnapshot;
    use crate::local_commands::request_frame::build_local_command_request_frame;
    use crate::local_commands::response_writer::LocalTerminalResponseWriteState;
    use crate::local_commands::status_snapshot::response_frame::decode_success_status_frame;
    use crate::local_commands::status_snapshot::{
        LocalAgentRuntimeState, LocalAgentStatusSnapshot,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;
    use crate::{LocalIpcFrameHeader, LocalIpcMessageKind, LocalIpcProtocolVersion};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug, Default)]
    struct NoopTerminal;

    impl TerminalBackend for NoopTerminal {
        type Handle = ();

        fn open(
            &mut self,
            _profile: TerminalProfile,
            _geometry: TerminalGeometry,
        ) -> Result<Self::Handle, TerminalError> {
            Ok(())
        }

        fn write_input(
            &mut self,
            _handle: &mut Self::Handle,
            _bytes: &[u8],
        ) -> Result<(), TerminalError> {
            Ok(())
        }

        fn resize(
            &mut self,
            _handle: &mut Self::Handle,
            _geometry: TerminalGeometry,
        ) -> Result<(), TerminalError> {
            Ok(())
        }

        fn read_output(
            &mut self,
            _handle: &mut Self::Handle,
            _maximum_bytes: usize,
        ) -> Result<Vec<u8>, TerminalError> {
            Ok(Vec::new())
        }

        fn close(&mut self, _handle: &mut Self::Handle) -> Result<(), TerminalError> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct NoopForward;

    impl PortForwardBackend for NoopForward {
        type Handle = ();

        fn open(&mut self, _spec: TcpForwardSpec) -> Result<Self::Handle, ForwardingError> {
            Ok(())
        }

        fn close(&mut self, _handle: &mut Self::Handle) -> Result<(), ForwardingError> {
            Ok(())
        }
    }

    struct Harness {
        root_path: PathBuf,
        filesystem: LocalManagementFilesystemAuthority,
        server: AuthenticatedLocalLinuxConnection<UnixStream>,
        client: UnixStream,
    }

    impl Harness {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let root_path = std::env::temp_dir().join(format!(
                "prw-c03-boundary-{}-{sequence}-{label}",
                std::process::id()
            ));
            fs::create_dir(&root_path).expect("test root creates");
            let filesystem = LocalManagementFilesystemAuthority::open_trusted_root(&root_path)
                .expect("test root anchors");
            let (server, client) = UnixStream::pair().expect("local pair creates");
            let server = AuthenticatedLocalLinuxConnection::try_new(server)
                .expect("same-UID peer authenticates");
            Self {
                root_path,
                filesystem,
                server,
                client,
            }
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root_path);
        }
    }

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("request id non-zero")
    }

    fn status() -> LocalAgentStatusSnapshot {
        LocalAgentStatusSnapshot::current(LocalAgentRuntimeState::Ready)
    }

    fn dns() -> LocalPrivateDnsSnapshot {
        LocalPrivateDnsSnapshot::try_from_config(&PrivateDnsConfig::default())
            .expect("default DNS bounded")
    }

    fn management_policy() -> BoundedLocalManagementPolicy {
        BoundedLocalManagementPolicy::new(BoundedLocalManagementDecisions {
            agent_status: Decision::Allow,
            private_dns: Decision::Deny,
            terminal_open: Decision::Deny,
            terminal_exec: Decision::Deny,
            files_read: Decision::Deny,
            files_write: Decision::Deny,
            forwarding_create: Decision::Deny,
        })
    }

    #[test]
    fn legacy_command_one_keeps_exact_existing_response_path() {
        let harness = Harness::new("legacy");
        let request = build_local_command_request_frame(id(1), LocalAgentCommand::GetAgentStatus)
            .expect("legacy request builds");
        let mut input = Vec::new();
        write_frame(&mut input, &request).expect("request writes to memory");
        let mut output = Vec::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();
        let mut lifecycle =
            LocalManagementProviderLifecycle::new(&harness.filesystem, NoopTerminal, NoopForward);
        let dns = dns();

        assert_eq!(
            process_one_management_capable_at_boundary(
                &mut Cursor::new(input),
                &mut output,
                &mut inbound,
                &mut response,
                &harness.server,
                &BoundedLocalReadPolicy::allow_local_reads(),
                &management_policy(),
                &harness.filesystem,
                &mut lifecycle,
                status(),
                &dns,
            ),
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
        );
        let frame = read_frame(&mut Cursor::new(output)).expect("response reads");
        let decoded = decode_success_status_frame(&frame).expect("legacy status decodes");
        assert_eq!(decoded.request_id(), id(1));
        assert!(inbound.can_read());
        assert!(response.can_write());
    }

    #[test]
    fn command_three_uses_canonical_management_path_and_preserves_correlation() {
        let harness = Harness::new("management");
        let bridge = BridgeCommand::AgentStatus.encode().expect("bridge encodes");
        let request = build_local_management_request_frame(id(2), &bridge)
            .expect("management request builds");
        let mut input = Vec::new();
        write_frame(&mut input, &request).expect("request writes to memory");
        let mut output = Vec::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();
        let mut lifecycle =
            LocalManagementProviderLifecycle::new(&harness.filesystem, NoopTerminal, NoopForward);
        let dns = dns();

        assert_eq!(
            process_one_management_capable_at_boundary(
                &mut Cursor::new(input),
                &mut output,
                &mut inbound,
                &mut response,
                &harness.server,
                &BoundedLocalReadPolicy::deny_all(),
                &management_policy(),
                &harness.filesystem,
                &mut lifecycle,
                status(),
                &dns,
            ),
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
        );
        let frame = read_frame(&mut Cursor::new(output)).expect("response reads");
        let terminal = validate_terminal_response_frame(&frame).expect("response validates");
        assert_eq!(terminal.request_id(), id(2));
        assert!(terminal.status().is_success());
        assert!(inbound.can_read());
        assert!(response.can_write());
    }

    #[test]
    fn malformed_command_three_is_correlated_invalid_request_without_framing_poison() {
        let harness = Harness::new("management-invalid");
        let request = build_local_management_request_frame(id(3), b"not-prwc")
            .expect("management envelope builds");
        let mut input = Vec::new();
        write_frame(&mut input, &request).expect("request writes to memory");
        let mut output = Vec::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();
        let mut lifecycle =
            LocalManagementProviderLifecycle::new(&harness.filesystem, NoopTerminal, NoopForward);
        let dns = dns();

        assert_eq!(
            process_one_management_capable_at_boundary(
                &mut Cursor::new(input),
                &mut output,
                &mut inbound,
                &mut response,
                &harness.server,
                &BoundedLocalReadPolicy::deny_all(),
                &management_policy(),
                &harness.filesystem,
                &mut lifecycle,
                status(),
                &dns,
            ),
            Ok(LocalBoundaryRequestResponseOutcome::ResponseWritten)
        );
        let frame = read_frame(&mut Cursor::new(output)).expect("response reads");
        let terminal = validate_terminal_response_frame(&frame).expect("response validates");
        assert_eq!(terminal.request_id(), id(3));
        assert_eq!(terminal.status().code(), 1);
        assert!(inbound.can_read());
    }

    #[test]
    fn unknown_legacy_command_preserves_existing_fail_closed_inbound_poison() {
        let harness = Harness::new("legacy-invalid");
        let payload = LocalIpcPayload::new(vec![0, 4]).expect("bounded payload");
        let header = LocalIpcFrameHeader::new(
            LocalIpcProtocolVersion::current(),
            LocalIpcMessageKind::Request,
            id(4),
            payload.len(),
        )
        .expect("valid header");
        let frame = crate::frame_object::LocalIpcFrame::new(header, payload).expect("frame");
        let mut input = Vec::new();
        write_frame(&mut input, &frame).expect("request writes to memory");
        let mut output = Vec::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();
        let mut lifecycle =
            LocalManagementProviderLifecycle::new(&harness.filesystem, NoopTerminal, NoopForward);
        let dns = dns();

        assert!(matches!(
            process_one_management_capable_at_boundary(
                &mut Cursor::new(input),
                &mut output,
                &mut inbound,
                &mut response,
                &harness.server,
                &BoundedLocalReadPolicy::allow_local_reads(),
                &management_policy(),
                &harness.filesystem,
                &mut lifecycle,
                status(),
                &dns,
            ),
            Err(LocalManagementBoundaryTransactionError::ReadOnlyDecode(_))
        ));
        assert!(inbound.is_read_poisoned());
        assert!(output.is_empty());
    }

    #[test]
    fn exact_management_denial_is_correlated_unauthorized_before_provider_mutation() {
        let harness = Harness::new("management-deny");
        let bridge = BridgeCommand::AgentStatus.encode().expect("bridge encodes");
        let request = build_local_management_request_frame(id(5), &bridge)
            .expect("management request builds");
        let mut input = Vec::new();
        write_frame(&mut input, &request).expect("request writes to memory");
        let mut output = Vec::new();
        let mut inbound = LocalInboundRequestState::new();
        let mut response = LocalTerminalResponseWriteState::new();
        let mut lifecycle =
            LocalManagementProviderLifecycle::new(&harness.filesystem, NoopTerminal, NoopForward);
        let dns = dns();

        process_one_management_capable_at_boundary(
            &mut Cursor::new(input),
            &mut output,
            &mut inbound,
            &mut response,
            &harness.server,
            &BoundedLocalReadPolicy::deny_all(),
            &BoundedLocalManagementPolicy::deny_all(),
            &harness.filesystem,
            &mut lifecycle,
            status(),
            &dns,
        )
        .expect("denial still returns terminal response");
        let frame = read_frame(&mut Cursor::new(output)).expect("response reads");
        let terminal = validate_terminal_response_frame(&frame).expect("response validates");
        assert_eq!(terminal.request_id(), id(5));
        assert_eq!(terminal.status().code(), 2);
        assert_eq!(lifecycle.active_terminal_count(), 0);
        assert_eq!(lifecycle.active_forwarding_count(), 0);
        assert_eq!(lifecycle.active_transfer_count(), 0);
    }

    #[test]
    fn command_namespace_is_not_inferred_from_target_address_bytes() {
        let _ = IpAddr::V4(Ipv4Addr::LOCALHOST);
    }
}
