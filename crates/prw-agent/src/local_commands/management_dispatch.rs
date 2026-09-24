//! C02a/C02c provider-neutral dispatch boundary for authenticated local management requests.
//!
//! C02a proves ordering: C01 admission must succeed, an Agent-owned authority context
//! must match the exact caller/request/capability/operation/provider family, and only
//! then may a provider-neutral dispatcher be invoked. C02c adds a crate-internal
//! construction seam that requires real family-specific Agent-owned authority evidence.
//! No real provider adapter is wired into the runtime server loop or Linux bootstrap.

use prw_policy::Capability;
use prw_remote_bridge::BridgeCommand;

use super::management_authority::LocalManagementFamilyAuthority;
use super::management_request::LocalManagementAdmission;
use crate::LocalIpcRequestId;

#[cfg(target_os = "linux")]
use super::LocalAgentResponseStatus;
#[cfg(target_os = "linux")]
use super::management_request::{
    LocalManagementAdmissionError, admit_authenticated_linux_management_request,
};
#[cfg(target_os = "linux")]
use super::terminal_response::builder::{
    LocalTerminalResponseBuildError, build_terminal_response_frame,
};
#[cfg(target_os = "linux")]
use crate::frame_object::LocalIpcFrame;
#[cfg(target_os = "linux")]
use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
#[cfg(target_os = "linux")]
use prw_policy::PolicyEvaluator;

/// Provider family required after canonical command admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalManagementAuthorityFamily {
    /// Agent-owned status authority.
    Agent,
    /// Descriptor-anchored bounded file-service authority.
    File,
    /// Descriptor-anchored transfer authority.
    Transfer,
    /// Terminal authority with a non-fabricated principal mapping.
    Terminal,
    /// Forwarding authority with a non-fabricated principal mapping.
    Forwarding,
}

/// Opaque request-bound authority token.
///
/// C02c permits crate-internal construction only when a matching
/// [`LocalManagementFamilyAuthority`] already exists outside request decoding.
/// The token remains correlation evidence rather than a provider object itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalManagementAuthorityContext {
    request_id: LocalIpcRequestId,
    peer_pid: i32,
    peer_uid: u32,
    peer_gid: u32,
    capability: Capability,
    operation_code: u16,
    family: LocalManagementAuthorityFamily,
}

impl LocalManagementAuthorityContext {
    /// Binds one admitted request to already-existing Agent-owned family authority.
    ///
    /// Returns `None` when the supplied authority family is not the family required by
    /// the canonical admitted command. Request ID, kernel peer credentials, capability,
    /// operation code and provider family are copied only from the admission token.
    pub(super) fn from_agent_owned_authority(
        admission: &LocalManagementAdmission,
        authority: LocalManagementFamilyAuthority<'_>,
    ) -> Option<Self> {
        let required_family = required_authority_family(admission.command());
        if authority.family() != required_family {
            return None;
        }

        Some(Self {
            request_id: admission.request_id(),
            peer_pid: admission.peer_pid(),
            peer_uid: admission.peer_uid(),
            peer_gid: admission.peer_gid(),
            capability: admission.capability(),
            operation_code: admission.command().operation_code(),
            family: required_family,
        })
    }

    fn matches(&self, admission: &LocalManagementAdmission) -> bool {
        self.request_id == admission.request_id()
            && self.peer_pid == admission.peer_pid()
            && self.peer_uid == admission.peer_uid()
            && self.peer_gid == admission.peer_gid()
            && self.capability == admission.capability()
            && self.operation_code == admission.command().operation_code()
            && self.family == required_authority_family(admission.command())
    }

    #[cfg(test)]
    const fn for_test(admission: &LocalManagementAdmission) -> Self {
        Self {
            request_id: admission.request_id(),
            peer_pid: admission.peer_pid(),
            peer_uid: admission.peer_uid(),
            peer_gid: admission.peer_gid(),
            capability: admission.capability(),
            operation_code: admission.command().operation_code(),
            family: required_authority_family(admission.command()),
        }
    }
}

/// Provider-neutral C02a dispatch boundary.
///
/// Current tests implement this trait with deterministic spies only. No production
/// terminal, file, transfer or forwarding provider implements it in this gate.
pub trait LocalManagementProviderDispatcher {
    /// Provider-neutral bounded dispatch error.
    type Error;

    /// Invokes one operation only after admission and exact authority matching.
    ///
    /// # Errors
    ///
    /// Returns the provider-neutral dispatch failure without creating success.
    fn dispatch(
        &mut self,
        admission: &LocalManagementAdmission,
        authority: &LocalManagementAuthorityContext,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Executes the provider-neutral ordering proof for one authenticated Linux peer.
///
/// Admission failures are converted to correlated fail-closed local terminal errors.
/// Missing/stale/mismatched authority fails with `Conflict` before dispatcher invocation.
/// Dispatcher failure produces `InternalError`. `Ok` is constructed only after the
/// dispatcher returns success.
///
/// This function remains deliberately disconnected from the local server loop in C02c.
///
/// # Errors
///
/// Returns only terminal-response frame construction failures.
#[cfg(target_os = "linux")]
pub fn process_authenticated_linux_management_request<E, D, S>(
    frame: &LocalIpcFrame,
    connection: &AuthenticatedLocalLinuxConnection<S>,
    evaluator: &E,
    authority: Option<&LocalManagementAuthorityContext>,
    dispatcher: &mut D,
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError>
where
    E: PolicyEvaluator + ?Sized,
    D: LocalManagementProviderDispatcher,
{
    let request_id = frame.header().request_id();
    let admission = match admit_authenticated_linux_management_request(frame, connection, evaluator)
    {
        Ok(admission) => admission,
        Err(error) => {
            return build_terminal_response_frame(request_id, admission_failure_status(error), &[]);
        }
    };

    let Some(authority) = authority else {
        return build_terminal_response_frame(request_id, LocalAgentResponseStatus::Conflict, &[]);
    };
    if !authority.matches(&admission) {
        return build_terminal_response_frame(request_id, LocalAgentResponseStatus::Conflict, &[]);
    }

    dispatcher.dispatch(&admission, authority).map_or_else(
        |_| build_terminal_response_frame(request_id, LocalAgentResponseStatus::InternalError, &[]),
        |body| build_terminal_response_frame(request_id, LocalAgentResponseStatus::Ok, &body),
    )
}

#[cfg(target_os = "linux")]
const fn admission_failure_status(
    error: LocalManagementAdmissionError,
) -> LocalAgentResponseStatus {
    match error {
        LocalManagementAdmissionError::Framing(_)
        | LocalManagementAdmissionError::CanonicalCommand(_) => {
            LocalAgentResponseStatus::InvalidRequest
        }
        LocalManagementAdmissionError::CapabilityDenied => LocalAgentResponseStatus::Unauthorized,
    }
}

pub(super) const fn required_authority_family(
    command: &BridgeCommand,
) -> LocalManagementAuthorityFamily {
    match command {
        BridgeCommand::AgentStatus => LocalManagementAuthorityFamily::Agent,
        BridgeCommand::FileList(_)
        | BridgeCommand::FileStat(_)
        | BridgeCommand::FileCreate { .. }
        | BridgeCommand::DirectoryCreate(_) => LocalManagementAuthorityFamily::File,
        BridgeCommand::UploadBegin(_)
        | BridgeCommand::UploadResume(_)
        | BridgeCommand::UploadChunk { .. }
        | BridgeCommand::UploadFinalize(_)
        | BridgeCommand::UploadAbort(_)
        | BridgeCommand::DownloadChunk { .. } => LocalManagementAuthorityFamily::Transfer,
        BridgeCommand::TerminalOpen { .. }
        | BridgeCommand::TerminalInput { .. }
        | BridgeCommand::TerminalResize { .. }
        | BridgeCommand::TerminalRead { .. }
        | BridgeCommand::TerminalClose(_) => LocalManagementAuthorityFamily::Terminal,
        BridgeCommand::ForwardOpen { .. } | BridgeCommand::ForwardClose(_) => {
            LocalManagementAuthorityFamily::Forwarding
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use prw_policy::{BoundedLocalReadPolicy, Capability, Decision, PolicyEvaluator};

    use super::{
        LocalManagementAuthorityContext, LocalManagementAuthorityFamily,
        LocalManagementProviderDispatcher, process_authenticated_linux_management_request,
    };
    use crate::LocalIpcRequestId;
    use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;
    use crate::local_commands::LocalAgentResponseStatus;
    use crate::local_commands::management_authority::LocalManagementFamilyAuthority;
    use crate::local_commands::management_request::{
        admit_authenticated_linux_management_request, build_local_management_request_frame,
    };
    use crate::local_commands::terminal_response::validate_terminal_response_frame;

    struct AllowAll;

    impl PolicyEvaluator for AllowAll {
        fn evaluate(&self, _capability: Capability) -> Decision {
            Decision::Allow
        }
    }

    #[derive(Debug, Default)]
    struct SpyDispatcher {
        calls: usize,
        fail: bool,
        body: Vec<u8>,
    }

    impl LocalManagementProviderDispatcher for SpyDispatcher {
        type Error = ();

        fn dispatch(
            &mut self,
            _admission: &crate::local_commands::management_request::LocalManagementAdmission,
            _authority: &LocalManagementAuthorityContext,
        ) -> Result<Vec<u8>, Self::Error> {
            self.calls += 1;
            if self.fail {
                Err(())
            } else {
                Ok(self.body.clone())
            }
        }
    }

    fn id(value: u64) -> LocalIpcRequestId {
        LocalIpcRequestId::new(value).expect("non-zero request id")
    }

    fn authenticated_connection() -> AuthenticatedLocalLinuxConnection<UnixStream> {
        let (server, _client) = UnixStream::pair().expect("anonymous local pair creates");
        AuthenticatedLocalLinuxConnection::try_new(server)
            .expect("same-UID local peer authenticates")
    }

    fn canonical_file_list_payload(path: &str) -> Vec<u8> {
        let path = path.as_bytes();
        let path_len = u16::try_from(path.len()).expect("test path length fits u16");
        let mut payload = Vec::new();
        payload.extend_from_slice(b"PRWC");
        payload.extend_from_slice(&1_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&2_u16.to_be_bytes());
        payload.extend_from_slice(&0_u16.to_be_bytes());
        payload.extend_from_slice(&path_len.to_be_bytes());
        payload.extend_from_slice(path);
        payload
    }

    fn file_list_request(request_id: u64) -> crate::frame_object::LocalIpcFrame {
        build_local_management_request_frame(
            id(request_id),
            &canonical_file_list_payload("documents"),
        )
        .expect("canonical file-list request builds")
    }

    fn authority_for(
        request: &crate::frame_object::LocalIpcFrame,
        connection: &AuthenticatedLocalLinuxConnection<UnixStream>,
    ) -> LocalManagementAuthorityContext {
        let admission =
            admit_authenticated_linux_management_request(request, connection, &AllowAll)
                .expect("allowed request admits for test authority construction");
        LocalManagementAuthorityContext::for_test(&admission)
    }

    fn assert_status(
        frame: &crate::frame_object::LocalIpcFrame,
        request_id: u64,
        status: LocalAgentResponseStatus,
    ) {
        let terminal = validate_terminal_response_frame(frame).expect("terminal frame validates");
        assert_eq!(terminal.request_id(), id(request_id));
        assert_eq!(terminal.status(), status);
    }

    #[test]
    fn malformed_request_stops_before_dispatch_and_is_correlated_invalid_request() {
        let connection = authenticated_connection();
        let request = build_local_management_request_frame(id(201), b"not-prwc")
            .expect("outer management framing remains valid");
        let mut dispatcher = SpyDispatcher::default();

        let response = process_authenticated_linux_management_request(
            &request,
            &connection,
            &AllowAll,
            None,
            &mut dispatcher,
        )
        .expect("correlated invalid response builds");

        assert_eq!(dispatcher.calls, 0);
        assert_status(&response, 201, LocalAgentResponseStatus::InvalidRequest);
    }

    #[test]
    fn production_policy_denial_stops_before_dispatch_and_is_unauthorized() {
        let connection = authenticated_connection();
        let request = file_list_request(202);
        let policy = BoundedLocalReadPolicy::allow_local_reads();
        let mut dispatcher = SpyDispatcher::default();

        let response = process_authenticated_linux_management_request(
            &request,
            &connection,
            &policy,
            None,
            &mut dispatcher,
        )
        .expect("correlated unauthorized response builds");

        assert_eq!(dispatcher.calls, 0);
        assert_status(&response, 202, LocalAgentResponseStatus::Unauthorized);
    }

    #[test]
    fn missing_authority_stops_before_dispatch() {
        let connection = authenticated_connection();
        let request = file_list_request(203);
        let mut dispatcher = SpyDispatcher::default();

        let response = process_authenticated_linux_management_request(
            &request,
            &connection,
            &AllowAll,
            None,
            &mut dispatcher,
        )
        .expect("correlated conflict response builds");

        assert_eq!(dispatcher.calls, 0);
        assert_status(&response, 203, LocalAgentResponseStatus::Conflict);
    }

    #[test]
    fn exact_authority_invokes_dispatcher_once_and_success_follows_provider_success() {
        let connection = authenticated_connection();
        let request = file_list_request(204);
        let authority = authority_for(&request, &connection);
        let mut dispatcher = SpyDispatcher {
            body: vec![9, 8],
            ..SpyDispatcher::default()
        };

        let response = process_authenticated_linux_management_request(
            &request,
            &connection,
            &AllowAll,
            Some(&authority),
            &mut dispatcher,
        )
        .expect("correlated success response builds");

        assert_eq!(dispatcher.calls, 1);
        assert_status(&response, 204, LocalAgentResponseStatus::Ok);
        assert_eq!(response.payload().as_bytes(), &[0, 0, 9, 8]);
    }

    #[test]
    fn provider_failure_never_creates_success_acknowledgement() {
        let connection = authenticated_connection();
        let request = file_list_request(205);
        let authority = authority_for(&request, &connection);
        let mut dispatcher = SpyDispatcher {
            fail: true,
            ..SpyDispatcher::default()
        };

        let response = process_authenticated_linux_management_request(
            &request,
            &connection,
            &AllowAll,
            Some(&authority),
            &mut dispatcher,
        )
        .expect("correlated provider failure response builds");

        assert_eq!(dispatcher.calls, 1);
        assert_status(&response, 205, LocalAgentResponseStatus::InternalError);
        assert_ne!(
            response.header().kind(),
            crate::LocalIpcMessageKind::Response
        );
    }

    #[test]
    fn agent_owned_family_mismatch_refuses_context_construction() {
        let connection = authenticated_connection();
        let request = file_list_request(206);
        let admission =
            admit_authenticated_linux_management_request(&request, &connection, &AllowAll)
                .expect("allowed request admits");

        let context = LocalManagementAuthorityContext::from_agent_owned_authority(
            &admission,
            LocalManagementFamilyAuthority::agent(),
        );

        assert_eq!(context, None);
    }

    #[test]
    fn stale_or_wrong_family_authority_stops_before_dispatch() {
        let connection = authenticated_connection();
        let first = file_list_request(207);
        let second = file_list_request(208);
        let stale = authority_for(&first, &connection);
        let mut dispatcher = SpyDispatcher::default();

        let stale_response = process_authenticated_linux_management_request(
            &second,
            &connection,
            &AllowAll,
            Some(&stale),
            &mut dispatcher,
        )
        .expect("stale authority conflict builds");
        assert_eq!(dispatcher.calls, 0);
        assert_status(&stale_response, 208, LocalAgentResponseStatus::Conflict);

        let mut wrong_family = authority_for(&second, &connection);
        wrong_family.family = LocalManagementAuthorityFamily::Terminal;
        let wrong_family_response = process_authenticated_linux_management_request(
            &second,
            &connection,
            &AllowAll,
            Some(&wrong_family),
            &mut dispatcher,
        )
        .expect("wrong-family authority conflict builds");
        assert_eq!(dispatcher.calls, 0);
        assert_status(
            &wrong_family_response,
            208,
            LocalAgentResponseStatus::Conflict,
        );
    }
}
