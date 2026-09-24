//! C02c complete crate-internal management execution seam.
//!
//! This module composes authenticated C01 admission, already-existing Agent-owned
//! family authority, typed provider dispatch, and deterministic correlated response
//! construction. It is deliberately not called by the production local server loop,
//! Linux bootstrap, or `main.rs` in C02c.

#[cfg(target_os = "linux")]
use prw_forwarding::PortForwardBackend;
#[cfg(target_os = "linux")]
use prw_policy::PolicyEvaluator;
#[cfg(target_os = "linux")]
use prw_terminal::TerminalBackend;

#[cfg(target_os = "linux")]
use super::LocalAgentResponseStatus;
#[cfg(target_os = "linux")]
use super::management_authority::{
    LocalManagementFamilyAuthority, LocalManagementFilesystemAuthority,
    LocalManagementLocalAuthoritySet, LocalManagementLocalPeerAuthority,
};
#[cfg(target_os = "linux")]
use super::management_provider_lifecycle::LocalManagementProviderLifecycle;
#[cfg(target_os = "linux")]
use super::management_request::{
    LocalManagementAdmissionError, admit_authenticated_linux_management_request,
};
#[cfg(target_os = "linux")]
use super::management_response::build_management_provider_response;
#[cfg(target_os = "linux")]
use super::management_typed_provider_dispatch::dispatch_admitted_management_command;
#[cfg(target_os = "linux")]
use super::status_snapshot::LocalAgentStatusSnapshot;
#[cfg(target_os = "linux")]
use super::terminal_response::builder::{
    LocalTerminalResponseBuildError, build_terminal_response_frame,
};
#[cfg(target_os = "linux")]
use crate::frame_object::LocalIpcFrame;
#[cfg(target_os = "linux")]
use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;

/// Runs the complete C02c management path without wiring it into production runtime.
///
/// Ordering is fail-closed:
///
/// 1. authenticate/canonical-decode/capability-admit through existing C01;
/// 2. require caller-supplied real Agent-owned family authority;
/// 3. dispatch only through the typed provider seam;
/// 4. encode `Ok` only after provider success and bounded success-body encoding;
/// 5. map provider/authority failures into correlated coarse local errors.
///
/// The caller must assemble lifecycle/backends and family authority outside request
/// decoding. This function does not select a filesystem root, create a registry
/// principal, construct a provider backend, alter policy defaults, or activate runtime
/// management.
///
/// # Errors
///
/// Returns only terminal-response frame construction failures.
#[cfg(target_os = "linux")]
pub(super) fn process_authenticated_linux_management_with_typed_providers<E, T, F, S>(
    frame: &LocalIpcFrame,
    connection: &AuthenticatedLocalLinuxConnection<S>,
    evaluator: &E,
    authority: Option<LocalManagementFamilyAuthority<'_>>,
    lifecycle: &mut LocalManagementProviderLifecycle<'_, T, F>,
    agent_status: LocalAgentStatusSnapshot,
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError>
where
    E: PolicyEvaluator + ?Sized,
    T: TerminalBackend,
    F: PortForwardBackend,
{
    let request_id = frame.header().request_id();
    let admission = match admit_authenticated_linux_management_request(frame, connection, evaluator)
    {
        Ok(admission) => admission,
        Err(error) => {
            return build_terminal_response_frame(request_id, admission_error_status(error), &[]);
        }
    };

    let Some(authority) = authority else {
        return build_terminal_response_frame(request_id, LocalAgentResponseStatus::Conflict, &[]);
    };

    let result =
        dispatch_admitted_management_command(&admission, authority, lifecycle, agent_status);
    build_management_provider_response(request_id, result)
}

/// Executes one authenticated same-UID local management request through the complete
/// C03 authority path. The filesystem root and provider lifecycle are caller-owned and
/// already exist before request decoding; local terminal/forwarding identity is derived
/// only from the authenticated connection.
///
/// Ordering remains admission -> local authority resolution -> typed provider dispatch ->
/// correlated response. A policy denial returns before any provider-family authority is
/// used for mutation.
#[cfg(target_os = "linux")]
pub(super) fn process_authenticated_linux_management_with_local_authorities<E, T, F, S>(
    frame: &LocalIpcFrame,
    connection: &AuthenticatedLocalLinuxConnection<S>,
    evaluator: &E,
    filesystem: &LocalManagementFilesystemAuthority,
    lifecycle: &mut LocalManagementProviderLifecycle<'_, T, F>,
    agent_status: LocalAgentStatusSnapshot,
) -> Result<LocalIpcFrame, LocalTerminalResponseBuildError>
where
    E: PolicyEvaluator + ?Sized,
    T: TerminalBackend,
    F: PortForwardBackend,
{
    let request_id = frame.header().request_id();
    let admission = match admit_authenticated_linux_management_request(frame, connection, evaluator)
    {
        Ok(admission) => admission,
        Err(error) => {
            return build_terminal_response_frame(request_id, admission_error_status(error), &[]);
        }
    };

    let local_peer = LocalManagementLocalPeerAuthority::from_authenticated_connection(connection);
    let authorities = LocalManagementLocalAuthoritySet::new(filesystem, &local_peer);
    let authority = authorities.resolve(admission.command());
    let result =
        dispatch_admitted_management_command(&admission, authority, lifecycle, agent_status);
    build_management_provider_response(request_id, result)
}

#[cfg(target_os = "linux")]
const fn admission_error_status(error: LocalManagementAdmissionError) -> LocalAgentResponseStatus {
    match error {
        LocalManagementAdmissionError::Framing(_)
        | LocalManagementAdmissionError::CanonicalCommand(_) => {
            LocalAgentResponseStatus::InvalidRequest
        }
        LocalManagementAdmissionError::CapabilityDenied => LocalAgentResponseStatus::Unauthorized,
    }
}
