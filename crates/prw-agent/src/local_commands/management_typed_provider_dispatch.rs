//! C02c typed provider dispatch seam for admitted local management commands.
//!
//! This module performs only typed provider operations over already-decoded
//! [`prw_remote_bridge::BridgeCommand`] values. It deliberately does not encode local
//! response bytes, enter the production server loop, select host filesystem roots,
//! fabricate remote principals, or construct provider backends from request data.

use std::ptr;

use prw_file_service::{FileServiceError, RemoteDirectoryEntry, RemoteMetadata};
use prw_file_transfer::{FileTransferError, download_chunk};
use prw_forwarding::{ForwardingError, ForwardingSessionPrincipal, PortForwardBackend};
use prw_remote_bridge::BridgeCommand;
use prw_terminal::{TerminalBackend, TerminalError, TerminalSessionPrincipal};

use super::management_authority::LocalManagementFamilyAuthority;
use super::management_dispatch::LocalManagementAuthorityContext;
use super::management_provider_lifecycle::LocalManagementProviderLifecycle;
use super::management_request::LocalManagementAdmission;
use super::status_snapshot::LocalAgentStatusSnapshot;

/// Typed provider result retained before any local response-byte encoding decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LocalManagementTypedProviderResult {
    /// Existing bounded Agent status snapshot.
    AgentStatus(LocalAgentStatusSnapshot),
    /// Existing descriptor-anchored bounded directory listing.
    DirectoryEntries(Vec<RemoteDirectoryEntry>),
    /// Existing descriptor-anchored bounded metadata snapshot.
    Metadata(RemoteMetadata),
    /// Provider operation completed with no response body selected at this gate.
    Empty,
    /// Transfer operation returned the exact persisted/resume offset.
    Offset(u64),
    /// Provider returned bounded bytes, for download or terminal output.
    Bytes(Vec<u8>),
}

/// Fail-closed typed provider-dispatch failure before response encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalManagementTypedProviderDispatchError {
    /// Supplied family authority does not match the admitted canonical command.
    AuthorityFamilyMismatch,
    /// File/transfer authority is not the exact filesystem authority owned by lifecycle.
    FilesystemAuthorityMismatch,
    /// Terminal/forwarding operation attempted to cross an existing principal binding.
    PrincipalMismatch,
    /// Descriptor-anchored file operation failed.
    File(FileServiceError),
    /// Descriptor-anchored transfer operation failed.
    Transfer(FileTransferError),
    /// Typed terminal broker operation failed.
    Terminal(TerminalError),
    /// Typed forwarding broker operation failed.
    Forwarding(ForwardingError),
}

/// Dispatches one admitted canonical command through already-owned typed providers.
///
/// The function first proves family correlation by constructing the existing C02c
/// request-bound authority context. Family-specific helpers then enforce exact
/// filesystem authority or registry/session principal binding before mutation.
///
/// No local response byte representation is chosen here. Successful output remains in
/// [`LocalManagementTypedProviderResult`] for the deterministic response layer.
///
/// # Errors
///
/// Fails before provider mutation on authority-family, filesystem-authority, or
/// principal-binding mismatch. Provider errors are retained as typed classifications.
pub(super) fn dispatch_admitted_management_command<T, F>(
    admission: &LocalManagementAdmission,
    authority: LocalManagementFamilyAuthority<'_>,
    lifecycle: &mut LocalManagementProviderLifecycle<'_, T, F>,
    agent_status: LocalAgentStatusSnapshot,
) -> Result<LocalManagementTypedProviderResult, LocalManagementTypedProviderDispatchError>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    LocalManagementAuthorityContext::from_agent_owned_authority(admission, authority)
        .ok_or(LocalManagementTypedProviderDispatchError::AuthorityFamilyMismatch)?;

    match admission.command() {
        BridgeCommand::AgentStatus => Ok(LocalManagementTypedProviderResult::AgentStatus(
            agent_status,
        )),
        BridgeCommand::FileList(_)
        | BridgeCommand::FileStat(_)
        | BridgeCommand::FileCreate { .. }
        | BridgeCommand::DirectoryCreate(_) => {
            dispatch_file_command(admission.command(), authority, lifecycle)
        }
        BridgeCommand::UploadBegin(_)
        | BridgeCommand::UploadResume(_)
        | BridgeCommand::UploadChunk { .. }
        | BridgeCommand::UploadFinalize(_)
        | BridgeCommand::UploadAbort(_)
        | BridgeCommand::DownloadChunk { .. } => {
            dispatch_transfer_command(admission.command(), authority, lifecycle)
        }
        BridgeCommand::TerminalOpen { .. }
        | BridgeCommand::TerminalInput { .. }
        | BridgeCommand::TerminalResize { .. }
        | BridgeCommand::TerminalRead { .. }
        | BridgeCommand::TerminalClose(_) => {
            dispatch_terminal_command(admission.command(), authority, lifecycle)
        }
        BridgeCommand::ForwardOpen { .. } | BridgeCommand::ForwardClose(_) => {
            dispatch_forwarding_command(admission.command(), authority, lifecycle)
        }
    }
}

#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "family helper rejects commands outside the preclassified file family"
)]
fn dispatch_file_command<T, F>(
    command: &BridgeCommand,
    authority: LocalManagementFamilyAuthority<'_>,
    lifecycle: &LocalManagementProviderLifecycle<'_, T, F>,
) -> Result<LocalManagementTypedProviderResult, LocalManagementTypedProviderDispatchError>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    require_exact_filesystem_authority(authority, lifecycle)?;
    let root = lifecycle.filesystem().root();

    match command {
        BridgeCommand::FileList(path) => root
            .list_directory(path)
            .map(LocalManagementTypedProviderResult::DirectoryEntries)
            .map_err(LocalManagementTypedProviderDispatchError::File),
        BridgeCommand::FileStat(path) => root
            .metadata(path)
            .map(LocalManagementTypedProviderResult::Metadata)
            .map_err(LocalManagementTypedProviderDispatchError::File),
        BridgeCommand::FileCreate { path, contents } => root
            .create_file(path, contents)
            .map(|()| LocalManagementTypedProviderResult::Empty)
            .map_err(LocalManagementTypedProviderDispatchError::File),
        BridgeCommand::DirectoryCreate(path) => root
            .create_directory(path)
            .map(|()| LocalManagementTypedProviderResult::Empty)
            .map_err(LocalManagementTypedProviderDispatchError::File),
        _ => Err(LocalManagementTypedProviderDispatchError::AuthorityFamilyMismatch),
    }
}

#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "family helper rejects commands outside the preclassified transfer family"
)]
fn dispatch_transfer_command<T, F>(
    command: &BridgeCommand,
    authority: LocalManagementFamilyAuthority<'_>,
    lifecycle: &mut LocalManagementProviderLifecycle<'_, T, F>,
) -> Result<LocalManagementTypedProviderResult, LocalManagementTypedProviderDispatchError>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    require_exact_filesystem_authority(authority, lifecycle)?;

    match command {
        BridgeCommand::UploadBegin(plan) => lifecycle
            .transfers_mut()
            .begin(plan.clone())
            .map(LocalManagementTypedProviderResult::Offset)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        BridgeCommand::UploadResume(plan) => lifecycle
            .transfers_mut()
            .resume(plan.clone())
            .map(LocalManagementTypedProviderResult::Offset)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        BridgeCommand::UploadChunk {
            transfer_id,
            offset,
            chunk,
        } => lifecycle
            .transfers_mut()
            .upload_chunk(*transfer_id, *offset, chunk)
            .map(LocalManagementTypedProviderResult::Offset)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        BridgeCommand::UploadFinalize(transfer_id) => lifecycle
            .transfers_mut()
            .finalize(*transfer_id)
            .map(|()| LocalManagementTypedProviderResult::Empty)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        BridgeCommand::UploadAbort(transfer_id) => lifecycle
            .transfers_mut()
            .abort(*transfer_id)
            .map(|()| LocalManagementTypedProviderResult::Empty)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        BridgeCommand::DownloadChunk {
            path,
            offset,
            requested_len,
        } => download_chunk(lifecycle.filesystem().root(), path, *offset, *requested_len)
            .map(LocalManagementTypedProviderResult::Bytes)
            .map_err(LocalManagementTypedProviderDispatchError::Transfer),
        _ => Err(LocalManagementTypedProviderDispatchError::AuthorityFamilyMismatch),
    }
}

#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "family helper rejects commands outside the preclassified terminal family"
)]
fn dispatch_terminal_command<T, F>(
    command: &BridgeCommand,
    authority: LocalManagementFamilyAuthority<'_>,
    lifecycle: &mut LocalManagementProviderLifecycle<'_, T, F>,
) -> Result<LocalManagementTypedProviderResult, LocalManagementTypedProviderDispatchError>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    let principal = terminal_principal(authority)?;

    match command {
        BridgeCommand::TerminalOpen {
            session_id,
            profile,
            geometry,
        } => {
            if let Some(existing) = lifecycle.terminal().session(*session_id) {
                require_same_terminal_principal(existing.principal(), &principal)?;
            }
            lifecycle
                .terminal_mut()
                .open_session(*session_id, principal, *profile, *geometry)
                .map(|_| LocalManagementTypedProviderResult::Empty)
                .map_err(LocalManagementTypedProviderDispatchError::Terminal)
        }
        BridgeCommand::TerminalInput { session_id, bytes } => {
            require_terminal_session_principal(lifecycle, *session_id, &principal)?;
            lifecycle
                .terminal_mut()
                .write_input(*session_id, bytes)
                .map(|()| LocalManagementTypedProviderResult::Empty)
                .map_err(LocalManagementTypedProviderDispatchError::Terminal)
        }
        BridgeCommand::TerminalResize {
            session_id,
            geometry,
        } => {
            require_terminal_session_principal(lifecycle, *session_id, &principal)?;
            lifecycle
                .terminal_mut()
                .resize_session(*session_id, *geometry)
                .map(|()| LocalManagementTypedProviderResult::Empty)
                .map_err(LocalManagementTypedProviderDispatchError::Terminal)
        }
        BridgeCommand::TerminalRead {
            session_id,
            maximum_bytes,
        } => {
            require_terminal_session_principal(lifecycle, *session_id, &principal)?;
            lifecycle
                .terminal_mut()
                .read_output(*session_id, *maximum_bytes)
                .map(LocalManagementTypedProviderResult::Bytes)
                .map_err(LocalManagementTypedProviderDispatchError::Terminal)
        }
        BridgeCommand::TerminalClose(session_id) => {
            require_terminal_session_principal(lifecycle, *session_id, &principal)?;
            lifecycle
                .terminal_mut()
                .close_session(*session_id)
                .map(|_| LocalManagementTypedProviderResult::Empty)
                .map_err(LocalManagementTypedProviderDispatchError::Terminal)
        }
        _ => Err(LocalManagementTypedProviderDispatchError::AuthorityFamilyMismatch),
    }
}

#[allow(
    clippy::wildcard_enum_match_arm,
    reason = "family helper rejects commands outside the preclassified forwarding family"
)]
fn dispatch_forwarding_command<T, F>(
    command: &BridgeCommand,
    authority: LocalManagementFamilyAuthority<'_>,
    lifecycle: &mut LocalManagementProviderLifecycle<'_, T, F>,
) -> Result<LocalManagementTypedProviderResult, LocalManagementTypedProviderDispatchError>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    let principal = forwarding_principal(authority)?;

    match command {
        BridgeCommand::ForwardOpen { forward_id, spec } => {
            if let Some(existing) = lifecycle.forwarding().session(*forward_id) {
                require_same_forwarding_principal(existing.principal(), &principal)?;
            }
            lifecycle
                .forwarding_mut()
                .open_session(*forward_id, principal, *spec)
                .map(|_| LocalManagementTypedProviderResult::Empty)
                .map_err(LocalManagementTypedProviderDispatchError::Forwarding)
        }
        BridgeCommand::ForwardClose(forward_id) => {
            require_forwarding_session_principal(lifecycle, *forward_id, &principal)?;
            lifecycle
                .forwarding_mut()
                .close_session(*forward_id)
                .map(|_| LocalManagementTypedProviderResult::Empty)
                .map_err(LocalManagementTypedProviderDispatchError::Forwarding)
        }
        _ => Err(LocalManagementTypedProviderDispatchError::AuthorityFamilyMismatch),
    }
}

fn require_exact_filesystem_authority<T, F>(
    authority: LocalManagementFamilyAuthority<'_>,
    lifecycle: &LocalManagementProviderLifecycle<'_, T, F>,
) -> Result<(), LocalManagementTypedProviderDispatchError>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    let supplied = authority
        .filesystem()
        .ok_or(LocalManagementTypedProviderDispatchError::AuthorityFamilyMismatch)?;
    if ptr::eq(supplied, lifecycle.filesystem()) {
        Ok(())
    } else {
        Err(LocalManagementTypedProviderDispatchError::FilesystemAuthorityMismatch)
    }
}

fn terminal_principal(
    authority: LocalManagementFamilyAuthority<'_>,
) -> Result<TerminalSessionPrincipal, LocalManagementTypedProviderDispatchError> {
    authority
        .terminal_session_principal()
        .ok_or(LocalManagementTypedProviderDispatchError::AuthorityFamilyMismatch)
}

fn forwarding_principal(
    authority: LocalManagementFamilyAuthority<'_>,
) -> Result<ForwardingSessionPrincipal, LocalManagementTypedProviderDispatchError> {
    authority
        .forwarding_session_principal()
        .ok_or(LocalManagementTypedProviderDispatchError::AuthorityFamilyMismatch)
}

fn require_same_terminal_principal(
    existing: &TerminalSessionPrincipal,
    current: &TerminalSessionPrincipal,
) -> Result<(), LocalManagementTypedProviderDispatchError> {
    if existing == current {
        Ok(())
    } else {
        Err(LocalManagementTypedProviderDispatchError::PrincipalMismatch)
    }
}

fn require_terminal_session_principal<T, F>(
    lifecycle: &LocalManagementProviderLifecycle<'_, T, F>,
    session_id: prw_terminal::TerminalSessionId,
    current: &TerminalSessionPrincipal,
) -> Result<(), LocalManagementTypedProviderDispatchError>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    let existing = lifecycle.terminal().session(session_id).ok_or(
        LocalManagementTypedProviderDispatchError::Terminal(TerminalError::UnknownSession),
    )?;
    require_same_terminal_principal(existing.principal(), current)
}

fn require_same_forwarding_principal(
    existing: &ForwardingSessionPrincipal,
    current: &ForwardingSessionPrincipal,
) -> Result<(), LocalManagementTypedProviderDispatchError> {
    if existing == current {
        Ok(())
    } else {
        Err(LocalManagementTypedProviderDispatchError::PrincipalMismatch)
    }
}

fn require_forwarding_session_principal<T, F>(
    lifecycle: &LocalManagementProviderLifecycle<'_, T, F>,
    forward_id: prw_forwarding::PortForwardId,
    current: &ForwardingSessionPrincipal,
) -> Result<(), LocalManagementTypedProviderDispatchError>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    let existing = lifecycle.forwarding().session(forward_id).ok_or(
        LocalManagementTypedProviderDispatchError::Forwarding(ForwardingError::UnknownSession),
    )?;
    require_same_forwarding_principal(existing.principal(), current)
}
