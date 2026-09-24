//! C02c Agent-owned authority foundation for local management providers.
//!
//! This module deliberately assembles no provider backend and is not wired into the
//! local server loop. It only captures the authority objects that a later reviewed
//! adapter must already possess before `LocalManagementAuthorityContext` may become
//! constructible outside tests.

use std::path::Path;

use prw_core::SessionId;
use prw_file_service::{AnchoredFileRoot, FileServiceError};
use prw_forwarding::{ForwardingPrincipal, ForwardingSessionPrincipal, LocalForwardingPrincipal};
use prw_registry::{RegistryError, RegistryValidatedPrincipal, WorkspaceDeviceRegistry};
use prw_session::AuthenticatedDeviceSession;
use prw_terminal::{LocalTerminalPrincipal, TerminalPrincipal, TerminalSessionPrincipal};

#[cfg(target_os = "linux")]
use crate::linux_identity::authenticated_connection::AuthenticatedLocalLinuxConnection;

use super::management_dispatch::{LocalManagementAuthorityFamily, required_authority_family};
use prw_remote_bridge::BridgeCommand;

/// Registry-current authenticated PRW-session authority retained by the Agent.
///
/// This authority cannot be fabricated from local `SO_PEERCRED`: construction
/// requires an already-authenticated device session and current registry
/// revalidation. The retained `SessionId` is copied only from that authenticated
/// session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalManagementRemoteSessionAuthority {
    principal: RegistryValidatedPrincipal,
    session_id: SessionId,
}

impl LocalManagementRemoteSessionAuthority {
    /// Revalidates one authenticated PRW session against current registry state.
    ///
    /// # Errors
    ///
    /// Propagates the registry's fail-closed membership/device/session-binding
    /// rejection. No authority object is returned on stale or mismatched state.
    #[must_use = "validated remote-session authority must be retained to authorize providers"]
    pub(super) fn revalidate(
        registry: &WorkspaceDeviceRegistry,
        session: &AuthenticatedDeviceSession,
    ) -> Result<Self, RegistryError> {
        let principal = registry.validate_authenticated_session(session)?;
        Ok(Self {
            principal,
            session_id: session.session_id().clone(),
        })
    }

    /// Returns the current registry-validated principal snapshot.
    #[must_use]
    pub(super) const fn principal(&self) -> &RegistryValidatedPrincipal {
        &self.principal
    }

    /// Returns the exact authenticated PRW session identifier.
    #[must_use]
    pub(super) const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Derives the terminal provider principal through the provider's locked API.
    #[must_use]
    pub(super) fn terminal_principal(&self) -> TerminalPrincipal {
        TerminalPrincipal::from_registry(&self.principal, self.session_id.clone())
    }

    /// Derives the forwarding provider principal through the provider's locked API.
    #[must_use]
    pub(super) fn forwarding_principal(&self) -> ForwardingPrincipal {
        ForwardingPrincipal::from_registry(&self.principal, self.session_id.clone())
    }
}

/// Agent-owned authority for one kernel-authenticated same-UID local peer.
///
/// This is intentionally not a registry principal. On Linux it can be constructed only
/// from the already-authenticated local connection object, so request bytes cannot
/// choose or override the UID retained for provider-session binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LocalManagementLocalPeerAuthority {
    uid: u32,
}

impl LocalManagementLocalPeerAuthority {
    /// Captures the authenticated local UID from an existing same-UID connection.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub(super) const fn from_authenticated_connection<S>(
        connection: &AuthenticatedLocalLinuxConnection<S>,
    ) -> Self {
        Self {
            uid: connection.peer_credentials().uid(),
        }
    }

    /// Returns the kernel-authenticated local UID.
    #[must_use]
    pub(super) const fn uid(self) -> u32 {
        self.uid
    }

    #[must_use]
    pub(super) const fn terminal_principal(self) -> LocalTerminalPrincipal {
        LocalTerminalPrincipal::new(self.uid)
    }

    #[must_use]
    pub(super) const fn forwarding_principal(self) -> LocalForwardingPrincipal {
        LocalForwardingPrincipal::new(self.uid)
    }
}

/// Agent-owned descriptor-anchored filesystem authority.
///
/// The constructor is crate-internal so request payload code cannot expose a public
/// host-root selection API. A later trusted configuration/bootstrap assembly must
/// choose the host path before local management dispatch can receive this authority.
#[derive(Debug)]
pub(super) struct LocalManagementFilesystemAuthority {
    root: AnchoredFileRoot,
}

impl LocalManagementFilesystemAuthority {
    /// Opens one trusted Agent-selected filesystem root into descriptor authority.
    ///
    /// # Errors
    ///
    /// Returns the file-service root-opening failure without retaining partial
    /// authority.
    #[must_use = "opened filesystem authority must be retained to authorize file providers"]
    pub(super) fn open_trusted_root(path: &Path) -> Result<Self, FileServiceError> {
        AnchoredFileRoot::open(path).map(|root| Self { root })
    }

    /// Returns the already-opened filesystem authority for file operations.
    #[must_use]
    pub(super) const fn root(&self) -> &AnchoredFileRoot {
        &self.root
    }
}

/// Complete Agent-owned authority set for one authenticated local management connection.
///
/// The filesystem descriptor authority is selected outside request decoding. The local
/// peer authority is derived from the already-authenticated same-UID connection.
#[derive(Debug, Clone, Copy)]
pub(super) struct LocalManagementLocalAuthoritySet<'authority> {
    filesystem: &'authority LocalManagementFilesystemAuthority,
    local_peer: &'authority LocalManagementLocalPeerAuthority,
}

impl<'authority> LocalManagementLocalAuthoritySet<'authority> {
    #[must_use]
    pub(super) const fn new(
        filesystem: &'authority LocalManagementFilesystemAuthority,
        local_peer: &'authority LocalManagementLocalPeerAuthority,
    ) -> Self {
        Self {
            filesystem,
            local_peer,
        }
    }

    /// Resolves family evidence only after the canonical command has been admitted.
    ///
    /// The same classifier used later by `LocalManagementAuthorityContext` is reused
    /// here, so there is no second family mapping for local runtime activation.
    #[must_use]
    pub(super) const fn resolve(
        self,
        command: &BridgeCommand,
    ) -> LocalManagementFamilyAuthority<'authority> {
        match required_authority_family(command) {
            LocalManagementAuthorityFamily::Agent => LocalManagementFamilyAuthority::agent(),
            LocalManagementAuthorityFamily::File => {
                LocalManagementFamilyAuthority::file(self.filesystem)
            }
            LocalManagementAuthorityFamily::Transfer => {
                LocalManagementFamilyAuthority::transfer(self.filesystem)
            }
            LocalManagementAuthorityFamily::Terminal => {
                LocalManagementFamilyAuthority::terminal_local(self.local_peer)
            }
            LocalManagementAuthorityFamily::Forwarding => {
                LocalManagementFamilyAuthority::forwarding_local(self.local_peer)
            }
        }
    }
}

/// Opaque family-specific authority evidence retained outside request decoding.
///
/// The variants are private; crate callers can obtain a value only through a
/// constructor that requires the corresponding real Agent-owned authority object.
#[derive(Debug, Clone, Copy)]
pub(super) struct LocalManagementFamilyAuthority<'authority> {
    inner: LocalManagementFamilyAuthorityKind<'authority>,
}

#[derive(Debug, Clone, Copy)]
enum LocalManagementFamilyAuthorityKind<'authority> {
    Agent,
    File(&'authority LocalManagementFilesystemAuthority),
    Transfer(&'authority LocalManagementFilesystemAuthority),
    TerminalRemote(&'authority LocalManagementRemoteSessionAuthority),
    TerminalLocal(&'authority LocalManagementLocalPeerAuthority),
    ForwardingRemote(&'authority LocalManagementRemoteSessionAuthority),
    ForwardingLocal(&'authority LocalManagementLocalPeerAuthority),
}

impl<'authority> LocalManagementFamilyAuthority<'authority> {
    /// Creates Agent-family authority that needs no external provider identity.
    #[must_use]
    pub(super) const fn agent() -> Self {
        Self {
            inner: LocalManagementFamilyAuthorityKind::Agent,
        }
    }

    /// Creates file-family evidence from an already-opened trusted root.
    #[must_use]
    pub(super) const fn file(authority: &'authority LocalManagementFilesystemAuthority) -> Self {
        Self {
            inner: LocalManagementFamilyAuthorityKind::File(authority),
        }
    }

    /// Creates transfer-family evidence from the same anchored filesystem authority.
    #[must_use]
    pub(super) const fn transfer(
        authority: &'authority LocalManagementFilesystemAuthority,
    ) -> Self {
        Self {
            inner: LocalManagementFamilyAuthorityKind::Transfer(authority),
        }
    }

    /// Creates terminal-family evidence from a registry-revalidated PRW session.
    #[must_use]
    pub(super) const fn terminal(
        authority: &'authority LocalManagementRemoteSessionAuthority,
    ) -> Self {
        Self {
            inner: LocalManagementFamilyAuthorityKind::TerminalRemote(authority),
        }
    }

    /// Creates terminal-family evidence from a kernel-authenticated same-UID local peer.
    #[must_use]
    pub(super) const fn terminal_local(
        authority: &'authority LocalManagementLocalPeerAuthority,
    ) -> Self {
        Self {
            inner: LocalManagementFamilyAuthorityKind::TerminalLocal(authority),
        }
    }

    /// Creates forwarding-family evidence from a registry-revalidated PRW session.
    #[must_use]
    pub(super) const fn forwarding(
        authority: &'authority LocalManagementRemoteSessionAuthority,
    ) -> Self {
        Self {
            inner: LocalManagementFamilyAuthorityKind::ForwardingRemote(authority),
        }
    }

    /// Creates forwarding-family evidence from a kernel-authenticated same-UID local peer.
    #[must_use]
    pub(super) const fn forwarding_local(
        authority: &'authority LocalManagementLocalPeerAuthority,
    ) -> Self {
        Self {
            inner: LocalManagementFamilyAuthorityKind::ForwardingLocal(authority),
        }
    }

    /// Returns the exact provider family proven by this authority object.
    #[must_use]
    pub(super) const fn family(self) -> LocalManagementAuthorityFamily {
        match self.inner {
            LocalManagementFamilyAuthorityKind::Agent => LocalManagementAuthorityFamily::Agent,
            LocalManagementFamilyAuthorityKind::File(_) => LocalManagementAuthorityFamily::File,
            LocalManagementFamilyAuthorityKind::Transfer(_) => {
                LocalManagementAuthorityFamily::Transfer
            }
            LocalManagementFamilyAuthorityKind::TerminalRemote(_)
            | LocalManagementFamilyAuthorityKind::TerminalLocal(_) => {
                LocalManagementAuthorityFamily::Terminal
            }
            LocalManagementFamilyAuthorityKind::ForwardingRemote(_)
            | LocalManagementFamilyAuthorityKind::ForwardingLocal(_) => {
                LocalManagementAuthorityFamily::Forwarding
            }
        }
    }

    /// Returns the filesystem authority only for file/transfer families.
    #[must_use]
    pub(super) const fn filesystem(self) -> Option<&'authority LocalManagementFilesystemAuthority> {
        match self.inner {
            LocalManagementFamilyAuthorityKind::File(authority)
            | LocalManagementFamilyAuthorityKind::Transfer(authority) => Some(authority),
            LocalManagementFamilyAuthorityKind::Agent
            | LocalManagementFamilyAuthorityKind::TerminalRemote(_)
            | LocalManagementFamilyAuthorityKind::TerminalLocal(_)
            | LocalManagementFamilyAuthorityKind::ForwardingRemote(_)
            | LocalManagementFamilyAuthorityKind::ForwardingLocal(_) => None,
        }
    }

    /// Returns the registry/session authority only for terminal/forwarding families.
    #[must_use]
    pub(super) const fn remote_session(
        self,
    ) -> Option<&'authority LocalManagementRemoteSessionAuthority> {
        match self.inner {
            LocalManagementFamilyAuthorityKind::TerminalRemote(authority)
            | LocalManagementFamilyAuthorityKind::ForwardingRemote(authority) => Some(authority),
            LocalManagementFamilyAuthorityKind::Agent
            | LocalManagementFamilyAuthorityKind::File(_)
            | LocalManagementFamilyAuthorityKind::Transfer(_)
            | LocalManagementFamilyAuthorityKind::TerminalLocal(_)
            | LocalManagementFamilyAuthorityKind::ForwardingLocal(_) => None,
        }
    }

    /// Returns local peer authority only for locally authenticated terminal/forwarding families.
    #[must_use]
    pub(super) const fn local_peer(self) -> Option<&'authority LocalManagementLocalPeerAuthority> {
        match self.inner {
            LocalManagementFamilyAuthorityKind::TerminalLocal(authority)
            | LocalManagementFamilyAuthorityKind::ForwardingLocal(authority) => Some(authority),
            LocalManagementFamilyAuthorityKind::Agent
            | LocalManagementFamilyAuthorityKind::File(_)
            | LocalManagementFamilyAuthorityKind::Transfer(_)
            | LocalManagementFamilyAuthorityKind::TerminalRemote(_)
            | LocalManagementFamilyAuthorityKind::ForwardingRemote(_) => None,
        }
    }

    /// Derives the exact terminal session-principal variant carried by this family authority.
    #[must_use]
    pub(super) fn terminal_session_principal(self) -> Option<TerminalSessionPrincipal> {
        match self.inner {
            LocalManagementFamilyAuthorityKind::TerminalRemote(authority) => {
                Some(authority.terminal_principal().into())
            }
            LocalManagementFamilyAuthorityKind::TerminalLocal(authority) => {
                Some(authority.terminal_principal().into())
            }
            _ => None,
        }
    }

    /// Derives the exact forwarding session-principal variant carried by this authority.
    #[must_use]
    pub(super) fn forwarding_session_principal(self) -> Option<ForwardingSessionPrincipal> {
        match self.inner {
            LocalManagementFamilyAuthorityKind::ForwardingRemote(authority) => {
                Some(authority.forwarding_principal().into())
            }
            LocalManagementFamilyAuthorityKind::ForwardingLocal(authority) => {
                Some(authority.forwarding_principal().into())
            }
            _ => None,
        }
    }
}
