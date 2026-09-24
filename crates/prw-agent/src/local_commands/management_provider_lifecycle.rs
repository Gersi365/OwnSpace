//! C02c provider lifecycle ownership seam for local management.
//!
//! This module deliberately owns no production backend implementation and is not
//! wired into the local server loop. It composes already-existing provider-neutral
//! brokers around caller-supplied backends and the Agent-owned filesystem authority.
//! Clean completion is explicit: the lifecycle can be consumed successfully only
//! when no transfer, terminal, or forwarding resource remains active.

use prw_file_transfer::UploadTransferManager;
use prw_forwarding::{PortForwardBackend, PortForwardBroker};
use prw_terminal::{TerminalBackend, TerminalBroker};

use super::management_authority::LocalManagementFilesystemAuthority;

/// Agent-owned local-management provider lifecycle assembled outside request decoding.
///
/// The filesystem root is borrowed from an already-opened Agent authority so the
/// transfer manager cannot outlive that descriptor authority. Terminal and forwarding
/// brokers own their caller-supplied provider backends for the same lifecycle scope.
///
/// No `Drop` implementation claims provider cleanup. Callers must explicitly close or
/// abort tracked resources through the typed provider APIs before `try_finish` can
/// report clean completion.
pub(super) struct LocalManagementProviderLifecycle<'authority, T, F>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    filesystem: &'authority LocalManagementFilesystemAuthority,
    transfers: UploadTransferManager<'authority>,
    terminal: TerminalBroker<T>,
    forwarding: PortForwardBroker<F>,
}

impl<'authority, T, F> LocalManagementProviderLifecycle<'authority, T, F>
where
    T: TerminalBackend,
    F: PortForwardBackend,
{
    /// Assembles one provider lifecycle from real authority plus caller-owned backends.
    ///
    /// This constructor performs no provider operation. In particular it does not
    /// open a terminal, create a transfer, bind a forward, or mutate the filesystem.
    #[must_use]
    pub(super) fn new(
        filesystem: &'authority LocalManagementFilesystemAuthority,
        terminal_backend: T,
        forwarding_backend: F,
    ) -> Self {
        Self {
            filesystem,
            transfers: UploadTransferManager::new(filesystem.root()),
            terminal: TerminalBroker::new(terminal_backend),
            forwarding: PortForwardBroker::new(forwarding_backend),
        }
    }

    /// Returns the exact Agent-owned descriptor authority backing file/transfer work.
    #[must_use]
    pub(super) const fn filesystem(&self) -> &'authority LocalManagementFilesystemAuthority {
        self.filesystem
    }

    /// Returns the transfer manager for typed create-only transfer operations.
    #[must_use]
    pub(super) const fn transfers_mut(&mut self) -> &mut UploadTransferManager<'authority> {
        &mut self.transfers
    }

    /// Returns the terminal broker for principal-binding inspection.
    #[must_use]
    pub(super) const fn terminal(&self) -> &TerminalBroker<T> {
        &self.terminal
    }

    /// Returns the terminal broker for typed terminal operations.
    #[must_use]
    pub(super) const fn terminal_mut(&mut self) -> &mut TerminalBroker<T> {
        &mut self.terminal
    }

    /// Returns the forwarding broker for principal-binding inspection.
    #[must_use]
    pub(super) const fn forwarding(&self) -> &PortForwardBroker<F> {
        &self.forwarding
    }

    /// Returns the forwarding broker for typed forwarding operations.
    #[must_use]
    pub(super) const fn forwarding_mut(&mut self) -> &mut PortForwardBroker<F> {
        &mut self.forwarding
    }

    /// Returns the currently active transfer transaction count.
    #[must_use]
    pub(super) fn active_transfer_count(&self) -> usize {
        self.transfers.active_count()
    }

    /// Returns the currently tracked terminal record count.
    #[must_use]
    pub(super) fn active_terminal_count(&self) -> usize {
        self.terminal.session_count()
    }

    /// Returns the currently tracked forwarding record count.
    #[must_use]
    pub(super) fn active_forwarding_count(&self) -> usize {
        self.forwarding.session_count()
    }

    /// Returns whether all provider resources have been explicitly drained.
    #[must_use]
    pub(super) fn is_quiescent(&self) -> bool {
        self.transfers.active_count() == 0 && self.terminal.is_empty() && self.forwarding.is_empty()
    }

    /// Consumes the lifecycle only when all provider resources are explicitly drained.
    ///
    /// On active state, returns the complete lifecycle owner in a box so the caller can
    /// continue typed cleanup without making the `Result` carry a large inline error
    /// variant. This avoids reporting clean completion while provider state is still
    /// tracked and avoids silently discarding active broker state.
    pub(super) fn try_finish(self) -> Result<(), Box<Self>> {
        if self.is_quiescent() {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
