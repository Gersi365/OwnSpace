//! Typed terminal-session foundation for Ownspace.
//!
//! Phase 133 defines a bounded lifecycle and typed backend boundary only. It does not
//! expose an arbitrary run-command API, spawn a PTY, launch a shell, select a remote
//! transport, or grant terminal capability by itself.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
};

use prw_core::{DeviceId, SessionId, UserId, WorkspaceId};
use prw_registry::RegistryValidatedPrincipal;

/// Maximum accepted terminal input or output chunk.
pub const MAX_TERMINAL_IO_BYTES: usize = 65_536;
/// Maximum terminal geometry dimension.
pub const MAX_TERMINAL_DIMENSION: u16 = 1_000;
/// Maximum simultaneously tracked terminal sessions in one broker.
pub const MAX_ACTIVE_TERMINAL_SESSIONS: usize = 32;

/// Stable terminal-session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalSessionId(u64);

impl TerminalSessionId {
    /// Creates a non-zero terminal-session identifier.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalError::InvalidIdentifier`] when `value` is zero.
    pub const fn new(value: u64) -> Result<Self, TerminalError> {
        if value == 0 {
            return Err(TerminalError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the raw broker-scoped identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Allowed named terminal launch profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalProfile {
    /// Provider-selected POSIX-compatible interactive shell profile.
    PosixShell,
    /// Provider-selected Bash interactive shell profile.
    BashShell,
}

/// Bounded terminal geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalGeometry {
    columns: u16,
    rows: u16,
}

impl TerminalGeometry {
    /// Creates non-zero geometry bounded to 1000 by 1000.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalError::InvalidGeometry`] when either dimension is zero or
    /// exceeds [`MAX_TERMINAL_DIMENSION`].
    pub const fn new(columns: u16, rows: u16) -> Result<Self, TerminalError> {
        if columns == 0
            || rows == 0
            || columns > MAX_TERMINAL_DIMENSION
            || rows > MAX_TERMINAL_DIMENSION
        {
            return Err(TerminalError::InvalidGeometry);
        }
        Ok(Self { columns, rows })
    }

    /// Returns the validated column count.
    #[must_use]
    pub const fn columns(self) -> u16 {
        self.columns
    }

    /// Returns the validated row count.
    #[must_use]
    pub const fn rows(self) -> u16 {
        self.rows
    }
}

/// Registry-current identity snapshot attached immutably to one terminal session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalPrincipal {
    workspace: WorkspaceId,
    user: UserId,
    device: DeviceId,
    authenticated_session: SessionId,
}

impl TerminalPrincipal {
    /// Captures current-registry identity plus the authenticated PRW session identifier.
    #[must_use]
    pub fn from_registry(principal: &RegistryValidatedPrincipal, session_id: SessionId) -> Self {
        Self {
            workspace: principal.workspace_id().clone(),
            user: principal.user_id().clone(),
            device: principal.device_id().clone(),
            authenticated_session: session_id,
        }
    }

    /// Returns the immutable workspace identifier.
    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace
    }

    /// Returns the immutable user identifier.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user
    }

    /// Returns the immutable device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device
    }

    /// Returns the immutable authenticated PRW session identifier.
    #[must_use]
    pub const fn authenticated_session_id(&self) -> &SessionId {
        &self.authenticated_session
    }
}

/// Same-UID local Linux principal for one Agent-authenticated terminal session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalTerminalPrincipal {
    uid: u32,
}

impl LocalTerminalPrincipal {
    /// Captures the kernel-authenticated local UID selected by the Agent.
    #[must_use]
    pub const fn new(uid: u32) -> Self {
        Self { uid }
    }

    /// Returns the authenticated local UID.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.uid
    }
}

/// Identity domain attached immutably to one terminal broker record.
///
/// Registry-derived remote identity and same-UID local identity are distinct variants
/// and therefore can never compare equal accidentally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalSessionPrincipal {
    /// Registry-current authenticated PRW session identity.
    Registry(TerminalPrincipal),
    /// Kernel-authenticated local same-UID identity.
    LocalSameUid(LocalTerminalPrincipal),
}

impl From<TerminalPrincipal> for TerminalSessionPrincipal {
    fn from(principal: TerminalPrincipal) -> Self {
        Self::Registry(principal)
    }
}

impl From<LocalTerminalPrincipal> for TerminalSessionPrincipal {
    fn from(principal: LocalTerminalPrincipal) -> Self {
        Self::LocalSameUid(principal)
    }
}

impl TerminalSessionPrincipal {
    /// Returns registry identity only for the registry-derived variant.
    #[must_use]
    pub const fn registry(&self) -> Option<&TerminalPrincipal> {
        match self {
            Self::Registry(principal) => Some(principal),
            Self::LocalSameUid(_) => None,
        }
    }

    /// Returns local same-UID identity only for the local variant.
    #[must_use]
    pub const fn local_same_uid(&self) -> Option<LocalTerminalPrincipal> {
        match self {
            Self::Registry(_) => None,
            Self::LocalSameUid(principal) => Some(*principal),
        }
    }
}

/// Terminal lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalState {
    /// Backend opening is in progress.
    Opening,
    /// Terminal is open and may accept bounded I/O and resize operations.
    Open,
    /// Explicit close is in progress.
    Closing,
    /// Close completed successfully.
    Closed,
    /// A backend operation failed and the record cannot resume normal I/O.
    Failed,
}

/// Typed terminal backend contract.
///
/// No method accepts an arbitrary executable path, argument vector, raw command string,
/// environment injection, filesystem path, network target, or privilege instruction.
pub trait TerminalBackend {
    /// Backend-owned terminal handle.
    type Handle;

    /// Opens one fixed named launch profile with already-validated geometry.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot open the terminal.
    fn open(
        &mut self,
        profile: TerminalProfile,
        geometry: TerminalGeometry,
    ) -> Result<Self::Handle, TerminalError>;

    /// Writes one already-bounded input chunk.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot accept the input.
    fn write_input(&mut self, handle: &mut Self::Handle, bytes: &[u8])
    -> Result<(), TerminalError>;

    /// Applies already-validated terminal geometry.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot resize the terminal.
    fn resize(
        &mut self,
        handle: &mut Self::Handle,
        geometry: TerminalGeometry,
    ) -> Result<(), TerminalError>;

    /// Reads at most `maximum_bytes` from the terminal.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot read terminal output.
    fn read_output(
        &mut self,
        handle: &mut Self::Handle,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, TerminalError>;

    /// Closes the provider handle.
    ///
    /// # Errors
    ///
    /// Returns an error when explicit provider close fails.
    fn close(&mut self, handle: &mut Self::Handle) -> Result<(), TerminalError>;
}

/// Provider-neutral terminal session record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSession {
    id: TerminalSessionId,
    principal: TerminalSessionPrincipal,
    profile: TerminalProfile,
    geometry: TerminalGeometry,
    state: TerminalState,
}

impl TerminalSession {
    const fn opening(
        id: TerminalSessionId,
        principal: TerminalSessionPrincipal,
        profile: TerminalProfile,
        geometry: TerminalGeometry,
    ) -> Self {
        Self {
            id,
            principal,
            profile,
            geometry,
            state: TerminalState::Opening,
        }
    }

    /// Returns the broker-scoped terminal identifier.
    #[must_use]
    pub const fn id(&self) -> TerminalSessionId {
        self.id
    }

    /// Returns current terminal lifecycle state.
    #[must_use]
    pub const fn state(&self) -> TerminalState {
        self.state
    }

    /// Returns the immutable identity snapshot.
    #[must_use]
    pub const fn principal(&self) -> &TerminalSessionPrincipal {
        &self.principal
    }

    /// Returns the immutable named launch profile.
    #[must_use]
    pub const fn profile(&self) -> TerminalProfile {
        self.profile
    }

    /// Returns current validated terminal geometry.
    #[must_use]
    pub const fn geometry(&self) -> TerminalGeometry {
        self.geometry
    }

    fn require_open(&self) -> Result<(), TerminalError> {
        if self.state != TerminalState::Open {
            return Err(TerminalError::InvalidState);
        }
        Ok(())
    }

    const fn mark_open(&mut self) {
        self.state = TerminalState::Open;
    }

    const fn mark_closing(&mut self) {
        self.state = TerminalState::Closing;
    }

    const fn mark_closed(&mut self) {
        self.state = TerminalState::Closed;
    }

    const fn mark_failed(&mut self) {
        self.state = TerminalState::Failed;
    }

    const fn apply_geometry(&mut self, geometry: TerminalGeometry) {
        self.geometry = geometry;
    }
}

#[derive(Debug)]
struct BrokerTerminal<H> {
    record: TerminalSession,
    handle: Option<H>,
}

/// Bounded terminal-session broker around one typed backend.
///
/// The broker enforces lifecycle and I/O bounds before calling the backend. Phase 133
/// deliberately does not perform capability evaluation or remote transport framing.
#[derive(Debug)]
pub struct TerminalBroker<B: TerminalBackend> {
    backend: B,
    sessions: HashMap<TerminalSessionId, BrokerTerminal<B::Handle>>,
}

impl<B: TerminalBackend> TerminalBroker<B> {
    /// Creates an empty broker around one backend instance.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            sessions: HashMap::new(),
        }
    }

    /// Returns the number of currently tracked open or failed terminal records.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns whether the broker currently tracks no terminal records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Returns one current terminal record without exposing the backend handle.
    #[must_use]
    pub fn session(&self, id: TerminalSessionId) -> Option<&TerminalSession> {
        self.sessions.get(&id).map(|terminal| &terminal.record)
    }

    /// Opens one bounded terminal using a fixed named profile.
    ///
    /// # Errors
    ///
    /// Rejects duplicate identifiers and broker capacity before a backend call. Backend
    /// open failure returns [`TerminalError::Backend`] and does not create a session.
    pub fn open_session<P: Into<TerminalSessionPrincipal>>(
        &mut self,
        id: TerminalSessionId,
        principal: P,
        profile: TerminalProfile,
        geometry: TerminalGeometry,
    ) -> Result<&TerminalSession, TerminalError> {
        let principal = principal.into();
        if self.sessions.contains_key(&id) {
            return Err(TerminalError::DuplicateSession);
        }
        if self.sessions.len() >= MAX_ACTIVE_TERMINAL_SESSIONS {
            return Err(TerminalError::SessionCapacity);
        }

        match self.sessions.entry(id) {
            Entry::Occupied(_) => Err(TerminalError::DuplicateSession),
            Entry::Vacant(entry) => {
                let handle = self
                    .backend
                    .open(profile, geometry)
                    .map_err(|_| TerminalError::Backend)?;
                let mut record = TerminalSession::opening(id, principal, profile, geometry);
                record.mark_open();
                Ok(&entry
                    .insert(BrokerTerminal {
                        record,
                        handle: Some(handle),
                    })
                    .record)
            }
        }
    }

    /// Writes one non-empty bounded input chunk to an open terminal.
    ///
    /// # Errors
    ///
    /// Rejects unknown/non-open sessions, empty chunks, and chunks above 64 KiB before
    /// backend mutation. A backend write failure transitions the session to `Failed`.
    pub fn write_input(
        &mut self,
        id: TerminalSessionId,
        bytes: &[u8],
    ) -> Result<(), TerminalError> {
        if bytes.is_empty() {
            return Err(TerminalError::EmptyIo);
        }
        if bytes.len() > MAX_TERMINAL_IO_BYTES {
            return Err(TerminalError::IoTooLarge);
        }

        let (backend, sessions) = (&mut self.backend, &mut self.sessions);
        let terminal = sessions.get_mut(&id).ok_or(TerminalError::UnknownSession)?;
        terminal.record.require_open()?;
        let handle = terminal
            .handle
            .as_mut()
            .ok_or(TerminalError::InvalidState)?;
        if backend.write_input(handle, bytes).is_err() {
            terminal.record.mark_failed();
            return Err(TerminalError::Backend);
        }
        Ok(())
    }

    /// Resizes one open terminal to already-validated geometry.
    ///
    /// # Errors
    ///
    /// Rejects unknown/non-open sessions before the backend call. A backend resize failure
    /// transitions the session to `Failed`.
    pub fn resize_session(
        &mut self,
        id: TerminalSessionId,
        geometry: TerminalGeometry,
    ) -> Result<(), TerminalError> {
        let (backend, sessions) = (&mut self.backend, &mut self.sessions);
        let terminal = sessions.get_mut(&id).ok_or(TerminalError::UnknownSession)?;
        terminal.record.require_open()?;
        let handle = terminal
            .handle
            .as_mut()
            .ok_or(TerminalError::InvalidState)?;
        if backend.resize(handle, geometry).is_err() {
            terminal.record.mark_failed();
            return Err(TerminalError::Backend);
        }
        terminal.record.apply_geometry(geometry);
        Ok(())
    }

    /// Reads a bounded output chunk from one open terminal.
    ///
    /// # Errors
    ///
    /// Rejects zero/oversized requests and unknown/non-open sessions before backend I/O.
    /// Backend failure transitions the session to `Failed`. Output larger than the requested
    /// or global bound is treated as a backend contract violation and also fails the session.
    pub fn read_output(
        &mut self,
        id: TerminalSessionId,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, TerminalError> {
        if maximum_bytes == 0 || maximum_bytes > MAX_TERMINAL_IO_BYTES {
            return Err(TerminalError::InvalidOutputRequest);
        }

        let (backend, sessions) = (&mut self.backend, &mut self.sessions);
        let terminal = sessions.get_mut(&id).ok_or(TerminalError::UnknownSession)?;
        terminal.record.require_open()?;
        let handle = terminal
            .handle
            .as_mut()
            .ok_or(TerminalError::InvalidState)?;
        let Ok(output) = backend.read_output(handle, maximum_bytes) else {
            terminal.record.mark_failed();
            return Err(TerminalError::Backend);
        };
        if output.len() > maximum_bytes || output.len() > MAX_TERMINAL_IO_BYTES {
            terminal.record.mark_failed();
            return Err(TerminalError::BackendOutputTooLarge);
        }
        Ok(output)
    }

    /// Explicitly closes one open terminal and returns its terminal `Closed` record.
    ///
    /// # Errors
    ///
    /// Rejects unknown/non-open sessions. Backend close failure retains the record in
    /// `Failed` state so later I/O cannot silently continue.
    pub fn close_session(
        &mut self,
        id: TerminalSessionId,
    ) -> Result<TerminalSession, TerminalError> {
        let mut terminal = self
            .sessions
            .remove(&id)
            .ok_or(TerminalError::UnknownSession)?;
        if let Err(error) = terminal.record.require_open() {
            self.sessions.insert(id, terminal);
            return Err(error);
        }
        terminal.record.mark_closing();

        let Some(handle) = terminal.handle.as_mut() else {
            terminal.record.mark_failed();
            self.sessions.insert(id, terminal);
            return Err(TerminalError::InvalidState);
        };

        if self.backend.close(handle).is_err() {
            terminal.record.mark_failed();
            self.sessions.insert(id, terminal);
            return Err(TerminalError::Backend);
        }

        terminal.handle = None;
        terminal.record.mark_closed();
        Ok(terminal.record)
    }

    /// Retries provider cleanup for one retained failed terminal record.
    ///
    /// This operation is teardown-only. It never reopens the terminal or resumes I/O.
    /// On backend failure the same failed record and handle remain tracked so cleanup
    /// may be attempted again later. On success the handle is cleared, the record is
    /// marked `Closed`, and the broker removes it.
    ///
    /// # Errors
    ///
    /// Rejects unknown or non-`Failed` records before calling the backend. A missing
    /// retained handle is an invalid state. Backend close failure preserves `Failed`.
    pub fn retry_failed_close(
        &mut self,
        id: TerminalSessionId,
    ) -> Result<TerminalSession, TerminalError> {
        let mut terminal = self
            .sessions
            .remove(&id)
            .ok_or(TerminalError::UnknownSession)?;
        if terminal.record.state() != TerminalState::Failed {
            self.sessions.insert(id, terminal);
            return Err(TerminalError::InvalidState);
        }

        let Some(handle) = terminal.handle.as_mut() else {
            self.sessions.insert(id, terminal);
            return Err(TerminalError::InvalidState);
        };

        if self.backend.close(handle).is_err() {
            terminal.record.mark_failed();
            self.sessions.insert(id, terminal);
            return Err(TerminalError::Backend);
        }

        terminal.handle = None;
        terminal.record.mark_closed();
        Ok(terminal.record)
    }
}

/// Stable terminal failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TerminalError {
    /// Terminal identifier was zero.
    InvalidIdentifier,
    /// Terminal geometry was zero or exceeded the dimension bound.
    InvalidGeometry,
    /// Terminal identifier is not currently tracked by the broker.
    UnknownSession,
    /// Terminal identifier is already active in the broker.
    DuplicateSession,
    /// Broker already tracks the maximum number of sessions.
    SessionCapacity,
    /// Operation is not valid for the current terminal lifecycle state.
    InvalidState,
    /// Empty terminal input is not a meaningful protocol operation.
    EmptyIo,
    /// Terminal input exceeded the 64 KiB per-operation bound.
    IoTooLarge,
    /// Output read request was zero or exceeded 64 KiB.
    InvalidOutputRequest,
    /// Backend operation failed.
    Backend,
    /// Backend returned more output than the broker allowed.
    BackendOutputTooLarge,
}

impl fmt::Display for TerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIdentifier => "terminal session id must be non-zero",
            Self::InvalidGeometry => "terminal geometry is out of bounds",
            Self::UnknownSession => "terminal session is not tracked",
            Self::DuplicateSession => "terminal session id is already active",
            Self::SessionCapacity => "terminal broker capacity reached",
            Self::InvalidState => "terminal operation is invalid for current state",
            Self::EmptyIo => "terminal input chunk must not be empty",
            Self::IoTooLarge => "terminal io chunk exceeds bound",
            Self::InvalidOutputRequest => "terminal output request exceeds bound or is zero",
            Self::Backend => "terminal backend operation failed",
            Self::BackendOutputTooLarge => {
                "terminal backend returned output above the requested bound"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TerminalError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    enum FailureMode {
        #[default]
        None,
        Open,
        Write,
        Read,
        Close,
    }

    #[derive(Debug, Default)]
    struct SpyBackend {
        open_calls: usize,
        write_calls: usize,
        resize_calls: usize,
        read_calls: usize,
        close_calls: usize,
        failure: FailureMode,
        last_profile: Option<TerminalProfile>,
        last_geometry: Option<TerminalGeometry>,
        output: Vec<u8>,
    }

    impl TerminalBackend for SpyBackend {
        type Handle = u64;

        fn open(
            &mut self,
            profile: TerminalProfile,
            geometry: TerminalGeometry,
        ) -> Result<Self::Handle, TerminalError> {
            self.open_calls += 1;
            self.last_profile = Some(profile);
            self.last_geometry = Some(geometry);
            if self.failure == FailureMode::Open {
                return Err(TerminalError::Backend);
            }
            Ok(u64::try_from(self.open_calls).expect("test open count fits u64"))
        }

        fn write_input(
            &mut self,
            _handle: &mut Self::Handle,
            _bytes: &[u8],
        ) -> Result<(), TerminalError> {
            self.write_calls += 1;
            if self.failure == FailureMode::Write {
                return Err(TerminalError::Backend);
            }
            Ok(())
        }

        fn resize(
            &mut self,
            _handle: &mut Self::Handle,
            geometry: TerminalGeometry,
        ) -> Result<(), TerminalError> {
            self.resize_calls += 1;
            self.last_geometry = Some(geometry);
            Ok(())
        }

        fn read_output(
            &mut self,
            _handle: &mut Self::Handle,
            _maximum_bytes: usize,
        ) -> Result<Vec<u8>, TerminalError> {
            self.read_calls += 1;
            if self.failure == FailureMode::Read {
                return Err(TerminalError::Backend);
            }
            Ok(self.output.clone())
        }

        fn close(&mut self, _handle: &mut Self::Handle) -> Result<(), TerminalError> {
            self.close_calls += 1;
            if self.failure == FailureMode::Close {
                return Err(TerminalError::Backend);
            }
            Ok(())
        }
    }

    fn principal() -> TerminalPrincipal {
        TerminalPrincipal {
            workspace: WorkspaceId::new("workspace-1").expect("workspace"),
            user: UserId::new("user-1").expect("user"),
            device: DeviceId::new("device-1").expect("device"),
            authenticated_session: SessionId::new("session-1").expect("session"),
        }
    }

    fn geometry() -> TerminalGeometry {
        TerminalGeometry::new(80, 24).expect("geometry")
    }

    fn id(value: u64) -> TerminalSessionId {
        TerminalSessionId::new(value).expect("terminal id")
    }

    #[test]
    fn identifiers_and_geometry_are_bounded() {
        assert_eq!(
            TerminalSessionId::new(0),
            Err(TerminalError::InvalidIdentifier)
        );
        assert_eq!(
            TerminalGeometry::new(0, 24),
            Err(TerminalError::InvalidGeometry)
        );
        assert_eq!(
            TerminalGeometry::new(MAX_TERMINAL_DIMENSION + 1, 24),
            Err(TerminalError::InvalidGeometry)
        );
        assert_eq!(geometry().columns(), 80);
        assert_eq!(geometry().rows(), 24);
    }

    #[test]
    fn broker_rejects_duplicate_identifier_before_backend_call() {
        let mut broker = TerminalBroker::new(SpyBackend::default());
        broker
            .open_session(id(1), principal(), TerminalProfile::PosixShell, geometry())
            .expect("first open");
        assert_eq!(
            broker.open_session(id(1), principal(), TerminalProfile::BashShell, geometry()),
            Err(TerminalError::DuplicateSession)
        );
        assert_eq!(broker.backend.open_calls, 1);
    }

    #[test]
    fn broker_capacity_fails_before_backend_call() {
        let mut broker = TerminalBroker::new(SpyBackend::default());
        let maximum = u64::try_from(MAX_ACTIVE_TERMINAL_SESSIONS).expect("bound fits u64");
        for raw_id in 1..=maximum {
            broker
                .open_session(
                    id(raw_id),
                    principal(),
                    TerminalProfile::PosixShell,
                    geometry(),
                )
                .expect("bounded open");
        }
        assert_eq!(broker.session_count(), MAX_ACTIVE_TERMINAL_SESSIONS);
        assert_eq!(
            broker.open_session(
                id(maximum + 1),
                principal(),
                TerminalProfile::PosixShell,
                geometry()
            ),
            Err(TerminalError::SessionCapacity)
        );
        assert_eq!(broker.backend.open_calls, MAX_ACTIVE_TERMINAL_SESSIONS);
    }

    #[test]
    fn broker_passes_only_named_profile_and_valid_geometry() {
        let mut broker = TerminalBroker::new(SpyBackend::default());
        let expected_geometry = TerminalGeometry::new(120, 40).expect("geometry");
        let record = broker
            .open_session(
                id(7),
                principal(),
                TerminalProfile::BashShell,
                expected_geometry,
            )
            .expect("open");
        assert_eq!(record.profile(), TerminalProfile::BashShell);
        assert_eq!(record.geometry(), expected_geometry);
        assert_eq!(
            broker.backend.last_profile,
            Some(TerminalProfile::BashShell)
        );
        assert_eq!(broker.backend.last_geometry, Some(expected_geometry));
    }

    #[test]
    fn backend_open_failure_never_creates_open_record() {
        let backend = SpyBackend {
            failure: FailureMode::Open,
            ..SpyBackend::default()
        };
        let mut broker = TerminalBroker::new(backend);
        assert_eq!(
            broker.open_session(id(2), principal(), TerminalProfile::PosixShell, geometry()),
            Err(TerminalError::Backend)
        );
        assert!(broker.is_empty());
        assert!(broker.session(id(2)).is_none());
    }

    #[test]
    fn empty_and_oversized_input_fail_before_backend_call() {
        let mut broker = TerminalBroker::new(SpyBackend::default());
        broker
            .open_session(id(3), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        assert_eq!(broker.write_input(id(3), b""), Err(TerminalError::EmptyIo));
        assert_eq!(
            broker.write_input(id(3), &vec![0; MAX_TERMINAL_IO_BYTES + 1]),
            Err(TerminalError::IoTooLarge)
        );
        assert_eq!(broker.backend.write_calls, 0);
        broker.write_input(id(3), b"bounded input").expect("write");
        assert_eq!(broker.backend.write_calls, 1);
    }

    #[test]
    fn resize_geometry_is_rejected_before_backend_call() {
        let mut broker = TerminalBroker::new(SpyBackend::default());
        broker
            .open_session(id(4), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        assert_eq!(
            TerminalGeometry::new(0, 40),
            Err(TerminalError::InvalidGeometry)
        );
        assert_eq!(broker.backend.resize_calls, 0);
        let resized = TerminalGeometry::new(100, 40).expect("geometry");
        broker.resize_session(id(4), resized).expect("resize");
        assert_eq!(broker.backend.resize_calls, 1);
        assert_eq!(broker.session(id(4)).expect("session").geometry(), resized);
    }

    #[test]
    fn output_request_bound_fails_before_backend_call() {
        let mut broker = TerminalBroker::new(SpyBackend::default());
        broker
            .open_session(id(5), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        assert_eq!(
            broker.read_output(id(5), 0),
            Err(TerminalError::InvalidOutputRequest)
        );
        assert_eq!(
            broker.read_output(id(5), MAX_TERMINAL_IO_BYTES + 1),
            Err(TerminalError::InvalidOutputRequest)
        );
        assert_eq!(broker.backend.read_calls, 0);
    }

    #[test]
    fn backend_failure_marks_session_failed_and_rejects_later_io() {
        let backend = SpyBackend {
            failure: FailureMode::Read,
            ..SpyBackend::default()
        };
        let mut broker = TerminalBroker::new(backend);
        broker
            .open_session(id(6), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        assert_eq!(broker.read_output(id(6), 64), Err(TerminalError::Backend));
        assert_eq!(
            broker.session(id(6)).expect("session").state(),
            TerminalState::Failed
        );
        assert_eq!(
            broker.write_input(id(6), b"later"),
            Err(TerminalError::InvalidState)
        );
        assert_eq!(broker.backend.write_calls, 0);
    }

    #[test]
    fn backend_oversized_output_fails_session() {
        let backend = SpyBackend {
            output: vec![0; 65],
            ..SpyBackend::default()
        };
        let mut broker = TerminalBroker::new(backend);
        broker
            .open_session(id(8), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        assert_eq!(
            broker.read_output(id(8), 64),
            Err(TerminalError::BackendOutputTooLarge)
        );
        assert_eq!(
            broker.session(id(8)).expect("session").state(),
            TerminalState::Failed
        );
    }

    #[test]
    fn close_is_terminal_for_returned_record_and_later_io_is_rejected() {
        let mut broker = TerminalBroker::new(SpyBackend::default());
        broker
            .open_session(id(9), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        let closed = broker.close_session(id(9)).expect("close");
        assert_eq!(closed.state(), TerminalState::Closed);
        assert_eq!(broker.backend.close_calls, 1);
        assert_eq!(
            broker.write_input(id(9), b"later"),
            Err(TerminalError::UnknownSession)
        );
    }

    #[test]
    fn close_failure_retains_failed_record() {
        let backend = SpyBackend {
            failure: FailureMode::Close,
            ..SpyBackend::default()
        };
        let mut broker = TerminalBroker::new(backend);
        broker
            .open_session(id(10), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        assert_eq!(broker.close_session(id(10)), Err(TerminalError::Backend));
        assert_eq!(
            broker.session(id(10)).expect("session").state(),
            TerminalState::Failed
        );
        assert_eq!(
            broker.write_input(id(10), b"later"),
            Err(TerminalError::InvalidState)
        );
    }

    #[test]
    fn failed_close_can_be_retried_to_closed_and_removed() {
        let backend = SpyBackend {
            failure: FailureMode::Close,
            ..SpyBackend::default()
        };
        let mut broker = TerminalBroker::new(backend);
        broker
            .open_session(id(12), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        assert_eq!(broker.close_session(id(12)), Err(TerminalError::Backend));
        assert_eq!(broker.backend.close_calls, 1);
        assert_eq!(
            broker.session(id(12)).expect("retained").state(),
            TerminalState::Failed
        );

        broker.backend.failure = FailureMode::None;
        let closed = broker.retry_failed_close(id(12)).expect("retry close");
        assert_eq!(closed.state(), TerminalState::Closed);
        assert_eq!(broker.backend.close_calls, 2);
        assert!(broker.session(id(12)).is_none());
        assert_eq!(
            broker.write_input(id(12), b"later"),
            Err(TerminalError::UnknownSession)
        );
    }

    #[test]
    fn failed_close_retry_failure_retains_failed_record() {
        let backend = SpyBackend {
            failure: FailureMode::Close,
            ..SpyBackend::default()
        };
        let mut broker = TerminalBroker::new(backend);
        broker
            .open_session(id(13), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        assert_eq!(broker.close_session(id(13)), Err(TerminalError::Backend));
        assert_eq!(
            broker.retry_failed_close(id(13)),
            Err(TerminalError::Backend)
        );
        assert_eq!(broker.backend.close_calls, 2);
        assert_eq!(
            broker.session(id(13)).expect("retained").state(),
            TerminalState::Failed
        );
    }

    #[test]
    fn failed_close_retry_rejects_open_or_unknown_before_backend_call() {
        let mut broker = TerminalBroker::new(SpyBackend::default());
        broker
            .open_session(id(14), principal(), TerminalProfile::PosixShell, geometry())
            .expect("open");
        assert_eq!(
            broker.retry_failed_close(id(14)),
            Err(TerminalError::InvalidState)
        );
        assert_eq!(
            broker.retry_failed_close(id(15)),
            Err(TerminalError::UnknownSession)
        );
        assert_eq!(broker.backend.close_calls, 0);
        assert_eq!(
            broker.session(id(14)).expect("open retained").state(),
            TerminalState::Open
        );
    }

    #[test]
    fn identity_binding_is_immutable_in_session_record() {
        let expected = principal();
        let mut broker = TerminalBroker::new(SpyBackend::default());
        let record = broker
            .open_session(
                id(11),
                expected.clone(),
                TerminalProfile::PosixShell,
                geometry(),
            )
            .expect("open");
        let registry = record.principal().registry().expect("registry principal");
        assert_eq!(registry, &expected);
        assert_eq!(registry.workspace_id().as_str(), "workspace-1");
        assert_eq!(registry.user_id().as_str(), "user-1");
        assert_eq!(registry.device_id().as_str(), "device-1");
        assert_eq!(registry.authenticated_session_id().as_str(), "session-1");
        assert!(record.principal().local_same_uid().is_none());
    }

    #[test]
    fn local_same_uid_principal_is_distinct_from_registry_identity() {
        let local = LocalTerminalPrincipal::new(1000);
        let registry = principal();
        assert_ne!(
            TerminalSessionPrincipal::from(local),
            TerminalSessionPrincipal::from(registry)
        );
        let mut broker = TerminalBroker::new(SpyBackend::default());
        let record = broker
            .open_session(id(16), local, TerminalProfile::PosixShell, geometry())
            .expect("local open");
        assert_eq!(record.principal().local_same_uid(), Some(local));
        assert!(record.principal().registry().is_none());
    }
}
