#![allow(
    dead_code,
    reason = "Phase 152 Slice A management projection is exercised by tests before live Agent capability wiring"
)]

use std::net::{IpAddr, Ipv4Addr};

use prw_connectivity::{
    CandidateId, ConnectivityCandidate, ConnectivityEndpoint, ConnectivityPathKind,
    PeerConnectivityIdentity, PeerConnectivityPlan, ReachabilityObservation,
    SelectedConnectivityPath, TransportIdentity,
};
use prw_core::DeviceId;
use prw_file_service::RemotePath;
use prw_file_transfer::{MAX_TRANSFER_BYTES, TransferId, UploadPlan};
use prw_forwarding::{ForwardTarget, LoopbackBind, LoopbackFamily, PortForwardId, TcpForwardSpec};
use prw_private_dns::{DnsDomainSuffix, PrivateDnsConfig, PrivateDnsMode, ResolverEndpoint};
use prw_remote_bridge::{BridgeCommand, MAX_BRIDGE_INLINE_BYTES};
use prw_terminal::{TerminalGeometry, TerminalProfile, TerminalSessionId};

const MAX_DESKTOP_DIRECTORY_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagementError {
    InvalidTerminal,
    InvalidPath,
    InvalidTransfer,
    InvalidForward,
    InvalidConnectivity,
    InvalidDns,
    InvalidState,
    InvalidAcknowledgement,
    Bridge,
}

fn bridge_payload(command: &BridgeCommand) -> Result<Vec<u8>, ManagementError> {
    command.encode().map_err(|_| ManagementError::Bridge)
}

pub(crate) fn encode_terminal_open(
    session_id: u64,
    profile: TerminalProfile,
    columns: u16,
    rows: u16,
) -> Result<Vec<u8>, ManagementError> {
    let session_id =
        TerminalSessionId::new(session_id).map_err(|_| ManagementError::InvalidTerminal)?;
    let geometry =
        TerminalGeometry::new(columns, rows).map_err(|_| ManagementError::InvalidTerminal)?;
    bridge_payload(&BridgeCommand::TerminalOpen {
        session_id,
        profile,
        geometry,
    })
}

pub(crate) fn encode_terminal_input(
    session_id: u64,
    input: &[u8],
) -> Result<Vec<u8>, ManagementError> {
    if input.is_empty() || input.len() > MAX_BRIDGE_INLINE_BYTES {
        return Err(ManagementError::InvalidTerminal);
    }
    let session_id =
        TerminalSessionId::new(session_id).map_err(|_| ManagementError::InvalidTerminal)?;
    bridge_payload(&BridgeCommand::TerminalInput {
        session_id,
        bytes: input.to_vec(),
    })
}

pub(crate) fn encode_terminal_close(session_id: u64) -> Result<Vec<u8>, ManagementError> {
    let session_id =
        TerminalSessionId::new(session_id).map_err(|_| ManagementError::InvalidTerminal)?;
    bridge_payload(&BridgeCommand::TerminalClose(session_id))
}

pub(crate) fn encode_file_list(path: &str) -> Result<Vec<u8>, ManagementError> {
    let path = RemotePath::parse(path).map_err(|_| ManagementError::InvalidPath)?;
    bridge_payload(&BridgeCommand::FileList(path))
}

fn upload_plan(
    transfer_id: &str,
    destination: &str,
    total_bytes: u64,
    sha256: [u8; 32],
) -> Result<UploadPlan, ManagementError> {
    if total_bytes > MAX_TRANSFER_BYTES {
        return Err(ManagementError::InvalidTransfer);
    }
    let transfer_id =
        TransferId::from_hex(transfer_id).map_err(|_| ManagementError::InvalidTransfer)?;
    let destination = RemotePath::parse(destination).map_err(|_| ManagementError::InvalidPath)?;
    UploadPlan::new(transfer_id, destination, total_bytes, sha256)
        .map_err(|_| ManagementError::InvalidTransfer)
}

pub(crate) fn encode_upload_begin(
    transfer_id: &str,
    destination: &str,
    total_bytes: u64,
    sha256: [u8; 32],
) -> Result<Vec<u8>, ManagementError> {
    bridge_payload(&BridgeCommand::UploadBegin(upload_plan(
        transfer_id,
        destination,
        total_bytes,
        sha256,
    )?))
}

pub(crate) fn encode_upload_chunk(
    transfer_id: &str,
    offset: u64,
    chunk: &[u8],
) -> Result<Vec<u8>, ManagementError> {
    if chunk.is_empty() || chunk.len() > MAX_BRIDGE_INLINE_BYTES {
        return Err(ManagementError::InvalidTransfer);
    }
    let transfer_id =
        TransferId::from_hex(transfer_id).map_err(|_| ManagementError::InvalidTransfer)?;
    bridge_payload(&BridgeCommand::UploadChunk {
        transfer_id,
        offset,
        chunk: chunk.to_vec(),
    })
}

pub(crate) fn encode_upload_finalize(transfer_id: &str) -> Result<Vec<u8>, ManagementError> {
    let transfer_id =
        TransferId::from_hex(transfer_id).map_err(|_| ManagementError::InvalidTransfer)?;
    bridge_payload(&BridgeCommand::UploadFinalize(transfer_id))
}

pub(crate) fn encode_forward_open(
    forward_id: u64,
    family: LoopbackFamily,
    bind_port: u16,
    target_address: IpAddr,
    target_port: u16,
) -> Result<Vec<u8>, ManagementError> {
    let forward_id = PortForwardId::new(forward_id).map_err(|_| ManagementError::InvalidForward)?;
    let bind = LoopbackBind::new(family, bind_port).map_err(|_| ManagementError::InvalidForward)?;
    let target = ForwardTarget::new(target_address, target_port)
        .map_err(|_| ManagementError::InvalidForward)?;
    bridge_payload(&BridgeCommand::ForwardOpen {
        forward_id,
        spec: TcpForwardSpec::new(bind, target),
    })
}

pub(crate) fn encode_forward_close(forward_id: u64) -> Result<Vec<u8>, ManagementError> {
    let forward_id = PortForwardId::new(forward_id).map_err(|_| ManagementError::InvalidForward)?;
    bridge_payload(&BridgeCommand::ForwardClose(forward_id))
}

fn disposable_candidate(
    id: u64,
    kind: ConnectivityPathKind,
    port: u16,
) -> Result<ConnectivityCandidate, ManagementError> {
    let id = CandidateId::new(id).map_err(|_| ManagementError::InvalidConnectivity)?;
    let endpoint = ConnectivityEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        .map_err(|_| ManagementError::InvalidConnectivity)?;
    Ok(ConnectivityCandidate::new(id, kind, endpoint))
}

pub(crate) fn select_disposable_connectivity_path(
    local: ReachabilityObservation,
    internet: ReachabilityObservation,
    relay: ReachabilityObservation,
) -> Result<SelectedConnectivityPath, ManagementError> {
    let peer = PeerConnectivityIdentity::new(
        DeviceId::new("phase152-desktop-disposable")
            .map_err(|_| ManagementError::InvalidConnectivity)?,
        TransportIdentity::new([152; 32]).map_err(|_| ManagementError::InvalidConnectivity)?,
    );
    let candidates = vec![
        disposable_candidate(1, ConnectivityPathKind::LocalDirect, 25_201)?,
        disposable_candidate(2, ConnectivityPathKind::InternetDirect, 25_202)?,
        disposable_candidate(3, ConnectivityPathKind::Relay, 25_203)?,
    ];
    let mut plan = PeerConnectivityPlan::new(peer, candidates)
        .map_err(|_| ManagementError::InvalidConnectivity)?;
    for (id, observation) in [(1, local), (2, internet), (3, relay)] {
        plan.set_observation(
            CandidateId::new(id).map_err(|_| ManagementError::InvalidConnectivity)?,
            observation,
        )
        .map_err(|_| ManagementError::InvalidConnectivity)?;
    }
    Ok(plan.selected_path())
}

fn optional_suffix(value: &str) -> Result<Option<DnsDomainSuffix>, ManagementError> {
    if value.is_empty() {
        return Ok(None);
    }
    DnsDomainSuffix::new(value)
        .map(Some)
        .map_err(|_| ManagementError::InvalidDns)
}

pub(crate) fn validate_private_dns(
    enabled: bool,
    device_naming: bool,
    device_domain: &str,
    resolver: Option<(IpAddr, u16)>,
    split_domain: &str,
) -> Result<PrivateDnsConfig, ManagementError> {
    let mode = if enabled {
        PrivateDnsMode::Enabled
    } else {
        PrivateDnsMode::Disabled
    };
    let device_domain = optional_suffix(device_domain)?;
    let split_domains = optional_suffix(split_domain)?.into_iter().collect();
    let resolvers = resolver
        .map(|(address, port)| {
            ResolverEndpoint::new(address, port).map_err(|_| ManagementError::InvalidDns)
        })
        .transpose()?
        .into_iter()
        .collect();
    PrivateDnsConfig::new(mode, device_naming, device_domain, resolvers, split_domains)
        .map_err(|_| ManagementError::InvalidDns)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalPresentationState {
    Closed,
    Opening,
    Open,
    Closing,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalPresentation {
    state: TerminalPresentationState,
    session_id: u64,
}

impl TerminalPresentation {
    #[must_use]
    pub(crate) const fn new(session_id: u64) -> Self {
        Self {
            state: TerminalPresentationState::Closed,
            session_id,
        }
    }

    #[must_use]
    pub(crate) const fn state(self) -> TerminalPresentationState {
        self.state
    }

    pub(crate) fn request_open(
        &mut self,
        profile: TerminalProfile,
        columns: u16,
        rows: u16,
    ) -> Result<Vec<u8>, ManagementError> {
        if self.state != TerminalPresentationState::Closed {
            return Err(ManagementError::InvalidState);
        }
        let payload = encode_terminal_open(self.session_id, profile, columns, rows)?;
        self.state = TerminalPresentationState::Opening;
        Ok(payload)
    }

    pub(crate) fn apply_open_acknowledgement(&mut self) -> Result<(), ManagementError> {
        if self.state != TerminalPresentationState::Opening {
            return Err(ManagementError::InvalidAcknowledgement);
        }
        self.state = TerminalPresentationState::Open;
        Ok(())
    }

    pub(crate) fn request_input(&self, input: &[u8]) -> Result<Vec<u8>, ManagementError> {
        if self.state != TerminalPresentationState::Open {
            return Err(ManagementError::InvalidState);
        }
        encode_terminal_input(self.session_id, input)
    }

    pub(crate) fn request_close(&mut self) -> Result<Vec<u8>, ManagementError> {
        if self.state != TerminalPresentationState::Open {
            return Err(ManagementError::InvalidState);
        }
        let payload = encode_terminal_close(self.session_id)?;
        self.state = TerminalPresentationState::Closing;
        Ok(payload)
    }

    pub(crate) fn apply_close_acknowledgement(&mut self) -> Result<(), ManagementError> {
        if self.state != TerminalPresentationState::Closing {
            return Err(ManagementError::InvalidAcknowledgement);
        }
        self.state = TerminalPresentationState::Closed;
        Ok(())
    }

    pub(crate) fn apply_failure(&mut self) {
        self.state = TerminalPresentationState::Failed;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileBrowserPresentation {
    current_path: String,
    pending: bool,
    entries: Vec<String>,
}

impl FileBrowserPresentation {
    #[must_use]
    pub(crate) fn new(path: impl Into<String>) -> Self {
        Self {
            current_path: path.into(),
            pending: false,
            entries: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) fn entries(&self) -> &[String] {
        &self.entries
    }

    pub(crate) fn request_list(&mut self) -> Result<Vec<u8>, ManagementError> {
        let payload = encode_file_list(&self.current_path)?;
        self.pending = true;
        Ok(payload)
    }

    pub(crate) fn apply_authoritative_snapshot(
        &mut self,
        entries: Vec<String>,
    ) -> Result<(), ManagementError> {
        if !self.pending || entries.len() > MAX_DESKTOP_DIRECTORY_ENTRIES {
            return Err(ManagementError::InvalidAcknowledgement);
        }
        self.entries = entries;
        self.pending = false;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadPresentationState {
    Idle,
    WaitingForBegin,
    Ready,
    Transferring,
    Finalizing,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UploadPresentation {
    transfer_id: String,
    destination: String,
    total_bytes: u64,
    sha256: [u8; 32],
    committed_bytes: u64,
    pending_chunk_end: Option<u64>,
    state: UploadPresentationState,
}

impl UploadPresentation {
    #[must_use]
    pub(crate) fn new(
        transfer_id: impl Into<String>,
        destination: impl Into<String>,
        total_bytes: u64,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            transfer_id: transfer_id.into(),
            destination: destination.into(),
            total_bytes,
            sha256,
            committed_bytes: 0,
            pending_chunk_end: None,
            state: UploadPresentationState::Idle,
        }
    }

    #[must_use]
    pub(crate) const fn committed_bytes(&self) -> u64 {
        self.committed_bytes
    }

    #[must_use]
    pub(crate) const fn state(&self) -> UploadPresentationState {
        self.state
    }

    pub(crate) fn request_begin(&mut self) -> Result<Vec<u8>, ManagementError> {
        if self.state != UploadPresentationState::Idle {
            return Err(ManagementError::InvalidState);
        }
        let payload = encode_upload_begin(
            &self.transfer_id,
            &self.destination,
            self.total_bytes,
            self.sha256,
        )?;
        self.state = UploadPresentationState::WaitingForBegin;
        Ok(payload)
    }

    pub(crate) fn apply_begin_acknowledgement(
        &mut self,
        committed_bytes: u64,
    ) -> Result<(), ManagementError> {
        if self.state != UploadPresentationState::WaitingForBegin
            || committed_bytes > self.total_bytes
        {
            return Err(ManagementError::InvalidAcknowledgement);
        }
        self.committed_bytes = committed_bytes;
        self.state = UploadPresentationState::Ready;
        Ok(())
    }

    pub(crate) fn request_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>, ManagementError> {
        if !matches!(
            self.state,
            UploadPresentationState::Ready | UploadPresentationState::Transferring
        ) || self.pending_chunk_end.is_some()
        {
            return Err(ManagementError::InvalidState);
        }
        let chunk_len = u64::try_from(chunk.len()).map_err(|_| ManagementError::InvalidTransfer)?;
        let end = self
            .committed_bytes
            .checked_add(chunk_len)
            .ok_or(ManagementError::InvalidTransfer)?;
        if end > self.total_bytes {
            return Err(ManagementError::InvalidTransfer);
        }
        let payload = encode_upload_chunk(&self.transfer_id, self.committed_bytes, chunk)?;
        self.pending_chunk_end = Some(end);
        self.state = UploadPresentationState::Transferring;
        Ok(payload)
    }

    pub(crate) fn apply_chunk_acknowledgement(
        &mut self,
        committed_bytes: u64,
    ) -> Result<(), ManagementError> {
        if self.pending_chunk_end != Some(committed_bytes) {
            return Err(ManagementError::InvalidAcknowledgement);
        }
        self.committed_bytes = committed_bytes;
        self.pending_chunk_end = None;
        self.state = UploadPresentationState::Ready;
        Ok(())
    }

    pub(crate) fn request_finalize(&mut self) -> Result<Vec<u8>, ManagementError> {
        if self.state != UploadPresentationState::Ready
            || self.committed_bytes != self.total_bytes
            || self.pending_chunk_end.is_some()
        {
            return Err(ManagementError::InvalidState);
        }
        let payload = encode_upload_finalize(&self.transfer_id)?;
        self.state = UploadPresentationState::Finalizing;
        Ok(payload)
    }

    pub(crate) fn apply_finalize_acknowledgement(&mut self) -> Result<(), ManagementError> {
        if self.state != UploadPresentationState::Finalizing {
            return Err(ManagementError::InvalidAcknowledgement);
        }
        self.state = UploadPresentationState::Completed;
        Ok(())
    }

    pub(crate) fn apply_failure(&mut self) {
        self.pending_chunk_end = None;
        self.state = UploadPresentationState::Failed;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardPresentationState {
    Closed,
    Opening,
    Active,
    Closing,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForwardPresentation {
    state: ForwardPresentationState,
    forward_id: u64,
}

impl ForwardPresentation {
    #[must_use]
    pub(crate) const fn new(forward_id: u64) -> Self {
        Self {
            state: ForwardPresentationState::Closed,
            forward_id,
        }
    }

    #[must_use]
    pub(crate) const fn state(self) -> ForwardPresentationState {
        self.state
    }

    pub(crate) fn request_open(
        &mut self,
        family: LoopbackFamily,
        bind_port: u16,
        target_address: IpAddr,
        target_port: u16,
    ) -> Result<Vec<u8>, ManagementError> {
        if self.state != ForwardPresentationState::Closed {
            return Err(ManagementError::InvalidState);
        }
        let payload = encode_forward_open(
            self.forward_id,
            family,
            bind_port,
            target_address,
            target_port,
        )?;
        self.state = ForwardPresentationState::Opening;
        Ok(payload)
    }

    pub(crate) fn apply_open_acknowledgement(&mut self) -> Result<(), ManagementError> {
        if self.state != ForwardPresentationState::Opening {
            return Err(ManagementError::InvalidAcknowledgement);
        }
        self.state = ForwardPresentationState::Active;
        Ok(())
    }

    pub(crate) fn request_close(&mut self) -> Result<Vec<u8>, ManagementError> {
        if self.state != ForwardPresentationState::Active {
            return Err(ManagementError::InvalidState);
        }
        let payload = encode_forward_close(self.forward_id)?;
        self.state = ForwardPresentationState::Closing;
        Ok(payload)
    }

    pub(crate) fn apply_close_acknowledgement(&mut self) -> Result<(), ManagementError> {
        if self.state != ForwardPresentationState::Closing {
            return Err(ManagementError::InvalidAcknowledgement);
        }
        self.state = ForwardPresentationState::Closed;
        Ok(())
    }

    pub(crate) fn apply_failure(&mut self) {
        self.state = ForwardPresentationState::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSFER_ID: &str = "abababababababababababababababab";

    #[test]
    fn terminal_intent_reuses_bridge_and_never_forges_open_or_closed() {
        let mut terminal = TerminalPresentation::new(152);
        let open = terminal
            .request_open(TerminalProfile::PosixShell, 80, 24)
            .expect("typed terminal open");
        assert!(matches!(
            BridgeCommand::decode(&open).expect("decode terminal open"),
            BridgeCommand::TerminalOpen { .. }
        ));
        assert_eq!(terminal.state(), TerminalPresentationState::Opening);
        assert!(terminal.request_input(b"pwd\n").is_err());

        terminal
            .apply_open_acknowledgement()
            .expect("authoritative open acknowledgement");
        assert_eq!(terminal.state(), TerminalPresentationState::Open);
        let input = terminal.request_input(b"pwd\n").expect("terminal input");
        assert!(matches!(
            BridgeCommand::decode(&input).expect("decode input"),
            BridgeCommand::TerminalInput { .. }
        ));

        let close = terminal.request_close().expect("terminal close intent");
        assert!(matches!(
            BridgeCommand::decode(&close).expect("decode close"),
            BridgeCommand::TerminalClose(_)
        ));
        assert_eq!(terminal.state(), TerminalPresentationState::Closing);
        terminal
            .apply_close_acknowledgement()
            .expect("authoritative close acknowledgement");
        assert_eq!(terminal.state(), TerminalPresentationState::Closed);
    }

    #[test]
    fn invalid_terminal_values_fail_closed_through_existing_authority() {
        assert!(encode_terminal_open(0, TerminalProfile::PosixShell, 80, 24).is_err());
        assert!(encode_terminal_open(1, TerminalProfile::PosixShell, 0, 24).is_err());
        assert!(encode_terminal_input(1, b"").is_err());
        assert!(encode_terminal_input(1, &vec![0; MAX_BRIDGE_INLINE_BYTES + 1]).is_err());
    }

    #[test]
    fn file_browser_request_does_not_fabricate_authoritative_entries() {
        let mut browser = FileBrowserPresentation::new("docs");
        let payload = browser.request_list().expect("typed list request");
        assert_eq!(browser.entries(), &[] as &[String]);
        assert!(matches!(
            BridgeCommand::decode(&payload).expect("decode file list"),
            BridgeCommand::FileList(_)
        ));
        browser
            .apply_authoritative_snapshot(vec!["readme.md".to_owned()])
            .expect("authoritative directory snapshot");
        assert_eq!(browser.entries(), &["readme.md".to_owned()]);
        assert!(encode_file_list("../escape").is_err());
        assert!(encode_file_list("/absolute").is_err());
    }

    #[test]
    fn upload_progress_advances_only_from_exact_acknowledgements() {
        let mut upload = UploadPresentation::new(TRANSFER_ID, "uploads/demo.bin", 3, [7; 32]);
        let begin = upload.request_begin().expect("begin intent");
        assert!(matches!(
            BridgeCommand::decode(&begin).expect("decode begin"),
            BridgeCommand::UploadBegin(_)
        ));
        assert_eq!(upload.committed_bytes(), 0);
        upload
            .apply_begin_acknowledgement(0)
            .expect("begin acknowledgement");

        let chunk = upload.request_chunk(b"abc").expect("chunk intent");
        assert!(matches!(
            BridgeCommand::decode(&chunk).expect("decode chunk"),
            BridgeCommand::UploadChunk { .. }
        ));
        assert_eq!(upload.committed_bytes(), 0);
        assert!(upload.apply_chunk_acknowledgement(2).is_err());
        assert_eq!(upload.committed_bytes(), 0);
        upload
            .apply_chunk_acknowledgement(3)
            .expect("exact chunk acknowledgement");
        assert_eq!(upload.committed_bytes(), 3);

        let finalize = upload.request_finalize().expect("finalize intent");
        assert!(matches!(
            BridgeCommand::decode(&finalize).expect("decode finalize"),
            BridgeCommand::UploadFinalize(_)
        ));
        assert_eq!(upload.state(), UploadPresentationState::Finalizing);
        upload
            .apply_finalize_acknowledgement()
            .expect("finalize acknowledgement");
        assert_eq!(upload.state(), UploadPresentationState::Completed);
    }

    #[test]
    fn forwarding_intent_reuses_typed_loopback_authority_and_ack_state() {
        let mut forward = ForwardPresentation::new(152);
        let open = forward
            .request_open(
                LoopbackFamily::Ipv4,
                41_152,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                22,
            )
            .expect("forward open intent");
        assert!(matches!(
            BridgeCommand::decode(&open).expect("decode forward"),
            BridgeCommand::ForwardOpen { .. }
        ));
        assert_eq!(forward.state(), ForwardPresentationState::Opening);
        forward
            .apply_open_acknowledgement()
            .expect("forward open acknowledgement");
        assert_eq!(forward.state(), ForwardPresentationState::Active);
        let close = forward.request_close().expect("forward close intent");
        assert!(matches!(
            BridgeCommand::decode(&close).expect("decode close"),
            BridgeCommand::ForwardClose(_)
        ));
        assert_eq!(forward.state(), ForwardPresentationState::Closing);
        forward
            .apply_close_acknowledgement()
            .expect("forward close acknowledgement");
        assert_eq!(forward.state(), ForwardPresentationState::Closed);

        assert!(
            encode_forward_open(
                152,
                LoopbackFamily::Ipv4,
                41_152,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                22
            )
            .is_err()
        );
    }

    #[test]
    fn connectivity_selection_uses_existing_deterministic_authority() {
        let selected = select_disposable_connectivity_path(
            ReachabilityObservation::Reachable,
            ReachabilityObservation::Reachable,
            ReachabilityObservation::Reachable,
        )
        .expect("selected path");
        assert!(matches!(
            selected,
            SelectedConnectivityPath::Candidate(candidate)
                if candidate.kind() == ConnectivityPathKind::LocalDirect
        ));

        let offline = select_disposable_connectivity_path(
            ReachabilityObservation::Unknown,
            ReachabilityObservation::Unknown,
            ReachabilityObservation::Unknown,
        )
        .expect("offline path");
        assert_eq!(offline, SelectedConnectivityPath::Offline);
    }

    #[test]
    fn private_dns_validation_never_claims_os_application() {
        let config = validate_private_dns(
            true,
            true,
            "prw.internal",
            Some((IpAddr::V4(Ipv4Addr::LOCALHOST), 53)),
            "dev.internal",
        )
        .expect("typed DNS config");
        assert_eq!(config.mode(), PrivateDnsMode::Enabled);
        assert!(validate_private_dns(true, true, "", None, "").is_err());
        assert!(validate_private_dns(false, false, "", None, "dev.internal").is_err());
    }
}
