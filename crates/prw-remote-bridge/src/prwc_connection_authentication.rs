//! Bridge-owned PRWA authentication execution for one accepted Phase 129 PRWC connection.
//!
//! C03e-CK composes the already-materialized generic accepted-stream primitive, PRWA codec,
//! verifier source, session-authentication service, current registry, and C03e-CJ request-ID
//! lifecycle. It does not bind a listener, spawn an accept loop, admit `Command` semantics,
//! select requester/rendezvous state, execute candidate publication, or activate product runtime.

use std::fmt;

use prw_control_plane::session_auth::SessionAuthProof;
use prw_control_transport::{ControlFrame, ControlFrameError, ControlTlsServerStream};
use prw_registry::{RegistryError, WorkspaceDeviceRegistry};
use prw_session::{
    AuthenticatedDeviceSession, SessionAuthenticationService, SessionServiceError,
    prwa_verifier_source::{
        PrwaVerifierSourceError, current_prwa_verifier_unix_seconds,
        new_prwa_verifier_session_context,
    },
};

use crate::{
    candidate_publication_control_frame::{
        CandidatePublicationControlFrame, CandidatePublicationControlFrameError,
        decode_candidate_publication_control_frame,
    },
    candidate_publication_execution::CandidatePublicationExecutionError,
    candidate_publication_result_wire::{
        CandidatePublicationResultWireError, encode_candidate_publication_execution_result_frame,
    },
    control_session_auth_wire::{
        ControlSessionAuthenticationMessage, ControlSessionAuthenticationWireError,
        decode_control_session_authentication_frame, encode_control_session_authentication_frame,
    },
    prwc_request_id_lifecycle::PrwcRequestIdLifecycle,
    reachability_owner::ReachabilityCommitOutcome,
};

/// Fail-closed bridge classification for one pre-mesh PRWA connection transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrwcConnectionAuthenticationError {
    /// Bounded PRWC frame read/write failed.
    Frame(ControlFrameError),
    /// PRWA frame encoding or decoding failed.
    Wire(ControlSessionAuthenticationWireError),
    /// The peer sent a structurally valid PRWA operation in an invalid transaction position.
    ProtocolOrder,
    /// A Proof used a different outer PRWC request ID from the Begin transaction.
    RequestIdMismatch,
    /// A Proof used a different PRWA `SessionId` from the verifier-issued Challenge.
    SessionIdMismatch,
    /// Begin selected no currently enrolled registered device binding.
    DeviceBindingUnavailable,
    /// Fresh verifier `SessionId` or verifier time acquisition failed.
    VerifierSource(PrwaVerifierSourceError),
    /// Existing session-authentication authority rejected the transaction.
    Session(SessionServiceError),
    /// Current registry revalidation rejected a completed authenticated session.
    Registry(RegistryError),
    /// Explicit pending-session cleanup itself failed.
    PendingCleanup(SessionServiceError),
}

impl fmt::Display for PrwcConnectionAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Frame(_) => "PRWC connection frame I/O failed",
            Self::Wire(_) => "PRWA connection authentication codec failed",
            Self::ProtocolOrder => "PRWA connection authentication protocol order rejected",
            Self::RequestIdMismatch => "PRWA proof request ID did not match Begin",
            Self::SessionIdMismatch => "PRWA proof SessionId did not match Challenge",
            Self::DeviceBindingUnavailable => {
                "PRWA Begin did not resolve a current enrolled device binding"
            }
            Self::VerifierSource(_) => "PRWA verifier source failed",
            Self::Session(_) => "PRWA session authentication failed",
            Self::Registry(_) => "PRWA authenticated session failed current registry validation",
            Self::PendingCleanup(_) => "PRWA pending-session cleanup failed",
        })
    }
}

impl std::error::Error for PrwcConnectionAuthenticationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::Wire(error) => Some(error),
            Self::VerifierSource(error) => Some(error),
            Self::Session(error) | Self::PendingCleanup(error) => Some(error),
            Self::Registry(error) => Some(error),
            Self::ProtocolOrder
            | Self::RequestIdMismatch
            | Self::SessionIdMismatch
            | Self::DeviceBindingUnavailable => None,
        }
    }
}

/// Fail-closed post-authenticated candidate-publication Command receive failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticatedPrwcCommandReceiveError {
    /// The existing bounded PRWC frame read failed.
    Frame(ControlFrameError),
    /// The received frame was not a valid candidate-publication Command.
    Command(CandidatePublicationControlFrameError),
    /// Candidate-publication I/O was already terminal before this receive attempt.
    Terminal,
}

impl fmt::Display for AuthenticatedPrwcCommandReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Frame(_) => "post-authenticated PRWC Command frame read failed",
            Self::Command(_) => "post-authenticated candidate-publication Command decode failed",
            Self::Terminal => "post-authenticated candidate-publication I/O is terminal",
        })
    }
}

impl std::error::Error for AuthenticatedPrwcCommandReceiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Frame(error) => Some(error),
            Self::Command(error) => Some(error),
            Self::Terminal => None,
        }
    }
}

/// Fail-closed one-shot candidate-publication terminal-result write failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticatedPrwcCandidatePublicationResultWriteError {
    /// Pure C03e-CV result projection/frame construction failed before stream I/O.
    Composition(CandidatePublicationResultWireError),
    /// The existing bounded PRWC frame write failed and terminalized candidate-publication I/O.
    Frame(ControlFrameError),
    /// Candidate-publication I/O was already terminal before composition or stream I/O.
    Terminal,
}

impl fmt::Display for AuthenticatedPrwcCandidatePublicationResultWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Composition(_) => "candidate-publication result frame composition failed",
            Self::Frame(_) => "candidate-publication result frame write failed",
            Self::Terminal => "post-authenticated candidate-publication I/O is terminal",
        })
    }
}

impl std::error::Error for AuthenticatedPrwcCandidatePublicationResultWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Composition(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Terminal => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidatePublicationReceiveState {
    Ready,
    Terminal,
}

/// One newly accepted generic PRWC stream before logical PRWA authentication.
///
/// Construction performs no frame I/O. The wrapper owns a fresh C03e-CJ request-ID lifecycle
/// for the same connection namespace, but peer-originated PRWA correlation continues to preserve
/// the inbound request ID rather than allocating a replacement.
#[derive(Debug)]
pub struct UnauthenticatedPrwcConnection {
    stream: ControlTlsServerStream,
    request_ids: PrwcRequestIdLifecycle,
}

impl UnauthenticatedPrwcConnection {
    /// Takes ownership of one already-accepted generic Phase 129 server stream.
    #[must_use]
    pub const fn new(stream: ControlTlsServerStream) -> Self {
        Self {
            stream,
            request_ids: PrwcRequestIdLifecycle::new(),
        }
    }

    /// Executes exactly one CA/CG-selected pre-mesh PRWA authentication transaction.
    ///
    /// This method consumes the unauthenticated connection. Any failure drops the accepted
    /// stream after explicit pending-session cleanup when required, so same-connection retry or
    /// reauthentication is unavailable. A successful return occurs only after terminal
    /// `Authenticated` delivery succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`PrwcConnectionAuthenticationError`] for frame, codec, ordering, verifier,
    /// session-service, cleanup, or current-registry failure.
    pub fn authenticate(
        mut self,
        sessions: &mut SessionAuthenticationService,
        registry: &WorkspaceDeviceRegistry,
    ) -> Result<AuthenticatedPrwcConnection, PrwcConnectionAuthenticationError> {
        match execute_authentication_transaction(&mut self.stream, sessions, registry) {
            Ok(session) => Ok(AuthenticatedPrwcConnection {
                stream: self.stream,
                request_ids: self.request_ids,
                session,
                candidate_publication_receive_state: CandidatePublicationReceiveState::Ready,
            }),
            Err(error) => {
                let _ = self.request_ids.abandon_all();
                Err(error)
            }
        }
    }
}

/// One accepted PRWC connection whose logical device session was authenticated and delivered.
///
/// The retained stream is intentionally not exposed by C03e-CK. Later Command execution remains
/// separately gated. Holding this value grants no capability and does not perform registry,
/// requester/rendezvous, freshness, publication, or policy decisions.
#[derive(Debug)]
pub struct AuthenticatedPrwcConnection {
    stream: ControlTlsServerStream,
    request_ids: PrwcRequestIdLifecycle,
    session: AuthenticatedDeviceSession,
    candidate_publication_receive_state: CandidatePublicationReceiveState,
}

impl AuthenticatedPrwcConnection {
    /// Returns the connection-local authenticated logical-session binding.
    #[must_use]
    pub const fn session(&self) -> &AuthenticatedDeviceSession {
        &self.session
    }

    /// Returns the connection-local C03e-CJ request-ID custody state.
    ///
    /// CK does not allocate locally originated IDs during PRWA authentication.
    #[must_use]
    pub const fn request_ids(&self) -> &PrwcRequestIdLifecycle {
        &self.request_ids
    }

    /// Receives exactly one post-authenticated candidate-publication Command.
    ///
    /// The raw `ControlTlsServerStream` remains private. Each non-terminal call performs exactly
    /// one existing bounded frame read and then strict candidate-publication Command decoding.
    /// Peer-originated request correlation is preserved by the existing frame adapter and never
    /// enters the locally-originated request-ID lifecycle.
    ///
    /// Any frame or candidate-publication decode failure terminalizes candidate-publication I/O.
    /// Later reads or result writes then fail immediately without another stream operation. This
    /// method writes no response, performs no retry/loop, consults no requester/rendezvous
    /// provider, and mutates no reachability state.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedPrwcCommandReceiveError`] for frame read failure, strict Command
    /// decode failure, or already-terminal candidate-publication I/O.
    pub fn receive_candidate_publication_command(
        &mut self,
    ) -> Result<CandidatePublicationControlFrame, AuthenticatedPrwcCommandReceiveError> {
        receive_candidate_publication_command_from_io(
            &mut self.stream,
            &mut self.candidate_publication_receive_state,
        )
    }

    /// Writes exactly one terminal result for an already-completed candidate-publication execution.
    ///
    /// The C03e-CV helper first projects the completed semantic result and composes the exact
    /// peer-correlated `Response`/`Error` frame. A pure composition failure occurs before stream
    /// I/O and leaves candidate-publication I/O ready. The private server stream is then written
    /// exactly once. An actual write failure terminalizes candidate-publication I/O before return;
    /// later candidate-publication reads and writes fail before another stream operation.
    ///
    /// This method allocates/registers no local request ID, performs no candidate semantic
    /// execution, retries nothing, starts no loop/task, and exposes no raw stream.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedPrwcCandidatePublicationResultWriteError`] for pure result-frame
    /// composition failure, bounded stream write failure, or already-terminal candidate-publication
    /// I/O.
    pub fn write_candidate_publication_result(
        &mut self,
        command: &CandidatePublicationControlFrame,
        result: Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError>,
    ) -> Result<(), AuthenticatedPrwcCandidatePublicationResultWriteError> {
        write_candidate_publication_result_to_io(
            &mut self.stream,
            &mut self.candidate_publication_receive_state,
            move || encode_candidate_publication_execution_result_frame(command, result),
        )
    }
}

trait PrwcCandidatePublicationFrameIo {
    fn read_frame(&mut self) -> Result<ControlFrame, ControlFrameError>;
}

impl PrwcCandidatePublicationFrameIo for ControlTlsServerStream {
    fn read_frame(&mut self) -> Result<ControlFrame, ControlFrameError> {
        Self::read_frame(self)
    }
}

fn receive_candidate_publication_command_from_io<I: PrwcCandidatePublicationFrameIo>(
    io: &mut I,
    state: &mut CandidatePublicationReceiveState,
) -> Result<CandidatePublicationControlFrame, AuthenticatedPrwcCommandReceiveError> {
    if *state == CandidatePublicationReceiveState::Terminal {
        return Err(AuthenticatedPrwcCommandReceiveError::Terminal);
    }

    let frame = match io.read_frame() {
        Ok(frame) => frame,
        Err(error) => {
            *state = CandidatePublicationReceiveState::Terminal;
            return Err(AuthenticatedPrwcCommandReceiveError::Frame(error));
        }
    };

    match decode_candidate_publication_control_frame(&frame) {
        Ok(command) => Ok(command),
        Err(error) => {
            *state = CandidatePublicationReceiveState::Terminal;
            Err(AuthenticatedPrwcCommandReceiveError::Command(error))
        }
    }
}

trait PrwcCandidatePublicationResultFrameIo {
    fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), ControlFrameError>;
}

impl PrwcCandidatePublicationResultFrameIo for ControlTlsServerStream {
    fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), ControlFrameError> {
        Self::write_frame(self, frame)
    }
}

fn write_candidate_publication_result_to_io<I, F>(
    io: &mut I,
    state: &mut CandidatePublicationReceiveState,
    compose: F,
) -> Result<(), AuthenticatedPrwcCandidatePublicationResultWriteError>
where
    I: PrwcCandidatePublicationResultFrameIo,
    F: FnOnce() -> Result<ControlFrame, CandidatePublicationResultWireError>,
{
    if *state == CandidatePublicationReceiveState::Terminal {
        return Err(AuthenticatedPrwcCandidatePublicationResultWriteError::Terminal);
    }

    let frame =
        compose().map_err(AuthenticatedPrwcCandidatePublicationResultWriteError::Composition)?;
    if let Err(error) = io.write_frame(&frame) {
        *state = CandidatePublicationReceiveState::Terminal;
        return Err(AuthenticatedPrwcCandidatePublicationResultWriteError::Frame(error));
    }

    Ok(())
}

trait PrwcAuthenticationFrameIo {
    fn read_frame(&mut self) -> Result<ControlFrame, ControlFrameError>;
    fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), ControlFrameError>;
}

impl PrwcAuthenticationFrameIo for ControlTlsServerStream {
    fn read_frame(&mut self) -> Result<ControlFrame, ControlFrameError> {
        Self::read_frame(self)
    }

    fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), ControlFrameError> {
        Self::write_frame(self, frame)
    }
}

#[allow(clippy::too_many_lines)]
fn execute_authentication_transaction<I: PrwcAuthenticationFrameIo>(
    io: &mut I,
    sessions: &mut SessionAuthenticationService,
    registry: &WorkspaceDeviceRegistry,
) -> Result<AuthenticatedDeviceSession, PrwcConnectionAuthenticationError> {
    let begin_frame = io
        .read_frame()
        .map_err(PrwcConnectionAuthenticationError::Frame)?;
    let request_id = begin_frame.request_id();
    let begin = match decode_control_session_authentication_frame(&begin_frame) {
        Ok(message) => message,
        Err(error) => {
            reject_best_effort(io, request_id);
            return Err(PrwcConnectionAuthenticationError::Wire(error));
        }
    };
    let ControlSessionAuthenticationMessage::Begin { device_id } = begin else {
        reject_best_effort(io, request_id);
        return Err(PrwcConnectionAuthenticationError::ProtocolOrder);
    };

    let binding = match registry.device(&device_id) {
        Some(device) if device.binding().lifecycle.can_participate() => device.binding().clone(),
        _ => {
            reject_best_effort(io, request_id);
            return Err(PrwcConnectionAuthenticationError::DeviceBindingUnavailable);
        }
    };

    let verifier = match new_prwa_verifier_session_context() {
        Ok(verifier) => verifier,
        Err(error) => {
            reject_best_effort(io, request_id);
            return Err(PrwcConnectionAuthenticationError::VerifierSource(error));
        }
    };
    let pending_session_id = verifier.session_id().clone();

    let challenge = match sessions.begin_session(
        binding,
        pending_session_id.clone(),
        verifier.issued_at_unix_seconds(),
        verifier.expires_at_unix_seconds(),
    ) {
        Ok(challenge) => challenge,
        Err(error) => {
            reject_best_effort(io, request_id);
            return Err(PrwcConnectionAuthenticationError::Session(error));
        }
    };

    let challenge_message = ControlSessionAuthenticationMessage::Challenge {
        session_id: challenge.session_id().clone(),
        nonce: challenge.nonce(),
        issued_at_unix_seconds: challenge.issued_at_unix_seconds(),
        expires_at_unix_seconds: challenge.expires_at_unix_seconds(),
    };
    let challenge_frame =
        match encode_control_session_authentication_frame(request_id, &challenge_message) {
            Ok(frame) => frame,
            Err(error) => {
                return fail_with_pending_cleanup(
                    io,
                    sessions,
                    &pending_session_id,
                    request_id,
                    PrwcConnectionAuthenticationError::Wire(error),
                );
            }
        };
    if let Err(error) = io.write_frame(&challenge_frame) {
        return fail_with_pending_cleanup(
            io,
            sessions,
            &pending_session_id,
            request_id,
            PrwcConnectionAuthenticationError::Frame(error),
        );
    }

    let proof_frame = match io.read_frame() {
        Ok(frame) => frame,
        Err(error) => {
            return fail_with_pending_cleanup(
                io,
                sessions,
                &pending_session_id,
                request_id,
                PrwcConnectionAuthenticationError::Frame(error),
            );
        }
    };
    if proof_frame.request_id() != request_id {
        return fail_with_pending_cleanup(
            io,
            sessions,
            &pending_session_id,
            request_id,
            PrwcConnectionAuthenticationError::RequestIdMismatch,
        );
    }
    let proof_message = match decode_control_session_authentication_frame(&proof_frame) {
        Ok(message) => message,
        Err(error) => {
            return fail_with_pending_cleanup(
                io,
                sessions,
                &pending_session_id,
                request_id,
                PrwcConnectionAuthenticationError::Wire(error),
            );
        }
    };
    let ControlSessionAuthenticationMessage::Proof {
        session_id: proof_session_id,
        nonce,
        signature,
    } = proof_message
    else {
        return fail_with_pending_cleanup(
            io,
            sessions,
            &pending_session_id,
            request_id,
            PrwcConnectionAuthenticationError::ProtocolOrder,
        );
    };
    if proof_session_id != pending_session_id {
        return fail_with_pending_cleanup(
            io,
            sessions,
            &pending_session_id,
            request_id,
            PrwcConnectionAuthenticationError::SessionIdMismatch,
        );
    }

    let proof = SessionAuthProof::new(proof_session_id, nonce, signature);
    let now_unix_seconds = match current_prwa_verifier_unix_seconds() {
        Ok(now) => now,
        Err(error) => {
            return fail_with_pending_cleanup(
                io,
                sessions,
                &pending_session_id,
                request_id,
                PrwcConnectionAuthenticationError::VerifierSource(error),
            );
        }
    };
    let authenticated = match sessions.submit_proof(&pending_session_id, &proof, now_unix_seconds) {
        Ok(authenticated) => authenticated,
        Err(error) => {
            return fail_with_pending_cleanup(
                io,
                sessions,
                &pending_session_id,
                request_id,
                PrwcConnectionAuthenticationError::Session(error),
            );
        }
    };

    registry
        .validate_authenticated_session(&authenticated)
        .map_err(PrwcConnectionAuthenticationError::Registry)?;

    let authenticated_message = ControlSessionAuthenticationMessage::Authenticated {
        session_id: authenticated.session_id().clone(),
    };
    let authenticated_frame =
        encode_control_session_authentication_frame(request_id, &authenticated_message)
            .map_err(PrwcConnectionAuthenticationError::Wire)?;
    io.write_frame(&authenticated_frame)
        .map_err(PrwcConnectionAuthenticationError::Frame)?;

    Ok(authenticated)
}

fn fail_with_pending_cleanup<I: PrwcAuthenticationFrameIo>(
    io: &mut I,
    sessions: &mut SessionAuthenticationService,
    pending_session_id: &prw_core::SessionId,
    request_id: u64,
    primary: PrwcConnectionAuthenticationError,
) -> Result<AuthenticatedDeviceSession, PrwcConnectionAuthenticationError> {
    sessions
        .abort_pending_session(pending_session_id)
        .map_err(PrwcConnectionAuthenticationError::PendingCleanup)?;
    reject_best_effort(io, request_id);
    Err(primary)
}

fn reject_best_effort<I: PrwcAuthenticationFrameIo>(io: &mut I, request_id: u64) {
    let rejected = ControlSessionAuthenticationMessage::Rejected;
    if let Ok(frame) = encode_control_session_authentication_frame(request_id, &rejected) {
        let _ = io.write_frame(&frame);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
    };
    use prw_control_plane::{DeviceIdentityBinding, session_auth::SessionAuthChallengeState};
    use prw_control_transport::{ControlFrame, ControlFrameError};
    use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
    use prw_device_identity_signer::UbuntuEnrollmentSigner;
    use prw_registry::{WorkspaceDeviceRegistry, WorkspaceRole};
    use prw_session::SessionAuthenticationService;

    use super::{
        PrwcAuthenticationFrameIo, PrwcConnectionAuthenticationError,
        execute_authentication_transaction,
    };
    use crate::control_session_auth_wire::{
        ControlSessionAuthenticationMessage, decode_control_session_authentication_frame,
        encode_control_session_authentication_frame,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProofMode {
        Valid,
        WrongRequestId,
        WrongSessionId,
    }

    struct Fixture {
        registry: WorkspaceDeviceRegistry,
        binding: DeviceIdentityBinding,
        signer: UbuntuEnrollmentSigner,
    }

    fn signer() -> UbuntuEnrollmentSigner {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable CK device key");
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
            .expect("load disposable CK signer")
    }

    fn fixture() -> Fixture {
        let signer = signer();
        let workspace_id = WorkspaceId::new("workspace-ck").expect("workspace id");
        let user_id = UserId::new("user-ck").expect("user id");
        let device_id = DeviceId::new("device-ck").expect("device id");
        let binding = DeviceIdentityBinding {
            workspace_id: workspace_id.clone(),
            user_id: user_id.clone(),
            device_id,
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };
        let mut registry = WorkspaceDeviceRegistry::new();
        registry
            .add_membership(workspace_id, user_id, WorkspaceRole::Member)
            .expect("add membership");
        registry
            .register_device(binding.clone())
            .expect("register device");
        Fixture {
            registry,
            binding,
            signer,
        }
    }

    struct FakeFrameIo<'a> {
        incoming: VecDeque<ControlFrame>,
        written: Vec<ControlFrame>,
        signer: &'a UbuntuEnrollmentSigner,
        binding: &'a DeviceIdentityBinding,
        proof_mode: ProofMode,
        fail_challenge_write: bool,
        fail_authenticated_write: bool,
    }

    impl<'a> FakeFrameIo<'a> {
        fn new(
            signer: &'a UbuntuEnrollmentSigner,
            binding: &'a DeviceIdentityBinding,
            request_id: u64,
            device_id: DeviceId,
        ) -> Self {
            let begin = encode_control_session_authentication_frame(
                request_id,
                &ControlSessionAuthenticationMessage::Begin { device_id },
            )
            .expect("encode Begin");
            Self {
                incoming: VecDeque::from([begin]),
                written: Vec::new(),
                signer,
                binding,
                proof_mode: ProofMode::Valid,
                fail_challenge_write: false,
                fail_authenticated_write: false,
            }
        }

        fn messages(&self) -> Vec<ControlSessionAuthenticationMessage> {
            self.written
                .iter()
                .map(|frame| {
                    decode_control_session_authentication_frame(frame).expect("decode written PRWA")
                })
                .collect()
        }
    }

    impl PrwcAuthenticationFrameIo for FakeFrameIo<'_> {
        fn read_frame(&mut self) -> Result<ControlFrame, ControlFrameError> {
            self.incoming
                .pop_front()
                .ok_or(ControlFrameError::TruncatedHeader)
        }

        fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), ControlFrameError> {
            let message = decode_control_session_authentication_frame(frame)
                .expect("valid bridge PRWA write");
            match &message {
                ControlSessionAuthenticationMessage::Challenge {
                    session_id,
                    nonce,
                    issued_at_unix_seconds,
                    expires_at_unix_seconds,
                } => {
                    if self.fail_challenge_write {
                        return Err(ControlFrameError::WriteIo);
                    }
                    self.written.push(frame.clone());

                    let state = SessionAuthChallengeState::new(
                        self.binding.clone(),
                        session_id.clone(),
                        *nonce,
                        *issued_at_unix_seconds,
                        *expires_at_unix_seconds,
                    )
                    .expect("reconstruct challenge for disposable signer");
                    let signature = self
                        .signer
                        .sign_session_auth_proof(self.binding, state.challenge())
                        .expect("sign PRWA proof")
                        .signature()
                        .clone();
                    let proof_session_id = match self.proof_mode {
                        ProofMode::WrongSessionId => {
                            SessionId::new("wrong-session").expect("wrong session id")
                        }
                        ProofMode::Valid | ProofMode::WrongRequestId => session_id.clone(),
                    };
                    let proof_request_id = match self.proof_mode {
                        ProofMode::WrongRequestId => {
                            frame.request_id().checked_add(1).expect("test request id")
                        }
                        ProofMode::Valid | ProofMode::WrongSessionId => frame.request_id(),
                    };
                    let proof = encode_control_session_authentication_frame(
                        proof_request_id,
                        &ControlSessionAuthenticationMessage::Proof {
                            session_id: proof_session_id,
                            nonce: *nonce,
                            signature,
                        },
                    )
                    .expect("encode Proof");
                    self.incoming.push_back(proof);
                    Ok(())
                }
                ControlSessionAuthenticationMessage::Authenticated { .. } => {
                    if self.fail_authenticated_write {
                        return Err(ControlFrameError::WriteIo);
                    }
                    self.written.push(frame.clone());
                    Ok(())
                }
                ControlSessionAuthenticationMessage::Rejected => {
                    self.written.push(frame.clone());
                    Ok(())
                }
                ControlSessionAuthenticationMessage::Begin { .. }
                | ControlSessionAuthenticationMessage::Proof { .. } => {
                    panic!("bridge must not write Begin or Proof")
                }
            }
        }
    }

    #[test]
    fn successful_transaction_preserves_request_id_and_delivers_authenticated_last() {
        let fixture = fixture();
        let request_id = 41;
        let mut io = FakeFrameIo::new(
            &fixture.signer,
            &fixture.binding,
            request_id,
            fixture.binding.device_id.clone(),
        );
        let mut sessions = SessionAuthenticationService::new();

        let authenticated =
            execute_authentication_transaction(&mut io, &mut sessions, &fixture.registry)
                .expect("authenticate");

        assert_eq!(authenticated.device_id(), &fixture.binding.device_id);
        assert_eq!(sessions.pending_count(), 0);
        assert_eq!(sessions.authenticated_count(), 1);
        assert_eq!(io.written.len(), 2);
        assert!(
            io.written
                .iter()
                .all(|frame| frame.request_id() == request_id)
        );
        assert!(matches!(
            io.messages().as_slice(),
            [
                ControlSessionAuthenticationMessage::Challenge { .. },
                ControlSessionAuthenticationMessage::Authenticated { .. }
            ]
        ));
    }

    #[test]
    fn proof_request_id_mismatch_aborts_pending_once_and_rejects_original_transaction() {
        let fixture = fixture();
        let request_id = 42;
        let mut io = FakeFrameIo::new(
            &fixture.signer,
            &fixture.binding,
            request_id,
            fixture.binding.device_id.clone(),
        );
        io.proof_mode = ProofMode::WrongRequestId;
        let mut sessions = SessionAuthenticationService::new();

        assert_eq!(
            execute_authentication_transaction(&mut io, &mut sessions, &fixture.registry),
            Err(PrwcConnectionAuthenticationError::RequestIdMismatch)
        );
        assert_eq!(sessions.pending_count(), 0);
        assert_eq!(sessions.authenticated_count(), 0);
        assert!(matches!(
            io.messages().last(),
            Some(ControlSessionAuthenticationMessage::Rejected)
        ));
        assert_eq!(
            io.written.last().expect("Rejected frame").request_id(),
            request_id
        );
    }

    #[test]
    fn proof_session_mismatch_aborts_pending_and_never_submits_proof() {
        let fixture = fixture();
        let mut io = FakeFrameIo::new(
            &fixture.signer,
            &fixture.binding,
            43,
            fixture.binding.device_id.clone(),
        );
        io.proof_mode = ProofMode::WrongSessionId;
        let mut sessions = SessionAuthenticationService::new();

        assert_eq!(
            execute_authentication_transaction(&mut io, &mut sessions, &fixture.registry),
            Err(PrwcConnectionAuthenticationError::SessionIdMismatch)
        );
        assert_eq!(sessions.pending_count(), 0);
        assert_eq!(sessions.authenticated_count(), 0);
        assert!(matches!(
            io.messages().last(),
            Some(ControlSessionAuthenticationMessage::Rejected)
        ));
    }

    #[test]
    fn challenge_write_failure_cleans_pending_state_before_connection_failure() {
        let fixture = fixture();
        let mut io = FakeFrameIo::new(
            &fixture.signer,
            &fixture.binding,
            44,
            fixture.binding.device_id.clone(),
        );
        io.fail_challenge_write = true;
        let mut sessions = SessionAuthenticationService::new();

        assert_eq!(
            execute_authentication_transaction(&mut io, &mut sessions, &fixture.registry),
            Err(PrwcConnectionAuthenticationError::Frame(
                ControlFrameError::WriteIo
            ))
        );
        assert_eq!(sessions.pending_count(), 0);
        assert_eq!(sessions.authenticated_count(), 0);
        assert!(matches!(
            io.messages().last(),
            Some(ControlSessionAuthenticationMessage::Rejected)
        ));
    }

    #[test]
    fn authenticated_write_failure_does_not_abort_completed_service_session() {
        let fixture = fixture();
        let mut io = FakeFrameIo::new(
            &fixture.signer,
            &fixture.binding,
            45,
            fixture.binding.device_id.clone(),
        );
        io.fail_authenticated_write = true;
        let mut sessions = SessionAuthenticationService::new();

        assert_eq!(
            execute_authentication_transaction(&mut io, &mut sessions, &fixture.registry),
            Err(PrwcConnectionAuthenticationError::Frame(
                ControlFrameError::WriteIo
            ))
        );
        assert_eq!(sessions.pending_count(), 0);
        assert_eq!(sessions.authenticated_count(), 1);
        assert!(
            !io.messages()
                .iter()
                .any(|message| matches!(message, ControlSessionAuthenticationMessage::Rejected))
        );
    }

    #[test]
    fn unknown_begin_device_is_rejected_before_pending_state_exists() {
        let fixture = fixture();
        let mut io = FakeFrameIo::new(
            &fixture.signer,
            &fixture.binding,
            46,
            DeviceId::new("unknown-device").expect("unknown device id"),
        );
        let mut sessions = SessionAuthenticationService::new();

        assert_eq!(
            execute_authentication_transaction(&mut io, &mut sessions, &fixture.registry),
            Err(PrwcConnectionAuthenticationError::DeviceBindingUnavailable)
        );
        assert_eq!(sessions.pending_count(), 0);
        assert_eq!(sessions.authenticated_count(), 0);
        assert_eq!(
            io.messages(),
            vec![ControlSessionAuthenticationMessage::Rejected]
        );
    }

    mod candidate_publication_receive_tests {
        use std::collections::VecDeque;

        use prw_connectivity::TransportIdentity;
        use prw_control_transport::{ControlFrame, ControlFrameError, ControlMessageKind};

        use crate::{
            candidate_publication_control_frame::{
                CandidatePublicationControlFrameError, encode_candidate_publication_control_frame,
            },
            candidate_publication_freshness::CandidatePublicationFreshnessToken,
            candidate_publication_wire::CandidatePublicationWireSubmission,
        };

        use super::super::{
            AuthenticatedPrwcCommandReceiveError, CandidatePublicationReceiveState,
            PrwcCandidatePublicationFrameIo, receive_candidate_publication_command_from_io,
        };

        struct FakeReceiveIo {
            frames: VecDeque<Result<ControlFrame, ControlFrameError>>,
            reads: usize,
        }

        impl FakeReceiveIo {
            fn new(
                frames: impl IntoIterator<Item = Result<ControlFrame, ControlFrameError>>,
            ) -> Self {
                Self {
                    frames: frames.into_iter().collect(),
                    reads: 0,
                }
            }
        }

        impl PrwcCandidatePublicationFrameIo for FakeReceiveIo {
            fn read_frame(&mut self) -> Result<ControlFrame, ControlFrameError> {
                self.reads += 1;
                self.frames
                    .pop_front()
                    .expect("receive test supplies one result per permitted read")
            }
        }

        fn submission() -> CandidatePublicationWireSubmission {
            CandidatePublicationWireSubmission::new(
                TransportIdentity::new([0x41; 32]).expect("non-zero transport identity"),
                CandidatePublicationFreshnessToken::new([0x42; 32])
                    .expect("non-zero freshness token"),
                Vec::new(),
            )
            .expect("empty candidate set remains bounded")
        }

        #[test]
        fn successful_receive_reads_exactly_one_frame_and_preserves_outer_request_id() {
            let frame = encode_candidate_publication_control_frame(&submission(), 71)
                .expect("valid candidate-publication Command");
            let mut io = FakeReceiveIo::new([Ok(frame)]);
            let mut state = CandidatePublicationReceiveState::Ready;

            let command = receive_candidate_publication_command_from_io(&mut io, &mut state)
                .expect("valid Command must decode");

            assert_eq!(command.request_id(), 71);
            assert_eq!(io.reads, 1);
            assert_eq!(state, CandidatePublicationReceiveState::Ready);
            assert!(io.frames.is_empty());
        }

        #[test]
        fn frame_failure_terminalizes_and_blocks_later_read() {
            let later = encode_candidate_publication_control_frame(&submission(), 72)
                .expect("valid later Command");
            let mut io = FakeReceiveIo::new([Err(ControlFrameError::ReadIo), Ok(later)]);
            let mut state = CandidatePublicationReceiveState::Ready;

            assert_eq!(
                receive_candidate_publication_command_from_io(&mut io, &mut state),
                Err(AuthenticatedPrwcCommandReceiveError::Frame(
                    ControlFrameError::ReadIo
                ))
            );
            assert_eq!(state, CandidatePublicationReceiveState::Terminal);
            assert_eq!(io.reads, 1);
            assert_eq!(io.frames.len(), 1);

            assert_eq!(
                receive_candidate_publication_command_from_io(&mut io, &mut state),
                Err(AuthenticatedPrwcCommandReceiveError::Terminal)
            );
            assert_eq!(io.reads, 1);
            assert_eq!(io.frames.len(), 1);
        }

        #[test]
        fn command_decode_failure_terminalizes_and_blocks_later_read() {
            let wrong_kind =
                ControlFrame::new(ControlMessageKind::Event, 73, submission().encode())
                    .expect("generic Event frame is structurally valid");
            let later = encode_candidate_publication_control_frame(&submission(), 74)
                .expect("valid later Command");
            let mut io = FakeReceiveIo::new([Ok(wrong_kind), Ok(later)]);
            let mut state = CandidatePublicationReceiveState::Ready;

            assert_eq!(
                receive_candidate_publication_command_from_io(&mut io, &mut state),
                Err(AuthenticatedPrwcCommandReceiveError::Command(
                    CandidatePublicationControlFrameError::WrongMessageKind
                ))
            );
            assert_eq!(state, CandidatePublicationReceiveState::Terminal);
            assert_eq!(io.reads, 1);
            assert_eq!(io.frames.len(), 1);

            assert_eq!(
                receive_candidate_publication_command_from_io(&mut io, &mut state),
                Err(AuthenticatedPrwcCommandReceiveError::Terminal)
            );
            assert_eq!(io.reads, 1);
            assert_eq!(io.frames.len(), 1);
        }
    }

    mod candidate_publication_result_write_tests {
        use std::cell::Cell;

        use prw_connectivity::TransportIdentity;
        use prw_control_transport::{ControlFrame, ControlFrameError, ControlMessageKind};

        use crate::{
            candidate_publication_control_frame::{
                CandidatePublicationControlFrame, decode_candidate_publication_control_frame,
                encode_candidate_publication_control_frame,
            },
            candidate_publication_execution::CandidatePublicationExecutionError,
            candidate_publication_freshness::CandidatePublicationFreshnessToken,
            candidate_publication_result_wire::{
                CandidatePublicationResultMessage, CandidatePublicationResultWireError,
                decode_candidate_publication_result_frame,
                encode_candidate_publication_execution_result_frame,
            },
            candidate_publication_wire::CandidatePublicationWireSubmission,
            reachability_owner::ReachabilityCommitOutcome,
        };

        use super::super::{
            AuthenticatedPrwcCandidatePublicationResultWriteError,
            AuthenticatedPrwcCommandReceiveError, AuthenticatedPrwcConnection,
            CandidatePublicationReceiveState, PrwcCandidatePublicationFrameIo,
            PrwcCandidatePublicationResultFrameIo, receive_candidate_publication_command_from_io,
            write_candidate_publication_result_to_io,
        };

        #[derive(Default)]
        struct FakeWriteIo {
            written: Vec<ControlFrame>,
            writes: usize,
            fail_write: bool,
        }

        impl PrwcCandidatePublicationResultFrameIo for FakeWriteIo {
            fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), ControlFrameError> {
                self.writes += 1;
                if self.fail_write {
                    return Err(ControlFrameError::WriteIo);
                }
                self.written.push(frame.clone());
                Ok(())
            }
        }

        #[derive(Default)]
        struct CountingReadIo {
            reads: usize,
        }

        impl PrwcCandidatePublicationFrameIo for CountingReadIo {
            fn read_frame(&mut self) -> Result<ControlFrame, ControlFrameError> {
                self.reads += 1;
                Err(ControlFrameError::ReadIo)
            }
        }

        fn submission() -> CandidatePublicationWireSubmission {
            CandidatePublicationWireSubmission::new(
                TransportIdentity::new([0x51; 32]).expect("non-zero CX transport identity"),
                CandidatePublicationFreshnessToken::new([0x52; 32]).expect("non-zero CX freshness"),
                Vec::new(),
            )
            .expect("empty CX candidate set remains bounded")
        }

        fn command(request_id: u64) -> CandidatePublicationControlFrame {
            let frame = encode_candidate_publication_control_frame(&submission(), request_id)
                .expect("encode CX candidate-publication Command");
            decode_candidate_publication_control_frame(&frame)
                .expect("decode CX candidate-publication Command")
        }

        #[test]
        fn successful_result_write_writes_exactly_once_and_preserves_command_request_id() {
            let command = command(81);
            let mut io = FakeWriteIo::default();
            let mut state = CandidatePublicationReceiveState::Ready;

            write_candidate_publication_result_to_io(&mut io, &mut state, || {
                encode_candidate_publication_execution_result_frame(
                    &command,
                    Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch),
                )
            })
            .expect("generic rejection result must write");

            assert_eq!(io.writes, 1);
            assert_eq!(io.written.len(), 1);
            assert_eq!(io.written[0].request_id(), 81);
            assert_eq!(io.written[0].kind(), ControlMessageKind::Error);
            assert_eq!(
                decode_candidate_publication_result_frame(&io.written[0]),
                Ok(CandidatePublicationResultMessage::Rejected)
            );
            assert_eq!(state, CandidatePublicationReceiveState::Ready);
        }

        #[test]
        fn terminal_state_blocks_composition_and_write_before_io() {
            let mut io = FakeWriteIo::default();
            let mut state = CandidatePublicationReceiveState::Terminal;
            let compositions = Cell::new(0);

            assert_eq!(
                write_candidate_publication_result_to_io(&mut io, &mut state, || {
                    compositions.set(compositions.get() + 1);
                    ControlFrame::new(ControlMessageKind::Error, 82, Vec::new())
                        .map_err(CandidatePublicationResultWireError::Frame)
                }),
                Err(AuthenticatedPrwcCandidatePublicationResultWriteError::Terminal)
            );
            assert_eq!(compositions.get(), 0);
            assert_eq!(io.writes, 0);
            assert_eq!(state, CandidatePublicationReceiveState::Terminal);
        }

        #[test]
        fn pure_composition_failure_performs_zero_writes_and_leaves_state_ready() {
            let mut io = FakeWriteIo::default();
            let mut state = CandidatePublicationReceiveState::Ready;

            assert_eq!(
                write_candidate_publication_result_to_io(&mut io, &mut state, || {
                    Err(CandidatePublicationResultWireError::Frame(
                        ControlFrameError::ZeroRequestId,
                    ))
                }),
                Err(
                    AuthenticatedPrwcCandidatePublicationResultWriteError::Composition(
                        CandidatePublicationResultWireError::Frame(
                            ControlFrameError::ZeroRequestId
                        )
                    )
                )
            );
            assert_eq!(io.writes, 0);
            assert!(io.written.is_empty());
            assert_eq!(state, CandidatePublicationReceiveState::Ready);
        }

        #[test]
        fn write_failure_terminalizes_and_blocks_later_write_before_composition() {
            let command = command(83);
            let mut io = FakeWriteIo {
                fail_write: true,
                ..FakeWriteIo::default()
            };
            let mut state = CandidatePublicationReceiveState::Ready;
            let compositions = Cell::new(0);

            assert_eq!(
                write_candidate_publication_result_to_io(&mut io, &mut state, || {
                    compositions.set(compositions.get() + 1);
                    encode_candidate_publication_execution_result_frame(
                        &command,
                        Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch),
                    )
                }),
                Err(
                    AuthenticatedPrwcCandidatePublicationResultWriteError::Frame(
                        ControlFrameError::WriteIo
                    )
                )
            );
            assert_eq!(compositions.get(), 1);
            assert_eq!(io.writes, 1);
            assert_eq!(state, CandidatePublicationReceiveState::Terminal);

            io.fail_write = false;
            assert_eq!(
                write_candidate_publication_result_to_io(&mut io, &mut state, || {
                    compositions.set(compositions.get() + 1);
                    encode_candidate_publication_execution_result_frame(
                        &command,
                        Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch),
                    )
                }),
                Err(AuthenticatedPrwcCandidatePublicationResultWriteError::Terminal)
            );
            assert_eq!(compositions.get(), 1);
            assert_eq!(io.writes, 1);
        }

        #[test]
        fn write_failure_terminal_state_blocks_later_receive_before_read_io() {
            let command = command(84);
            let mut write_io = FakeWriteIo {
                fail_write: true,
                ..FakeWriteIo::default()
            };
            let mut state = CandidatePublicationReceiveState::Ready;

            assert_eq!(
                write_candidate_publication_result_to_io(&mut write_io, &mut state, || {
                    encode_candidate_publication_execution_result_frame(
                        &command,
                        Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch),
                    )
                }),
                Err(
                    AuthenticatedPrwcCandidatePublicationResultWriteError::Frame(
                        ControlFrameError::WriteIo
                    )
                )
            );

            let mut read_io = CountingReadIo::default();
            assert_eq!(
                receive_candidate_publication_command_from_io(&mut read_io, &mut state),
                Err(AuthenticatedPrwcCommandReceiveError::Terminal)
            );
            assert_eq!(read_io.reads, 0);
        }

        #[test]
        fn public_write_signature_accepts_only_an_already_completed_semantic_result() {
            type CandidatePublicationResultWriteFn =
                fn(
                    &mut AuthenticatedPrwcConnection,
                    &CandidatePublicationControlFrame,
                    Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError>,
                )
                    -> Result<(), AuthenticatedPrwcCandidatePublicationResultWriteError>;

            let function: CandidatePublicationResultWriteFn =
                AuthenticatedPrwcConnection::write_candidate_publication_result;
            let _ = function;
        }
    }
}
