//! Provider-neutral candidate-publication semantic execution composition.
//!
//! C03e-CQ materializes only the C03e-CP-selected bounded composition from one already-authenticated
//! PRWC connection and one already-received candidate-publication Command into the existing
//! requester/rendezvous authority port and production reachability owner. It performs no frame I/O,
//! request-ID allocation, response encoding, retry/loop/task creation, concrete rendezvous-provider
//! selection, listener/runtime activation, networking mutation, deployment, or merge behavior.

use std::{fmt, future::Future};

use prw_registry::WorkspaceDeviceRegistry;
use prw_session::AuthenticatedDeviceSession;

use crate::{
    candidate_publication_control_frame::CandidatePublicationControlFrame,
    candidate_publication_freshness::CandidatePublicationFreshnessToken,
    candidate_reachability::{
        AuthenticatedCandidatePublication, CandidateReachabilityError, publish_current_candidates,
    },
    prwc_connection_authentication::AuthenticatedPrwcConnection,
    reachability_owner::{
        CandidatePublicationFreshnessTokenSource, ProductionReachabilityOwner,
        ReachabilityCommitOutcome, ReachabilityDurableStore, ReachabilityOwnerError,
    },
    requester_rendezvous_authority::{
        RequesterRendezvousAuthorityError, RequesterRendezvousAuthorityProvider,
    },
};

/// Stable fail-closed error surface for one candidate-publication execution attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidatePublicationExecutionError {
    /// Authenticated publisher/session/transport/candidate construction failed.
    Candidate(CandidateReachabilityError),
    /// Current requester/rendezvous authority could not be established.
    RequesterAuthority(RequesterRendezvousAuthorityError),
    /// The one-shot authority grant selected a different publisher device.
    ExpectedPublisherMismatch,
    /// Existing production reachability ownership rejected or failed the durable commit.
    Reachability(ReachabilityOwnerError),
}

impl fmt::Display for CandidatePublicationExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Candidate(error) => {
                write!(
                    formatter,
                    "candidate publication construction failed: {error}"
                )
            }
            Self::RequesterAuthority(error) => {
                write!(
                    formatter,
                    "requester rendezvous authorization failed: {error}"
                )
            }
            Self::ExpectedPublisherMismatch => formatter.write_str(
                "requester rendezvous authority selected a different candidate publisher",
            ),
            Self::Reachability(error) => {
                write!(
                    formatter,
                    "candidate publication reachability commit failed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for CandidatePublicationExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Candidate(error) => Some(error),
            Self::RequesterAuthority(error) => Some(error),
            Self::Reachability(error) => Some(error),
            Self::ExpectedPublisherMismatch => None,
        }
    }
}

/// Executes one already-received candidate-publication Command through existing authorities.
///
/// The publisher logical identity is obtained only from `connection.session()`. The outer PRWC
/// request ID remains untouched correlation state in `command`; this function never reads it.
/// Ordering is fixed: current publisher/transport publication construction -> exactly one current
/// requester/rendezvous authorization -> exact expected-publisher equality -> existing durable
/// reachability-owner commit.
///
/// This function reads no frame, writes no frame, retries nothing, allocates no request ID and
/// selects no concrete requester/rendezvous provider. The caller owns polling of the durable
/// operation; this composition owns no async runtime or background task.
///
/// # Errors
///
/// Returns [`CandidatePublicationExecutionError`] on publisher/transport/candidate construction,
/// requester/rendezvous authorization, expected-publisher mismatch, or existing reachability-owner
/// commit failure. No later stage runs after an earlier failure.
pub async fn execute_authenticated_candidate_publication<S, T, P>(
    connection: &AuthenticatedPrwcConnection,
    command: &CandidatePublicationControlFrame,
    registry: &WorkspaceDeviceRegistry,
    requester_authority: &mut P,
    owner: &mut ProductionReachabilityOwner<S, T>,
) -> Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError>
where
    S: ReachabilityDurableStore,
    T: CandidatePublicationFreshnessTokenSource,
    P: RequesterRendezvousAuthorityProvider,
{
    execute_candidate_publication_for_session(
        connection.session(),
        command,
        registry,
        requester_authority,
        owner,
    )
    .await
}

trait CandidatePublicationCommit {
    fn commit_candidate_publication<'a>(
        &'a mut self,
        registry: &'a WorkspaceDeviceRegistry,
        requester_session: &'a AuthenticatedDeviceSession,
        publication: &'a AuthenticatedCandidatePublication,
        presented_freshness: CandidatePublicationFreshnessToken,
    ) -> impl Future<Output = Result<ReachabilityCommitOutcome, ReachabilityOwnerError>> + 'a;
}

impl<S, T> CandidatePublicationCommit for ProductionReachabilityOwner<S, T>
where
    S: ReachabilityDurableStore,
    T: CandidatePublicationFreshnessTokenSource,
{
    fn commit_candidate_publication<'a>(
        &'a mut self,
        registry: &'a WorkspaceDeviceRegistry,
        requester_session: &'a AuthenticatedDeviceSession,
        publication: &'a AuthenticatedCandidatePublication,
        presented_freshness: CandidatePublicationFreshnessToken,
    ) -> impl Future<Output = Result<ReachabilityCommitOutcome, ReachabilityOwnerError>> + 'a {
        Self::commit_candidate_publication(
            self,
            registry,
            requester_session,
            publication,
            presented_freshness,
        )
    }
}

async fn execute_candidate_publication_for_session<P, C>(
    publisher_session: &AuthenticatedDeviceSession,
    command: &CandidatePublicationControlFrame,
    registry: &WorkspaceDeviceRegistry,
    requester_authority: &mut P,
    owner: &mut C,
) -> Result<ReachabilityCommitOutcome, CandidatePublicationExecutionError>
where
    P: RequesterRendezvousAuthorityProvider,
    C: CandidatePublicationCommit,
{
    let submission = command.submission();
    let publication = publish_current_candidates(
        registry,
        publisher_session,
        submission.presented_transport_identity(),
        submission.candidates().to_vec(),
    )
    .map_err(CandidatePublicationExecutionError::Candidate)?;

    let publisher_device_id = publication.peer().device_id();
    let grant = requester_authority
        .authorize_current_for_publisher(publisher_device_id)
        .map_err(CandidatePublicationExecutionError::RequesterAuthority)?;
    if grant.expected_publisher_device_id() != publisher_device_id {
        return Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch);
    }

    owner
        .commit_candidate_publication(
            registry,
            grant.requester_session(),
            &publication,
            submission.presented_freshness(),
        )
        .await
        .map_err(CandidatePublicationExecutionError::Reachability)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        future::{Future, ready},
        rc::Rc,
        task::{Context, Poll, Waker},
    };

    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
    };
    use prw_connectivity::TransportIdentity;
    use prw_control_plane::DeviceIdentityBinding;
    use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
    use prw_device_identity_signer::UbuntuEnrollmentSigner;
    use prw_registry::{RegistryError, WorkspaceDeviceRegistry, WorkspaceRole};
    use prw_session::{AuthenticatedDeviceSession, SessionAuthenticationService};

    use crate::{
        candidate_publication_control_frame::{
            CandidatePublicationControlFrame, decode_candidate_publication_control_frame,
            encode_candidate_publication_control_frame,
        },
        candidate_publication_freshness::CandidatePublicationFreshnessToken,
        candidate_publication_wire::CandidatePublicationWireSubmission,
        candidate_reachability::{AuthenticatedCandidatePublication, CandidateReachabilityError},
        reachability_owner::{ReachabilityCommitOutcome, ReachabilityOwnerError},
        requester_rendezvous_authority::{
            AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError,
            RequesterRendezvousAuthorityProvider,
        },
    };

    use super::{
        CandidatePublicationCommit, CandidatePublicationExecutionError,
        execute_candidate_publication_for_session,
    };

    fn resolve_ready<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    struct Fixture {
        registry: WorkspaceDeviceRegistry,
        publisher_session: AuthenticatedDeviceSession,
        publisher_device_id: DeviceId,
        transport_identity: TransportIdentity,
        freshness: CandidatePublicationFreshnessToken,
    }

    fn signer() -> UbuntuEnrollmentSigner {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable CQ device key");
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
            .expect("load disposable CQ signer")
    }

    fn authenticate(
        signer: &UbuntuEnrollmentSigner,
        binding: &DeviceIdentityBinding,
        session_name: &str,
    ) -> AuthenticatedDeviceSession {
        let mut service = SessionAuthenticationService::new();
        let session_id = SessionId::new(session_name).expect("valid session id");
        let challenge = service
            .begin_session(binding.clone(), session_id.clone(), 1_000, 1_300)
            .expect("begin disposable session");
        let proof = signer
            .sign_session_auth_proof(binding, &challenge)
            .expect("sign disposable session proof");
        service
            .submit_proof(&session_id, &proof, 1_001)
            .expect("authenticate disposable session")
    }

    fn fixture() -> Fixture {
        let signer = signer();
        let workspace_id = WorkspaceId::new("workspace-cq").expect("workspace id");
        let user_id = UserId::new("publisher-user-cq").expect("user id");
        let publisher_device_id = DeviceId::new("publisher-device-cq").expect("device id");
        let binding = DeviceIdentityBinding {
            workspace_id: workspace_id.clone(),
            user_id: user_id.clone(),
            device_id: publisher_device_id.clone(),
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };
        let transport_identity =
            TransportIdentity::new([0x41; 32]).expect("non-zero transport identity");
        let freshness =
            CandidatePublicationFreshnessToken::new([0x51; 32]).expect("non-zero freshness");
        let mut registry = WorkspaceDeviceRegistry::new();
        registry
            .add_membership(workspace_id, user_id, WorkspaceRole::Member)
            .expect("add publisher membership");
        registry
            .register_device(binding.clone())
            .expect("register publisher device");
        registry
            .bind_transport_identity(&publisher_device_id, transport_identity)
            .expect("bind publisher transport identity");
        let publisher_session = authenticate(&signer, &binding, "publisher-session-cq");

        Fixture {
            registry,
            publisher_session,
            publisher_device_id,
            transport_identity,
            freshness,
        }
    }

    fn command(
        transport_identity: TransportIdentity,
        freshness: CandidatePublicationFreshnessToken,
        request_id: u64,
    ) -> CandidatePublicationControlFrame {
        let submission =
            CandidatePublicationWireSubmission::new(transport_identity, freshness, Vec::new())
                .expect("empty bounded candidate set");
        let frame = encode_candidate_publication_control_frame(&submission, request_id)
            .expect("encode candidate-publication command");
        decode_candidate_publication_control_frame(&frame)
            .expect("decode candidate-publication command")
    }

    struct FakeAuthorityProvider {
        calls: usize,
        selected_publishers: Vec<DeviceId>,
        order: Rc<RefCell<Vec<&'static str>>>,
        result: Option<Result<AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError>>,
    }

    impl RequesterRendezvousAuthorityProvider for FakeAuthorityProvider {
        fn authorize_current_for_publisher(
            &mut self,
            publisher_device_id: &DeviceId,
        ) -> Result<AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError> {
            self.calls += 1;
            self.selected_publishers.push(publisher_device_id.clone());
            self.order.borrow_mut().push("authority");
            self.result.take().expect("one-shot provider result")
        }
    }

    struct FakeCommit {
        calls: usize,
        order: Rc<RefCell<Vec<&'static str>>>,
        observed_publisher: Option<DeviceId>,
        observed_freshness: Option<CandidatePublicationFreshnessToken>,
        error: ReachabilityOwnerError,
    }

    impl CandidatePublicationCommit for FakeCommit {
        fn commit_candidate_publication<'a>(
            &'a mut self,
            _registry: &'a WorkspaceDeviceRegistry,
            _requester_session: &'a AuthenticatedDeviceSession,
            publication: &'a AuthenticatedCandidatePublication,
            presented_freshness: CandidatePublicationFreshnessToken,
        ) -> impl Future<Output = Result<ReachabilityCommitOutcome, ReachabilityOwnerError>> + 'a
        {
            self.calls += 1;
            self.order.borrow_mut().push("commit");
            self.observed_publisher = Some(publication.peer().device_id().clone());
            self.observed_freshness = Some(presented_freshness);
            ready(Err(self.error))
        }
    }

    fn fake_commit(order: Rc<RefCell<Vec<&'static str>>>) -> FakeCommit {
        FakeCommit {
            calls: 0,
            order,
            observed_publisher: None,
            observed_freshness: None,
            error: ReachabilityOwnerError::RecoveryRequired,
        }
    }

    #[test]
    fn publisher_admission_failure_prevents_authority_and_commit() {
        let fixture = fixture();
        let command = command(fixture.transport_identity, fixture.freshness, 11);
        let order = Rc::new(RefCell::new(Vec::new()));
        let mut authority = FakeAuthorityProvider {
            calls: 0,
            selected_publishers: Vec::new(),
            order: Rc::clone(&order),
            result: Some(Err(RequesterRendezvousAuthorityError::Missing)),
        };
        let mut commit = fake_commit(Rc::clone(&order));
        let empty_registry = WorkspaceDeviceRegistry::new();

        assert_eq!(
            resolve_ready(execute_candidate_publication_for_session(
                &fixture.publisher_session,
                &command,
                &empty_registry,
                &mut authority,
                &mut commit,
            )),
            Err(CandidatePublicationExecutionError::Candidate(
                CandidateReachabilityError::Registry(RegistryError::MembershipUnknown)
            ))
        );
        assert_eq!(authority.calls, 0);
        assert_eq!(commit.calls, 0);
        assert!(order.borrow().is_empty());
    }

    #[test]
    fn authority_failure_is_preserved_and_prevents_commit() {
        let fixture = fixture();
        let command = command(fixture.transport_identity, fixture.freshness, 13);
        let order = Rc::new(RefCell::new(Vec::new()));
        let mut authority = FakeAuthorityProvider {
            calls: 0,
            selected_publishers: Vec::new(),
            order: Rc::clone(&order),
            result: Some(Err(RequesterRendezvousAuthorityError::Ambiguous)),
        };
        let mut commit = fake_commit(Rc::clone(&order));

        assert_eq!(
            resolve_ready(execute_candidate_publication_for_session(
                &fixture.publisher_session,
                &command,
                &fixture.registry,
                &mut authority,
                &mut commit,
            )),
            Err(CandidatePublicationExecutionError::RequesterAuthority(
                RequesterRendezvousAuthorityError::Ambiguous
            ))
        );
        assert_eq!(authority.calls, 1);
        assert_eq!(
            authority.selected_publishers.as_slice(),
            &[fixture.publisher_device_id]
        );
        assert_eq!(commit.calls, 0);
        assert_eq!(order.borrow().as_slice(), &["authority"]);
    }

    #[test]
    fn expected_publisher_mismatch_is_fail_closed_before_commit() {
        let fixture = fixture();
        let command = command(fixture.transport_identity, fixture.freshness, 17);
        let order = Rc::new(RefCell::new(Vec::new()));
        let wrong_publisher = DeviceId::new("different-publisher-cq").expect("device id");
        let grant = AuthorizedRequesterRendezvous::from_authority(
            fixture.publisher_session.clone(),
            wrong_publisher,
        );
        let mut authority = FakeAuthorityProvider {
            calls: 0,
            selected_publishers: Vec::new(),
            order: Rc::clone(&order),
            result: Some(Ok(grant)),
        };
        let mut commit = fake_commit(Rc::clone(&order));

        assert_eq!(
            resolve_ready(execute_candidate_publication_for_session(
                &fixture.publisher_session,
                &command,
                &fixture.registry,
                &mut authority,
                &mut commit,
            )),
            Err(CandidatePublicationExecutionError::ExpectedPublisherMismatch)
        );
        assert_eq!(authority.calls, 1);
        assert_eq!(commit.calls, 0);
        assert_eq!(order.borrow().as_slice(), &["authority"]);
    }

    #[test]
    fn authority_precedes_exactly_one_commit_and_preserves_semantic_inputs() {
        let fixture = fixture();
        let command = command(fixture.transport_identity, fixture.freshness, 19);
        let order = Rc::new(RefCell::new(Vec::new()));
        let grant = AuthorizedRequesterRendezvous::from_authority(
            fixture.publisher_session.clone(),
            fixture.publisher_device_id.clone(),
        );
        let mut authority = FakeAuthorityProvider {
            calls: 0,
            selected_publishers: Vec::new(),
            order: Rc::clone(&order),
            result: Some(Ok(grant)),
        };
        let mut commit = fake_commit(Rc::clone(&order));

        assert_eq!(
            resolve_ready(execute_candidate_publication_for_session(
                &fixture.publisher_session,
                &command,
                &fixture.registry,
                &mut authority,
                &mut commit,
            )),
            Err(CandidatePublicationExecutionError::Reachability(
                ReachabilityOwnerError::RecoveryRequired
            ))
        );
        assert_eq!(authority.calls, 1);
        assert_eq!(
            authority.selected_publishers.as_slice(),
            std::slice::from_ref(&fixture.publisher_device_id)
        );
        assert_eq!(commit.calls, 1);
        assert_eq!(commit.observed_publisher, Some(fixture.publisher_device_id));
        assert_eq!(commit.observed_freshness, Some(fixture.freshness));
        assert_eq!(order.borrow().as_slice(), &["authority", "commit"]);
    }

    #[test]
    fn nested_execution_errors_preserve_sources_but_mismatch_has_none() {
        use std::error::Error;

        let authority = CandidatePublicationExecutionError::RequesterAuthority(
            RequesterRendezvousAuthorityError::UnavailableOrIndeterminate,
        );
        let reachability = CandidatePublicationExecutionError::Reachability(
            ReachabilityOwnerError::RecoveryRequired,
        );
        let mismatch = CandidatePublicationExecutionError::ExpectedPublisherMismatch;

        assert!(authority.source().is_some());
        assert!(reachability.source().is_some());
        assert!(mismatch.source().is_none());
    }
}
