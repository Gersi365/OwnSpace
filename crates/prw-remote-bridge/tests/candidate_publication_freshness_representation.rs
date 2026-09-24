//! Phase 152 C02e Tranche 3 executable checks for the selected freshness representation.
//!
//! These tests exercise only provider-neutral value/lifecycle semantics. They perform no network
//! I/O and do not select a production persistence backend, wire codec, or upper composition owner.

#[path = "../src/candidate_publication_freshness.rs"]
mod candidate_publication_freshness;

use candidate_publication_freshness::{
    CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES, CandidatePublicationFreshnessLifecycle,
    CandidatePublicationFreshnessRecord, CandidatePublicationFreshnessRepresentationError,
    CandidatePublicationFreshnessToken,
};
use prw_connectivity::{PeerConnectivityIdentity, TransportIdentity};
use prw_core::DeviceId;

fn peer(device: &str, transport_seed: u8) -> PeerConnectivityIdentity {
    PeerConnectivityIdentity::new(
        DeviceId::new(device).expect("device id"),
        TransportIdentity::new([transport_seed; 32]).expect("transport identity"),
    )
}

fn token(seed: u8) -> CandidatePublicationFreshnessToken {
    CandidatePublicationFreshnessToken::new([seed; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES])
        .expect("non-zero verifier token")
}

#[test]
fn freshness_token_is_exactly_32_opaque_non_zero_bytes() {
    assert_eq!(CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES, 32);
    assert_eq!(
        CandidatePublicationFreshnessToken::new([0; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES]),
        Err(CandidatePublicationFreshnessRepresentationError::InvalidAllZeroToken)
    );

    let selected = token(7);
    assert_eq!(selected.as_bytes(), &[7; 32]);
    assert_eq!(
        CandidatePublicationFreshnessRepresentationError::InvalidAllZeroToken.to_string(),
        "candidate publication freshness token must not be all zero"
    );
}

#[test]
fn durable_lifecycle_states_do_not_alias_missing_recovery_or_retired_state() {
    let target = peer("target-freshness-representation", 1);
    let bootstrap = token(2);
    let established = token(3);

    let new_record =
        CandidatePublicationFreshnessRecord::new_lifecycle_eligible(target.clone(), bootstrap);
    let established_record =
        CandidatePublicationFreshnessRecord::established(target.clone(), established);
    let recovery_record = CandidatePublicationFreshnessRecord::recovery_required(target.clone());
    let retired_record = CandidatePublicationFreshnessRecord::retired(target.clone());

    assert_eq!(new_record.peer(), &target);
    assert_eq!(established_record.peer(), &target);
    assert_eq!(recovery_record.peer(), &target);
    assert_eq!(retired_record.peer(), &target);

    assert_eq!(
        new_record.lifecycle(),
        CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(bootstrap)
    );
    assert_eq!(
        established_record.lifecycle(),
        CandidatePublicationFreshnessLifecycle::Established(established)
    );
    assert_eq!(
        recovery_record.lifecycle(),
        CandidatePublicationFreshnessLifecycle::RecoveryRequired
    );
    assert_eq!(
        retired_record.lifecycle(),
        CandidatePublicationFreshnessLifecycle::Retired
    );

    assert_eq!(new_record.lifecycle().current_token(), Some(bootstrap));
    assert_eq!(
        established_record.lifecycle().current_token(),
        Some(established)
    );
    assert_eq!(recovery_record.lifecycle().current_token(), None);
    assert_eq!(retired_record.lifecycle().current_token(), None);
}

#[test]
fn same_transport_bytes_for_another_device_are_a_distinct_peer_scope() {
    let first = peer("target-one-freshness-representation", 9);
    let second = peer("target-two-freshness-representation", 9);
    let first_record = CandidatePublicationFreshnessRecord::established(first.clone(), token(4));
    let second_record = CandidatePublicationFreshnessRecord::established(second.clone(), token(5));

    assert_ne!(first_record.peer(), second_record.peer());
    assert_eq!(first_record.peer(), &first);
    assert_eq!(second_record.peer(), &second);
}

#[test]
fn retired_exact_peer_identity_remains_distinct_from_new_lifecycle_eligibility() {
    let historical_peer = peer("target-retired-freshness-representation", 12);
    let retired = CandidatePublicationFreshnessRecord::retired(historical_peer.clone());
    let hypothetical_new =
        CandidatePublicationFreshnessRecord::new_lifecycle_eligible(historical_peer, token(13));

    assert_ne!(retired.lifecycle(), hypothetical_new.lifecycle());
    assert_eq!(retired.lifecycle().current_token(), None);
    assert!(matches!(
        hypothetical_new.lifecycle(),
        CandidatePublicationFreshnessLifecycle::NewLifecycleEligible(_)
    ));
}
