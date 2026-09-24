//! Bounded process-local requester/rendezvous authority provider for candidate publication.
//!
//! C03e-CT materializes only the C03e-CS-selected in-memory provider representation. It does not
//! select a runtime owner, persistence, clock/TTL policy, synchronization primitive, PRWC response
//! mapping, frame loop, listener, production networking, deployment, or merge behavior.

use std::fmt;

use prw_core::{DeviceId, SessionId};
use prw_session::AuthenticatedDeviceSession;

use crate::requester_rendezvous_authority::{
    AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError,
    RequesterRendezvousAuthorityProvider,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequesterRendezvousRecordLifecycle {
    Current,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequesterRendezvousRecord {
    requester_session: AuthenticatedDeviceSession,
    expected_publisher_device_id: DeviceId,
    lifecycle: RequesterRendezvousRecordLifecycle,
}

/// Stable lifecycle-mutation failure for the bounded in-memory requester/rendezvous provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousLifecycleError {
    /// Provider construction requested zero record capacity.
    InvalidCapacity,
    /// Registration would exceed the configured finite record capacity.
    CapacityExhausted,
    /// The exact requester-session/publisher record identity already exists.
    RecordAlreadyExists,
    /// The exact requester-session/publisher record identity does not exist.
    RecordUnknown,
    /// The exact authority record is already retired.
    RecordAlreadyRetired,
    /// Retired-record removal was requested while the exact record is still current.
    CurrentRecordCannotBeRemoved,
}

impl fmt::Display for RequesterRendezvousLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCapacity => "requester rendezvous provider capacity must be non-zero",
            Self::CapacityExhausted => "requester rendezvous provider capacity is exhausted",
            Self::RecordAlreadyExists => "requester rendezvous authority record already exists",
            Self::RecordUnknown => "requester rendezvous authority record is unknown",
            Self::RecordAlreadyRetired => {
                "requester rendezvous authority record is already retired"
            }
            Self::CurrentRecordCannotBeRemoved => {
                "current requester rendezvous authority record cannot be removed as retired"
            }
        })
    }
}

impl std::error::Error for RequesterRendezvousLifecycleError {}

/// Caller-owned bounded process-local requester/rendezvous authority provider.
///
/// Records are intentionally non-durable and retain no clock, TTL, synchronization primitive,
/// transport identity, candidate-publication payload, request ID, or runtime handle. Record order
/// has no authority meaning.
#[derive(Debug)]
pub struct InMemoryRequesterRendezvousAuthorityProvider {
    max_records: usize,
    records: Vec<RequesterRendezvousRecord>,
}

impl InMemoryRequesterRendezvousAuthorityProvider {
    /// Creates an empty provider with one explicit finite non-zero record bound.
    ///
    /// # Errors
    ///
    /// Returns [`RequesterRendezvousLifecycleError::InvalidCapacity`] when `max_records` is zero.
    pub const fn new(max_records: usize) -> Result<Self, RequesterRendezvousLifecycleError> {
        if max_records == 0 {
            return Err(RequesterRendezvousLifecycleError::InvalidCapacity);
        }
        Ok(Self {
            max_records,
            records: Vec::new(),
        })
    }

    /// Registers one exact current requester/rendezvous authority record.
    ///
    /// The authenticated requester session is retained as server-owned lifecycle authority. This
    /// operation does not authenticate raw identity material and does not grant publication
    /// authority by itself.
    ///
    /// # Errors
    ///
    /// Rejects an exact existing requester-session/publisher identity or capacity exhaustion before
    /// insertion.
    pub fn register_current(
        &mut self,
        requester_session: AuthenticatedDeviceSession,
        expected_publisher_device_id: DeviceId,
    ) -> Result<(), RequesterRendezvousLifecycleError> {
        if self
            .record_index(
                requester_session.session_id(),
                &expected_publisher_device_id,
            )
            .is_some()
        {
            return Err(RequesterRendezvousLifecycleError::RecordAlreadyExists);
        }
        if self.records.len() >= self.max_records {
            return Err(RequesterRendezvousLifecycleError::CapacityExhausted);
        }

        self.records.push(RequesterRendezvousRecord {
            requester_session,
            expected_publisher_device_id,
            lifecycle: RequesterRendezvousRecordLifecycle::Current,
        });
        Ok(())
    }

    /// Explicitly retires one exact current authority record.
    ///
    /// # Errors
    ///
    /// Returns `RecordUnknown` when the exact identity is absent and `RecordAlreadyRetired` when it
    /// has already been retired.
    pub fn retire(
        &mut self,
        requester_session_id: &SessionId,
        expected_publisher_device_id: &DeviceId,
    ) -> Result<(), RequesterRendezvousLifecycleError> {
        let index = self
            .record_index(requester_session_id, expected_publisher_device_id)
            .ok_or(RequesterRendezvousLifecycleError::RecordUnknown)?;
        let record = &mut self.records[index];
        if record.lifecycle == RequesterRendezvousRecordLifecycle::Retired {
            return Err(RequesterRendezvousLifecycleError::RecordAlreadyRetired);
        }
        record.lifecycle = RequesterRendezvousRecordLifecycle::Retired;
        Ok(())
    }

    /// Removes one exact already-retired authority record and frees one capacity slot.
    ///
    /// Removal is caller-driven and synchronous. No timer, cleanup task, or implicit retirement is
    /// performed.
    ///
    /// # Errors
    ///
    /// Returns `RecordUnknown` when the exact identity is absent and
    /// `CurrentRecordCannotBeRemoved` while it remains current.
    pub fn remove_retired(
        &mut self,
        requester_session_id: &SessionId,
        expected_publisher_device_id: &DeviceId,
    ) -> Result<(), RequesterRendezvousLifecycleError> {
        let index = self
            .record_index(requester_session_id, expected_publisher_device_id)
            .ok_or(RequesterRendezvousLifecycleError::RecordUnknown)?;
        if self.records[index].lifecycle == RequesterRendezvousRecordLifecycle::Current {
            return Err(RequesterRendezvousLifecycleError::CurrentRecordCannotBeRemoved);
        }
        self.records.remove(index);
        Ok(())
    }

    fn record_index(
        &self,
        requester_session_id: &SessionId,
        expected_publisher_device_id: &DeviceId,
    ) -> Option<usize> {
        self.records.iter().position(|record| {
            record.requester_session.session_id() == requester_session_id
                && &record.expected_publisher_device_id == expected_publisher_device_id
        })
    }
}

impl RequesterRendezvousAuthorityProvider for InMemoryRequesterRendezvousAuthorityProvider {
    fn authorize_current_for_publisher(
        &mut self,
        publisher_device_id: &DeviceId,
    ) -> Result<AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError> {
        let mut current_count = 0_usize;
        let mut selected_current = None;
        let mut retired_seen = false;

        for record in &self.records {
            if &record.expected_publisher_device_id != publisher_device_id {
                continue;
            }

            match record.lifecycle {
                RequesterRendezvousRecordLifecycle::Current => {
                    current_count += 1;
                    if current_count == 1 {
                        selected_current = Some(record);
                    }
                }
                RequesterRendezvousRecordLifecycle::Retired => retired_seen = true,
            }
        }

        if current_count > 1 {
            return Err(RequesterRendezvousAuthorityError::Ambiguous);
        }

        if let Some(record) = selected_current {
            return Ok(AuthorizedRequesterRendezvous::from_authority(
                record.requester_session.clone(),
                record.expected_publisher_device_id.clone(),
            ));
        }

        if retired_seen {
            Err(RequesterRendezvousAuthorityError::StaleOrRetired)
        } else {
            Err(RequesterRendezvousAuthorityError::Missing)
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
    };
    use prw_control_plane::DeviceIdentityBinding;
    use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
    use prw_device_identity_signer::UbuntuEnrollmentSigner;
    use prw_session::{AuthenticatedDeviceSession, SessionAuthenticationService};

    use crate::requester_rendezvous_authority::{
        RequesterRendezvousAuthorityError, RequesterRendezvousAuthorityProvider,
    };

    use super::{
        InMemoryRequesterRendezvousAuthorityProvider, RequesterRendezvousLifecycleError,
        RequesterRendezvousRecordLifecycle,
    };

    fn signer() -> UbuntuEnrollmentSigner {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable CT requester key");
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
            .expect("load disposable CT requester signer")
    }

    fn authenticated_session(
        session_name: &str,
        user_name: &str,
        device_name: &str,
    ) -> AuthenticatedDeviceSession {
        let signer = signer();
        let binding = DeviceIdentityBinding {
            workspace_id: WorkspaceId::new("workspace-ct").expect("workspace id"),
            user_id: UserId::new(user_name).expect("user id"),
            device_id: DeviceId::new(device_name).expect("device id"),
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };
        let session_id = SessionId::new(session_name).expect("session id");
        let mut service = SessionAuthenticationService::new();
        let challenge = service
            .begin_session(binding.clone(), session_id.clone(), 1_000, 1_300)
            .expect("begin disposable requester session");
        let proof = signer
            .sign_session_auth_proof(&binding, &challenge)
            .expect("sign disposable requester proof");
        service
            .submit_proof(&session_id, &proof, 1_001)
            .expect("authenticate disposable requester session")
    }

    fn publisher(name: &str) -> DeviceId {
        DeviceId::new(name).expect("publisher device id")
    }

    #[test]
    fn zero_capacity_is_rejected() {
        assert_eq!(
            InMemoryRequesterRendezvousAuthorityProvider::new(0).unwrap_err(),
            RequesterRendezvousLifecycleError::InvalidCapacity
        );
    }

    #[test]
    fn configured_capacity_is_enforced_before_mutation() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(1).expect("provider");
        let first = authenticated_session("ct-session-a", "ct-user-a", "ct-device-a");
        let second = authenticated_session("ct-session-b", "ct-user-b", "ct-device-b");
        provider
            .register_current(first, publisher("ct-publisher-a"))
            .expect("register first");

        assert_eq!(
            provider.register_current(second, publisher("ct-publisher-b")),
            Err(RequesterRendezvousLifecycleError::CapacityExhausted)
        );
        assert_eq!(provider.records.len(), 1);
    }

    #[test]
    fn exact_duplicate_identity_is_rejected_without_replacement() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(2).expect("provider");
        let requester = authenticated_session("ct-session-duplicate", "ct-user-a", "ct-device-a");
        let expected_publisher = publisher("ct-publisher-duplicate");
        provider
            .register_current(requester.clone(), expected_publisher.clone())
            .expect("register first");

        assert_eq!(
            provider.register_current(requester, expected_publisher),
            Err(RequesterRendezvousLifecycleError::RecordAlreadyExists)
        );
        assert_eq!(provider.records.len(), 1);
    }

    #[test]
    fn one_current_record_returns_exact_owned_grant() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(1).expect("provider");
        let requester = authenticated_session("ct-session-current", "ct-user-a", "ct-device-a");
        let expected_publisher = publisher("ct-publisher-current");
        provider
            .register_current(requester.clone(), expected_publisher.clone())
            .expect("register current");

        let grant = provider
            .authorize_current_for_publisher(&expected_publisher)
            .expect("authorize current");
        assert_eq!(grant.requester_session(), &requester);
        assert_eq!(grant.expected_publisher_device_id(), &expected_publisher);
    }

    #[test]
    fn two_distinct_current_requesters_for_one_publisher_are_ambiguous() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(2).expect("provider");
        let first = authenticated_session("ct-session-a", "ct-user-a", "ct-device-a");
        let second = authenticated_session("ct-session-b", "ct-user-b", "ct-device-b");
        let expected_publisher = publisher("ct-publisher-ambiguous");
        provider
            .register_current(first, expected_publisher.clone())
            .expect("register first");
        provider
            .register_current(second, expected_publisher.clone())
            .expect("register second");

        assert_eq!(
            provider.authorize_current_for_publisher(&expected_publisher),
            Err(RequesterRendezvousAuthorityError::Ambiguous)
        );
        assert_eq!(provider.records.len(), 2);
        assert!(
            provider
                .records
                .iter()
                .all(|record| { record.lifecycle == RequesterRendezvousRecordLifecycle::Current })
        );
    }

    #[test]
    fn retired_only_matches_are_stale_or_retired() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(1).expect("provider");
        let requester = authenticated_session("ct-session-retired", "ct-user-a", "ct-device-a");
        let requester_session_id = requester.session_id().clone();
        let expected_publisher = publisher("ct-publisher-retired");
        provider
            .register_current(requester, expected_publisher.clone())
            .expect("register current");
        provider
            .retire(&requester_session_id, &expected_publisher)
            .expect("retire current");

        assert_eq!(
            provider.authorize_current_for_publisher(&expected_publisher),
            Err(RequesterRendezvousAuthorityError::StaleOrRetired)
        );
    }

    #[test]
    fn no_matching_record_is_missing() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(1).expect("provider");
        assert_eq!(
            provider.authorize_current_for_publisher(&publisher("ct-publisher-missing")),
            Err(RequesterRendezvousAuthorityError::Missing)
        );
    }

    #[test]
    fn authorization_is_non_consuming_and_repeatable_as_fresh_grants() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(1).expect("provider");
        let requester = authenticated_session("ct-session-repeat", "ct-user-a", "ct-device-a");
        let expected_publisher = publisher("ct-publisher-repeat");
        provider
            .register_current(requester.clone(), expected_publisher.clone())
            .expect("register current");

        let first = provider
            .authorize_current_for_publisher(&expected_publisher)
            .expect("first grant");
        let second = provider
            .authorize_current_for_publisher(&expected_publisher)
            .expect("second grant");

        assert_eq!(first.requester_session(), &requester);
        assert_eq!(second.requester_session(), &requester);
        assert_eq!(provider.records.len(), 1);
        assert_eq!(
            provider.records[0].lifecycle,
            RequesterRendezvousRecordLifecycle::Current
        );
    }

    #[test]
    fn retirement_transitions_only_the_exact_record() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(2).expect("provider");
        let first = authenticated_session("ct-session-retire-a", "ct-user-a", "ct-device-a");
        let first_id = first.session_id().clone();
        let second = authenticated_session("ct-session-retire-b", "ct-user-b", "ct-device-b");
        let second_id = second.session_id().clone();
        let first_publisher = publisher("ct-publisher-retire-a");
        let second_publisher = publisher("ct-publisher-retire-b");
        provider
            .register_current(first, first_publisher.clone())
            .expect("register first");
        provider
            .register_current(second, second_publisher.clone())
            .expect("register second");

        provider
            .retire(&first_id, &first_publisher)
            .expect("retire exact first");
        assert_eq!(
            provider.retire(&first_id, &first_publisher),
            Err(RequesterRendezvousLifecycleError::RecordAlreadyRetired)
        );
        assert_eq!(
            provider.retire(&second_id, &first_publisher),
            Err(RequesterRendezvousLifecycleError::RecordUnknown)
        );
        assert_eq!(
            provider.authorize_current_for_publisher(&first_publisher),
            Err(RequesterRendezvousAuthorityError::StaleOrRetired)
        );
        assert!(
            provider
                .authorize_current_for_publisher(&second_publisher)
                .is_ok()
        );
    }

    #[test]
    fn current_record_cannot_be_removed_as_retired() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(1).expect("provider");
        let requester = authenticated_session("ct-session-remove", "ct-user-a", "ct-device-a");
        let requester_id = requester.session_id().clone();
        let expected_publisher = publisher("ct-publisher-remove");
        provider
            .register_current(requester, expected_publisher.clone())
            .expect("register current");

        assert_eq!(
            provider.remove_retired(&requester_id, &expected_publisher),
            Err(RequesterRendezvousLifecycleError::CurrentRecordCannotBeRemoved)
        );
        assert_eq!(provider.records.len(), 1);
    }

    #[test]
    fn retired_removal_frees_exactly_one_capacity_slot() {
        let mut provider = InMemoryRequesterRendezvousAuthorityProvider::new(1).expect("provider");
        let first = authenticated_session("ct-session-free-a", "ct-user-a", "ct-device-a");
        let first_id = first.session_id().clone();
        let first_publisher = publisher("ct-publisher-free-a");
        provider
            .register_current(first, first_publisher.clone())
            .expect("register first");
        provider
            .retire(&first_id, &first_publisher)
            .expect("retire first");
        provider
            .remove_retired(&first_id, &first_publisher)
            .expect("remove retired first");
        assert_eq!(provider.records.len(), 0);

        let second = authenticated_session("ct-session-free-b", "ct-user-b", "ct-device-b");
        provider
            .register_current(second, publisher("ct-publisher-free-b"))
            .expect("freed capacity accepts second");
        assert_eq!(provider.records.len(), 1);
    }

    #[test]
    fn insertion_order_never_resolves_ambiguity() {
        let first = authenticated_session("ct-session-order-a", "ct-user-a", "ct-device-a");
        let second = authenticated_session("ct-session-order-b", "ct-user-b", "ct-device-b");
        let expected_publisher = publisher("ct-publisher-order");

        let mut forward = InMemoryRequesterRendezvousAuthorityProvider::new(2).expect("provider");
        forward
            .register_current(first.clone(), expected_publisher.clone())
            .expect("forward first");
        forward
            .register_current(second.clone(), expected_publisher.clone())
            .expect("forward second");

        let mut reverse = InMemoryRequesterRendezvousAuthorityProvider::new(2).expect("provider");
        reverse
            .register_current(second, expected_publisher.clone())
            .expect("reverse second");
        reverse
            .register_current(first, expected_publisher.clone())
            .expect("reverse first");

        assert_eq!(
            forward.authorize_current_for_publisher(&expected_publisher),
            Err(RequesterRendezvousAuthorityError::Ambiguous)
        );
        assert_eq!(
            reverse.authorize_current_for_publisher(&expected_publisher),
            Err(RequesterRendezvousAuthorityError::Ambiguous)
        );
    }
}
