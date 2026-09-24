//! Agent-owned lifetime custody for candidate-publication requester/rendezvous authority.
//!
//! C03e-CZ materializes the C03e-CY-selected by-value lifetime owner. C03e-DN additionally
//! materializes only the C03e-DM-selected crate-internal registration mutation composition after
//! registry validation and dedicated requester/rendezvous-start policy authorization. C03e-FY adds
//! only narrow crate-internal current-grant selection and exact post-commit retire+remove seams for
//! the existing private provider. It does not expose raw provider access, start tasks/listeners,
//! perform I/O, publish readiness, or activate production networking.

use prw_core::{DeviceId, SessionId};
use prw_remote_bridge::{
    requester_rendezvous_authority::{
        AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError,
        RequesterRendezvousAuthorityProvider,
    },
    requester_rendezvous_in_memory_provider::{
        InMemoryRequesterRendezvousAuthorityProvider, RequesterRendezvousLifecycleError,
    },
};

use crate::candidate_publication_requester_rendezvous_start_intent::policy_admission::PolicyAuthorizedRequesterRendezvousStart;

/// Owns exactly one already-configured process-local requester/rendezvous authority provider.
///
/// Construction transfers lifetime custody only. The provider remains private. The exposed
/// crate-internal operations are narrow provenance-preserving compositions for registration,
/// one current-grant selection, and exact post-commit lifecycle cleanup. No raw provider reference,
/// task/thread ownership, synchronization primitive, persistence, readiness, or networking surface
/// is exposed.
#[derive(Debug)]
pub struct CandidatePublicationRequesterRendezvousRuntimeOwner {
    provider: InMemoryRequesterRendezvousAuthorityProvider,
}

impl CandidatePublicationRequesterRendezvousRuntimeOwner {
    /// Takes by-value lifetime ownership of one already-configured provider.
    ///
    /// Provider capacity and lifecycle state are established by the caller before construction.
    /// This constructor performs no registration, authorization, I/O, task creation, or readiness
    /// publication.
    #[must_use]
    pub const fn new(provider: InMemoryRequesterRendezvousAuthorityProvider) -> Self {
        Self { provider }
    }

    /// Registers one policy-authorized requester/rendezvous start in the private provider.
    ///
    /// The sole authority input is the consumed C03e-DK policy-authorized provenance carrier. The
    /// exact authenticated requester session and DI-validated target `DeviceId` are cloned only
    /// inside this post-policy mutation boundary to satisfy the concrete provider's owned storage
    /// signature. No raw provider reference or reusable registration token is exposed.
    ///
    /// # Errors
    ///
    /// Propagates the bounded requester/rendezvous provider lifecycle error. Duplicate identity and
    /// capacity exhaustion therefore remain fail-before-mutation outcomes of `register_current`.
    pub(crate) fn register_policy_authorized_requester_rendezvous_start(
        &mut self,
        authorized: PolicyAuthorizedRequesterRendezvousStart,
    ) -> Result<(), RequesterRendezvousLifecycleError> {
        let validated = authorized.registry_validated();
        let requester_session = validated.requester_session().clone();
        let target_device_id = validated.target_device_id().clone();

        let result = self
            .provider
            .register_current(requester_session, target_device_id);
        drop(authorized);
        result
    }

    /// Selects one current requester/rendezvous grant for the exact authenticated publisher.
    ///
    /// This delegates once to the existing provider-neutral current-authority port. The returned
    /// owned grant is operation authority for one candidate-publication attempt only. Selection
    /// performs no lifecycle retirement/removal and exposes no provider custody.
    ///
    /// # Errors
    ///
    /// Returns the existing fail-closed requester/rendezvous authority classification unchanged.
    pub(crate) fn authorize_current_requester_rendezvous_for_publisher(
        &mut self,
        publisher_device_id: &DeviceId,
    ) -> Result<AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError> {
        self.provider
            .authorize_current_for_publisher(publisher_device_id)
    }

    /// Retires then removes exactly one committed requester/rendezvous lifecycle record.
    ///
    /// The exact composite identity is caller-preserved non-authorizing provenance from the same
    /// one-shot grant used by the successful candidate-publication attempt. Retirement and removal
    /// execute synchronously against this private provider under the caller's already-selected
    /// synchronization custody. A successful return reclaims exactly one bounded provider slot.
    ///
    /// # Errors
    ///
    /// Returns the first existing lifecycle error unchanged. If retirement fails, removal is not
    /// attempted. If retirement succeeds and removal fails, the record remains retired; no rollback
    /// to `Current` is attempted.
    pub(crate) fn cleanup_committed_requester_rendezvous_record(
        &mut self,
        requester_session_id: &SessionId,
        expected_publisher_device_id: &DeviceId,
    ) -> Result<(), RequesterRendezvousLifecycleError> {
        self.provider
            .retire(requester_session_id, expected_publisher_device_id)?;
        self.provider
            .remove_retired(requester_session_id, expected_publisher_device_id)
    }
}

#[cfg(test)]
mod tests {
    use prw_core::{DeviceId, SessionId};
    use prw_remote_bridge::{
        requester_rendezvous_authority::{
            AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError,
        },
        requester_rendezvous_in_memory_provider::{
            InMemoryRequesterRendezvousAuthorityProvider, RequesterRendezvousLifecycleError,
        },
    };

    use super::CandidatePublicationRequesterRendezvousRuntimeOwner;
    use crate::candidate_publication_requester_rendezvous_start_intent::policy_admission::PolicyAuthorizedRequesterRendezvousStart;

    #[test]
    fn constructor_has_exact_selected_by_value_shape() {
        let constructor: fn(
            InMemoryRequesterRendezvousAuthorityProvider,
        ) -> CandidatePublicationRequesterRendezvousRuntimeOwner =
            CandidatePublicationRequesterRendezvousRuntimeOwner::new;
        let provider = InMemoryRequesterRendezvousAuthorityProvider::new(1)
            .expect("explicit non-zero provider capacity");

        let _owner = constructor(provider);
    }

    #[test]
    fn owner_construction_consumes_an_existing_provider_without_provider_clone() {
        let provider = InMemoryRequesterRendezvousAuthorityProvider::new(2)
            .expect("explicit non-zero provider capacity");

        let _owner = CandidatePublicationRequesterRendezvousRuntimeOwner::new(provider);
    }

    #[test]
    fn registration_method_has_exact_selected_consuming_shape() {
        let registration: fn(
            &mut CandidatePublicationRequesterRendezvousRuntimeOwner,
            PolicyAuthorizedRequesterRendezvousStart,
        ) -> Result<(), RequesterRendezvousLifecycleError> =
            CandidatePublicationRequesterRendezvousRuntimeOwner::register_policy_authorized_requester_rendezvous_start;

        let _ = registration;
    }

    #[test]
    fn current_grant_selection_has_exact_narrow_shape() {
        let authorization: fn(
            &mut CandidatePublicationRequesterRendezvousRuntimeOwner,
            &DeviceId,
        ) -> Result<AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError> =
            CandidatePublicationRequesterRendezvousRuntimeOwner::authorize_current_requester_rendezvous_for_publisher;

        let _ = authorization;
    }

    #[test]
    fn committed_cleanup_has_exact_composite_identity_shape() {
        let cleanup: fn(
            &mut CandidatePublicationRequesterRendezvousRuntimeOwner,
            &SessionId,
            &DeviceId,
        ) -> Result<(), RequesterRendezvousLifecycleError> =
            CandidatePublicationRequesterRendezvousRuntimeOwner::cleanup_committed_requester_rendezvous_record;

        let _ = cleanup;
    }

    #[test]
    fn committed_cleanup_preserves_unknown_record_error() {
        let provider = InMemoryRequesterRendezvousAuthorityProvider::new(1)
            .expect("explicit non-zero provider capacity");
        let mut owner = CandidatePublicationRequesterRendezvousRuntimeOwner::new(provider);
        let requester_session_id =
            SessionId::new("fy-requester-session-unknown").expect("valid requester session id");
        let publisher_device_id =
            DeviceId::new("fy-publisher-device-unknown").expect("valid publisher device id");

        assert_eq!(
            owner.cleanup_committed_requester_rendezvous_record(
                &requester_session_id,
                &publisher_device_id,
            ),
            Err(RequesterRendezvousLifecycleError::RecordUnknown)
        );
    }
}
