//! Provider-neutral requester/rendezvous authority carrier for candidate publication.
//!
//! C03e-CM materializes only the C03e-CL-selected one-shot server-side authority grant and
//! provider-neutral authorization port. It does not select or activate a concrete rendezvous
//! provider, storage backend, clock/TTL policy, broker, PRWC frame loop, candidate-publication
//! execution, reachability mutation, networking, product runtime wiring, or deployment.

use std::fmt;

use prw_core::DeviceId;
use prw_session::AuthenticatedDeviceSession;

/// One server-authorized requester/rendezvous grant for one publication execution attempt.
///
/// Construction is exposed for future concrete authority adapters, but possession alone is not
/// requester/rendezvous authority. Production composition must obtain this value from a concrete
/// [`RequesterRendezvousAuthorityProvider`] after that provider has established exactly one current
/// server-side requester/rendezvous selection for the authenticated publisher device.
///
/// This value is intentionally neither `Copy` nor `Clone`: later execution must consume one grant
/// for at most one candidate-publication attempt rather than caching or replaying it.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedRequesterRendezvous {
    requester_session: AuthenticatedDeviceSession,
    expected_publisher_device_id: DeviceId,
}

impl AuthorizedRequesterRendezvous {
    /// Constructs one grant from already-authoritative provider results.
    ///
    /// This is an adapter boundary, not an authorization check. Production code must call it only
    /// after a concrete requester/rendezvous authority has linearized one exact current selection.
    #[must_use]
    pub const fn from_authority(
        requester_session: AuthenticatedDeviceSession,
        expected_publisher_device_id: DeviceId,
    ) -> Self {
        Self {
            requester_session,
            expected_publisher_device_id,
        }
    }

    /// Returns the authenticated requester session carried by this one-shot grant.
    #[must_use]
    pub const fn requester_session(&self) -> &AuthenticatedDeviceSession {
        &self.requester_session
    }

    /// Returns the logical publisher device selected by server-side rendezvous authority.
    #[must_use]
    pub const fn expected_publisher_device_id(&self) -> &DeviceId {
        &self.expected_publisher_device_id
    }
}

/// Fail-closed requester/rendezvous authority outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequesterRendezvousAuthorityError {
    /// No current requester/rendezvous selection exists for the publisher.
    Missing,
    /// A known selection exists but is no longer current authority.
    StaleOrRetired,
    /// More than one current candidate exists where exactly one authority is required.
    Ambiguous,
    /// Current authority cannot be established because provider state is unavailable/indeterminate.
    UnavailableOrIndeterminate,
}

impl fmt::Display for RequesterRendezvousAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "requester rendezvous authority is missing",
            Self::StaleOrRetired => "requester rendezvous authority is stale or retired",
            Self::Ambiguous => "requester rendezvous authority is ambiguous",
            Self::UnavailableOrIndeterminate => {
                "requester rendezvous authority is unavailable or indeterminate"
            }
        })
    }
}

impl std::error::Error for RequesterRendezvousAuthorityError {}

/// Provider-neutral current requester/rendezvous authorization port.
///
/// `publisher_device_id` is a lookup selector only and must come from the authenticated publisher
/// session. It is never requester authority by itself. A concrete provider owns storage,
/// synchronization, staleness/abandonment semantics and the authorization linearization mechanism.
/// None of those implementation choices are selected by this trait.
///
/// A successful return means exactly one current server-side requester/rendezvous selection was
/// authorized into one owned operation grant. Missing, stale, ambiguous, unavailable or
/// indeterminate authority must fail closed.
pub trait RequesterRendezvousAuthorityProvider {
    /// Authorizes one current requester/rendezvous selection for `publisher_device_id`.
    ///
    /// The returned grant is one-shot operation evidence. Later candidate-publication composition
    /// must still compare its expected publisher with the authenticated publisher and repeat the
    /// existing requester/publisher/workspace/target currentness checks before reachability commit.
    ///
    /// # Errors
    ///
    /// Returns a stable fail-closed authority classification when exactly one current server-side
    /// requester/rendezvous selection cannot be established.
    fn authorize_current_for_publisher(
        &mut self,
        publisher_device_id: &DeviceId,
    ) -> Result<AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError>;
}

#[cfg(test)]
mod tests {
    use prw_core::DeviceId;
    use prw_session::AuthenticatedDeviceSession;

    use super::{
        AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError,
        RequesterRendezvousAuthorityProvider,
    };

    struct FailClosedReferenceProvider;

    impl RequesterRendezvousAuthorityProvider for FailClosedReferenceProvider {
        fn authorize_current_for_publisher(
            &mut self,
            _publisher_device_id: &DeviceId,
        ) -> Result<AuthorizedRequesterRendezvous, RequesterRendezvousAuthorityError> {
            Err(RequesterRendezvousAuthorityError::UnavailableOrIndeterminate)
        }
    }

    fn assert_provider<T: RequesterRendezvousAuthorityProvider>() {}

    fn assert_grant_constructor_signature(
        constructor: fn(AuthenticatedDeviceSession, DeviceId) -> AuthorizedRequesterRendezvous,
    ) {
        let _ = constructor;
    }

    #[test]
    fn selected_provider_port_is_provider_neutral_and_fail_closed() {
        assert_provider::<FailClosedReferenceProvider>();

        let publisher = DeviceId::new("cm-publisher").expect("valid publisher device id");
        let mut provider = FailClosedReferenceProvider;
        assert_eq!(
            provider.authorize_current_for_publisher(&publisher),
            Err(RequesterRendezvousAuthorityError::UnavailableOrIndeterminate)
        );
    }

    #[test]
    fn grant_constructor_has_selected_owned_input_shape() {
        assert_grant_constructor_signature(AuthorizedRequesterRendezvous::from_authority);
    }

    #[test]
    fn authority_errors_have_stable_fail_closed_messages() {
        let cases = [
            (
                RequesterRendezvousAuthorityError::Missing,
                "requester rendezvous authority is missing",
            ),
            (
                RequesterRendezvousAuthorityError::StaleOrRetired,
                "requester rendezvous authority is stale or retired",
            ),
            (
                RequesterRendezvousAuthorityError::Ambiguous,
                "requester rendezvous authority is ambiguous",
            ),
            (
                RequesterRendezvousAuthorityError::UnavailableOrIndeterminate,
                "requester rendezvous authority is unavailable or indeterminate",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }
}
