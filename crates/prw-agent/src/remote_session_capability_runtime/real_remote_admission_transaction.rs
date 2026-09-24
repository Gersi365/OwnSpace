//! One bounded expected-device real remote admission transaction.
//!
//! C03e-AJ composes existing current-registry, lower-transport acceptance, logical-session
//! authentication, and post-authentication binding seams for exactly one intended logical device.
//! It does not run a listener loop, spawn workers, insert into the persistent collection, publish
//! readiness, or wire the Agent binary.

use std::{fmt, ops::Range};

use prw_core::{DeviceId, SessionId};
use prw_policy::PolicyEvaluator;
use prw_registry::RegistryError;
use prw_remote_bridge::{MAX_REMOTE_SESSION_LEASE_SECONDS, RemoteBridgeError};
use prw_session::{SessionAuthenticationService, prwa_verifier_source::PrwaVerifierSourceError};

use super::{
    AuthenticatedRemoteSessionRuntimeOwner, SharedCurrentCapabilityAuthority,
    authenticated_remote_session_runtime::{
        close_authenticated_remote_session_binding_failure, compose_authenticated_remote_session,
    },
};
use crate::{
    remote_session_authentication_transaction::{
        AgentRemoteSessionAuthenticationFailure, complete_registry_bound_session_authentication,
        complete_registry_bound_session_authentication_with_fresh_verifier_time,
    },
    remote_transport_runtime::{
        AgentRemotePeerAcceptError, AgentRemoteSessionChallengeError, AgentRemoteTransportRuntime,
    },
};

const REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_CODE: u32 = 5;
const REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_REASON: &[u8] =
    b"remote session admission preparation failed";

/// Invalid process-owned application-lease lifetime policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteSessionApplicationLeasePolicyError {
    /// The selected lifetime is zero or exceeds the existing remote-session lease ceiling.
    InvalidLifetime,
}

impl fmt::Display for RemoteSessionApplicationLeasePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("remote session application lease lifetime is invalid")
    }
}

impl std::error::Error for RemoteSessionApplicationLeasePolicyError {}

/// One validated process-owned application-session lease duration policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteSessionApplicationLeasePolicy {
    lifetime_seconds: u64,
}

impl RemoteSessionApplicationLeasePolicy {
    /// Validates one explicit positive whole-second lease lifetime.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above [`MAX_REMOTE_SESSION_LEASE_SECONDS`]. No default, fallback,
    /// clamping or saturation is applied.
    pub const fn new(
        lifetime_seconds: u64,
    ) -> Result<Self, RemoteSessionApplicationLeasePolicyError> {
        if lifetime_seconds == 0 || lifetime_seconds > MAX_REMOTE_SESSION_LEASE_SECONDS {
            return Err(RemoteSessionApplicationLeasePolicyError::InvalidLifetime);
        }
        Ok(Self { lifetime_seconds })
    }

    /// Returns the already-validated whole-second lease lifetime.
    #[must_use]
    pub const fn lifetime_seconds(&self) -> u64 {
        self.lifetime_seconds
    }
}

/// Bounded failure for one expected-device real remote admission transaction.
#[derive(Debug)]
#[non_exhaustive]
pub enum RemoteSessionRealAdmissionError {
    /// Current registry state could not resolve one valid expected lower-transport identity.
    Registry(RegistryError),
    /// Exact expected lower-transport peer acceptance failed.
    Accept(AgentRemotePeerAcceptError),
    /// Post-accept current-registry challenge preparation failed.
    Challenge(AgentRemoteSessionChallengeError),
    /// Existing logical-session challenge/proof transaction failed.
    Authentication(AgentRemoteSessionAuthenticationFailure),
    /// Fresh post-authentication application-lease issue-time acquisition failed.
    ApplicationLeaseVerifierTime(PrwaVerifierSourceError),
    /// Checked construction of the post-authentication application-lease expiry overflowed.
    ApplicationLeaseExpiryOverflow,
    /// Existing post-authentication bound-session composition failed.
    Binding(RemoteBridgeError),
}

impl fmt::Display for RemoteSessionRealAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(_) => {
                formatter.write_str("remote session expected transport resolution failed")
            }
            Self::Accept(_) => formatter.write_str("remote session lower-transport accept failed"),
            Self::Challenge(_) => {
                formatter.write_str("remote session challenge preparation failed")
            }
            Self::Authentication(_) => formatter.write_str("remote session authentication failed"),
            Self::ApplicationLeaseVerifierTime(_) => {
                formatter.write_str("remote session application lease verifier time failed")
            }
            Self::ApplicationLeaseExpiryOverflow => {
                formatter.write_str("remote session application lease expiry overflowed")
            }
            Self::Binding(_) => formatter.write_str("remote session binding failed"),
        }
    }
}

impl std::error::Error for RemoteSessionRealAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(error) => Some(error),
            Self::Accept(error) => Some(error),
            Self::Challenge(error) => Some(error),
            Self::Authentication(error) => Some(error),
            Self::ApplicationLeaseVerifierTime(error) => Some(error),
            Self::ApplicationLeaseExpiryOverflow => None,
            Self::Binding(error) => Some(error),
        }
    }
}

impl From<RegistryError> for RemoteSessionRealAdmissionError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<AgentRemotePeerAcceptError> for RemoteSessionRealAdmissionError {
    fn from(error: AgentRemotePeerAcceptError) -> Self {
        Self::Accept(error)
    }
}

impl From<AgentRemoteSessionChallengeError> for RemoteSessionRealAdmissionError {
    fn from(error: AgentRemoteSessionChallengeError) -> Self {
        Self::Challenge(error)
    }
}

impl From<AgentRemoteSessionAuthenticationFailure> for RemoteSessionRealAdmissionError {
    fn from(error: AgentRemoteSessionAuthenticationFailure) -> Self {
        Self::Authentication(error)
    }
}

impl From<RemoteBridgeError> for RemoteSessionRealAdmissionError {
    fn from(error: RemoteBridgeError) -> Self {
        Self::Binding(error)
    }
}

/// Admits exactly one real lower-transport peer expected for one logical `DeviceId`, authenticates
/// one logical session, and composes one authenticated remote-session runtime owner.
///
/// The first current-authority read resolves the expected transport identity from current registry
/// state and is released before network acceptance. After one exact lower-transport peer is
/// accepted, a second independent current-authority read delegates to the existing registry-bound
/// challenge-preparation seam so revocation or transport rotation during the accept wait remains
/// visible before logical-session wire I/O.
///
/// If post-accept challenge preparation fails, this seam owns the otherwise-unclaimed accepted peer
/// cleanup and closes it exactly once with the fixed code-5 diagnostic. Once challenge preparation
/// succeeds, the existing authentication transaction exclusively owns pending-session cleanup and
/// code-1 failure close. After authentication succeeds, the existing post-authentication binding
/// seam exclusively owns code-2 binding-failure close.
///
/// This function performs no retry, reconnect, worker spawn, collection insertion, cancellation,
/// nested runtime drive, readiness publication, or Agent bootstrap wiring.
///
/// # Errors
///
/// Returns [`RemoteSessionRealAdmissionError`] preserving the exact bounded phase that failed.
#[expect(
    clippy::too_many_arguments,
    reason = "C03e-AJ intentionally keeps the selected transaction inputs explicit and typed"
)]
pub async fn admit_expected_remote_device_session<P>(
    runtime: &AgentRemoteTransportRuntime,
    authority: &SharedCurrentCapabilityAuthority<P>,
    session_authentication: &mut SessionAuthenticationService,
    expected_device_id: &DeviceId,
    session_id: SessionId,
    challenge_validity_unix_seconds: Range<u64>,
    authentication_request_id: u64,
    authentication_now_unix_seconds: u64,
    application_lease_unix_seconds: Range<u64>,
) -> Result<AuthenticatedRemoteSessionRuntimeOwner, RemoteSessionRealAdmissionError>
where
    P: PolicyEvaluator + Send + Sync,
{
    let expected_transport_identity = authority
        .with_current_authority(|registry, _policy| {
            let registered_device = registry
                .device(expected_device_id)
                .ok_or(RegistryError::DeviceUnknown)?;
            let expected_transport_identity = registered_device
                .transport_identity()
                .ok_or(RegistryError::TransportIdentityMissing)?;
            registry
                .validate_transport_identity(expected_device_id, expected_transport_identity)?;
            Ok::<_, RegistryError>(expected_transport_identity)
        })
        .await?;

    let peer = runtime
        .accept_authenticated_peer(expected_transport_identity)
        .await?;

    let challenge = authority
        .with_current_authority(|registry, _policy| {
            runtime.begin_registry_bound_session_challenge(
                &peer,
                registry,
                session_authentication,
                expected_device_id,
                session_id,
                challenge_validity_unix_seconds,
            )
        })
        .await;

    let challenge = match challenge {
        Ok(challenge) => challenge,
        Err(error) => {
            peer.close(
                REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_CODE,
                REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_REASON,
            );
            return Err(error.into());
        }
    };

    let authenticated_session = complete_registry_bound_session_authentication(
        runtime,
        &peer,
        session_authentication,
        &challenge,
        authentication_request_id,
        authentication_now_unix_seconds,
    )
    .await?;

    compose_authenticated_remote_session(
        peer,
        authenticated_session,
        application_lease_unix_seconds,
    )
    .map_err(Into::into)
}

#[expect(
    clippy::too_many_arguments,
    reason = "C03e-SZ preserves the selected AJ inputs while replacing only proof-time now with the retained request-owned verifier source"
)]
pub async fn admit_expected_remote_device_session_with_fresh_verifier_time<P, T>(
    runtime: &AgentRemoteTransportRuntime,
    authority: &SharedCurrentCapabilityAuthority<P>,
    session_authentication: &mut SessionAuthenticationService,
    expected_device_id: &DeviceId,
    session_id: SessionId,
    challenge_validity_unix_seconds: Range<u64>,
    authentication_request_id: u64,
    verifier_time_unix_seconds: &mut T,
    application_lease_unix_seconds: Range<u64>,
) -> Result<AuthenticatedRemoteSessionRuntimeOwner, RemoteSessionRealAdmissionError>
where
    P: PolicyEvaluator + Send + Sync,
    T: FnMut() -> Result<u64, prw_session::prwa_verifier_source::PrwaVerifierSourceError>,
{
    let expected_transport_identity = authority
        .with_current_authority(|registry, _policy| {
            let registered_device = registry
                .device(expected_device_id)
                .ok_or(RegistryError::DeviceUnknown)?;
            let expected_transport_identity = registered_device
                .transport_identity()
                .ok_or(RegistryError::TransportIdentityMissing)?;
            registry
                .validate_transport_identity(expected_device_id, expected_transport_identity)?;
            Ok::<_, RegistryError>(expected_transport_identity)
        })
        .await?;

    let peer = runtime
        .accept_authenticated_peer(expected_transport_identity)
        .await?;

    let challenge = authority
        .with_current_authority(|registry, _policy| {
            runtime.begin_registry_bound_session_challenge(
                &peer,
                registry,
                session_authentication,
                expected_device_id,
                session_id,
                challenge_validity_unix_seconds,
            )
        })
        .await;

    let challenge = match challenge {
        Ok(challenge) => challenge,
        Err(error) => {
            peer.close(
                REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_CODE,
                REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_REASON,
            );
            return Err(error.into());
        }
    };

    let authenticated_session =
        complete_registry_bound_session_authentication_with_fresh_verifier_time(
            runtime,
            &peer,
            session_authentication,
            &challenge,
            authentication_request_id,
            verifier_time_unix_seconds,
        )
        .await?;

    compose_authenticated_remote_session(
        peer,
        authenticated_session,
        application_lease_unix_seconds,
    )
    .map_err(Into::into)
}

/// Admits one expected peer with fresh proof time and a separately validated application-lease policy.
///
/// This production sibling preserves the current expected-transport and challenge-preparation path.
/// The exact request-owned verifier-time provider is first borrowed by the existing fresh logical
/// authentication transaction. Only after that transaction succeeds is the same provider sampled
/// once again for application-lease issue time. The validated lease duration is then added with
/// checked arithmetic and the resulting exact interval is passed to the existing binding seam.
///
/// No compatibility authentication-now value or preconstructed absolute lease range is accepted.
/// No verifier-time retry, resample, fallback, saturation, clamping, replacement session or worker
/// activation is performed here.
///
/// # Errors
///
/// Returns the existing bounded registry/accept/challenge/authentication/binding stages, or the exact
/// post-authentication application-lease verifier-time/expiry-overflow classifications selected by
/// C03e-TC. Lease-preparation failure closes the same authenticated peer with the existing binding
/// failure diagnostic before returning.
#[allow(
    dead_code,
    reason = "C03e-TD materializes the TC-selected core production sibling before separately gated repeated-admission caller migration"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "C03e-TD keeps exact request correlation, fresh verifier provider and validated lease policy explicit without widening historical APIs"
)]
pub async fn admit_expected_remote_device_session_with_fresh_verifier_time_and_application_lease_policy<
    P,
    T,
>(
    runtime: &AgentRemoteTransportRuntime,
    authority: &SharedCurrentCapabilityAuthority<P>,
    session_authentication: &mut SessionAuthenticationService,
    expected_device_id: &DeviceId,
    session_id: SessionId,
    challenge_validity_unix_seconds: Range<u64>,
    authentication_request_id: u64,
    verifier_time_unix_seconds: &mut T,
    application_lease_policy: RemoteSessionApplicationLeasePolicy,
) -> Result<AuthenticatedRemoteSessionRuntimeOwner, RemoteSessionRealAdmissionError>
where
    P: PolicyEvaluator + Send + Sync,
    T: FnMut() -> Result<u64, PrwaVerifierSourceError>,
{
    let expected_transport_identity = authority
        .with_current_authority(|registry, _policy| {
            let registered_device = registry
                .device(expected_device_id)
                .ok_or(RegistryError::DeviceUnknown)?;
            let expected_transport_identity = registered_device
                .transport_identity()
                .ok_or(RegistryError::TransportIdentityMissing)?;
            registry
                .validate_transport_identity(expected_device_id, expected_transport_identity)?;
            Ok::<_, RegistryError>(expected_transport_identity)
        })
        .await?;

    let peer = runtime
        .accept_authenticated_peer(expected_transport_identity)
        .await?;

    let challenge = authority
        .with_current_authority(|registry, _policy| {
            runtime.begin_registry_bound_session_challenge(
                &peer,
                registry,
                session_authentication,
                expected_device_id,
                session_id,
                challenge_validity_unix_seconds,
            )
        })
        .await;

    let challenge = match challenge {
        Ok(challenge) => challenge,
        Err(error) => {
            peer.close(
                REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_CODE,
                REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_REASON,
            );
            return Err(error.into());
        }
    };

    let authenticated_session =
        complete_registry_bound_session_authentication_with_fresh_verifier_time(
            runtime,
            &peer,
            session_authentication,
            &challenge,
            authentication_request_id,
            verifier_time_unix_seconds,
        )
        .await?;

    let application_lease_issued_at_unix_seconds = match verifier_time_unix_seconds() {
        Ok(now_unix_seconds) => now_unix_seconds,
        Err(error) => {
            close_authenticated_remote_session_binding_failure(&peer);
            return Err(RemoteSessionRealAdmissionError::ApplicationLeaseVerifierTime(error));
        }
    };
    let Some(application_lease_expires_at_unix_seconds) = application_lease_issued_at_unix_seconds
        .checked_add(application_lease_policy.lifetime_seconds())
    else {
        close_authenticated_remote_session_binding_failure(&peer);
        return Err(RemoteSessionRealAdmissionError::ApplicationLeaseExpiryOverflow);
    };

    compose_authenticated_remote_session(
        peer,
        authenticated_session,
        application_lease_issued_at_unix_seconds..application_lease_expires_at_unix_seconds,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use prw_registry::RegistryError;
    use prw_remote_bridge::{MAX_REMOTE_SESSION_LEASE_SECONDS, RemoteBridgeError};
    use prw_session::prwa_verifier_source::PrwaVerifierSourceError;

    use super::{
        REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_CODE,
        REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_REASON,
        RemoteSessionApplicationLeasePolicy, RemoteSessionApplicationLeasePolicyError,
        RemoteSessionRealAdmissionError, admit_expected_remote_device_session,
        admit_expected_remote_device_session_with_fresh_verifier_time,
        admit_expected_remote_device_session_with_fresh_verifier_time_and_application_lease_policy,
    };
    use crate::{
        remote_session_authentication_transaction::AgentRemoteSessionAuthenticationFailure,
        remote_transport_runtime::{AgentRemotePeerAcceptError, AgentRemoteSessionChallengeError},
    };

    fn assert_accept_mapping(
        mapping: fn(AgentRemotePeerAcceptError) -> RemoteSessionRealAdmissionError,
    ) {
        let _ = mapping;
    }

    fn assert_challenge_mapping(
        mapping: fn(AgentRemoteSessionChallengeError) -> RemoteSessionRealAdmissionError,
    ) {
        let _ = mapping;
    }

    fn assert_authentication_mapping(
        mapping: fn(AgentRemoteSessionAuthenticationFailure) -> RemoteSessionRealAdmissionError,
    ) {
        let _ = mapping;
    }

    fn assert_binding_mapping(mapping: fn(RemoteBridgeError) -> RemoteSessionRealAdmissionError) {
        let _ = mapping;
    }

    #[test]
    fn transaction_surface_is_materialized_without_transport_identity_input() {
        let _ = admit_expected_remote_device_session::<prw_policy::BoundedLocalManagementPolicy>;
    }

    #[test]
    fn fresh_verifier_time_transaction_surface_is_materialized() {
        let _ = admit_expected_remote_device_session_with_fresh_verifier_time::<
            prw_policy::BoundedLocalManagementPolicy,
            fn() -> Result<u64, PrwaVerifierSourceError>,
        >;
    }

    #[test]
    fn production_lease_policy_transaction_surface_is_materialized() {
        let _ =
            admit_expected_remote_device_session_with_fresh_verifier_time_and_application_lease_policy::<
                prw_policy::BoundedLocalManagementPolicy,
                fn() -> Result<u64, PrwaVerifierSourceError>,
            >;
    }

    #[test]
    fn application_lease_policy_accepts_only_positive_values_through_existing_ceiling() {
        assert_eq!(
            RemoteSessionApplicationLeasePolicy::new(0),
            Err(RemoteSessionApplicationLeasePolicyError::InvalidLifetime)
        );
        assert_eq!(
            RemoteSessionApplicationLeasePolicy::new(1)
                .expect("one-second lease policy")
                .lifetime_seconds(),
            1
        );
        assert_eq!(
            RemoteSessionApplicationLeasePolicy::new(MAX_REMOTE_SESSION_LEASE_SECONDS)
                .expect("maximum lease policy")
                .lifetime_seconds(),
            MAX_REMOTE_SESSION_LEASE_SECONDS
        );
        assert_eq!(
            RemoteSessionApplicationLeasePolicy::new(MAX_REMOTE_SESSION_LEASE_SECONDS + 1),
            Err(RemoteSessionApplicationLeasePolicyError::InvalidLifetime)
        );
    }

    #[test]
    fn post_auth_lease_verifier_time_error_preserves_exact_source() {
        let inner = PrwaVerifierSourceError::VerifierTime;
        let error = RemoteSessionRealAdmissionError::ApplicationLeaseVerifierTime(inner);

        assert_eq!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<PrwaVerifierSourceError>()),
            Some(&inner)
        );
    }

    #[test]
    fn post_auth_lease_expiry_overflow_is_source_free() {
        let error = RemoteSessionRealAdmissionError::ApplicationLeaseExpiryOverflow;
        assert!(error.source().is_none());
    }

    #[test]
    fn registry_failure_maps_to_registry_phase() {
        assert!(matches!(
            RemoteSessionRealAdmissionError::from(RegistryError::TransportIdentityMissing),
            RemoteSessionRealAdmissionError::Registry(RegistryError::TransportIdentityMissing)
        ));
    }

    #[test]
    fn existing_bounded_failures_have_exact_phase_mappings() {
        assert_accept_mapping(RemoteSessionRealAdmissionError::from);
        assert_challenge_mapping(RemoteSessionRealAdmissionError::from);
        assert_authentication_mapping(RemoteSessionRealAdmissionError::from);
        assert_binding_mapping(RemoteSessionRealAdmissionError::from);
    }

    #[test]
    fn challenge_preparation_failure_peer_close_diagnostic_is_fixed() {
        assert_eq!(REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_CODE, 5);
        assert_eq!(
            REMOTE_SESSION_ADMISSION_PREPARATION_FAILURE_CLOSE_REASON,
            b"remote session admission preparation failed"
        );
    }
}
