//! Agent-owned production durable-registry systemd custody composition seam.
//!
//! C03e-JB materializes only the C03e-JA-selected join between the existing fixed production
//! durable-registry systemd credential loader, the existing control-plane provider bootstrap, and
//! the existing semantic durable-registry store. The facade accepts no endpoint, trust,
//! certificate, private-key, credential-directory, raw provider-client, request-id, or IP input.
//!
//! Calling the async facade reads the existing fixed registry service credentials and, only after
//! successful custody validation, performs the existing one-shot provider bootstrap before wrapping
//! the bounded executor in the existing semantic store. It performs no registry semantic operation,
//! creates no retry/fallback/runtime task, wires no startup/readiness callsite, deploys nothing, and
//! creates or mutates no production registry record.
//!
//! C03e-KE adds only the C03e-KD-selected production durable capability-authority population
//! composition. It performs the existing durable-registry bootstrap exactly once and then applies the
//! existing infallible runtime-custody and deny-all capability-authority ownership adaptations. It
//! performs no registry semantic read, mutex acquisition, authorization, policy evaluation, runtime
//! activation or executable wiring.
//!
//! C03e-LZ adds only the C03e-LY-selected same-custody peer + durable capability-authority
//! population seam. It performs the existing durable-registry bootstrap exactly once, resolves the
//! current peer transport identity from that exact runtime custody, and then consumes the same
//! surviving custody into the existing durable capability authority. It adds no second bootstrap,
//! requester/rendezvous population, caller, task, listener, readiness, or executable activation.

use std::fmt;

use prw_connectivity::PeerConnectivityIdentity;
use prw_control_plane::durable_registry_etcd_bootstrap::{
    DurableRegistryProductionEtcdBootstrapError, bootstrap_durable_registry_production_executor,
};
use prw_core::DeviceId;
use prw_reachability_custody::durable_registry_custody::{
    DurableRegistryCustodyError,
    load_durable_registry_production_etcd_bootstrap_config_from_systemd_credentials,
};
use prw_registry::{
    durable_registry_authority::DurableRegistryAuthorityError,
    durable_registry_etcd_store::DurableRegistryEtcdStore,
};

use crate::production_durable_registry_runtime_custody::{
    ProductionDurableCapabilityAuthority, ProductionDurableRegistryRuntimeCustody,
};

/// Bounded Agent-level failure while joining durable-registry custody to provider composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionDurableRegistryCustodyBootstrapError {
    /// The fixed production registry service-credential set failed custody validation.
    Custody(DurableRegistryCustodyError),
    /// The validated opaque registry config reached control-plane but provider bootstrap failed.
    ProviderBootstrap(DurableRegistryProductionEtcdBootstrapError),
}

impl fmt::Display for ProductionDurableRegistryCustodyBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custody(_) => {
                formatter.write_str("production durable registry custody bootstrap failed")
            }
            Self::ProviderBootstrap(_) => {
                formatter.write_str("production durable registry provider bootstrap failed")
            }
        }
    }
}

impl std::error::Error for ProductionDurableRegistryCustodyBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Custody(error) => Some(error),
            Self::ProviderBootstrap(error) => Some(error),
        }
    }
}

impl From<DurableRegistryCustodyError> for ProductionDurableRegistryCustodyBootstrapError {
    fn from(error: DurableRegistryCustodyError) -> Self {
        Self::Custody(error)
    }
}

impl From<DurableRegistryProductionEtcdBootstrapError>
    for ProductionDurableRegistryCustodyBootstrapError
{
    fn from(error: DurableRegistryProductionEtcdBootstrapError) -> Self {
        Self::ProviderBootstrap(error)
    }
}

/// Bounded failure while deriving one current peer and durable capability authority from one custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionDurablePeerCapabilityAuthorityPopulationError {
    /// The single production durable-registry custody/provider bootstrap failed.
    Bootstrap(ProductionDurableRegistryCustodyBootstrapError),
    /// The current same-device durable-registry peer lookup failed.
    PeerLookup(DurableRegistryAuthorityError),
}

impl fmt::Display for ProductionDurablePeerCapabilityAuthorityPopulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bootstrap(_) => "production durable peer capability authority bootstrap failed",
            Self::PeerLookup(_) => "production durable peer lookup failed",
        })
    }
}

impl std::error::Error for ProductionDurablePeerCapabilityAuthorityPopulationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bootstrap(error) => Some(error),
            Self::PeerLookup(error) => Some(error),
        }
    }
}

impl From<ProductionDurableRegistryCustodyBootstrapError>
    for ProductionDurablePeerCapabilityAuthorityPopulationError
{
    fn from(error: ProductionDurableRegistryCustodyBootstrapError) -> Self {
        Self::Bootstrap(error)
    }
}

impl From<DurableRegistryAuthorityError>
    for ProductionDurablePeerCapabilityAuthorityPopulationError
{
    fn from(error: DurableRegistryAuthorityError) -> Self {
        Self::PeerLookup(error)
    }
}

/// Loads fixed production registry credentials, bootstraps the provider, and returns the semantic
/// durable-registry store without performing any registry operation.
///
/// Custody is attempted exactly once through the existing fixed systemd loader. Only its validated
/// opaque [`prw_control_plane::durable_registry_etcd_bootstrap::DurableRegistryProductionEtcdBootstrapConfig`]
/// is moved into the existing control-plane provider bootstrap. The returned bounded executor is
/// moved directly into [`DurableRegistryEtcdStore::new`]. No raw provider client, endpoint, trust,
/// certificate, private-key or credential-directory value enters this Agent facade.
///
/// Calling this function performs the already-existing credential-file reads and provider network
/// bootstrap. It performs no registry Get/Txn/Put, adds no retry/fallback/reconnect/background task,
/// and creates no startup/readiness/runtime callsite or production registry record.
///
/// # Errors
///
/// Returns [`ProductionDurableRegistryCustodyBootstrapError::Custody`] when bounded systemd custody
/// fails before provider I/O, or
/// [`ProductionDurableRegistryCustodyBootstrapError::ProviderBootstrap`] when the existing provider
/// bootstrap fails. No partial, degraded, cached, or in-memory fallback store is returned.
pub async fn bootstrap_production_durable_registry_from_systemd_credentials()
-> Result<DurableRegistryEtcdStore, ProductionDurableRegistryCustodyBootstrapError> {
    let config = load_durable_registry_production_etcd_bootstrap_config_from_systemd_credentials()
        .map_err(ProductionDurableRegistryCustodyBootstrapError::Custody)?;

    let executor = bootstrap_durable_registry_production_executor(config)
        .await
        .map_err(ProductionDurableRegistryCustodyBootstrapError::ProviderBootstrap)?;

    Ok(DurableRegistryEtcdStore::new(executor))
}

/// Populates one dormant production durable capability authority from the fixed production
/// durable-registry systemd custody/provider bootstrap.
///
/// The existing durable-registry bootstrap is awaited exactly once. On success, the returned semantic
/// store is consumed exactly once into [`ProductionDurableRegistryRuntimeCustody`] and that custody is
/// then consumed exactly once into [`ProductionDurableCapabilityAuthority`]. The authority retains the
/// existing production deny-all policy baseline through its existing constructor.
///
/// Population performs no registry semantic read, mutex acquisition, session or transport validation,
/// policy evaluation, authorization, request decoding, dispatcher invocation, response I/O, task
/// spawn, readiness publication or runtime/network activation.
///
/// # Errors
///
/// Propagates [`ProductionDurableRegistryCustodyBootstrapError`] unchanged from the existing one-shot
/// production durable-registry bootstrap. No retry, fallback, synthetic authority or partial custody
/// is returned.
pub async fn bootstrap_production_durable_capability_authority_from_systemd_credentials()
-> Result<ProductionDurableCapabilityAuthority, ProductionDurableRegistryCustodyBootstrapError> {
    let store = bootstrap_production_durable_registry_from_systemd_credentials().await?;
    let registry_custody = ProductionDurableRegistryRuntimeCustody::from_authority(store);
    Ok(ProductionDurableCapabilityAuthority::from_registry_custody(
        registry_custody,
    ))
}

/// Populates one current production peer and durable capability authority from one registry custody.
///
/// The existing durable-registry bootstrap is awaited exactly once. Its exact semantic store is
/// consumed into one [`ProductionDurableRegistryRuntimeCustody`]. The current same-device
/// [`PeerConnectivityIdentity`] is then resolved exactly once from that custody using only the
/// supplied logical [`DeviceId`]. After successful lookup, the same surviving custody is consumed
/// exactly once into [`ProductionDurableCapabilityAuthority`].
///
/// This helper performs no second provider/bootstrap sequence, generic custody extraction, registry
/// write, requester/rendezvous population, runtime task creation, endpoint bind, readiness
/// publication, executable invocation, retry, fallback, cache or degraded-authority construction.
///
/// # Errors
///
/// Returns [`ProductionDurablePeerCapabilityAuthorityPopulationError::Bootstrap`] if the existing
/// one-shot durable-registry custody/provider bootstrap fails, or
/// [`ProductionDurablePeerCapabilityAuthorityPopulationError::PeerLookup`] if the current same-device
/// registry lookup fails. No capability authority is constructed after a failed peer lookup.
#[allow(
    dead_code,
    reason = "C03e-LZ materializes the LY-selected same-custody peer and durable capability-authority population before separately gated caller population"
)]
pub async fn bootstrap_production_peer_and_durable_capability_authority_from_systemd_credentials(
    device_id: DeviceId,
) -> Result<
    (
        PeerConnectivityIdentity,
        ProductionDurableCapabilityAuthority,
    ),
    ProductionDurablePeerCapabilityAuthorityPopulationError,
> {
    let store = bootstrap_production_durable_registry_from_systemd_credentials().await?;
    let mut registry_custody = ProductionDurableRegistryRuntimeCustody::from_authority(store);
    let peer = registry_custody
        .peer_connectivity_identity(device_id)
        .await?;
    let capability_authority =
        ProductionDurableCapabilityAuthority::from_registry_custody(registry_custody);
    Ok((peer, capability_authority))
}

#[cfg(test)]
mod tests {
    use std::{error::Error, future::Future};

    use prw_connectivity::PeerConnectivityIdentity;
    use prw_control_plane::durable_registry_etcd_bootstrap::DurableRegistryProductionEtcdBootstrapError;
    use prw_core::DeviceId;
    use prw_reachability_custody::durable_registry_custody::DurableRegistryCustodyError;
    use prw_registry::{
        durable_registry_authority::DurableRegistryAuthorityError,
        durable_registry_etcd_store::DurableRegistryEtcdStore,
    };

    use super::{
        ProductionDurablePeerCapabilityAuthorityPopulationError,
        ProductionDurableRegistryCustodyBootstrapError,
        bootstrap_production_durable_capability_authority_from_systemd_credentials,
        bootstrap_production_durable_registry_from_systemd_credentials,
        bootstrap_production_peer_and_durable_capability_authority_from_systemd_credentials,
    };
    use crate::production_durable_registry_runtime_custody::ProductionDurableCapabilityAuthority;

    fn assert_bootstrap_signature() {
        fn assert_future<F>(_future: F)
        where
            F: Future<
                Output = Result<
                    DurableRegistryEtcdStore,
                    ProductionDurableRegistryCustodyBootstrapError,
                >,
            >,
        {
        }

        assert_future(bootstrap_production_durable_registry_from_systemd_credentials());
    }

    fn assert_capability_authority_bootstrap_signature() {
        fn assert_future<F>(_future: F)
        where
            F: Future<
                Output = Result<
                    ProductionDurableCapabilityAuthority,
                    ProductionDurableRegistryCustodyBootstrapError,
                >,
            >,
        {
        }

        assert_future(bootstrap_production_durable_capability_authority_from_systemd_credentials());
    }

    fn assert_same_custody_population_signature(device_id: DeviceId) {
        fn assert_future<F>(_future: F)
        where
            F: Future<
                Output = Result<
                    (
                        PeerConnectivityIdentity,
                        ProductionDurableCapabilityAuthority,
                    ),
                    ProductionDurablePeerCapabilityAuthorityPopulationError,
                >,
            >,
        {
        }

        assert_future(
            bootstrap_production_peer_and_durable_capability_authority_from_systemd_credentials(
                device_id,
            ),
        );
    }

    #[test]
    fn production_registry_custody_bootstrap_has_zero_argument_store_return_shape() {
        let _ = assert_bootstrap_signature as fn();
    }

    #[test]
    fn production_capability_authority_bootstrap_has_selected_zero_argument_return_shape() {
        let _ = assert_capability_authority_bootstrap_signature as fn();
    }

    #[test]
    fn same_custody_peer_capability_authority_population_has_exact_device_input_shape() {
        let _ = assert_same_custody_population_signature as fn(DeviceId);
    }

    #[test]
    fn custody_failure_is_wrapped_without_secret_detail_in_display() {
        let error = ProductionDurableRegistryCustodyBootstrapError::from(
            DurableRegistryCustodyError::CredentialsDirectoryMissing,
        );
        assert!(matches!(
            error,
            ProductionDurableRegistryCustodyBootstrapError::Custody(
                DurableRegistryCustodyError::CredentialsDirectoryMissing
            )
        ));
        assert_eq!(
            error.to_string(),
            "production durable registry custody bootstrap failed"
        );
        assert!(error.source().is_some());
    }

    #[test]
    fn provider_bootstrap_failure_is_wrapped_without_provider_detail_in_display() {
        let error = ProductionDurableRegistryCustodyBootstrapError::from(
            DurableRegistryProductionEtcdBootstrapError::RegistryConnect,
        );
        assert!(matches!(
            error,
            ProductionDurableRegistryCustodyBootstrapError::ProviderBootstrap(
                DurableRegistryProductionEtcdBootstrapError::RegistryConnect
            )
        ));
        assert_eq!(
            error.to_string(),
            "production durable registry provider bootstrap failed"
        );
        assert!(error.source().is_some());
    }

    #[test]
    fn same_custody_population_bootstrap_failure_preserves_source_without_detail() {
        let source = ProductionDurableRegistryCustodyBootstrapError::from(
            DurableRegistryCustodyError::CredentialsDirectoryMissing,
        );
        let error = ProductionDurablePeerCapabilityAuthorityPopulationError::from(source);
        assert!(matches!(
            error,
            ProductionDurablePeerCapabilityAuthorityPopulationError::Bootstrap(
                ProductionDurableRegistryCustodyBootstrapError::Custody(
                    DurableRegistryCustodyError::CredentialsDirectoryMissing
                )
            )
        ));
        assert_eq!(
            error.to_string(),
            "production durable peer capability authority bootstrap failed"
        );
        assert!(error.source().is_some());
    }

    #[test]
    fn same_custody_population_peer_lookup_failure_preserves_source_without_detail() {
        let error = ProductionDurablePeerCapabilityAuthorityPopulationError::from(
            DurableRegistryAuthorityError::ReadUnavailable,
        );
        assert!(matches!(
            error,
            ProductionDurablePeerCapabilityAuthorityPopulationError::PeerLookup(
                DurableRegistryAuthorityError::ReadUnavailable
            )
        ));
        assert_eq!(error.to_string(), "production durable peer lookup failed");
        assert!(error.source().is_some());
    }
}
