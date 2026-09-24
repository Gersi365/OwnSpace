//! Established-state startup authority verifier.
//!
//! This path performs only the post-retirement restart proof. It accepts no
//! setup-intent custody choice, performs no first-run transaction, and is reached
//! only through the fail-closed startup-state dispatcher.

use std::fmt;

use prw_control_plane::{DeviceIdentityBinding, PublicIdentityMaterial};
use prw_core::DeviceLifecycle;
use prw_registry::{
    MembershipLifecycle, WorkspaceRole,
    durable_registry_authority::DurableRegistryAuthorityError,
    durable_registry_sqlite_custody::{
        DurableRegistrySqliteCustodyError, open_existing_owner_pc_sqlite_authority_from_env,
    },
    durable_registry_sqlite_store::DurableRegistrySqliteStore,
};
use prw_transport_identity_provisioning::{
    TransportIdentityProvisioningPolicy, TransportIdentityRecoveryError,
    recover_established_ubuntu_transport_identity_from_persisted_binding,
};

use crate::owner_first_setup_bootstrap_inputs::{
    OwnerFirstSetupBootstrapInputError, OwnerLogicalIdentityRecord,
    load_owner_logical_identity_record_from_env,
};

/// Successful read-only proof that post-first-run local startup authority is established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerEstablishedStartupAuthorityProof {
    transport_policy: TransportIdentityProvisioningPolicy,
}

impl OwnerEstablishedStartupAuthorityProof {
    /// Returns the canonical established transport policy read from persisted custody.
    #[must_use]
    pub const fn transport_policy(self) -> TransportIdentityProvisioningPolicy {
        self.transport_policy
    }
}

/// Fail-closed established-startup authority verification error.
#[derive(Debug)]
pub enum OwnerEstablishedStartupAuthorityError {
    /// The authoritative owner logical-identity record was absent, insecure, or malformed.
    OwnerIdentity(OwnerFirstSetupBootstrapInputError),
    /// Canonical established transport custody could not be validated and recovered.
    TransportIdentity(TransportIdentityRecoveryError),
    /// Existing owner-PC `SQLite` custody could not be opened read-only.
    DatabaseCustody(DurableRegistrySqliteCustodyError),
    /// Provider-neutral `SQLite` record reads failed.
    AuthorityRead(DurableRegistryAuthorityError),
    /// The exact owner membership record is absent.
    OwnerMembershipMissing,
    /// The exact owner membership is not current Owner/Active state.
    OwnerMembershipNotCurrent,
    /// The exact owner device record is absent.
    OwnerDeviceMissing,
    /// The exact owner device binding or current transport identity does not match established state.
    OwnerDeviceNotCurrent,
}

impl fmt::Display for OwnerEstablishedStartupAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerIdentity(error) => {
                write!(
                    formatter,
                    "established owner identity validation failed: {error}"
                )
            }
            Self::TransportIdentity(error) => {
                write!(
                    formatter,
                    "established transport custody validation failed: {error}"
                )
            }
            Self::DatabaseCustody(error) => {
                write!(
                    formatter,
                    "established SQLite custody validation failed: {error}"
                )
            }
            Self::AuthorityRead(error) => {
                write!(
                    formatter,
                    "established SQLite authority read failed: {error}"
                )
            }
            Self::OwnerMembershipMissing => {
                formatter.write_str("established owner membership is missing")
            }
            Self::OwnerMembershipNotCurrent => {
                formatter.write_str("established owner membership is not current")
            }
            Self::OwnerDeviceMissing => formatter.write_str("established owner device is missing"),
            Self::OwnerDeviceNotCurrent => {
                formatter.write_str("established owner device is not current")
            }
        }
    }
}

impl std::error::Error for OwnerEstablishedStartupAuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OwnerIdentity(error) => Some(error),
            Self::TransportIdentity(error) => Some(error),
            Self::DatabaseCustody(error) => Some(error),
            Self::AuthorityRead(error) => Some(error),
            Self::OwnerMembershipMissing
            | Self::OwnerMembershipNotCurrent
            | Self::OwnerDeviceMissing
            | Self::OwnerDeviceNotCurrent => None,
        }
    }
}

/// Verifies exact established owner startup authority without setup intent or semantic mutation.
///
/// The verifier loads the authoritative owner logical identity, derives custody policy only from the
/// canonical persisted transport binding, recovers that established transport identity, opens only an
/// already-existing owner-PC `SQLite` authority read-only, and proves exact membership/device/current
/// transport agreement.
///
/// It does not create or retire setup intent, provision or replace transport identity, invoke the
/// fresh-owner bootstrap transaction, or activate runtime/socket/network behavior.
///
/// # Errors
///
/// Returns the exact bounded failure stage when owner identity, established transport custody, `SQLite`
/// custody, or current authority proof fails. No fallback custody tier or alternate authority source
/// is attempted.
pub fn verify_established_owner_startup_authority(
    public_device_identity: &PublicIdentityMaterial,
) -> Result<OwnerEstablishedStartupAuthorityProof, OwnerEstablishedStartupAuthorityError> {
    let owner = load_owner_logical_identity_record_from_env()
        .map_err(OwnerEstablishedStartupAuthorityError::OwnerIdentity)?;
    let transport = recover_established_ubuntu_transport_identity_from_persisted_binding()
        .map_err(OwnerEstablishedStartupAuthorityError::TransportIdentity)?;
    let authority = open_existing_owner_pc_sqlite_authority_from_env()
        .map_err(OwnerEstablishedStartupAuthorityError::DatabaseCustody)?;

    verify_established_owner_startup_authority_with_store(
        &authority,
        &owner,
        public_device_identity,
        transport.policy(),
        transport.transport_identity(),
    )
}

fn verify_established_owner_startup_authority_with_store(
    authority: &DurableRegistrySqliteStore,
    owner: &OwnerLogicalIdentityRecord,
    public_device_identity: &PublicIdentityMaterial,
    transport_policy: TransportIdentityProvisioningPolicy,
    transport_identity: prw_connectivity::TransportIdentity,
) -> Result<OwnerEstablishedStartupAuthorityProof, OwnerEstablishedStartupAuthorityError> {
    let membership = authority
        .membership(owner.workspace_id(), owner.user_id())
        .map_err(OwnerEstablishedStartupAuthorityError::AuthorityRead)?
        .ok_or(OwnerEstablishedStartupAuthorityError::OwnerMembershipMissing)?;

    if membership.workspace_id() != owner.workspace_id()
        || membership.user_id() != owner.user_id()
        || membership.role() != WorkspaceRole::Owner
        || membership.lifecycle() != MembershipLifecycle::Active
    {
        return Err(OwnerEstablishedStartupAuthorityError::OwnerMembershipNotCurrent);
    }

    let device = authority
        .device(owner.device_id())
        .map_err(OwnerEstablishedStartupAuthorityError::AuthorityRead)?
        .ok_or(OwnerEstablishedStartupAuthorityError::OwnerDeviceMissing)?;

    let expected_binding = DeviceIdentityBinding {
        workspace_id: owner.workspace_id().clone(),
        user_id: owner.user_id().clone(),
        device_id: owner.device_id().clone(),
        public_identity: public_device_identity.clone(),
        lifecycle: DeviceLifecycle::Enrolled,
    };

    if device.binding() != &expected_binding
        || device.transport_identity() != Some(transport_identity)
    {
        return Err(OwnerEstablishedStartupAuthorityError::OwnerDeviceNotCurrent);
    }

    Ok(OwnerEstablishedStartupAuthorityProof { transport_policy })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use prw_connectivity::TransportIdentity;
    use prw_control_plane::{
        DeviceIdentityAlgorithm, DeviceIdentityBinding, DeviceIdentityPublicKeyEncoding,
        PublicIdentityMaterial,
    };
    use prw_core::DeviceLifecycle;
    use prw_registry::durable_registry_sqlite_store::DurableRegistrySqliteStore;
    use prw_transport_identity_provisioning::TransportIdentityProvisioningPolicy;

    use super::{
        OwnerEstablishedStartupAuthorityError,
        verify_established_owner_startup_authority_with_store,
    };
    use crate::owner_first_setup_bootstrap_inputs::generate_owner_logical_identity_record;

    fn database_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "prw-agent-established-startup-{label}-{}-{nonce}.sqlite3",
            std::process::id()
        ))
    }

    fn public_identity(byte: u8) -> PublicIdentityMaterial {
        PublicIdentityMaterial::new(
            DeviceIdentityAlgorithm::EcdsaP256Sha256,
            DeviceIdentityPublicKeyEncoding::SubjectPublicKeyInfoDer,
            vec![byte; 65],
        )
        .expect("public identity")
    }

    #[test]
    fn exact_owner_records_and_transport_produce_established_proof() {
        for policy in [
            TransportIdentityProvisioningPolicy::Preferred,
            TransportIdentityProvisioningPolicy::HostKeyOnly,
        ] {
            let path = database_path("exact");
            let mut store = DurableRegistrySqliteStore::open(&path).expect("open disposable store");
            let owner = generate_owner_logical_identity_record().expect("owner identity");
            let public_identity = public_identity(0x41);
            let transport_identity = TransportIdentity::new([0x51; 32]).expect("transport");
            let binding = DeviceIdentityBinding {
                workspace_id: owner.workspace_id().clone(),
                user_id: owner.user_id().clone(),
                device_id: owner.device_id().clone(),
                public_identity: public_identity.clone(),
                lifecycle: DeviceLifecycle::Enrolled,
            };
            store
                .bootstrap_fresh_owner_authority(binding, transport_identity)
                .expect("bootstrap disposable authority");

            let proof = verify_established_owner_startup_authority_with_store(
                &store,
                &owner,
                &public_identity,
                policy,
                transport_identity,
            )
            .expect("exact established proof");
            assert_eq!(proof.transport_policy(), policy);

            drop(store);
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
            let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
        }
    }

    #[test]
    fn missing_owner_membership_fails_closed() {
        let path = database_path("missing");
        let store = DurableRegistrySqliteStore::open(&path).expect("open disposable store");
        let owner = generate_owner_logical_identity_record().expect("owner identity");
        let public_identity = public_identity(0x42);
        let transport_identity = TransportIdentity::new([0x52; 32]).expect("transport");

        assert!(matches!(
            verify_established_owner_startup_authority_with_store(
                &store,
                &owner,
                &public_identity,
                TransportIdentityProvisioningPolicy::Preferred,
                transport_identity,
            ),
            Err(OwnerEstablishedStartupAuthorityError::OwnerMembershipMissing)
        ));

        drop(store);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn public_identity_or_transport_mismatch_fails_closed() {
        let path = database_path("mismatch");
        let mut store = DurableRegistrySqliteStore::open(&path).expect("open disposable store");
        let owner = generate_owner_logical_identity_record().expect("owner identity");
        let stored_public_identity = public_identity(0x43);
        let expected_public_identity = public_identity(0x44);
        let stored_transport = TransportIdentity::new([0x53; 32]).expect("stored transport");
        let other_transport = TransportIdentity::new([0x54; 32]).expect("other transport");
        let binding = DeviceIdentityBinding {
            workspace_id: owner.workspace_id().clone(),
            user_id: owner.user_id().clone(),
            device_id: owner.device_id().clone(),
            public_identity: stored_public_identity,
            lifecycle: DeviceLifecycle::Enrolled,
        };
        store
            .bootstrap_fresh_owner_authority(binding, stored_transport)
            .expect("bootstrap disposable authority");

        for (public_identity, transport_identity) in [
            (expected_public_identity, stored_transport),
            (public_identity(0x43), other_transport),
        ] {
            assert!(matches!(
                verify_established_owner_startup_authority_with_store(
                    &store,
                    &owner,
                    &public_identity,
                    TransportIdentityProvisioningPolicy::Preferred,
                    transport_identity,
                ),
                Err(OwnerEstablishedStartupAuthorityError::OwnerDeviceNotCurrent)
            ));
        }

        drop(store);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn suspended_membership_or_revoked_device_fails_closed() {
        for case in ["suspended", "revoked"] {
            let path = database_path(case);
            let mut store = DurableRegistrySqliteStore::open(&path).expect("open disposable store");
            let owner = generate_owner_logical_identity_record().expect("owner identity");
            let public_identity = public_identity(0x45);
            let transport_identity = TransportIdentity::new([0x55; 32]).expect("transport");
            let binding = DeviceIdentityBinding {
                workspace_id: owner.workspace_id().clone(),
                user_id: owner.user_id().clone(),
                device_id: owner.device_id().clone(),
                public_identity: public_identity.clone(),
                lifecycle: DeviceLifecycle::Enrolled,
            };
            store
                .bootstrap_fresh_owner_authority(binding, transport_identity)
                .expect("bootstrap disposable authority");

            if case == "suspended" {
                store
                    .suspend_membership(owner.workspace_id(), owner.user_id())
                    .expect("suspend");
            } else {
                store.revoke_device(owner.device_id()).expect("revoke");
            }

            let result = verify_established_owner_startup_authority_with_store(
                &store,
                &owner,
                &public_identity,
                TransportIdentityProvisioningPolicy::Preferred,
                transport_identity,
            );
            assert!(matches!(
                result,
                Err(
                    OwnerEstablishedStartupAuthorityError::OwnerMembershipNotCurrent
                        | OwnerEstablishedStartupAuthorityError::OwnerDeviceNotCurrent
                )
            ));

            drop(store);
            let _ = fs::remove_file(&path);
        }
    }
}
