//! Bounded workspace-membership and enrolled-device registry for PRW.
//!
//! This crate revalidates authenticated device-session identity against current membership and
//! device lifecycle state and owns provider-neutral persistence semantics plus bounded provider
//! adapters. It deliberately does not authenticate accounts, map roles to capabilities, or select
//! a transport.

pub mod durable_registry_authority;
pub mod durable_registry_codec;
pub mod durable_registry_etcd_store;
mod durable_registry_mutation_semantics;
mod durable_registry_semantics;
#[cfg(target_os = "linux")]
pub mod durable_registry_sqlite_custody;
#[cfg(target_os = "linux")]
pub mod durable_registry_sqlite_store;

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
};

use prw_connectivity::TransportIdentity;
use prw_control_plane::{DeviceIdentityBinding, PublicIdentityMaterial};
use prw_core::{DeviceId, DeviceLifecycle, UserId, WorkspaceId};
use prw_session::AuthenticatedDeviceSession;

/// Maximum membership entries held by one Phase 130 in-memory registry.
pub const MAX_MEMBERSHIPS: usize = 4096;
/// Maximum device entries held by one Phase 130 in-memory registry.
pub const MAX_REGISTERED_DEVICES: usize = 4096;

/// Workspace-membership role metadata.
///
/// Phase 130 does not translate roles into capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkspaceRole {
    /// Workspace owner role metadata.
    Owner,
    /// Workspace administrator role metadata.
    Admin,
    /// Ordinary workspace member role metadata.
    Member,
}

/// Current membership lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MembershipLifecycle {
    /// Membership may participate in current-registry validation.
    Active,
    /// Membership is retained but currently blocked.
    Suspended,
    /// Membership is terminally removed in the initial model.
    Removed,
}

/// Immutable workspace/user key plus mutable membership lifecycle metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMembership {
    workspace_id: WorkspaceId,
    user_id: UserId,
    role: WorkspaceRole,
    lifecycle: MembershipLifecycle,
}

impl WorkspaceMembership {
    /// Returns the workspace identifier.
    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    /// Returns the logical user identifier.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns membership role metadata.
    #[must_use]
    pub const fn role(&self) -> WorkspaceRole {
        self.role
    }

    /// Returns current membership lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> MembershipLifecycle {
        self.lifecycle
    }
}

/// Registered immutable device identity tuple plus current lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredDevice {
    binding: DeviceIdentityBinding,
    transport_identity: Option<TransportIdentity>,
}

impl RegisteredDevice {
    /// Returns the current exact device identity binding.
    #[must_use]
    pub const fn binding(&self) -> &DeviceIdentityBinding {
        &self.binding
    }

    /// Returns the current separately rotatable transport identity, when bound.
    #[must_use]
    pub const fn transport_identity(&self) -> Option<TransportIdentity> {
        self.transport_identity
    }
}

/// Registry-current principal snapshot after membership/device revalidation.
///
/// This type intentionally contains no capability set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryValidatedPrincipal {
    workspace_id: WorkspaceId,
    user_id: UserId,
    device_id: DeviceId,
    public_identity: PublicIdentityMaterial,
    role: WorkspaceRole,
}

impl RegistryValidatedPrincipal {
    /// Returns the validated workspace identifier.
    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    /// Returns the validated logical user identifier.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the validated device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Returns the validated canonical device public identity.
    #[must_use]
    pub const fn public_identity(&self) -> &PublicIdentityMaterial {
        &self.public_identity
    }

    /// Returns current membership role metadata.
    #[must_use]
    pub const fn role(&self) -> WorkspaceRole {
        self.role
    }
}

/// Stable Phase 130 registry failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    /// Membership entry count reached the locked bound.
    MembershipCapacity,
    /// Exact workspace/user membership key already exists.
    MembershipAlreadyExists,
    /// Exact workspace/user membership does not exist.
    MembershipUnknown,
    /// Membership is present but not active.
    MembershipNotActive,
    /// Membership removal is terminal.
    MembershipRemoved,
    /// Requested membership lifecycle transition is not valid.
    InvalidMembershipTransition,
    /// Device entry count reached the locked bound.
    DeviceCapacity,
    /// Device identifier already exists and cannot be rebound.
    DeviceAlreadyExists,
    /// Device is not exactly enrolled at registration time.
    DeviceNotEnrolled,
    /// Device identifier is absent.
    DeviceUnknown,
    /// Device is already revoked or cannot participate.
    DeviceRevoked,
    /// Authenticated session identity differs from current registry identity.
    SessionBindingMismatch,
    /// A current transport identity is already bound for this device.
    TransportIdentityAlreadyBound,
    /// No current transport identity is bound for this device.
    TransportIdentityMissing,
    /// Presented/expected transport identity differs from the current binding.
    TransportIdentityMismatch,
    /// Transport rotation supplied the same identity as replacement.
    TransportIdentityUnchanged,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MembershipCapacity => "membership registry capacity reached",
            Self::MembershipAlreadyExists => "membership already exists",
            Self::MembershipUnknown => "membership not found",
            Self::MembershipNotActive => "membership is not active",
            Self::MembershipRemoved => "membership was removed",
            Self::InvalidMembershipTransition => "invalid membership transition",
            Self::DeviceCapacity => "device registry capacity reached",
            Self::DeviceAlreadyExists => "device already exists",
            Self::DeviceNotEnrolled => "device is not enrolled",
            Self::DeviceUnknown => "device not found",
            Self::DeviceRevoked => "device is revoked",
            Self::SessionBindingMismatch => "authenticated session binding mismatch",
            Self::TransportIdentityAlreadyBound => "transport identity already bound",
            Self::TransportIdentityMissing => "transport identity is not bound",
            Self::TransportIdentityMismatch => "transport identity does not match current binding",
            Self::TransportIdentityUnchanged => {
                "transport identity rotation requires a distinct replacement"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RegistryError {}

/// Bounded in-memory Phase 130 registry authority.
#[derive(Debug, Default)]
pub struct WorkspaceDeviceRegistry {
    memberships: HashMap<(WorkspaceId, UserId), WorkspaceMembership>,
    devices: HashMap<DeviceId, RegisteredDevice>,
}

impl WorkspaceDeviceRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts one active membership with immutable workspace/user key.
    ///
    /// # Errors
    ///
    /// Rejects duplicate keys and capacity overflow before state mutation.
    pub fn add_membership(
        &mut self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> Result<&WorkspaceMembership, RegistryError> {
        let key = (workspace_id.clone(), user_id.clone());
        let at_capacity = self.memberships.len() >= MAX_MEMBERSHIPS;
        match self.memberships.entry(key) {
            Entry::Occupied(_) => Err(RegistryError::MembershipAlreadyExists),
            Entry::Vacant(entry) => {
                if at_capacity {
                    return Err(RegistryError::MembershipCapacity);
                }
                Ok(entry.insert(WorkspaceMembership {
                    workspace_id,
                    user_id,
                    role,
                    lifecycle: MembershipLifecycle::Active,
                }))
            }
        }
    }

    /// Returns an exact membership by workspace/user key.
    #[must_use]
    pub fn membership(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Option<&WorkspaceMembership> {
        self.memberships
            .get(&(workspace_id.clone(), user_id.clone()))
    }

    /// Suspends an active membership.
    ///
    /// # Errors
    ///
    /// Rejects absent, already suspended, or removed memberships.
    pub fn suspend_membership(
        &mut self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), RegistryError> {
        let membership = self
            .memberships
            .get_mut(&(workspace_id.clone(), user_id.clone()))
            .ok_or(RegistryError::MembershipUnknown)?;
        match membership.lifecycle {
            MembershipLifecycle::Active => {
                membership.lifecycle = MembershipLifecycle::Suspended;
                Ok(())
            }
            MembershipLifecycle::Suspended => Err(RegistryError::InvalidMembershipTransition),
            MembershipLifecycle::Removed => Err(RegistryError::MembershipRemoved),
        }
    }

    /// Removes an active or suspended membership terminally.
    ///
    /// # Errors
    ///
    /// Rejects absent or already removed memberships.
    pub fn remove_membership(
        &mut self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), RegistryError> {
        let membership = self
            .memberships
            .get_mut(&(workspace_id.clone(), user_id.clone()))
            .ok_or(RegistryError::MembershipUnknown)?;
        match membership.lifecycle {
            MembershipLifecycle::Active | MembershipLifecycle::Suspended => {
                membership.lifecycle = MembershipLifecycle::Removed;
                Ok(())
            }
            MembershipLifecycle::Removed => Err(RegistryError::MembershipRemoved),
        }
    }

    /// Registers one exact enrolled device binding under an active membership.
    ///
    /// # Errors
    ///
    /// Rejects non-enrolled devices, absent/inactive memberships, duplicate device
    /// identifiers, and capacity overflow before insertion.
    pub fn register_device(
        &mut self,
        binding: DeviceIdentityBinding,
    ) -> Result<&RegisteredDevice, RegistryError> {
        if binding.lifecycle != DeviceLifecycle::Enrolled {
            return Err(RegistryError::DeviceNotEnrolled);
        }
        let membership = self
            .membership(&binding.workspace_id, &binding.user_id)
            .ok_or(RegistryError::MembershipUnknown)?;
        if membership.lifecycle != MembershipLifecycle::Active {
            return Err(RegistryError::MembershipNotActive);
        }
        let at_capacity = self.devices.len() >= MAX_REGISTERED_DEVICES;
        let device_id = binding.device_id.clone();
        match self.devices.entry(device_id) {
            Entry::Occupied(_) => Err(RegistryError::DeviceAlreadyExists),
            Entry::Vacant(entry) => {
                if at_capacity {
                    return Err(RegistryError::DeviceCapacity);
                }
                Ok(entry.insert(RegisteredDevice {
                    binding,
                    transport_identity: None,
                }))
            }
        }
    }

    /// Returns a registered device by identifier.
    #[must_use]
    pub fn device(&self, device_id: &DeviceId) -> Option<&RegisteredDevice> {
        self.devices.get(device_id)
    }

    /// Binds the first current mesh transport identity to one enrolled registered device.
    ///
    /// # Errors
    ///
    /// Rejects unknown/revoked devices and a second initial bind.
    pub fn bind_transport_identity(
        &mut self,
        device_id: &DeviceId,
        identity: TransportIdentity,
    ) -> Result<(), RegistryError> {
        let device = self
            .devices
            .get_mut(device_id)
            .ok_or(RegistryError::DeviceUnknown)?;
        if device.binding.lifecycle != DeviceLifecycle::Enrolled {
            return Err(RegistryError::DeviceRevoked);
        }
        if device.transport_identity.is_some() {
            return Err(RegistryError::TransportIdentityAlreadyBound);
        }
        device.transport_identity = Some(identity);
        Ok(())
    }

    /// Atomically compare-and-rotates one current mesh transport identity.
    ///
    /// # Errors
    ///
    /// Rejects unknown/revoked/unbound devices, stale expected identity or an unchanged replacement.
    pub fn rotate_transport_identity(
        &mut self,
        device_id: &DeviceId,
        expected_current: TransportIdentity,
        replacement: TransportIdentity,
    ) -> Result<(), RegistryError> {
        if expected_current == replacement {
            return Err(RegistryError::TransportIdentityUnchanged);
        }
        let device = self
            .devices
            .get_mut(device_id)
            .ok_or(RegistryError::DeviceUnknown)?;
        if device.binding.lifecycle != DeviceLifecycle::Enrolled {
            return Err(RegistryError::DeviceRevoked);
        }
        let current = device
            .transport_identity
            .ok_or(RegistryError::TransportIdentityMissing)?;
        if current != expected_current {
            return Err(RegistryError::TransportIdentityMismatch);
        }
        device.transport_identity = Some(replacement);
        Ok(())
    }

    /// Validates one presented mesh transport identity against current device state.
    ///
    /// # Errors
    ///
    /// Rejects unknown/revoked/unbound devices and stale or mismatched identities.
    pub fn validate_transport_identity(
        &self,
        device_id: &DeviceId,
        presented: TransportIdentity,
    ) -> Result<(), RegistryError> {
        let device = self
            .devices
            .get(device_id)
            .ok_or(RegistryError::DeviceUnknown)?;
        if device.binding.lifecycle != DeviceLifecycle::Enrolled {
            return Err(RegistryError::DeviceRevoked);
        }
        let current = device
            .transport_identity
            .ok_or(RegistryError::TransportIdentityMissing)?;
        if current != presented {
            return Err(RegistryError::TransportIdentityMismatch);
        }
        Ok(())
    }

    /// Revokes one enrolled device terminally while retaining its immutable tuple.
    ///
    /// # Errors
    ///
    /// Rejects unknown or already non-participating devices.
    pub fn revoke_device(&mut self, device_id: &DeviceId) -> Result<(), RegistryError> {
        let device = self
            .devices
            .get_mut(device_id)
            .ok_or(RegistryError::DeviceUnknown)?;
        match device.binding.lifecycle {
            DeviceLifecycle::Enrolled => {
                device.binding.lifecycle = DeviceLifecycle::Revoked;
                Ok(())
            }
            DeviceLifecycle::PendingEnrollment => Err(RegistryError::DeviceNotEnrolled),
            DeviceLifecycle::Revoked => Err(RegistryError::DeviceRevoked),
        }
    }

    /// Revalidates a Phase 128 authenticated session against current registry state.
    ///
    /// The returned principal contains current role metadata but no capabilities.
    ///
    /// # Errors
    ///
    /// Rejects missing/inactive membership, missing/revoked device, or any mismatch
    /// between the authenticated-session snapshot and the immutable registry tuple.
    pub fn validate_authenticated_session(
        &self,
        session: &AuthenticatedDeviceSession,
    ) -> Result<RegistryValidatedPrincipal, RegistryError> {
        let membership = self
            .membership(session.workspace_id(), session.user_id())
            .ok_or(RegistryError::MembershipUnknown)?;
        if membership.lifecycle != MembershipLifecycle::Active {
            return Err(RegistryError::MembershipNotActive);
        }

        let device = self
            .devices
            .get(session.device_id())
            .ok_or(RegistryError::DeviceUnknown)?;
        if device.binding.lifecycle != DeviceLifecycle::Enrolled {
            return Err(RegistryError::DeviceRevoked);
        }
        if &device.binding.workspace_id != session.workspace_id()
            || &device.binding.user_id != session.user_id()
            || &device.binding.device_id != session.device_id()
            || &device.binding.public_identity != session.public_identity()
        {
            return Err(RegistryError::SessionBindingMismatch);
        }

        Ok(RegistryValidatedPrincipal {
            workspace_id: session.workspace_id().clone(),
            user_id: session.user_id().clone(),
            device_id: session.device_id().clone(),
            public_identity: session.public_identity().clone(),
            role: membership.role,
        })
    }

    /// Returns current membership entry count.
    #[must_use]
    pub fn membership_count(&self) -> usize {
        self.memberships.len()
    }

    /// Returns current registered-device entry count.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.len()
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
    use prw_session::SessionAuthenticationService;

    use super::{
        MAX_MEMBERSHIPS, MAX_REGISTERED_DEVICES, MembershipLifecycle, RegistryError,
        WorkspaceDeviceRegistry, WorkspaceRole,
    };

    fn signer() -> UbuntuEnrollmentSigner {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable registry key");
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
            .expect("load disposable registry signer")
    }

    fn ids() -> (WorkspaceId, UserId) {
        (
            WorkspaceId::new("workspace-1").expect("workspace id"),
            UserId::new("user-1").expect("user id"),
        )
    }

    fn binding(
        signer: &UbuntuEnrollmentSigner,
        workspace_id: WorkspaceId,
        user_id: UserId,
        device: &str,
        lifecycle: DeviceLifecycle,
    ) -> DeviceIdentityBinding {
        DeviceIdentityBinding {
            workspace_id,
            user_id,
            device_id: DeviceId::new(device).expect("device id"),
            public_identity: signer.public_identity().clone(),
            lifecycle,
        }
    }

    fn authenticated_session(
        signer: &UbuntuEnrollmentSigner,
        binding: &DeviceIdentityBinding,
        session: &str,
    ) -> prw_session::AuthenticatedDeviceSession {
        let mut service = SessionAuthenticationService::new();
        let session_id = SessionId::new(session).expect("session id");
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

    #[test]
    fn membership_uniqueness_and_role_are_exact() {
        let (workspace, user) = ids();
        let mut registry = WorkspaceDeviceRegistry::new();
        let membership = registry
            .add_membership(workspace.clone(), user.clone(), WorkspaceRole::Admin)
            .expect("add membership");
        assert_eq!(membership.role(), WorkspaceRole::Admin);
        assert_eq!(membership.lifecycle(), MembershipLifecycle::Active);
        assert_eq!(
            registry.add_membership(workspace, user, WorkspaceRole::Owner),
            Err(RegistryError::MembershipAlreadyExists)
        );
        assert_eq!(registry.membership_count(), 1);
    }

    #[test]
    fn membership_capacity_fails_before_insertion() {
        let mut registry = WorkspaceDeviceRegistry::new();
        for index in 0..MAX_MEMBERSHIPS {
            registry
                .add_membership(
                    WorkspaceId::new(format!("workspace-{index}")).expect("workspace id"),
                    UserId::new("user").expect("user id"),
                    WorkspaceRole::Member,
                )
                .expect("fill bounded memberships");
        }
        assert_eq!(
            registry.add_membership(
                WorkspaceId::new("workspace-overflow").expect("workspace id"),
                UserId::new("user").expect("user id"),
                WorkspaceRole::Member,
            ),
            Err(RegistryError::MembershipCapacity)
        );
        assert_eq!(registry.membership_count(), MAX_MEMBERSHIPS);
    }

    #[test]
    fn device_registration_requires_active_membership_and_enrolled_lifecycle() {
        let signer = signer();
        let (workspace, user) = ids();
        let mut registry = WorkspaceDeviceRegistry::new();
        assert_eq!(
            registry.register_device(binding(
                &signer,
                workspace.clone(),
                user.clone(),
                "device-1",
                DeviceLifecycle::Enrolled,
            )),
            Err(RegistryError::MembershipUnknown)
        );
        registry
            .add_membership(workspace.clone(), user.clone(), WorkspaceRole::Member)
            .expect("membership");
        assert_eq!(
            registry.register_device(binding(
                &signer,
                workspace.clone(),
                user.clone(),
                "pending-device",
                DeviceLifecycle::PendingEnrollment,
            )),
            Err(RegistryError::DeviceNotEnrolled)
        );
        assert_eq!(
            registry.register_device(binding(
                &signer,
                workspace,
                user,
                "revoked-device",
                DeviceLifecycle::Revoked,
            )),
            Err(RegistryError::DeviceNotEnrolled)
        );
    }

    #[test]
    fn duplicate_device_id_never_rebinds() {
        let signer = signer();
        let (workspace, user) = ids();
        let mut registry = WorkspaceDeviceRegistry::new();
        registry
            .add_membership(workspace.clone(), user.clone(), WorkspaceRole::Owner)
            .expect("membership");
        let original = binding(
            &signer,
            workspace,
            user,
            "device-1",
            DeviceLifecycle::Enrolled,
        );
        registry
            .register_device(original.clone())
            .expect("register device");
        assert_eq!(
            registry.register_device(original),
            Err(RegistryError::DeviceAlreadyExists)
        );
        assert_eq!(registry.device_count(), 1);
    }

    #[test]
    fn device_capacity_fails_before_insertion() {
        let signer = signer();
        let (workspace, user) = ids();
        let mut registry = WorkspaceDeviceRegistry::new();
        registry
            .add_membership(workspace.clone(), user.clone(), WorkspaceRole::Member)
            .expect("membership");
        for index in 0..MAX_REGISTERED_DEVICES {
            registry
                .register_device(binding(
                    &signer,
                    workspace.clone(),
                    user.clone(),
                    &format!("device-{index}"),
                    DeviceLifecycle::Enrolled,
                ))
                .expect("fill device registry");
        }
        assert_eq!(
            registry.register_device(binding(
                &signer,
                workspace,
                user,
                "device-overflow",
                DeviceLifecycle::Enrolled,
            )),
            Err(RegistryError::DeviceCapacity)
        );
        assert_eq!(registry.device_count(), MAX_REGISTERED_DEVICES);
    }

    #[test]
    fn authenticated_session_revalidates_current_membership_and_device_state() {
        let signer = signer();
        let (workspace, user) = ids();
        let bound = binding(
            &signer,
            workspace.clone(),
            user.clone(),
            "device-1",
            DeviceLifecycle::Enrolled,
        );
        let session = authenticated_session(&signer, &bound, "session-1");

        let mut registry = WorkspaceDeviceRegistry::new();
        registry
            .add_membership(workspace.clone(), user.clone(), WorkspaceRole::Admin)
            .expect("membership");
        registry.register_device(bound).expect("register device");

        let principal = registry
            .validate_authenticated_session(&session)
            .expect("current registry validation");
        assert_eq!(principal.workspace_id(), &workspace);
        assert_eq!(principal.user_id(), &user);
        assert_eq!(principal.role(), WorkspaceRole::Admin);

        registry
            .suspend_membership(&workspace, &user)
            .expect("suspend membership");
        assert_eq!(
            registry.validate_authenticated_session(&session),
            Err(RegistryError::MembershipNotActive)
        );
    }

    #[test]
    fn removal_and_revocation_are_terminal_for_validation() {
        let signer = signer();
        let (workspace, user) = ids();
        let bound = binding(
            &signer,
            workspace.clone(),
            user.clone(),
            "device-1",
            DeviceLifecycle::Enrolled,
        );
        let session = authenticated_session(&signer, &bound, "session-terminal");

        let mut registry = WorkspaceDeviceRegistry::new();
        registry
            .add_membership(workspace.clone(), user.clone(), WorkspaceRole::Member)
            .expect("membership");
        registry.register_device(bound).expect("register device");
        registry
            .revoke_device(session.device_id())
            .expect("revoke device");
        assert_eq!(
            registry.validate_authenticated_session(&session),
            Err(RegistryError::DeviceRevoked)
        );
        assert_eq!(
            registry.revoke_device(session.device_id()),
            Err(RegistryError::DeviceRevoked)
        );

        registry
            .remove_membership(&workspace, &user)
            .expect("remove membership");
        assert_eq!(
            registry.remove_membership(&workspace, &user),
            Err(RegistryError::MembershipRemoved)
        );
    }
}
