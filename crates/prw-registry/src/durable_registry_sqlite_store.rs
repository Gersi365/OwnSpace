//! Owner-PC local `SQLite` implementation of the provider-neutral durable registry authority.
//!
//! This checkpoint creates only a dormant local provider. It does not wire startup, migrate live
//! state, delete the historical provider, or activate a database in the installed product.

use std::{fmt, path::Path};

use prw_connectivity::TransportIdentity;
use prw_control_plane::DeviceIdentityBinding;
use prw_core::{DeviceId, DeviceLifecycle, UserId, WorkspaceId};
use prw_session::AuthenticatedDeviceSession;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::{
    MembershipLifecycle, RegisteredDevice, RegistryError, RegistryValidatedPrincipal,
    WorkspaceMembership, WorkspaceRole,
    durable_registry_authority::{
        DurableRegistryAuthority, DurableRegistryAuthorityError, DurableRegistryAuthorityFuture,
    },
    durable_registry_codec::{
        decode_bound_device_record, decode_bound_membership_record, encode_device_key,
        encode_device_value, encode_membership_key, encode_membership_value,
    },
    durable_registry_mutation_semantics::{
        bind_transport_successor, remove_membership_successor, revoke_device_successor,
        rotate_transport_successor, suspend_membership_successor,
    },
    durable_registry_semantics::{
        current_transport_from_device, validate_presented_transport_from_device,
        validate_session_records,
    },
};

const SQLITE_SCHEMA_VERSION: i64 = 1;

const CREATE_SCHEMA_V1: &str = "
CREATE TABLE prw_registry_memberships (
    workspace_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE prw_registry_devices (
    device_id TEXT PRIMARY KEY NOT NULL,
    record BLOB NOT NULL
);

PRAGMA user_version = 1;
";

/// Failure while opening/configuring the dormant local `SQLite` authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableRegistrySqliteOpenError {
    Open,
    Configure,
    Migration,
    UnsupportedSchemaVersion,
}

impl fmt::Display for DurableRegistrySqliteOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Open => "local registry database open failed",
            Self::Configure => "local registry database configuration failed",
            Self::Migration => "local registry database migration failed",
            Self::UnsupportedSchemaVersion => "local registry database schema version unsupported",
        })
    }
}

impl std::error::Error for DurableRegistrySqliteOpenError {}

/// Dormant owner-PC `SQLite` registry authority.
pub struct DurableRegistrySqliteStore {
    connection: Connection,
}

/// Result of one fresh-install owner authority bootstrap attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerPcLocalAuthorityBootstrapOutcome {
    /// The empty local authority was initialized atomically.
    Initialized,
    /// The exact same owner membership, device binding, and transport identity were already current.
    AlreadyCurrent,
}

impl DurableRegistrySqliteStore {
    /// Opens one owner-PC local database, applies the locked WAL/foreign-key baseline and initializes
    /// the explicit v1 schema when the database is new.
    ///
    /// This function does not import old provider data and does not activate application startup.
    ///
    /// # Errors
    ///
    /// Fails closed on open/configuration/migration error or an unsupported future schema version.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DurableRegistrySqliteOpenError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let mut connection = Connection::open_with_flags(path, flags)
            .map_err(|_| DurableRegistrySqliteOpenError::Open)?;

        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|_| DurableRegistrySqliteOpenError::Configure)?;

        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
            .map_err(|_| DurableRegistrySqliteOpenError::Configure)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(DurableRegistrySqliteOpenError::Configure);
        }

        let foreign_keys: i64 = connection
            .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
            .map_err(|_| DurableRegistrySqliteOpenError::Configure)?;
        if foreign_keys != 1 {
            return Err(DurableRegistrySqliteOpenError::Configure);
        }

        migrate_schema(&mut connection)?;

        Ok(Self { connection })
    }

    /// Opens one already-existing owner-PC authority without creating or migrating state.
    ///
    /// This read-only path is for post-first-run restart validation. It never creates the database,
    /// changes journal mode, runs schema migration, or performs a semantic registry mutation.
    ///
    /// # Errors
    ///
    /// Fails closed when the database cannot be opened read-only, is not on the locked WAL baseline,
    /// or does not carry the exact current schema version.
    pub fn open_existing_read_only(
        path: impl AsRef<Path>,
    ) -> Result<Self, DurableRegistrySqliteOpenError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(path, flags)
            .map_err(|_| DurableRegistrySqliteOpenError::Open)?;

        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
            .map_err(|_| DurableRegistrySqliteOpenError::Configure)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(DurableRegistrySqliteOpenError::Configure);
        }

        let user_version: i64 = connection
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .map_err(|_| DurableRegistrySqliteOpenError::Configure)?;
        if user_version != SQLITE_SCHEMA_VERSION {
            return Err(DurableRegistrySqliteOpenError::UnsupportedSchemaVersion);
        }
        verify_schema_v1(&connection)?;

        Ok(Self { connection })
    }

    /// Loads one exact current membership from the local authority.
    ///
    /// # Errors
    ///
    /// Fails closed when the local authority cannot be read or contains malformed bound data.
    pub fn membership(
        &self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<Option<WorkspaceMembership>, DurableRegistryAuthorityError> {
        load_membership_from_connection(&self.connection, workspace_id, user_id)
    }

    /// Loads one exact current registered device from the local authority.
    ///
    /// # Errors
    ///
    /// Fails closed when the local authority cannot be read or contains malformed bound data.
    pub fn device(
        &self,
        device_id: &DeviceId,
    ) -> Result<Option<RegisteredDevice>, DurableRegistryAuthorityError> {
        load_device_from_connection(&self.connection, device_id)
    }

    /// Creates one active membership only when the exact key is absent.
    ///
    /// # Errors
    ///
    /// Preserves the existing duplicate-membership semantic and fails closed on local mutation
    /// uncertainty.
    pub fn add_membership(
        &mut self,
        workspace_id: WorkspaceId,
        user_id: UserId,
        role: WorkspaceRole,
    ) -> Result<WorkspaceMembership, DurableRegistryAuthorityError> {
        let membership = WorkspaceMembership {
            workspace_id,
            user_id,
            role,
            lifecycle: MembershipLifecycle::Active,
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;

        if load_membership_from_connection(
            &transaction,
            membership.workspace_id(),
            membership.user_id(),
        )?
        .is_some()
        {
            return Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::MembershipAlreadyExists,
            ));
        }

        let value = encode_membership_value(&membership)
            .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;
        let changed = transaction
            .execute(
                "INSERT INTO prw_registry_memberships (workspace_id, user_id, record)
                 VALUES (?1, ?2, ?3);",
                params![
                    membership.workspace_id().as_str(),
                    membership.user_id().as_str(),
                    value
                ],
            )
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        if changed != 1 {
            return Err(DurableRegistryAuthorityError::InvalidAuthority);
        }
        transaction
            .commit()
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        Ok(membership)
    }

    /// Suspends one exact active membership in one immediate local transaction.
    ///
    /// # Errors
    ///
    /// Preserves the existing membership lifecycle semantics and fails closed on local mutation
    /// uncertainty.
    pub fn suspend_membership(
        &mut self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), DurableRegistryAuthorityError> {
        self.update_membership(workspace_id, user_id, suspend_membership_successor)
    }

    /// Terminally removes one exact active or suspended membership in one immediate local
    /// transaction.
    ///
    /// # Errors
    ///
    /// Preserves the existing membership lifecycle semantics and fails closed on local mutation
    /// uncertainty.
    pub fn remove_membership(
        &mut self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
    ) -> Result<(), DurableRegistryAuthorityError> {
        self.update_membership(workspace_id, user_id, remove_membership_successor)
    }

    /// Registers one enrolled/unbound device under one exact active membership.
    ///
    /// # Errors
    ///
    /// Preserves the existing registration precondition order and commits membership validation plus
    /// device creation atomically in one immediate local transaction.
    pub fn register_device(
        &mut self,
        binding: DeviceIdentityBinding,
    ) -> Result<RegisteredDevice, DurableRegistryAuthorityError> {
        if binding.lifecycle != DeviceLifecycle::Enrolled {
            return Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::DeviceNotEnrolled,
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        let membership =
            load_membership_from_connection(&transaction, &binding.workspace_id, &binding.user_id)?
                .ok_or(DurableRegistryAuthorityError::Semantic(
                    RegistryError::MembershipUnknown,
                ))?;
        if membership.lifecycle() != MembershipLifecycle::Active {
            return Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::MembershipNotActive,
            ));
        }

        if load_device_from_connection(&transaction, &binding.device_id)?.is_some() {
            return Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::DeviceAlreadyExists,
            ));
        }

        let device = RegisteredDevice {
            binding,
            transport_identity: None,
        };
        let value = encode_device_value(&device)
            .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;
        let changed = transaction
            .execute(
                "INSERT INTO prw_registry_devices (device_id, record)
                 VALUES (?1, ?2);",
                params![device.binding().device_id.as_str(), value],
            )
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        if changed != 1 {
            return Err(DurableRegistryAuthorityError::InvalidAuthority);
        }
        transaction
            .commit()
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        Ok(device)
    }

    /// Binds the first current transport identity to one exact enrolled/unbound device.
    ///
    /// # Errors
    ///
    /// Preserves unknown/revoked/already-bound semantics.
    pub fn bind_transport_identity(
        &mut self,
        device_id: &DeviceId,
        identity: TransportIdentity,
    ) -> Result<(), DurableRegistryAuthorityError> {
        self.update_device(device_id, |current| {
            bind_transport_successor(current, identity)
        })
    }

    /// Rotates one current transport identity when the exact expected identity is still current.
    ///
    /// # Errors
    ///
    /// Preserves missing/mismatch/unchanged/revoked semantics.
    pub fn rotate_transport_identity(
        &mut self,
        device_id: &DeviceId,
        expected_current: TransportIdentity,
        replacement: TransportIdentity,
    ) -> Result<(), DurableRegistryAuthorityError> {
        self.update_device(device_id, |current| {
            rotate_transport_successor(current, expected_current, replacement)
        })
    }

    /// Terminally revokes one enrolled device while preserving immutable identity and transport
    /// binding data.
    ///
    /// # Errors
    ///
    /// Preserves unknown/already-revoked semantics.
    pub fn revoke_device(
        &mut self,
        device_id: &DeviceId,
    ) -> Result<(), DurableRegistryAuthorityError> {
        self.update_device(device_id, revoke_device_successor)
    }

    fn update_membership<F>(
        &mut self,
        workspace_id: &WorkspaceId,
        user_id: &UserId,
        successor: F,
    ) -> Result<(), DurableRegistryAuthorityError>
    where
        F: FnOnce(
            &WorkspaceMembership,
        ) -> Result<WorkspaceMembership, DurableRegistryAuthorityError>,
    {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        let current = load_membership_from_connection(&transaction, workspace_id, user_id)?.ok_or(
            DurableRegistryAuthorityError::Semantic(RegistryError::MembershipUnknown),
        )?;
        let replacement = successor(&current)?;
        let value = encode_membership_value(&replacement)
            .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;
        let changed = transaction
            .execute(
                "UPDATE prw_registry_memberships
                 SET record = ?3
                 WHERE workspace_id = ?1 AND user_id = ?2;",
                params![workspace_id.as_str(), user_id.as_str(), value],
            )
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        if changed != 1 {
            return Err(DurableRegistryAuthorityError::CurrentnessConflict);
        }
        transaction
            .commit()
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)
    }

    fn update_device<F>(
        &mut self,
        device_id: &DeviceId,
        successor: F,
    ) -> Result<(), DurableRegistryAuthorityError>
    where
        F: FnOnce(&RegisteredDevice) -> Result<RegisteredDevice, DurableRegistryAuthorityError>,
    {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        let current = load_device_from_connection(&transaction, device_id)?.ok_or(
            DurableRegistryAuthorityError::Semantic(RegistryError::DeviceUnknown),
        )?;
        let replacement = successor(&current)?;
        let value = encode_device_value(&replacement)
            .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;
        let changed = transaction
            .execute(
                "UPDATE prw_registry_devices
                 SET record = ?2
                 WHERE device_id = ?1;",
                params![device_id.as_str(), value],
            )
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        if changed != 1 {
            return Err(DurableRegistryAuthorityError::CurrentnessConflict);
        }
        transaction
            .commit()
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)
    }

    /// Returns the exact current enrolled/bound transport identity for one logical device.
    ///
    /// # Errors
    ///
    /// Preserves unknown/revoked/unbound semantics and fails closed on malformed local authority.
    pub fn current_transport_identity(
        &mut self,
        device_id: &DeviceId,
    ) -> Result<TransportIdentity, DurableRegistryAuthorityError> {
        let device = self
            .device(device_id)?
            .ok_or(DurableRegistryAuthorityError::Semantic(
                RegistryError::DeviceUnknown,
            ))?;
        current_transport_from_device(&device)
    }

    /// Revalidates one authenticated session and its presented transport identity against one `SQLite`
    /// read transaction.
    ///
    /// # Errors
    ///
    /// Preserves membership/device/session/transport semantic errors while mapping local read failures
    /// to the provider-neutral durable authority envelope.
    pub fn validate_authenticated_session_and_transport_identity(
        &mut self,
        session: &AuthenticatedDeviceSession,
        presented: TransportIdentity,
    ) -> Result<RegistryValidatedPrincipal, DurableRegistryAuthorityError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| DurableRegistryAuthorityError::ReadUnavailable)?;

        let membership_blob: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record
                 FROM prw_registry_memberships
                 WHERE workspace_id = ?1 AND user_id = ?2;",
                params![session.workspace_id().as_str(), session.user_id().as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| DurableRegistryAuthorityError::ReadUnavailable)?;

        let membership_blob = membership_blob.ok_or(DurableRegistryAuthorityError::Semantic(
            RegistryError::MembershipUnknown,
        ))?;
        let membership_key = encode_membership_key(session.workspace_id(), session.user_id())
            .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;
        let membership = decode_bound_membership_record(
            &membership_key,
            &membership_blob,
            session.workspace_id(),
            session.user_id(),
        )
        .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;

        if membership.lifecycle() != MembershipLifecycle::Active {
            return Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::MembershipNotActive,
            ));
        }

        let device_blob: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT record
                 FROM prw_registry_devices
                 WHERE device_id = ?1;",
                params![session.device_id().as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| DurableRegistryAuthorityError::ReadUnavailable)?;

        let device_blob = device_blob.ok_or(DurableRegistryAuthorityError::Semantic(
            RegistryError::DeviceUnknown,
        ))?;
        let device_key = encode_device_key(session.device_id())
            .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;
        let device = decode_bound_device_record(&device_key, &device_blob, session.device_id())
            .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;

        let principal = validate_session_records(
            session.workspace_id(),
            session.user_id(),
            session.device_id(),
            session.public_identity(),
            &membership,
            &device,
        )?;
        validate_presented_transport_from_device(&device, presented)?;
        Ok(principal)
    }
    /// Atomically initializes the fresh owner-PC authority for one enrolled owner device.
    ///
    /// The transaction creates exactly one active owner membership and one enrolled device already
    /// bound to its current transport identity. Repeating the exact same input is idempotent and
    /// returns the already-current outcome. Any partial or conflicting pre-existing authority fails
    /// closed without mutation.
    ///
    /// This method is dormant: it is not wired into Agent startup or any production activation path.
    ///
    /// # Errors
    ///
    /// Rejects non-enrolled bindings, malformed authority, unavailable local reads, indeterminate
    /// local writes, or any pre-existing state that is not the exact already-current bootstrap tuple.
    pub fn bootstrap_fresh_owner_authority(
        &mut self,
        binding: DeviceIdentityBinding,
        transport_identity: TransportIdentity,
    ) -> Result<OwnerPcLocalAuthorityBootstrapOutcome, DurableRegistryAuthorityError> {
        if binding.lifecycle != DeviceLifecycle::Enrolled {
            return Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::DeviceNotEnrolled,
            ));
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
        let membership =
            load_membership_from_connection(&transaction, &binding.workspace_id, &binding.user_id)?;
        let device = load_device_from_connection(&transaction, &binding.device_id)?;

        match (membership, device) {
            (None, None) => {
                let membership = WorkspaceMembership {
                    workspace_id: binding.workspace_id.clone(),
                    user_id: binding.user_id.clone(),
                    role: WorkspaceRole::Owner,
                    lifecycle: MembershipLifecycle::Active,
                };
                let device = RegisteredDevice {
                    binding,
                    transport_identity: Some(transport_identity),
                };
                let membership_value = encode_membership_value(&membership)
                    .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;
                let device_value = encode_device_value(&device)
                    .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;

                let membership_changed = transaction
                    .execute(
                        "INSERT INTO prw_registry_memberships (workspace_id, user_id, record)\n                         VALUES (?1, ?2, ?3);",
                        params![
                            membership.workspace_id().as_str(),
                            membership.user_id().as_str(),
                            membership_value
                        ],
                    )
                    .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
                let device_changed = transaction
                    .execute(
                        "INSERT INTO prw_registry_devices (device_id, record)\n                         VALUES (?1, ?2);",
                        params![device.binding().device_id.as_str(), device_value],
                    )
                    .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
                if membership_changed != 1 || device_changed != 1 {
                    return Err(DurableRegistryAuthorityError::InvalidAuthority);
                }

                transaction
                    .commit()
                    .map_err(|_| DurableRegistryAuthorityError::MutationIndeterminate)?;
                Ok(OwnerPcLocalAuthorityBootstrapOutcome::Initialized)
            }
            (Some(membership), Some(device))
                if membership.role() == WorkspaceRole::Owner
                    && membership.lifecycle() == MembershipLifecycle::Active
                    && device.binding() == &binding
                    && device.transport_identity() == Some(transport_identity) =>
            {
                Ok(OwnerPcLocalAuthorityBootstrapOutcome::AlreadyCurrent)
            }
            _ => Err(DurableRegistryAuthorityError::CurrentnessConflict),
        }
    }
}

fn load_membership_from_connection(
    connection: &Connection,
    workspace_id: &WorkspaceId,
    user_id: &UserId,
) -> Result<Option<WorkspaceMembership>, DurableRegistryAuthorityError> {
    let record: Option<Vec<u8>> = connection
        .query_row(
            "SELECT record
             FROM prw_registry_memberships
             WHERE workspace_id = ?1 AND user_id = ?2;",
            params![workspace_id.as_str(), user_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| DurableRegistryAuthorityError::ReadUnavailable)?;

    record
        .map(|record| {
            let key = encode_membership_key(workspace_id, user_id)
                .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;
            decode_bound_membership_record(&key, &record, workspace_id, user_id)
                .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)
        })
        .transpose()
}

fn load_device_from_connection(
    connection: &Connection,
    device_id: &DeviceId,
) -> Result<Option<RegisteredDevice>, DurableRegistryAuthorityError> {
    let record: Option<Vec<u8>> = connection
        .query_row(
            "SELECT record
             FROM prw_registry_devices
             WHERE device_id = ?1;",
            params![device_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| DurableRegistryAuthorityError::ReadUnavailable)?;

    record
        .map(|record| {
            let key = encode_device_key(device_id)
                .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)?;
            decode_bound_device_record(&key, &record, device_id)
                .map_err(|_| DurableRegistryAuthorityError::InvalidAuthority)
        })
        .transpose()
}

impl DurableRegistryAuthority for DurableRegistrySqliteStore {
    fn current_transport_identity<'a>(
        &'a mut self,
        device_id: &'a DeviceId,
    ) -> DurableRegistryAuthorityFuture<'a, TransportIdentity> {
        Box::pin(async move { Self::current_transport_identity(self, device_id) })
    }

    fn validate_authenticated_session_and_transport_identity<'a>(
        &'a mut self,
        session: &'a AuthenticatedDeviceSession,
        presented: TransportIdentity,
    ) -> DurableRegistryAuthorityFuture<'a, RegistryValidatedPrincipal> {
        Box::pin(async move {
            Self::validate_authenticated_session_and_transport_identity(self, session, presented)
        })
    }
}

fn migrate_schema(connection: &mut Connection) -> Result<(), DurableRegistrySqliteOpenError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|_| DurableRegistrySqliteOpenError::Migration)?;

    match version {
        0 => {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| DurableRegistrySqliteOpenError::Migration)?;
            transaction
                .execute_batch(CREATE_SCHEMA_V1)
                .map_err(|_| DurableRegistrySqliteOpenError::Migration)?;
            transaction
                .commit()
                .map_err(|_| DurableRegistrySqliteOpenError::Migration)?;
            Ok(())
        }
        SQLITE_SCHEMA_VERSION => verify_schema_v1(connection),
        _ => Err(DurableRegistrySqliteOpenError::UnsupportedSchemaVersion),
    }
}

fn verify_schema_v1(connection: &Connection) -> Result<(), DurableRegistrySqliteOpenError> {
    connection
        .prepare(
            "SELECT workspace_id, user_id, record
             FROM prw_registry_memberships
             LIMIT 0;",
        )
        .map_err(|_| DurableRegistrySqliteOpenError::Migration)?;
    connection
        .prepare(
            "SELECT device_id, record
             FROM prw_registry_devices
             LIMIT 0;",
        )
        .map_err(|_| DurableRegistrySqliteOpenError::Migration)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::symlink,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
    };
    use prw_connectivity::TransportIdentity;
    use prw_control_plane::DeviceIdentityBinding;
    use prw_core::{DeviceId, DeviceLifecycle, SessionId, UserId, WorkspaceId};
    use prw_device_identity_signer::UbuntuEnrollmentSigner;
    use prw_session::SessionAuthenticationService;

    use super::*;
    use crate::{
        MembershipLifecycle, RegisteredDevice, WorkspaceMembership, WorkspaceRole,
        durable_registry_codec::{encode_device_value, encode_membership_value},
    };

    static NEXT_TEST_DATABASE: AtomicU64 = AtomicU64::new(1);

    fn test_database_path(label: &str) -> PathBuf {
        let sequence = NEXT_TEST_DATABASE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "prw-registry-{label}-{}-{sequence}.sqlite3",
            std::process::id()
        ))
    }

    fn signer() -> UbuntuEnrollmentSigner {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable registry key");
        UbuntuEnrollmentSigner::from_pkcs8_v1_der(pkcs8.as_ref())
            .expect("load disposable registry signer")
    }

    fn membership(workspace_id: WorkspaceId, user_id: UserId) -> WorkspaceMembership {
        WorkspaceMembership {
            workspace_id,
            user_id,
            role: WorkspaceRole::Owner,
            lifecycle: MembershipLifecycle::Active,
        }
    }

    fn registered_device(
        binding: DeviceIdentityBinding,
        transport_identity: TransportIdentity,
    ) -> RegisteredDevice {
        RegisteredDevice {
            binding,
            transport_identity: Some(transport_identity),
        }
    }

    fn insert_membership(store: &DurableRegistrySqliteStore, membership: &WorkspaceMembership) {
        let value = encode_membership_value(membership).expect("membership encoding");
        store
            .connection
            .execute(
                "INSERT INTO prw_registry_memberships (workspace_id, user_id, record)
                 VALUES (?1, ?2, ?3);",
                params![
                    membership.workspace_id().as_str(),
                    membership.user_id().as_str(),
                    value
                ],
            )
            .expect("insert membership");
    }

    fn insert_device(store: &DurableRegistrySqliteStore, device: &RegisteredDevice) {
        let value = encode_device_value(device).expect("device encoding");
        store
            .connection
            .execute(
                "INSERT INTO prw_registry_devices (device_id, record)
                 VALUES (?1, ?2);",
                params![device.binding().device_id.as_str(), value],
            )
            .expect("insert device");
    }

    #[test]
    fn open_initializes_explicit_v1_wal_schema() {
        let path = test_database_path("schema");
        let store = DurableRegistrySqliteStore::open(&path).expect("open local sqlite authority");

        let user_version: i64 = store
            .connection
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .expect("user version");
        let journal_mode: String = store
            .connection
            .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
            .expect("journal mode");
        let foreign_keys: i64 = store
            .connection
            .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
            .expect("foreign keys");

        assert_eq!(user_version, SQLITE_SCHEMA_VERSION);
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(foreign_keys, 1);

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn open_rejects_symbolic_link_database_path() {
        let target = test_database_path("nofollow-target");
        let link = test_database_path("nofollow-link");
        let store = DurableRegistrySqliteStore::open(&target)
            .expect("create local sqlite authority target");
        drop(store);
        symlink(&target, &link).expect("create database symlink");

        assert!(matches!(
            DurableRegistrySqliteStore::open(&link),
            Err(DurableRegistrySqliteOpenError::Open)
        ));

        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
        let _ = fs::remove_file(target.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(target.with_extension("sqlite3-shm"));
    }

    #[test]
    fn read_only_open_requires_existing_current_schema() {
        let path = test_database_path("read-only-existing");
        {
            let _store =
                DurableRegistrySqliteStore::open(&path).expect("create current local authority");
        }

        let read_only = DurableRegistrySqliteStore::open_existing_read_only(&path)
            .expect("open current authority read-only");
        drop(read_only);

        let missing_path = test_database_path("read-only-missing");
        assert!(matches!(
            DurableRegistrySqliteStore::open_existing_read_only(&missing_path),
            Err(DurableRegistrySqliteOpenError::Open)
        ));
        assert!(!missing_path.exists());

        let malformed_path = test_database_path("read-only-malformed-v1");
        {
            let connection =
                rusqlite::Connection::open(&malformed_path).expect("create malformed v1 database");
            connection
                .execute_batch("PRAGMA journal_mode = WAL; PRAGMA user_version = 1;")
                .expect("mark malformed database as v1");
        }
        assert!(matches!(
            DurableRegistrySqliteStore::open_existing_read_only(&malformed_path),
            Err(DurableRegistrySqliteOpenError::Migration)
        ));
        let _ = fs::remove_file(&malformed_path);
        let _ = fs::remove_file(malformed_path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(malformed_path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn reads_current_transport_through_neutral_semantics() {
        let path = test_database_path("transport");
        let mut store =
            DurableRegistrySqliteStore::open(&path).expect("open local sqlite authority");
        let signer = signer();
        let binding = DeviceIdentityBinding {
            workspace_id: WorkspaceId::new("workspace-1").expect("workspace"),
            user_id: UserId::new("owner").expect("user"),
            device_id: DeviceId::new("device-1").expect("device"),
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };
        let transport = TransportIdentity::new([7; 32]).expect("transport");
        let device = registered_device(binding, transport);
        insert_device(&store, &device);

        assert_eq!(
            store
                .current_transport_identity(&device.binding().device_id)
                .expect("current transport"),
            transport
        );

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn validates_session_and_transport_from_one_local_transaction() {
        let path = test_database_path("session");
        let mut store =
            DurableRegistrySqliteStore::open(&path).expect("open local sqlite authority");
        let signer = signer();
        let workspace_id = WorkspaceId::new("workspace-1").expect("workspace");
        let user_id = UserId::new("owner").expect("user");
        let binding = DeviceIdentityBinding {
            workspace_id: workspace_id.clone(),
            user_id: user_id.clone(),
            device_id: DeviceId::new("device-1").expect("device"),
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };
        let transport = TransportIdentity::new([9; 32]).expect("transport");
        let membership = membership(workspace_id, user_id);
        let device = registered_device(binding.clone(), transport);
        insert_membership(&store, &membership);
        insert_device(&store, &device);

        let mut authentication = SessionAuthenticationService::new();
        let session_id = SessionId::new("session-1").expect("session");
        let challenge = authentication
            .begin_session(binding.clone(), session_id.clone(), 1_000, 1_300)
            .expect("begin session");
        let proof = signer
            .sign_session_auth_proof(&binding, &challenge)
            .expect("session proof");
        let session = authentication
            .submit_proof(&session_id, &proof, 1_001)
            .expect("authenticated session");

        let principal = store
            .validate_authenticated_session_and_transport_identity(&session, transport)
            .expect("validated principal");

        assert_eq!(principal.workspace_id(), membership.workspace_id());
        assert_eq!(principal.user_id(), membership.user_id());
        assert_eq!(principal.device_id(), &binding.device_id);

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn membership_mutations_preserve_terminal_lifecycle_semantics() {
        let path = test_database_path("membership-mutations");
        let mut store =
            DurableRegistrySqliteStore::open(&path).expect("open local sqlite authority");
        let workspace_id = WorkspaceId::new("workspace-m").expect("workspace");
        let user_id = UserId::new("owner-m").expect("user");

        let created = store
            .add_membership(workspace_id.clone(), user_id.clone(), WorkspaceRole::Owner)
            .expect("create membership");
        assert_eq!(created.lifecycle(), MembershipLifecycle::Active);
        assert_eq!(
            store.add_membership(workspace_id.clone(), user_id.clone(), WorkspaceRole::Owner,),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::MembershipAlreadyExists
            ))
        );

        store
            .suspend_membership(&workspace_id, &user_id)
            .expect("suspend active membership");
        assert_eq!(
            store
                .membership(&workspace_id, &user_id)
                .expect("read membership")
                .expect("membership present")
                .lifecycle(),
            MembershipLifecycle::Suspended
        );
        assert_eq!(
            store.suspend_membership(&workspace_id, &user_id),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::InvalidMembershipTransition
            ))
        );

        store
            .remove_membership(&workspace_id, &user_id)
            .expect("remove suspended membership");
        assert_eq!(
            store
                .membership(&workspace_id, &user_id)
                .expect("read membership")
                .expect("membership present")
                .lifecycle(),
            MembershipLifecycle::Removed
        );
        assert_eq!(
            store.remove_membership(&workspace_id, &user_id),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::MembershipRemoved
            ))
        );

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn device_mutations_are_atomic_and_preserve_identity_tuple() {
        let path = test_database_path("device-mutations");
        let mut store =
            DurableRegistrySqliteStore::open(&path).expect("open local sqlite authority");
        let signer = signer();
        let workspace_id = WorkspaceId::new("workspace-d").expect("workspace");
        let user_id = UserId::new("owner-d").expect("user");
        store
            .add_membership(workspace_id.clone(), user_id.clone(), WorkspaceRole::Owner)
            .expect("create active membership");

        let binding = DeviceIdentityBinding {
            workspace_id,
            user_id,
            device_id: DeviceId::new("device-d").expect("device"),
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };
        let registered = store
            .register_device(binding.clone())
            .expect("register device");
        assert_eq!(registered.binding(), &binding);
        assert_eq!(registered.transport_identity(), None);
        assert_eq!(
            store.register_device(binding.clone()),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::DeviceAlreadyExists
            ))
        );

        let first = TransportIdentity::new([11; 32]).expect("first transport");
        let second = TransportIdentity::new([12; 32]).expect("second transport");
        let stale = TransportIdentity::new([13; 32]).expect("stale transport");

        store
            .bind_transport_identity(&binding.device_id, first)
            .expect("bind first transport");
        assert_eq!(
            store.bind_transport_identity(&binding.device_id, second),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::TransportIdentityAlreadyBound
            ))
        );
        assert_eq!(
            store.rotate_transport_identity(&binding.device_id, stale, second),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::TransportIdentityMismatch
            ))
        );
        assert_eq!(
            store.rotate_transport_identity(&binding.device_id, first, first),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::TransportIdentityUnchanged
            ))
        );

        store
            .rotate_transport_identity(&binding.device_id, first, second)
            .expect("rotate transport");
        let rotated = store
            .device(&binding.device_id)
            .expect("read device")
            .expect("device present");
        assert_eq!(rotated.binding(), &binding);
        assert_eq!(rotated.transport_identity(), Some(second));

        store
            .revoke_device(&binding.device_id)
            .expect("revoke device");
        let revoked = store
            .device(&binding.device_id)
            .expect("read revoked device")
            .expect("device present");
        assert_eq!(revoked.binding().lifecycle, DeviceLifecycle::Revoked);
        assert_eq!(revoked.transport_identity(), Some(second));
        assert_eq!(
            store.revoke_device(&binding.device_id),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::DeviceRevoked
            ))
        );

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn device_registration_requires_active_membership_and_enrolled_binding() {
        let path = test_database_path("registration-preconditions");
        let mut store =
            DurableRegistrySqliteStore::open(&path).expect("open local sqlite authority");
        let signer = signer();
        let workspace_id = WorkspaceId::new("workspace-p").expect("workspace");
        let user_id = UserId::new("owner-p").expect("user");
        let mut binding = DeviceIdentityBinding {
            workspace_id: workspace_id.clone(),
            user_id: user_id.clone(),
            device_id: DeviceId::new("device-p").expect("device"),
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };

        assert_eq!(
            store.register_device(binding.clone()),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::MembershipUnknown
            ))
        );

        store
            .add_membership(workspace_id.clone(), user_id.clone(), WorkspaceRole::Owner)
            .expect("create membership");
        store
            .suspend_membership(&workspace_id, &user_id)
            .expect("suspend membership");
        assert_eq!(
            store.register_device(binding.clone()),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::MembershipNotActive
            ))
        );

        binding.lifecycle = DeviceLifecycle::PendingEnrollment;
        assert_eq!(
            store.register_device(binding),
            Err(DurableRegistryAuthorityError::Semantic(
                RegistryError::DeviceNotEnrolled
            ))
        );

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn fresh_owner_bootstrap_is_atomic_and_exactly_idempotent() {
        let path = test_database_path("fresh-owner-bootstrap");
        let mut store =
            DurableRegistrySqliteStore::open(&path).expect("open local sqlite authority");
        let signer = signer();
        let binding = DeviceIdentityBinding {
            workspace_id: WorkspaceId::new("workspace-1").expect("workspace"),
            user_id: UserId::new("owner").expect("user"),
            device_id: DeviceId::new("device-1").expect("device"),
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };
        let transport = TransportIdentity::new([21; 32]).expect("transport");

        assert_eq!(
            store
                .bootstrap_fresh_owner_authority(binding.clone(), transport)
                .expect("initialize fresh owner authority"),
            OwnerPcLocalAuthorityBootstrapOutcome::Initialized
        );
        assert_eq!(
            store
                .bootstrap_fresh_owner_authority(binding.clone(), transport)
                .expect("repeat exact owner bootstrap"),
            OwnerPcLocalAuthorityBootstrapOutcome::AlreadyCurrent
        );

        let membership = store
            .membership(&binding.workspace_id, &binding.user_id)
            .expect("membership read")
            .expect("owner membership");
        assert_eq!(membership.role(), WorkspaceRole::Owner);
        assert_eq!(membership.lifecycle(), MembershipLifecycle::Active);
        let device = store
            .device(&binding.device_id)
            .expect("device read")
            .expect("owner device");
        assert_eq!(device.binding(), &binding);
        assert_eq!(device.transport_identity(), Some(transport));

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn fresh_owner_bootstrap_rejects_partial_or_conflicting_existing_authority() {
        let path = test_database_path("fresh-owner-bootstrap-conflict");
        let mut store =
            DurableRegistrySqliteStore::open(&path).expect("open local sqlite authority");
        let signer = signer();
        let workspace_id = WorkspaceId::new("workspace-1").expect("workspace");
        let user_id = UserId::new("owner").expect("user");
        let binding = DeviceIdentityBinding {
            workspace_id: workspace_id.clone(),
            user_id: user_id.clone(),
            device_id: DeviceId::new("device-1").expect("device"),
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };
        let transport = TransportIdentity::new([22; 32]).expect("transport");
        insert_membership(&store, &membership(workspace_id, user_id));

        assert_eq!(
            store.bootstrap_fresh_owner_authority(binding.clone(), transport),
            Err(DurableRegistryAuthorityError::CurrentnessConflict)
        );
        assert!(
            store
                .device(&binding.device_id)
                .expect("device read after conflict")
                .is_none()
        );

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn fresh_owner_bootstrap_rejects_conflicting_exact_device_transport_without_mutation() {
        let path = test_database_path("fresh-owner-bootstrap-transport-conflict");
        let mut store =
            DurableRegistrySqliteStore::open(&path).expect("open local sqlite authority");
        let signer = signer();
        let binding = DeviceIdentityBinding {
            workspace_id: WorkspaceId::new("workspace-1").expect("workspace"),
            user_id: UserId::new("owner").expect("user"),
            device_id: DeviceId::new("device-1").expect("device"),
            public_identity: signer.public_identity().clone(),
            lifecycle: DeviceLifecycle::Enrolled,
        };
        let original = TransportIdentity::new([23; 32]).expect("original transport");
        let conflicting = TransportIdentity::new([24; 32]).expect("conflicting transport");
        assert_eq!(
            store
                .bootstrap_fresh_owner_authority(binding.clone(), original)
                .expect("initialize fresh owner authority"),
            OwnerPcLocalAuthorityBootstrapOutcome::Initialized
        );

        assert_eq!(
            store.bootstrap_fresh_owner_authority(binding.clone(), conflicting),
            Err(DurableRegistryAuthorityError::CurrentnessConflict)
        );
        assert_eq!(
            store
                .current_transport_identity(&binding.device_id)
                .expect("current transport after conflict"),
            original
        );

        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }
}
