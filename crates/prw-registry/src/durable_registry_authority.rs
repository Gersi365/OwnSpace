//! Provider-neutral durable-registry authority boundary.
//!
//! C03e-YG extracts only the exact durable registry semantics already required by current
//! peer-identity lookup and post-auth capability authorization. It selects no database,
//! provider bootstrap, schema, credential source, runtime activation or migration behavior.

use std::{fmt, future::Future, pin::Pin};

use prw_connectivity::TransportIdentity;
use prw_core::DeviceId;
use prw_session::AuthenticatedDeviceSession;

use crate::{RegistryError, RegistryValidatedPrincipal};

/// Provider-neutral failure surface for authoritative durable-registry operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurableRegistryAuthorityError {
    /// Registry domain semantics rejected the requested observation or state.
    Semantic(RegistryError),
    /// An authoritative read could not be obtained.
    ReadUnavailable,
    /// A mutation returned no definitive commit outcome.
    MutationIndeterminate,
    /// Stored authority shape or canonical registry state is malformed or inconsistent.
    InvalidAuthority,
    /// Currentness moved without proving a registry-domain semantic error.
    CurrentnessConflict,
}

impl fmt::Display for DurableRegistryAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Semantic(error) => {
                write!(formatter, "durable registry semantic failure: {error}")
            }
            Self::ReadUnavailable => {
                formatter.write_str("durable registry authoritative read unavailable")
            }
            Self::MutationIndeterminate => {
                formatter.write_str("durable registry mutation outcome is indeterminate")
            }
            Self::InvalidAuthority => formatter.write_str("durable registry authority is invalid"),
            Self::CurrentnessConflict => {
                formatter.write_str("durable registry currentness conflict")
            }
        }
    }
}

impl std::error::Error for DurableRegistryAuthorityError {}

/// Minimal authoritative registry port required by the current production callers.
///
/// This boundary intentionally contains only the two read/revalidation semantics proven by current
/// callers. Lifecycle mutation methods remain outside this first port until a later caller-driven
/// checkpoint requires them.
/// Boxed provider-neutral operation future used to keep the authority boundary object-safe.
pub type DurableRegistryAuthorityFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DurableRegistryAuthorityError>> + Send + 'a>>;

pub trait DurableRegistryAuthority: Send {
    /// Returns the exact current enrolled/bound transport identity for one logical device.
    fn current_transport_identity<'a>(
        &'a mut self,
        device_id: &'a DeviceId,
    ) -> DurableRegistryAuthorityFuture<'a, TransportIdentity>;

    /// Revalidates one authenticated session and its presented transport identity against one
    /// consistent authoritative current registry observation.
    fn validate_authenticated_session_and_transport_identity<'a>(
        &'a mut self,
        session: &'a AuthenticatedDeviceSession,
        presented: TransportIdentity,
    ) -> DurableRegistryAuthorityFuture<'a, RegistryValidatedPrincipal>;
}
