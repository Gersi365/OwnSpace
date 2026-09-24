//! Shared domain types for Ownspace.

use std::fmt;

/// Strongly typed workspace identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceId(String);

impl WorkspaceId {
    /// Creates a workspace identifier from a non-empty value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::Empty`] if the supplied value is empty or whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        build_identifier(value).map(Self)
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Strongly typed user identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl UserId {
    /// Creates a user identifier from a non-empty value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::Empty`] if the supplied value is empty or whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        build_identifier(value).map(Self)
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Strongly typed device identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Creates a device identifier from a non-empty value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::Empty`] if the supplied value is empty or whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        build_identifier(value).map(Self)
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Strongly typed transfer identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransferId(String);

impl TransferId {
    /// Creates a transfer identifier from a non-empty value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::Empty`] if the supplied value is empty or whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        build_identifier(value).map(Self)
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Strongly typed session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Creates a session identifier from a non-empty value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::Empty`] if the supplied value is empty or whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        build_identifier(value).map(Self)
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Strongly typed enrollment identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnrollmentId(String);

impl EnrollmentId {
    /// Creates an enrollment identifier from a non-empty value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError::Empty`] if the supplied value is empty or whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        build_identifier(value).map(Self)
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Device enrollment lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLifecycle {
    /// Device exists but has not completed enrollment.
    PendingEnrollment,
    /// Device is enrolled and may participate according to policy.
    Enrolled,
    /// Device has been revoked.
    Revoked,
}

impl DeviceLifecycle {
    /// Returns whether this lifecycle state permits normal enrolled-device participation.
    #[must_use]
    pub const fn can_participate(self) -> bool {
        matches!(self, Self::Enrolled)
    }
}

/// Abstract connectivity path selected for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityPath {
    /// Direct path on a local network.
    LocalDirect,
    /// Direct path across the Internet.
    InternetDirect,
    /// Encrypted application traffic carried through a relay.
    Relay,
    /// No usable path is currently available.
    Offline,
}

/// Identifier validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifierError {
    /// The supplied identifier was empty or whitespace.
    Empty,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("identifier must not be empty"),
        }
    }
}

impl std::error::Error for IdentifierError {}

fn build_identifier(value: impl Into<String>) -> Result<String, IdentifierError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(IdentifierError::Empty);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{DeviceId, DeviceLifecycle, EnrollmentId, IdentifierError};

    #[test]
    fn rejects_empty_identifier() {
        assert_eq!(DeviceId::new("   "), Err(IdentifierError::Empty));
    }

    #[test]
    fn preserves_non_empty_identifier() {
        let id = DeviceId::new("device-1").expect("valid identifier");
        assert_eq!(id.as_str(), "device-1");
    }

    #[test]
    fn enrollment_identifier_is_strongly_typed() {
        let id = EnrollmentId::new("enrollment-1").expect("valid enrollment identifier");
        assert_eq!(id.as_str(), "enrollment-1");
    }

    #[test]
    fn only_enrolled_devices_can_participate() {
        assert!(!DeviceLifecycle::PendingEnrollment.can_participate());
        assert!(DeviceLifecycle::Enrolled.can_participate());
        assert!(!DeviceLifecycle::Revoked.can_participate());
    }
}
