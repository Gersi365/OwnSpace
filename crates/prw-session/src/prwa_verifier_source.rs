//! Pure server-local verifier source for PRWA pre-mesh authentication.
//!
//! This module materializes only the C03e-CE-selected `SessionId` and verifier-time
//! source. It performs no network I/O, owns no session registry, and does not begin
//! or verify an authentication transaction.

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use prw_control_plane::session_auth::MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS;
use prw_core::SessionId;

/// Exact cryptographically secure random input length for one PRWA verifier session ID.
pub const PRWA_VERIFIER_SESSION_ID_RANDOM_BYTES: usize = 32;
/// Exact lowercase hexadecimal byte length for one PRWA verifier session ID.
pub const PRWA_VERIFIER_SESSION_ID_HEX_BYTES: usize = 64;
/// Exact PRWA verifier challenge lifetime selected by C03e-CE.
pub const PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS: u64 =
    MAX_SESSION_AUTH_CHALLENGE_LIFETIME_SECONDS;

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Fresh server-owned correlation and time window for one PRWA authentication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrwaVerifierSessionContext {
    session_id: SessionId,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl PrwaVerifierSessionContext {
    /// Returns the freshly generated opaque session identifier.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the verifier-owned issue time in whole Unix seconds.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    /// Returns the verifier-owned expiry time in whole Unix seconds.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

/// Fail-closed PRWA verifier-source failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrwaVerifierSourceError {
    /// The OS-backed cryptographic provider could not produce `SessionId` randomness.
    SessionIdRandomness,
    /// The generated opaque hexadecimal value could not become a typed `SessionId`.
    SessionIdConstruction,
    /// The verifier wall clock could not be represented as Unix seconds.
    VerifierTime,
    /// Adding the locked challenge lifetime overflowed `u64` Unix seconds.
    ExpiryOverflow,
}

impl fmt::Display for PrwaVerifierSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SessionIdRandomness => "PRWA verifier SessionId randomness failed",
            Self::SessionIdConstruction => "PRWA verifier SessionId construction failed",
            Self::VerifierTime => "PRWA verifier time is not representable",
            Self::ExpiryOverflow => "PRWA verifier challenge expiry overflowed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PrwaVerifierSourceError {}

/// Creates one fresh server-local `SessionId` and exact verifier-owned challenge window.
///
/// This function performs exactly one randomness acquisition. It contains no collision
/// retry loop; duplicate-session rejection remains with `SessionAuthenticationService`
/// when a future runtime passes this context into `begin_session(...)`.
///
/// # Errors
///
/// Fails closed on cryptographic randomness failure, typed `SessionId` construction
/// failure, non-representable verifier time, or checked expiry overflow.
pub fn new_prwa_verifier_session_context()
-> Result<PrwaVerifierSessionContext, PrwaVerifierSourceError> {
    let mut random_bytes = [0_u8; PRWA_VERIFIER_SESSION_ID_RANDOM_BYTES];
    SystemRandom::new()
        .fill(&mut random_bytes)
        .map_err(|_| PrwaVerifierSourceError::SessionIdRandomness)?;
    let session_id = session_id_from_random_bytes(random_bytes)?;
    let issued_at_unix_seconds = current_prwa_verifier_unix_seconds()?;
    context_from_issued_at(session_id, issued_at_unix_seconds)
}

/// Observes the same verifier wall-clock authority used for later proof submission.
///
/// # Errors
///
/// Fails closed when the server wall clock precedes the Unix epoch.
pub fn current_prwa_verifier_unix_seconds() -> Result<u64, PrwaVerifierSourceError> {
    unix_seconds_from_system_time(SystemTime::now())
}

fn session_id_from_random_bytes(
    random_bytes: [u8; PRWA_VERIFIER_SESSION_ID_RANDOM_BYTES],
) -> Result<SessionId, PrwaVerifierSourceError> {
    let mut encoded = String::with_capacity(PRWA_VERIFIER_SESSION_ID_HEX_BYTES);
    for byte in random_bytes {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    debug_assert_eq!(encoded.len(), PRWA_VERIFIER_SESSION_ID_HEX_BYTES);
    SessionId::new(encoded).map_err(|_| PrwaVerifierSourceError::SessionIdConstruction)
}

fn unix_seconds_from_system_time(time: SystemTime) -> Result<u64, PrwaVerifierSourceError> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PrwaVerifierSourceError::VerifierTime)
}

fn context_from_issued_at(
    session_id: SessionId,
    issued_at_unix_seconds: u64,
) -> Result<PrwaVerifierSessionContext, PrwaVerifierSourceError> {
    let expires_at_unix_seconds = issued_at_unix_seconds
        .checked_add(PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS)
        .ok_or(PrwaVerifierSourceError::ExpiryOverflow)?;
    Ok(PrwaVerifierSessionContext {
        session_id,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prw_core::SessionId;

    use super::{
        PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS, PRWA_VERIFIER_SESSION_ID_HEX_BYTES,
        PrwaVerifierSourceError, context_from_issued_at, new_prwa_verifier_session_context,
        session_id_from_random_bytes, unix_seconds_from_system_time,
    };

    #[test]
    fn fixed_random_bytes_encode_exact_lowercase_hex_session_id() {
        let session_id = session_id_from_random_bytes([0xab; 32]).expect("typed session id");
        assert_eq!(session_id.as_str(), "ab".repeat(32));
        assert_eq!(
            session_id.as_str().len(),
            PRWA_VERIFIER_SESSION_ID_HEX_BYTES
        );
    }

    #[test]
    fn fixed_issue_time_builds_exact_locked_window() {
        let session_id = SessionId::new("session-test").expect("session id");
        let context = context_from_issued_at(session_id, 1_000).expect("verifier context");
        assert_eq!(context.issued_at_unix_seconds(), 1_000);
        assert_eq!(
            context.expires_at_unix_seconds(),
            1_000 + PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS
        );
    }

    #[test]
    fn unix_epoch_maps_to_zero_seconds() {
        assert_eq!(unix_seconds_from_system_time(super::UNIX_EPOCH), Ok(0));
    }

    #[test]
    fn pre_epoch_time_fails_closed() {
        let before_epoch = super::UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("representable pre-epoch time");
        assert_eq!(
            unix_seconds_from_system_time(before_epoch),
            Err(PrwaVerifierSourceError::VerifierTime)
        );
    }

    #[test]
    fn expiry_overflow_fails_closed() {
        let session_id = SessionId::new("session-overflow").expect("session id");
        assert_eq!(
            context_from_issued_at(session_id, u64::MAX),
            Err(PrwaVerifierSourceError::ExpiryOverflow)
        );
    }

    #[test]
    fn public_source_returns_locked_shape() {
        let context = new_prwa_verifier_session_context().expect("verifier context");
        assert_eq!(
            context.session_id().as_str().len(),
            PRWA_VERIFIER_SESSION_ID_HEX_BYTES
        );
        assert!(
            context
                .session_id()
                .as_str()
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
        assert_eq!(
            context.expires_at_unix_seconds() - context.issued_at_unix_seconds(),
            PRWA_VERIFIER_CHALLENGE_LIFETIME_SECONDS
        );
    }
}
