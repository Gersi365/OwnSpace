//! Agent-owned production candidate-publication freshness-token source.
//!
//! C03e-GT materializes only the C03e-GS-selected concrete verifier entropy source behind the
//! existing provider-neutral `CandidatePublicationFreshnessTokenSource` contract. This module owns
//! no durable store, production-owner recovery, owner-map population, candidate handoff, bootstrap
//! callsite, listener, networking, deployment, or runtime activation.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use prw_remote_bridge::{
    candidate_publication_freshness::{
        CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES, CandidatePublicationFreshnessToken,
    },
    reachability_owner::{CandidatePublicationFreshnessTokenSource, FreshnessTokenSourceError},
};

/// Agent-owned concrete production source for verifier freshness tokens.
///
/// The source is intentionally stateless. Each logical issuance performs exactly one OS-backed
/// cryptographic provider fill into one fresh 32-byte buffer. It owns no token pool, retry loop,
/// clock, counter, UUID, identity-derived seed, persistence, or fallback generator.
#[derive(Debug, Default)]
pub struct ProductionReachabilityFreshnessTokenSource;

impl ProductionReachabilityFreshnessTokenSource {
    /// Creates the stateless production freshness-token source.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CandidatePublicationFreshnessTokenSource for ProductionReachabilityFreshnessTokenSource {
    fn issue_token(
        &mut self,
    ) -> Result<CandidatePublicationFreshnessToken, FreshnessTokenSourceError> {
        issue_token_with_fill(|bytes| {
            SystemRandom::new()
                .fill(bytes)
                .map_err(|_| FreshnessTokenSourceError::Unavailable)
        })
    }
}

fn issue_token_with_fill(
    fill: impl FnOnce(
        &mut [u8; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES],
    ) -> Result<(), FreshnessTokenSourceError>,
) -> Result<CandidatePublicationFreshnessToken, FreshnessTokenSourceError> {
    let mut bytes = [0_u8; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES];
    fill(&mut bytes)?;
    CandidatePublicationFreshnessToken::new(bytes)
        .map_err(|_| FreshnessTokenSourceError::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use prw_remote_bridge::reachability_owner::{
        CandidatePublicationFreshnessTokenSource, FreshnessTokenSourceError,
    };

    use super::{
        CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES, ProductionReachabilityFreshnessTokenSource,
        issue_token_with_fill,
    };

    #[test]
    fn fixed_fill_is_called_once_and_returns_exact_typed_token() {
        let calls = Cell::new(0_u8);
        let token = issue_token_with_fill(|bytes| {
            calls.set(calls.get() + 1);
            bytes.fill(0xa5);
            Ok(())
        })
        .expect("non-zero fixed bytes should become one freshness token");

        assert_eq!(calls.get(), 1);
        assert_eq!(
            token.as_bytes(),
            &[0xa5; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES]
        );
    }

    #[test]
    fn provider_failure_is_one_call_and_fails_closed() {
        let calls = Cell::new(0_u8);
        let result = issue_token_with_fill(|_bytes| {
            calls.set(calls.get() + 1);
            Err(FreshnessTokenSourceError::Unavailable)
        });

        assert_eq!(calls.get(), 1);
        assert_eq!(result, Err(FreshnessTokenSourceError::Unavailable));
    }

    #[test]
    fn all_zero_provider_output_is_one_call_and_fails_closed() {
        let calls = Cell::new(0_u8);
        let result = issue_token_with_fill(|bytes| {
            calls.set(calls.get() + 1);
            bytes.fill(0);
            Ok(())
        });

        assert_eq!(calls.get(), 1);
        assert_eq!(result, Err(FreshnessTokenSourceError::Unavailable));
    }

    #[test]
    fn production_source_returns_one_non_zero_token() {
        let mut source = ProductionReachabilityFreshnessTokenSource::new();
        let token = source
            .issue_token()
            .expect("OS-backed production freshness issuance should succeed in validation");

        assert_ne!(
            token.as_bytes(),
            &[0_u8; CANDIDATE_PUBLICATION_FRESHNESS_TOKEN_BYTES]
        );
    }
}
