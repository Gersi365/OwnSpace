use std::{error::Error, fmt};

use super::RemoteSessionExpectedDeviceAdmissionRequest;

#[allow(
    dead_code,
    reason = "C03e-SX materializes the selected dormant timing source error family before separately gated provider/sink activation"
)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "C03e-SX keeps crate-visible re-export semantics for this private child module"
)]
#[non_exhaustive]
pub(crate) enum RemoteSessionAdmissionTimingSourceError<Cause> {
    Acquisition(Cause),
    Policy(Cause),
    InvalidChallengeValidity,
    InvalidApplicationLease,
    ArithmeticOverflow,
}

impl<Cause> fmt::Debug for RemoteSessionAdmissionTimingSourceError<Cause> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acquisition(_) => "RemoteSessionAdmissionTimingSourceError::Acquisition",
            Self::Policy(_) => "RemoteSessionAdmissionTimingSourceError::Policy",
            Self::InvalidChallengeValidity => {
                "RemoteSessionAdmissionTimingSourceError::InvalidChallengeValidity"
            }
            Self::InvalidApplicationLease => {
                "RemoteSessionAdmissionTimingSourceError::InvalidApplicationLease"
            }
            Self::ArithmeticOverflow => {
                "RemoteSessionAdmissionTimingSourceError::ArithmeticOverflow"
            }
        })
    }
}

impl<Cause> fmt::Display for RemoteSessionAdmissionTimingSourceError<Cause> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acquisition(_) => "remote session admission timing acquisition failed",
            Self::Policy(_) => "remote session admission timing policy failed",
            Self::InvalidChallengeValidity => {
                "remote session admission challenge validity is invalid"
            }
            Self::InvalidApplicationLease => {
                "remote session admission application lease is invalid"
            }
            Self::ArithmeticOverflow => "remote session admission timing arithmetic overflowed",
        })
    }
}

impl<Cause> Error for RemoteSessionAdmissionTimingSourceError<Cause>
where
    Cause: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Acquisition(cause) | Self::Policy(cause) => Some(cause),
            Self::InvalidChallengeValidity
            | Self::InvalidApplicationLease
            | Self::ArithmeticOverflow => None,
        }
    }
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "C03e-SX keeps crate-visible re-export semantics for this private child module"
)]
pub(crate) struct RemoteSessionAdmissionTimingFailure<D, T, TimingError> {
    error: TimingError,
    request: RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
}

impl<D, T, TimingError> RemoteSessionAdmissionTimingFailure<D, T, TimingError> {
    #[must_use]
    pub(crate) const fn new(
        error: TimingError,
        request: RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
    ) -> Self {
        Self { error, request }
    }

    #[allow(
        dead_code,
        reason = "C03e-SX exposes the selected bounded borrowed error view before separately gated timing-failure consumers"
    )]
    #[must_use]
    pub(crate) const fn error(&self) -> &TimingError {
        &self.error
    }

    #[allow(
        dead_code,
        reason = "C03e-SX exposes the selected intact borrowed request view before separately gated timing-failure consumers"
    )]
    #[must_use]
    pub(crate) const fn request(&self) -> &RemoteSessionExpectedDeviceAdmissionRequest<D, T> {
        &self.request
    }

    #[must_use]
    pub(crate) fn into_parts(
        self,
    ) -> (
        TimingError,
        RemoteSessionExpectedDeviceAdmissionRequest<D, T>,
    ) {
        (self.error, self.request)
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt};

    use prw_core::{DeviceId, SessionId};

    use super::{
        RemoteSessionAdmissionTimingFailure, RemoteSessionAdmissionTimingSourceError,
        RemoteSessionExpectedDeviceAdmissionRequest,
    };

    struct SentinelCause(&'static str);

    impl fmt::Debug for SentinelCause {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "SentinelCause({})", self.0)
        }
    }

    impl fmt::Display for SentinelCause {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for SentinelCause {}

    struct NonCloneDispatcher {
        token: u8,
    }

    struct NonCloneVerifier {
        token: u8,
    }

    struct TimingError {
        token: u8,
    }

    #[test]
    fn admission_timing_source_error_debug_is_bounded_and_hides_cause() {
        let error = RemoteSessionAdmissionTimingSourceError::Acquisition(SentinelCause(
            "secret-acquisition-cause",
        ));

        assert_eq!(
            format!("{error:?}"),
            "RemoteSessionAdmissionTimingSourceError::Acquisition"
        );
        assert_eq!(
            format!("{error}"),
            "remote session admission timing acquisition failed"
        );
        assert!(!format!("{error:?}").contains("secret-acquisition-cause"));
    }

    #[test]
    fn admission_timing_source_error_preserves_acquisition_and_policy_causes() {
        let acquisition = RemoteSessionAdmissionTimingSourceError::Acquisition(SentinelCause(
            "acquisition-cause",
        ));
        let policy = RemoteSessionAdmissionTimingSourceError::Policy(SentinelCause("policy-cause"));

        let acquisition_source =
            Error::source(&acquisition).and_then(|source| source.downcast_ref::<SentinelCause>());
        let policy_source =
            Error::source(&policy).and_then(|source| source.downcast_ref::<SentinelCause>());

        assert!(matches!(acquisition_source, Some(cause) if cause.0 == "acquisition-cause"));
        assert!(matches!(policy_source, Some(cause) if cause.0 == "policy-cause"));
    }

    #[test]
    fn admission_timing_source_structural_variants_have_no_source() {
        let errors = [
            RemoteSessionAdmissionTimingSourceError::<SentinelCause>::InvalidChallengeValidity,
            RemoteSessionAdmissionTimingSourceError::InvalidApplicationLease,
            RemoteSessionAdmissionTimingSourceError::ArithmeticOverflow,
        ];

        for error in errors {
            assert!(Error::source(&error).is_none());
        }
    }

    #[test]
    fn admission_timing_failure_borrows_and_recovers_exact_non_cloneable_request() {
        let request = RemoteSessionExpectedDeviceAdmissionRequest::new(
            DeviceId::new("device-timing-failure").expect("non-empty DeviceId"),
            SessionId::new("session-timing-failure").expect("non-empty SessionId"),
            41,
            NonCloneDispatcher { token: 17 },
            NonCloneVerifier { token: 29 },
        );
        let failure = RemoteSessionAdmissionTimingFailure::new(TimingError { token: 53 }, request);

        assert_eq!(failure.error().token, 53);
        assert_eq!(
            failure.request().expected_device_id().as_str(),
            "device-timing-failure"
        );

        let (error, request) = failure.into_parts();
        let (device_id, session_id, request_id, dispatcher, verifier) = request.into_parts();

        assert_eq!(error.token, 53);
        assert_eq!(device_id.as_str(), "device-timing-failure");
        assert_eq!(session_id.as_str(), "session-timing-failure");
        assert_eq!(request_id, 41);
        assert_eq!(dispatcher.token, 17);
        assert_eq!(verifier.token, 29);
    }
}
