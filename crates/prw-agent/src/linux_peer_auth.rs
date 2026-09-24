//! Linux same-effective-UID local peer authorization.
//!
//! Phase 058 turns kernel peer credentials into a typed authorization token
//! without reading application protocol bytes or owning socket lifecycle.

use rustix::fd::AsFd;

use crate::linux_identity::{
    LocalLinuxIdentityError, LocalLinuxPeerCredentials, effective_agent_uid, peer_credentials,
};

/// Proof that the Linux kernel-reported peer UID matched the Agent effective UID.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedLocalLinuxPeer {
    credentials: LocalLinuxPeerCredentials,
}

impl AuthorizedLocalLinuxPeer {
    /// Returns the immutable kernel-reported peer credentials that were authorized.
    #[must_use]
    pub const fn credentials(&self) -> LocalLinuxPeerCredentials {
        self.credentials
    }
}

/// Retrieves kernel peer credentials and authorizes exact same-effective-UID use.
///
/// No application data is read from `fd`. The returned token has no public
/// constructor and is created only after exact peer-UID equality is proven.
///
/// # Errors
///
/// Returns [`LocalLinuxPeerAuthorizationError::Identity`] when kernel credential
/// lookup fails, or [`LocalLinuxPeerAuthorizationError::UserIdMismatch`] when
/// the kernel-reported peer UID differs from the Agent effective UID.
pub fn authorize_same_effective_uid<Fd: AsFd>(
    fd: Fd,
) -> Result<AuthorizedLocalLinuxPeer, LocalLinuxPeerAuthorizationError> {
    let credentials = peer_credentials(fd).map_err(LocalLinuxPeerAuthorizationError::Identity)?;
    let agent_uid = effective_agent_uid();

    if !user_ids_match(credentials.uid(), agent_uid) {
        return Err(LocalLinuxPeerAuthorizationError::UserIdMismatch);
    }

    Ok(AuthorizedLocalLinuxPeer { credentials })
}

const fn user_ids_match(peer_uid: u32, agent_uid: u32) -> bool {
    peer_uid == agent_uid
}

/// Bounded Linux same-UID authorization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalLinuxPeerAuthorizationError {
    /// Kernel peer-identity acquisition failed.
    Identity(LocalLinuxIdentityError),
    /// Kernel-reported peer UID did not match the Agent effective UID.
    UserIdMismatch,
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::net::UnixStream;

    use super::{LocalLinuxPeerAuthorizationError, authorize_same_effective_uid, user_ids_match};
    use crate::linux_identity::{LocalLinuxIdentityError, effective_agent_uid};

    #[test]
    fn uid_equality_predicate_is_exact() {
        assert!(user_ids_match(1000, 1000));
        assert!(!user_ids_match(1000, 1001));
        assert!(!user_ids_match(1001, 1000));
    }

    #[test]
    fn anonymous_unix_pair_authorizes_current_effective_uid() {
        let (left, _right) = UnixStream::pair().expect("anonymous Unix pair creates");

        let authorized =
            authorize_same_effective_uid(&left).expect("same-UID peer authorizes successfully");

        assert_eq!(authorized.credentials().uid(), effective_agent_uid());
    }

    #[test]
    fn non_socket_descriptor_fails_closed() {
        let file = File::open("/dev/null").expect("read-only /dev/null opens");

        assert_eq!(
            authorize_same_effective_uid(&file),
            Err(LocalLinuxPeerAuthorizationError::Identity(
                LocalLinuxIdentityError::PeerCredentialLookup
            ))
        );
    }
}
