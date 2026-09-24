//! Ubuntu transport-identity provisioning and established-state recovery for Ownspace.
//!
//! This crate materializes explicit preferred TPM2-plus-host-secret and lower-tier
//! host-key-only provisioning entrypoints. Both perform read-only custody capability
//! checks before production key generation, generate one dedicated P-256 transport
//! key in memory, pass plaintext only through the stdin pipe to `systemd-creds`,
//! atomically persist only the encrypted credential, and write one fixed per-user
//! systemd credential binding. Host-key-only is never selected automatically. This
//! crate does not reload systemd, start/restart the Agent, issue certificates, open
//! `SQLite`, or expose private-key bytes to callers.

#![cfg(target_os = "linux")]

use std::{
    env, fmt,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_connectivity::TransportIdentity;
use prw_transport_identity_custody::{
    MAX_UBUNTU_TRANSPORT_IDENTITY_PKCS8_BYTES, SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME,
    derive_transport_identity_from_pkcs8_v1_der,
};
use rustix::{
    fs::{CWD, Mode, OFlags, RenameFlags, open, renameat_with},
    process::getuid,
};
use zeroize::{Zeroize, Zeroizing};

/// Persistent encrypted transport-key credential location below the owner state root.
pub const TRANSPORT_IDENTITY_CIPHERTEXT_RELATIVE_PATH: &str =
    "private-remote-workspace/credentials/transport-identity-private-key-v1.cred";

/// Per-user systemd drop-in that binds the encrypted transport-key credential.
pub const TRANSPORT_IDENTITY_DROPIN_RELATIVE_PATH: &str =
    "systemd/user/prw-agent.service.d/30-transport-identity-credential.conf";

/// Stable non-secret preferred custody-tier marker persisted inside the service drop-in.
pub const TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER: &str = "TPM2_PLUS_HOST_SECRET";

/// Stable non-secret explicit fallback custody-tier marker.
pub const TRANSPORT_IDENTITY_HOST_KEY_ONLY_CUSTODY_TIER: &str = "HOST_KEY_ONLY";

/// Explicit first-setup transport-identity provisioning policy.
///
/// This type carries only non-secret policy intent. Constructing or storing it does
/// not inspect host capability, generate key material, or write provisioning state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportIdentityProvisioningPolicy {
    /// Preferred TPM2-plus-host-secret custody policy.
    Preferred,
    /// Explicit lower-tier host-key-only fallback policy.
    HostKeyOnly,
}

impl TransportIdentityProvisioningPolicy {
    /// Returns the stable non-secret custody-tier marker for this selected policy.
    #[must_use]
    pub const fn custody_tier(self) -> &'static str {
        match self {
            Self::Preferred => TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER,
            Self::HostKeyOnly => TRANSPORT_IDENTITY_HOST_KEY_ONLY_CUSTODY_TIER,
        }
    }

    const fn uses_host_key_only_override(self) -> bool {
        matches!(self, Self::HostKeyOnly)
    }
}

/// Read-only classification of the fixed persistent transport-custody artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportIdentityPersistentState {
    /// Neither the fixed encrypted credential nor the fixed service binding exists.
    Absent,
    /// Both fixed artifacts exist and match the already-selected custody policy.
    Established,
}

/// Read-only recovery result derived from canonical established transport custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstablishedTransportIdentityRecovery {
    policy: TransportIdentityProvisioningPolicy,
    transport_identity: TransportIdentity,
}

impl EstablishedTransportIdentityRecovery {
    /// Returns the custody policy encoded by the canonical persisted service binding.
    #[must_use]
    pub const fn policy(self) -> TransportIdentityProvisioningPolicy {
        self.policy
    }

    /// Returns the transport identity recovered from the established encrypted credential.
    #[must_use]
    pub const fn transport_identity(self) -> TransportIdentity {
        self.transport_identity
    }
}

const SYSTEMD_CREDS_PATH: &str = "/usr/bin/systemd-creds";
const SYSTEMD_ANALYZE_PATH: &str = "/usr/bin/systemd-analyze";
const SYSTEMD_HOST_CREDENTIAL_SECRET_PATH: &str = "/var/lib/systemd/credential.secret";

const MAX_ENCRYPTED_CREDENTIAL_BYTES: u64 = 65_536;
const MAX_DROPIN_BYTES: usize = 4_096;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const CIPHERTEXT_MODE: u32 = 0o600;
const DROPIN_MODE: u32 = 0o600;
const FORBIDDEN_INITIAL_CIPHERTEXT_MODE_BITS: u32 = 0o133;
const INSECURE_SYSTEM_FILE_WRITE_BITS: u32 = 0o022;

/// Successful preferred-policy transport-identity provisioning result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedTransportIdentity {
    transport_identity: TransportIdentity,
    encrypted_credential_path: PathBuf,
    service_dropin_path: PathBuf,
}

impl ProvisionedTransportIdentity {
    /// Returns the provisioned opaque PRW transport identity.
    #[must_use]
    pub const fn transport_identity(&self) -> &TransportIdentity {
        &self.transport_identity
    }

    /// Returns the committed encrypted-credential path.
    #[must_use]
    pub fn encrypted_credential_path(&self) -> &Path {
        &self.encrypted_credential_path
    }

    /// Returns the committed per-user systemd service drop-in path.
    #[must_use]
    pub fn service_dropin_path(&self) -> &Path {
        &self.service_dropin_path
    }
}

/// Bounded non-secret failure classification for first transport-key provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportIdentityProvisioningError {
    /// XDG state/HOME did not resolve to an absolute usable state root.
    InvalidStateRoot,
    /// XDG config/HOME did not resolve to an absolute usable config root.
    InvalidConfigRoot,
    /// A required existing directory failed ownership/type/mode validation.
    InsecureDirectory,
    /// The production transport ciphertext or transport service binding already exists.
    AlreadyProvisioned,
    /// A required private PRW directory could not be created safely.
    DirectoryCreationFailed,
    /// The fixed `systemd-creds` binary failed immutable-system-file validation.
    SystemdCredsUnavailable,
    /// The fixed `systemd-analyze` binary failed immutable-system-file validation.
    SystemdAnalyzeUnavailable,
    /// The supported systemd TPM2 capability check did not prove usable TPM2.
    Tpm2Unavailable,
    /// Explicit host-key-only fallback was requested while usable TPM2 is still available.
    HostKeyOnlyFallbackForbidden,
    /// The host credential secret required for the selected policy was absent.
    HostSecretUnavailable,
    /// The host credential secret failed type/ownership/write-permission validation.
    HostSecretInsecure,
    /// Local P-256 transport private-key generation failed.
    KeyGenerationFailed,
    /// The generated P-256 key failed canonical transport-identity derivation.
    GeneratedIdentityInvalid,
    /// The preferred systemd encrypted-credential operation failed.
    CredentialEncryptionFailed,
    /// The encrypted credential output was empty or exceeded its bound.
    EncryptedCredentialOutOfBounds,
    /// Temporary ciphertext persistence or validation failed.
    CiphertextWriteFailed,
    /// No-replace atomic ciphertext commit failed.
    CiphertextCommitFailed,
    /// The fixed transport credential binding could not be rendered safely.
    InvalidCredentialBinding,
    /// Temporary service drop-in persistence or validation failed.
    DropinWriteFailed,
    /// No-replace atomic service drop-in commit failed.
    DropinCommitFailed,
    /// Required parent-directory durability synchronization failed.
    DirectorySyncFailed,
}

impl fmt::Display for TransportIdentityProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStateRoot => "invalid transport identity state root",
            Self::InvalidConfigRoot => "invalid transport identity config root",
            Self::InsecureDirectory => "insecure transport identity directory",
            Self::AlreadyProvisioned => "transport identity is already provisioned",
            Self::DirectoryCreationFailed => "transport identity directory creation failed",
            Self::SystemdCredsUnavailable => "systemd-creds is unavailable or insecure",
            Self::SystemdAnalyzeUnavailable => "systemd-analyze is unavailable or insecure",
            Self::Tpm2Unavailable => "usable TPM2 was not proven before transport key generation",
            Self::HostKeyOnlyFallbackForbidden => {
                "host-key-only fallback is forbidden while usable TPM2 is available"
            }
            Self::HostSecretUnavailable => {
                "systemd host credential secret is unavailable before transport key generation"
            }
            Self::HostSecretInsecure => "systemd host credential secret is insecure",
            Self::KeyGenerationFailed => "transport identity key generation failed",
            Self::GeneratedIdentityInvalid => "generated transport identity failed validation",
            Self::CredentialEncryptionFailed => "transport identity credential encryption failed",
            Self::EncryptedCredentialOutOfBounds => {
                "encrypted transport identity credential out of bounds"
            }
            Self::CiphertextWriteFailed => "encrypted transport identity persistence failed",
            Self::CiphertextCommitFailed => "encrypted transport identity commit failed",
            Self::InvalidCredentialBinding => "invalid transport identity credential binding",
            Self::DropinWriteFailed => "transport identity credential drop-in persistence failed",
            Self::DropinCommitFailed => "transport identity credential drop-in commit failed",
            Self::DirectorySyncFailed => "transport identity directory sync failed",
        })
    }
}

impl std::error::Error for TransportIdentityProvisioningError {}

/// Bounded failure while recovering an already-established Ubuntu transport identity.
///
/// Recovery is deliberately read-only with respect to persistent PRW state. It
/// validates the exact encrypted credential and fixed service binding selected
/// during first-time setup, decrypts only through the fixed `systemd-creds`
/// boundary, and returns only the derived opaque `TransportIdentity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportIdentityRecoveryError {
    /// XDG state/HOME did not resolve to an absolute usable state root.
    InvalidStateRoot,
    /// XDG config/HOME did not resolve to an absolute usable config root.
    InvalidConfigRoot,
    /// A required existing state/config directory is missing or insecure.
    InsecureDirectory,
    /// Exactly one fixed transport-custody artifact exists; retry must fail closed.
    PartialState,
    /// The expected encrypted transport credential is absent or cannot be opened safely.
    CiphertextUnavailable,
    /// The encrypted transport credential violates the locked file boundary.
    CiphertextInsecure,
    /// The expected fixed systemd service binding is absent or cannot be opened safely.
    DropinUnavailable,
    /// The fixed service binding violates the locked file boundary.
    DropinInsecure,
    /// The established service binding does not match the explicitly selected custody policy.
    CustodyPolicyMismatch,
    /// The fixed `systemd-creds` binary is unavailable or insecure.
    SystemdCredsUnavailable,
    /// Name-bound authenticated decryption of the established credential failed.
    CredentialDecryptionFailed,
    /// The decrypted credential is empty or exceeds the locked plaintext bound.
    DecryptedCredentialOutOfBounds,
    /// The recovered plaintext is not the canonical dedicated P-256 transport credential.
    InvalidPrivateCredential,
}

impl fmt::Display for TransportIdentityRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStateRoot => "invalid transport identity recovery state root",
            Self::InvalidConfigRoot => "invalid transport identity recovery config root",
            Self::InsecureDirectory => "insecure transport identity recovery directory",
            Self::PartialState => "transport identity custody is only partially established",
            Self::CiphertextUnavailable => "encrypted transport identity credential unavailable",
            Self::CiphertextInsecure => "encrypted transport identity credential insecure",
            Self::DropinUnavailable => "transport identity credential binding unavailable",
            Self::DropinInsecure => "transport identity credential binding insecure",
            Self::CustodyPolicyMismatch => {
                "established transport identity custody policy does not match setup selection"
            }
            Self::SystemdCredsUnavailable => "systemd-creds is unavailable or insecure",
            Self::CredentialDecryptionFailed => {
                "established transport identity credential decryption failed"
            }
            Self::DecryptedCredentialOutOfBounds => {
                "decrypted transport identity credential out of bounds"
            }
            Self::InvalidPrivateCredential => {
                "recovered transport identity private credential is invalid"
            }
        })
    }
}

impl std::error::Error for TransportIdentityRecoveryError {}

/// Inspects whether the fixed first-time-setup transport custody is absent or established.
///
/// This operation is read-only. It validates every existing parent directory in the
/// fixed state/config chains, fails closed on partial artifact state, and when both
/// artifacts exist requires their metadata and service binding to match the exact
/// already-selected custody policy. It does not decrypt the credential.
///
/// # Errors
///
/// Fails closed for invalid roots, insecure existing directories or leaf files,
/// partial state, or a custody-policy/binding mismatch.
pub fn inspect_ubuntu_transport_identity_persistent_state(
    policy: TransportIdentityProvisioningPolicy,
) -> Result<TransportIdentityPersistentState, TransportIdentityRecoveryError> {
    let uid = getuid().as_raw();
    let state_root = resolve_xdg_root("XDG_STATE_HOME", ".local/state")
        .ok_or(TransportIdentityRecoveryError::InvalidStateRoot)?;
    let config_root = resolve_xdg_root("XDG_CONFIG_HOME", ".config")
        .ok_or(TransportIdentityRecoveryError::InvalidConfigRoot)?;

    validate_existing_root(&state_root, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;

    let ciphertext_parent_exists =
        validate_optional_transport_state_parent_chain(&state_root, uid)?;
    let dropin_parent_exists = validate_optional_transport_dropin_parent_chain(&config_root, uid)?;

    let ciphertext_path = state_root.join(TRANSPORT_IDENTITY_CIPHERTEXT_RELATIVE_PATH);
    let dropin_path = config_root.join(TRANSPORT_IDENTITY_DROPIN_RELATIVE_PATH);
    let ciphertext_exists = if ciphertext_parent_exists {
        recovery_leaf_exists(
            &ciphertext_path,
            TransportIdentityRecoveryError::CiphertextUnavailable,
        )?
    } else {
        false
    };
    let dropin_exists = if dropin_parent_exists {
        recovery_leaf_exists(
            &dropin_path,
            TransportIdentityRecoveryError::DropinUnavailable,
        )?
    } else {
        false
    };

    let state = classify_transport_identity_persistent_state(ciphertext_exists, dropin_exists)?;
    if state == TransportIdentityPersistentState::Established {
        let expected_dropin =
            render_transport_identity_dropin(&ciphertext_path, policy.custody_tier())
                .map_err(|_| TransportIdentityRecoveryError::CustodyPolicyMismatch)?;
        drop(open_existing_transport_ciphertext_for_recovery(
            &ciphertext_path,
            uid,
        )?);
        validate_existing_transport_dropin_for_recovery(&dropin_path, &expected_dropin, uid)?;
    }

    Ok(state)
}

/// Recovers the already-established Ubuntu transport identity for a retry path.
///
/// This is not a provisioning entrypoint. It never creates, replaces, rekeys, or
/// converts persistent identity state. The caller supplies the exact first-time
/// setup policy already selected before provisioning. The persisted drop-in must
/// bind the fixed credential path and carry that same custody tier.
///
/// The encrypted credential is opened with `O_NOFOLLOW` and passed to
/// `systemd-creds` through stdin, so the child does not reopen a path after
/// validation. Decrypted PKCS#8 bytes exist only in a zeroizing process buffer,
/// are bounded, validated, and used only to derive `TransportIdentity`.
///
/// # Errors
///
/// Fails closed for missing/insecure established state, custody-policy mismatch,
/// unavailable `systemd-creds`, authenticated decryption failure, or invalid
/// canonical P-256 credential material.
pub fn recover_existing_ubuntu_transport_identity(
    policy: TransportIdentityProvisioningPolicy,
) -> Result<TransportIdentity, TransportIdentityRecoveryError> {
    let uid = getuid().as_raw();
    let state_root = resolve_xdg_root("XDG_STATE_HOME", ".local/state")
        .ok_or(TransportIdentityRecoveryError::InvalidStateRoot)?;
    let config_root = resolve_xdg_root("XDG_CONFIG_HOME", ".config")
        .ok_or(TransportIdentityRecoveryError::InvalidConfigRoot)?;

    validate_existing_root(&state_root, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;
    validate_existing_root(&config_root, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;

    let application_dir = state_root.join("private-remote-workspace");
    validate_private_directory_for_recovery(&application_dir, uid)?;
    let credential_dir = application_dir.join("credentials");
    validate_private_directory_for_recovery(&credential_dir, uid)?;

    let systemd_dir = config_root.join("systemd");
    validate_existing_root(&systemd_dir, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;
    let user_dir = systemd_dir.join("user");
    validate_existing_root(&user_dir, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;
    let dropin_dir = user_dir.join("prw-agent.service.d");
    validate_existing_root(&dropin_dir, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;

    let ciphertext_path = state_root.join(TRANSPORT_IDENTITY_CIPHERTEXT_RELATIVE_PATH);
    let dropin_path = config_root.join(TRANSPORT_IDENTITY_DROPIN_RELATIVE_PATH);
    let expected_dropin = render_transport_identity_dropin(&ciphertext_path, policy.custody_tier())
        .map_err(|_| TransportIdentityRecoveryError::CustodyPolicyMismatch)?;

    let ciphertext = open_existing_transport_ciphertext_for_recovery(&ciphertext_path, uid)?;
    validate_existing_transport_dropin_for_recovery(&dropin_path, &expected_dropin, uid)?;

    validate_secure_system_program(Path::new(SYSTEMD_CREDS_PATH))
        .map_err(|()| TransportIdentityRecoveryError::SystemdCredsUnavailable)?;

    decrypt_existing_transport_identity(ciphertext)
}

/// Recovers established transport identity by reading the canonical persisted custody binding.
///
/// This post-first-run path accepts no setup/user custody choice. It reads the existing fixed service
/// binding exactly once, requires that binding to equal one of the two canonical payloads for the fixed
/// encrypted credential path, and decrypts the established credential exactly once.
///
/// It never probes TPM capability to select a tier, never retries another tier after failure, never
/// rewrites the service binding, and never provisions or replaces transport identity state.
///
/// # Errors
///
/// Fails closed for missing/insecure established state, a non-canonical or unknown persisted custody
/// binding, unavailable `systemd-creds`, authenticated decryption failure, or invalid credential
/// material.
pub fn recover_established_ubuntu_transport_identity_from_persisted_binding()
-> Result<EstablishedTransportIdentityRecovery, TransportIdentityRecoveryError> {
    let uid = getuid().as_raw();
    let state_root = resolve_xdg_root("XDG_STATE_HOME", ".local/state")
        .ok_or(TransportIdentityRecoveryError::InvalidStateRoot)?;
    let config_root = resolve_xdg_root("XDG_CONFIG_HOME", ".config")
        .ok_or(TransportIdentityRecoveryError::InvalidConfigRoot)?;

    validate_existing_root(&state_root, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;
    validate_existing_root(&config_root, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;

    let application_dir = state_root.join("private-remote-workspace");
    validate_private_directory_for_recovery(&application_dir, uid)?;
    let credential_dir = application_dir.join("credentials");
    validate_private_directory_for_recovery(&credential_dir, uid)?;

    let systemd_dir = config_root.join("systemd");
    validate_existing_root(&systemd_dir, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;
    let user_dir = systemd_dir.join("user");
    validate_existing_root(&user_dir, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;
    let dropin_dir = user_dir.join("prw-agent.service.d");
    validate_existing_root(&dropin_dir, uid)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;

    let ciphertext_path = state_root.join(TRANSPORT_IDENTITY_CIPHERTEXT_RELATIVE_PATH);
    let dropin_path = config_root.join(TRANSPORT_IDENTITY_DROPIN_RELATIVE_PATH);

    let ciphertext = open_existing_transport_ciphertext_for_recovery(&ciphertext_path, uid)?;
    let dropin_payload = read_existing_transport_dropin_for_recovery(&dropin_path, uid)?;
    let policy = established_policy_from_dropin_payload(&dropin_payload, &ciphertext_path)?;

    validate_secure_system_program(Path::new(SYSTEMD_CREDS_PATH))
        .map_err(|()| TransportIdentityRecoveryError::SystemdCredsUnavailable)?;

    let transport_identity = decrypt_existing_transport_identity(ciphertext)?;
    Ok(EstablishedTransportIdentityRecovery {
        policy,
        transport_identity,
    })
}

/// Generates and atomically commits the first Ubuntu transport identity using only
/// the preferred TPM2-plus-host-secret systemd policy.
///
/// Capability checks run before P-256 key generation. This function deliberately
/// never retries with `HOST_KEY_ONLY`.
///
/// # Errors
///
/// Returns `TransportIdentityProvisioningError` for invalid roots, existing identity
/// artifacts, failed preferred-policy preflight, generation/encryption failure,
/// insecure filesystem state, or durability/atomic-commit failure.
pub fn provision_first_ubuntu_transport_identity_preferred()
-> Result<ProvisionedTransportIdentity, TransportIdentityProvisioningError> {
    provision_first_ubuntu_transport_identity_for_policy(
        TransportIdentityProvisioningPolicy::Preferred,
    )
}

/// Generates and atomically commits the first Ubuntu transport identity using the
/// explicitly selected lower-tier host-key-only systemd policy.
///
/// This is a distinct entrypoint rather than an automatic retry. It first proves
/// that the supported TPM2 capability check reports TPM2 unusable, then validates
/// the host credential secret, and only then permits P-256 key generation. It never
/// converts or replaces an existing transport identity.
///
/// # Errors
///
/// Returns `TransportIdentityProvisioningError` if usable TPM2 is still available,
/// the fallback prerequisites are not satisfied, identity artifacts already exist,
/// or the normal generation/encryption/atomic-commit checks fail.
pub fn provision_first_ubuntu_transport_identity_host_key_only()
-> Result<ProvisionedTransportIdentity, TransportIdentityProvisioningError> {
    provision_first_ubuntu_transport_identity_for_policy(
        TransportIdentityProvisioningPolicy::HostKeyOnly,
    )
}

fn provision_first_ubuntu_transport_identity_for_policy(
    policy: TransportIdentityProvisioningPolicy,
) -> Result<ProvisionedTransportIdentity, TransportIdentityProvisioningError> {
    let uid = getuid().as_raw();
    let state_root = resolve_xdg_root("XDG_STATE_HOME", ".local/state")
        .ok_or(TransportIdentityProvisioningError::InvalidStateRoot)?;
    let config_root = resolve_xdg_root("XDG_CONFIG_HOME", ".config")
        .ok_or(TransportIdentityProvisioningError::InvalidConfigRoot)?;

    validate_existing_root(&state_root, uid)?;
    if config_root.exists() {
        validate_existing_root(&config_root, uid)?;
    }

    let final_ciphertext = state_root.join(TRANSPORT_IDENTITY_CIPHERTEXT_RELATIVE_PATH);
    let dropin = config_root.join(TRANSPORT_IDENTITY_DROPIN_RELATIVE_PATH);
    let dropin_payload =
        render_transport_identity_dropin(&final_ciphertext, policy.custody_tier())?;

    require_absent(&final_ciphertext)?;
    require_absent(&dropin)?;

    validate_selected_custody_capability(policy)?;

    let application_dir = state_root.join("private-remote-workspace");
    ensure_private_directory(&application_dir, uid)?;
    let credential_dir = application_dir.join("credentials");
    ensure_private_directory(&credential_dir, uid)?;
    require_absent(&final_ciphertext)?;

    let generated =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .map_err(|_| TransportIdentityProvisioningError::KeyGenerationFailed)?;
    let private_pkcs8 = Zeroizing::new(generated.as_ref().to_vec());
    drop(generated);

    let transport_identity = derive_transport_identity_from_pkcs8_v1_der(private_pkcs8.as_slice())
        .map_err(|_| TransportIdentityProvisioningError::GeneratedIdentityInvalid)?;

    let temp_ciphertext = credential_dir.join(format!(
        ".transport-identity-private-key-v1.cred.c03e-ys.{}.tmp",
        std::process::id()
    ));
    require_absent(&temp_ciphertext)
        .map_err(|_| TransportIdentityProvisioningError::CiphertextWriteFailed)?;

    if let Err(error) = encrypt_with_systemd_creds(&temp_ciphertext, private_pkcs8, policy) {
        let _ = fs::remove_file(&temp_ciphertext);
        return Err(error);
    }

    let (opened_temp, opened_metadata) =
        match harden_validate_and_sync_ciphertext_temp(&temp_ciphertext, uid) {
            Ok(validated) => validated,
            Err(error) => {
                let _ = fs::remove_file(&temp_ciphertext);
                return Err(error);
            }
        };

    if renameat_with(
        CWD,
        &temp_ciphertext,
        CWD,
        &final_ciphertext,
        RenameFlags::NOREPLACE,
    )
    .is_err()
    {
        let _ = fs::remove_file(&temp_ciphertext);
        return Err(TransportIdentityProvisioningError::CiphertextCommitFailed);
    }

    let Ok(final_metadata) = fs::symlink_metadata(&final_ciphertext) else {
        let _ = fs::remove_file(&final_ciphertext);
        return Err(TransportIdentityProvisioningError::CiphertextCommitFailed);
    };
    if validate_ciphertext_metadata(&final_metadata, uid).is_err()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        let _ = fs::remove_file(&final_ciphertext);
        let _ = sync_directory(&credential_dir);
        return Err(TransportIdentityProvisioningError::CiphertextCommitFailed);
    }
    drop(opened_temp);

    if sync_directory(&credential_dir).is_err() {
        let _ = fs::remove_file(&final_ciphertext);
        let _ = sync_directory(&credential_dir);
        return Err(TransportIdentityProvisioningError::DirectorySyncFailed);
    }

    if let Err(error) =
        commit_transport_identity_dropin(&config_root, &dropin, &dropin_payload, uid)
    {
        let _ = fs::remove_file(&final_ciphertext);
        let _ = sync_directory(&credential_dir);
        return Err(error);
    }

    Ok(ProvisionedTransportIdentity {
        transport_identity,
        encrypted_credential_path: final_ciphertext,
        service_dropin_path: dropin,
    })
}

fn validate_optional_transport_state_parent_chain(
    state_root: &Path,
    uid: u32,
) -> Result<bool, TransportIdentityRecoveryError> {
    let application_dir = state_root.join("private-remote-workspace");
    if !validate_optional_private_directory_for_recovery(&application_dir, uid)? {
        return Ok(false);
    }
    validate_optional_private_directory_for_recovery(&application_dir.join("credentials"), uid)
}

fn validate_optional_transport_dropin_parent_chain(
    config_root: &Path,
    uid: u32,
) -> Result<bool, TransportIdentityRecoveryError> {
    if !validate_optional_user_directory_for_recovery(config_root, uid)? {
        return Ok(false);
    }
    let systemd_dir = config_root.join("systemd");
    if !validate_optional_user_directory_for_recovery(&systemd_dir, uid)? {
        return Ok(false);
    }
    let user_dir = systemd_dir.join("user");
    if !validate_optional_user_directory_for_recovery(&user_dir, uid)? {
        return Ok(false);
    }
    validate_optional_user_directory_for_recovery(&user_dir.join("prw-agent.service.d"), uid)
}

fn validate_optional_private_directory_for_recovery(
    path: &Path,
    uid: u32,
) -> Result<bool, TransportIdentityRecoveryError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_private_directory_for_recovery(path, uid)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(TransportIdentityRecoveryError::InsecureDirectory),
    }
}

fn validate_optional_user_directory_for_recovery(
    path: &Path,
    uid: u32,
) -> Result<bool, TransportIdentityRecoveryError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_existing_root(path, uid)
                .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(TransportIdentityRecoveryError::InsecureDirectory),
    }
}

fn recovery_leaf_exists(
    path: &Path,
    unavailable: TransportIdentityRecoveryError,
) -> Result<bool, TransportIdentityRecoveryError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(unavailable),
    }
}

const fn classify_transport_identity_persistent_state(
    ciphertext_exists: bool,
    dropin_exists: bool,
) -> Result<TransportIdentityPersistentState, TransportIdentityRecoveryError> {
    match (ciphertext_exists, dropin_exists) {
        (false, false) => Ok(TransportIdentityPersistentState::Absent),
        (true, true) => Ok(TransportIdentityPersistentState::Established),
        (true, false) | (false, true) => Err(TransportIdentityRecoveryError::PartialState),
    }
}

fn validate_private_directory_for_recovery(
    path: &Path,
    uid: u32,
) -> Result<(), TransportIdentityRecoveryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| TransportIdentityRecoveryError::InsecureDirectory)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(TransportIdentityRecoveryError::InsecureDirectory);
    }
    Ok(())
}

fn open_existing_transport_ciphertext_for_recovery(
    path: &Path,
    uid: u32,
) -> Result<File, TransportIdentityRecoveryError> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(TransportIdentityRecoveryError::CiphertextUnavailable);
        }
        Err(_) => return Err(TransportIdentityRecoveryError::CiphertextUnavailable),
    };
    validate_ciphertext_metadata(&before, uid)
        .map_err(|_| TransportIdentityRecoveryError::CiphertextInsecure)?;

    let owned_fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| TransportIdentityRecoveryError::CiphertextUnavailable)?;
    let file = File::from(owned_fd);
    let opened = file
        .metadata()
        .map_err(|_| TransportIdentityRecoveryError::CiphertextUnavailable)?;
    validate_ciphertext_metadata(&opened, uid)
        .map_err(|_| TransportIdentityRecoveryError::CiphertextInsecure)?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(TransportIdentityRecoveryError::CiphertextInsecure);
    }
    Ok(file)
}

fn validate_existing_transport_dropin_for_recovery(
    path: &Path,
    expected: &[u8],
    uid: u32,
) -> Result<(), TransportIdentityRecoveryError> {
    let payload = read_existing_transport_dropin_for_recovery(path, uid)?;
    if payload != expected {
        return Err(TransportIdentityRecoveryError::CustodyPolicyMismatch);
    }
    Ok(())
}

fn read_existing_transport_dropin_for_recovery(
    path: &Path,
    uid: u32,
) -> Result<Vec<u8>, TransportIdentityRecoveryError> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(TransportIdentityRecoveryError::DropinUnavailable);
        }
        Err(_) => return Err(TransportIdentityRecoveryError::DropinUnavailable),
    };
    validate_dropin_metadata(&before, uid)
        .map_err(|_| TransportIdentityRecoveryError::DropinInsecure)?;

    let owned_fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| TransportIdentityRecoveryError::DropinUnavailable)?;
    let file = File::from(owned_fd);
    let opened = file
        .metadata()
        .map_err(|_| TransportIdentityRecoveryError::DropinUnavailable)?;
    validate_dropin_metadata(&opened, uid)
        .map_err(|_| TransportIdentityRecoveryError::DropinInsecure)?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(TransportIdentityRecoveryError::DropinInsecure);
    }

    let mut payload = Vec::new();
    file.take((MAX_DROPIN_BYTES + 1) as u64)
        .read_to_end(&mut payload)
        .map_err(|_| TransportIdentityRecoveryError::DropinInsecure)?;
    if payload.len() > MAX_DROPIN_BYTES {
        return Err(TransportIdentityRecoveryError::DropinInsecure);
    }
    Ok(payload)
}

fn established_policy_from_dropin_payload(
    payload: &[u8],
    encrypted_credential_path: &Path,
) -> Result<TransportIdentityProvisioningPolicy, TransportIdentityRecoveryError> {
    for policy in [
        TransportIdentityProvisioningPolicy::Preferred,
        TransportIdentityProvisioningPolicy::HostKeyOnly,
    ] {
        let expected =
            render_transport_identity_dropin(encrypted_credential_path, policy.custody_tier())
                .map_err(|_| TransportIdentityRecoveryError::CustodyPolicyMismatch)?;
        if payload == expected {
            return Ok(policy);
        }
    }
    Err(TransportIdentityRecoveryError::CustodyPolicyMismatch)
}

fn decrypt_existing_transport_identity(
    ciphertext: File,
) -> Result<TransportIdentity, TransportIdentityRecoveryError> {
    let mut child = Command::new(SYSTEMD_CREDS_PATH)
        .arg("--user")
        .arg(format!(
            "--name={SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME}"
        ))
        .arg("decrypt")
        .arg("-")
        .arg("-")
        .stdin(Stdio::from(ciphertext))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| TransportIdentityRecoveryError::CredentialDecryptionFailed)?;

    let mut credential = Zeroizing::new(Vec::new());
    let read_result = child.stdout.take().map_or_else(
        || Err(io::Error::other("systemd-creds stdout unavailable")),
        |stdout| {
            stdout
                .take((MAX_UBUNTU_TRANSPORT_IDENTITY_PKCS8_BYTES + 1) as u64)
                .read_to_end(&mut credential)
        },
    );
    if read_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(TransportIdentityRecoveryError::CredentialDecryptionFailed);
    }
    if credential.is_empty() || credential.len() > MAX_UBUNTU_TRANSPORT_IDENTITY_PKCS8_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(TransportIdentityRecoveryError::DecryptedCredentialOutOfBounds);
    }

    let status = child
        .wait()
        .map_err(|_| TransportIdentityRecoveryError::CredentialDecryptionFailed)?;
    if !status.success() {
        return Err(TransportIdentityRecoveryError::CredentialDecryptionFailed);
    }

    derive_transport_identity_from_pkcs8_v1_der(credential.as_slice())
        .map_err(|_| TransportIdentityRecoveryError::InvalidPrivateCredential)
}

fn validate_selected_custody_capability(
    policy: TransportIdentityProvisioningPolicy,
) -> Result<(), TransportIdentityProvisioningError> {
    validate_secure_system_program(Path::new(SYSTEMD_CREDS_PATH))
        .map_err(|()| TransportIdentityProvisioningError::SystemdCredsUnavailable)?;
    validate_secure_system_program(Path::new(SYSTEMD_ANALYZE_PATH))
        .map_err(|()| TransportIdentityProvisioningError::SystemdAnalyzeUnavailable)?;

    let tpm2_usable = query_tpm2_usability()?;
    match policy {
        TransportIdentityProvisioningPolicy::Preferred if !tpm2_usable => {
            return Err(TransportIdentityProvisioningError::Tpm2Unavailable);
        }
        TransportIdentityProvisioningPolicy::HostKeyOnly if tpm2_usable => {
            return Err(TransportIdentityProvisioningError::HostKeyOnlyFallbackForbidden);
        }
        TransportIdentityProvisioningPolicy::Preferred
        | TransportIdentityProvisioningPolicy::HostKeyOnly => {}
    }

    validate_host_credential_secret(Path::new(SYSTEMD_HOST_CREDENTIAL_SECRET_PATH))
}

fn query_tpm2_usability() -> Result<bool, TransportIdentityProvisioningError> {
    let status = Command::new(SYSTEMD_ANALYZE_PATH)
        .arg("has-tpm2")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| TransportIdentityProvisioningError::SystemdAnalyzeUnavailable)?;
    if status.code().is_none() {
        return Err(TransportIdentityProvisioningError::SystemdAnalyzeUnavailable);
    }
    Ok(status.success())
}

fn validate_secure_system_program(path: &Path) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & INSECURE_SYSTEM_FILE_WRITE_BITS != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(());
    }
    Ok(())
}

fn validate_host_credential_secret(path: &Path) -> Result<(), TransportIdentityProvisioningError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(TransportIdentityProvisioningError::HostSecretUnavailable);
        }
        Err(_) => return Err(TransportIdentityProvisioningError::HostSecretUnavailable),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & INSECURE_SYSTEM_FILE_WRITE_BITS != 0
        || metadata.len() == 0
    {
        return Err(TransportIdentityProvisioningError::HostSecretInsecure);
    }
    Ok(())
}

fn resolve_xdg_root(variable: &str, home_suffix: &str) -> Option<PathBuf> {
    if let Some(value) = env::var_os(variable) {
        if value.is_empty() {
            return None;
        }
        let path = PathBuf::from(value);
        return path.is_absolute().then_some(path);
    }

    let home = env::var_os("HOME")?;
    if home.is_empty() {
        return None;
    }
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return None;
    }
    Some(home.join(home_suffix))
}

fn validate_existing_root(path: &Path, uid: u32) -> Result<(), TransportIdentityProvisioningError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| TransportIdentityProvisioningError::InsecureDirectory)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(TransportIdentityProvisioningError::InsecureDirectory);
    }
    Ok(())
}

fn ensure_private_directory(
    path: &Path,
    uid: u32,
) -> Result<(), TransportIdentityProvisioningError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != uid
                || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
            {
                return Err(TransportIdentityProvisioningError::InsecureDirectory);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| TransportIdentityProvisioningError::DirectoryCreationFailed)?;
            fs::set_permissions(path, Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .map_err(|_| TransportIdentityProvisioningError::DirectoryCreationFailed)?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| TransportIdentityProvisioningError::DirectoryCreationFailed)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != uid
                || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
            {
                return Err(TransportIdentityProvisioningError::InsecureDirectory);
            }
        }
        Err(_) => return Err(TransportIdentityProvisioningError::InsecureDirectory),
    }
    Ok(())
}

fn ensure_user_directory(path: &Path, uid: u32) -> Result<(), TransportIdentityProvisioningError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_existing_root(path, uid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)
                .map_err(|_| TransportIdentityProvisioningError::DirectoryCreationFailed)?;
            fs::set_permissions(path, Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
                .map_err(|_| TransportIdentityProvisioningError::DirectoryCreationFailed)?;
            validate_existing_root(path, uid)
        }
        Err(_) => Err(TransportIdentityProvisioningError::InsecureDirectory),
    }
}

fn require_absent(path: &Path) -> Result<(), TransportIdentityProvisioningError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(TransportIdentityProvisioningError::AlreadyProvisioned),
    }
}

fn render_transport_identity_dropin(
    encrypted_credential_path: &Path,
    custody_tier: &str,
) -> Result<Vec<u8>, TransportIdentityProvisioningError> {
    if !encrypted_credential_path.is_absolute() {
        return Err(TransportIdentityProvisioningError::InvalidCredentialBinding);
    }
    let path = encrypted_credential_path
        .to_str()
        .ok_or(TransportIdentityProvisioningError::InvalidCredentialBinding)?;
    if path.is_empty()
        || path.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'\\' | b'\'' | b'"' | b'%')
        })
    {
        return Err(TransportIdentityProvisioningError::InvalidCredentialBinding);
    }

    if custody_tier != TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER
        && custody_tier != TRANSPORT_IDENTITY_HOST_KEY_ONLY_CUSTODY_TIER
    {
        return Err(TransportIdentityProvisioningError::InvalidCredentialBinding);
    }

    let payload = format!(
        "# PRW_TRANSPORT_CUSTODY_TIER={custody_tier}\n[Service]\nLoadCredentialEncrypted={SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME}:{path}\n"
    )
    .into_bytes();
    if payload.is_empty() || payload.len() > MAX_DROPIN_BYTES {
        return Err(TransportIdentityProvisioningError::InvalidCredentialBinding);
    }
    Ok(payload)
}

fn commit_transport_identity_dropin(
    config_root: &Path,
    final_dropin: &Path,
    payload: &[u8],
    uid: u32,
) -> Result<(), TransportIdentityProvisioningError> {
    ensure_user_directory(config_root, uid)?;
    let systemd_dir = config_root.join("systemd");
    ensure_user_directory(&systemd_dir, uid)?;
    let user_dir = systemd_dir.join("user");
    ensure_user_directory(&user_dir, uid)?;
    let dropin_dir = user_dir.join("prw-agent.service.d");
    ensure_user_directory(&dropin_dir, uid)?;
    require_absent(final_dropin)?;

    let temp_dropin = dropin_dir.join(format!(
        ".30-transport-identity-credential.conf.{}.tmp",
        std::process::id()
    ));
    require_absent(&temp_dropin)
        .map_err(|_| TransportIdentityProvisioningError::DropinWriteFailed)?;

    let (opened_temp, opened_metadata) =
        match write_validate_and_sync_dropin_temp(&temp_dropin, payload, uid) {
            Ok(validated) => validated,
            Err(error) => {
                let _ = fs::remove_file(&temp_dropin);
                return Err(error);
            }
        };

    if renameat_with(CWD, &temp_dropin, CWD, final_dropin, RenameFlags::NOREPLACE).is_err() {
        let _ = fs::remove_file(&temp_dropin);
        return Err(TransportIdentityProvisioningError::DropinCommitFailed);
    }

    let Ok(final_metadata) = fs::symlink_metadata(final_dropin) else {
        let _ = fs::remove_file(final_dropin);
        return Err(TransportIdentityProvisioningError::DropinCommitFailed);
    };
    if validate_dropin_metadata(&final_metadata, uid).is_err()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
    {
        let _ = fs::remove_file(final_dropin);
        let _ = sync_directory(&dropin_dir);
        return Err(TransportIdentityProvisioningError::DropinCommitFailed);
    }
    drop(opened_temp);

    if sync_directory(&dropin_dir).is_err() {
        let _ = fs::remove_file(final_dropin);
        let _ = sync_directory(&dropin_dir);
        return Err(TransportIdentityProvisioningError::DirectorySyncFailed);
    }

    Ok(())
}

fn write_validate_and_sync_dropin_temp(
    path: &Path,
    payload: &[u8],
    uid: u32,
) -> Result<(File, fs::Metadata), TransportIdentityProvisioningError> {
    if payload.is_empty() || payload.len() > MAX_DROPIN_BYTES {
        return Err(TransportIdentityProvisioningError::DropinWriteFailed);
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(DROPIN_MODE)
        .open(path)
        .map_err(|_| TransportIdentityProvisioningError::DropinWriteFailed)?;
    file.set_permissions(Permissions::from_mode(DROPIN_MODE))
        .map_err(|_| TransportIdentityProvisioningError::DropinWriteFailed)?;
    file.write_all(payload)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|_| TransportIdentityProvisioningError::DropinWriteFailed)?;

    let metadata = file
        .metadata()
        .map_err(|_| TransportIdentityProvisioningError::DropinWriteFailed)?;
    validate_dropin_metadata(&metadata, uid)?;
    Ok((file, metadata))
}

fn validate_dropin_metadata(
    metadata: &fs::Metadata,
    uid: u32,
) -> Result<(), TransportIdentityProvisioningError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != DROPIN_MODE
        || metadata.len() == 0
        || metadata.len() > MAX_DROPIN_BYTES as u64
    {
        return Err(TransportIdentityProvisioningError::DropinWriteFailed);
    }
    Ok(())
}

fn encrypt_with_systemd_creds(
    temp_ciphertext: &Path,
    mut private_pkcs8: Zeroizing<Vec<u8>>,
    policy: TransportIdentityProvisioningPolicy,
) -> Result<(), TransportIdentityProvisioningError> {
    let mut command = Command::new(SYSTEMD_CREDS_PATH);
    command.arg("--user");
    if policy.uses_host_key_only_override() {
        command.arg("-H");
    }
    let mut child = command
        .arg("encrypt")
        .arg(format!(
            "--name={SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME}"
        ))
        .arg("-")
        .arg(temp_ciphertext)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| TransportIdentityProvisioningError::CredentialEncryptionFailed)?;

    let write_result = child.stdin.take().map_or_else(
        || Err(io::Error::other("systemd-creds stdin unavailable")),
        |mut stdin| {
            stdin
                .write_all(private_pkcs8.as_slice())
                .and_then(|()| stdin.flush())
        },
    );
    private_pkcs8.zeroize();
    drop(private_pkcs8);

    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(TransportIdentityProvisioningError::CredentialEncryptionFailed);
    }

    let status = child
        .wait()
        .map_err(|_| TransportIdentityProvisioningError::CredentialEncryptionFailed)?;
    if !status.success() {
        return Err(TransportIdentityProvisioningError::CredentialEncryptionFailed);
    }
    Ok(())
}

fn harden_validate_and_sync_ciphertext_temp(
    path: &Path,
    uid: u32,
) -> Result<(File, fs::Metadata), TransportIdentityProvisioningError> {
    let before = fs::symlink_metadata(path)
        .map_err(|_| TransportIdentityProvisioningError::CiphertextWriteFailed)?;
    validate_initial_ciphertext_metadata(&before, uid)?;

    let owned_fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| TransportIdentityProvisioningError::CiphertextWriteFailed)?;
    let file = File::from(owned_fd);
    let opened = file
        .metadata()
        .map_err(|_| TransportIdentityProvisioningError::CiphertextWriteFailed)?;
    validate_initial_ciphertext_metadata(&opened, uid)?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(TransportIdentityProvisioningError::CiphertextWriteFailed);
    }

    file.set_permissions(Permissions::from_mode(CIPHERTEXT_MODE))
        .map_err(|_| TransportIdentityProvisioningError::CiphertextWriteFailed)?;
    let hardened = file
        .metadata()
        .map_err(|_| TransportIdentityProvisioningError::CiphertextWriteFailed)?;
    validate_ciphertext_metadata(&hardened, uid)?;
    if hardened.dev() != opened.dev() || hardened.ino() != opened.ino() {
        return Err(TransportIdentityProvisioningError::CiphertextWriteFailed);
    }
    file.sync_all()
        .map_err(|_| TransportIdentityProvisioningError::CiphertextWriteFailed)?;
    Ok((file, hardened))
}

fn validate_initial_ciphertext_metadata(
    metadata: &fs::Metadata,
    uid: u32,
) -> Result<(), TransportIdentityProvisioningError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & FORBIDDEN_INITIAL_CIPHERTEXT_MODE_BITS != 0
    {
        return Err(TransportIdentityProvisioningError::CiphertextWriteFailed);
    }
    validate_ciphertext_size(metadata)
}

fn validate_ciphertext_metadata(
    metadata: &fs::Metadata,
    uid: u32,
) -> Result<(), TransportIdentityProvisioningError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != CIPHERTEXT_MODE
    {
        return Err(TransportIdentityProvisioningError::CiphertextWriteFailed);
    }
    validate_ciphertext_size(metadata)
}

fn validate_ciphertext_size(
    metadata: &fs::Metadata,
) -> Result<(), TransportIdentityProvisioningError> {
    if metadata.len() == 0 || metadata.len() > MAX_ENCRYPTED_CREDENTIAL_BYTES {
        return Err(TransportIdentityProvisioningError::EncryptedCredentialOutOfBounds);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
    };

    use super::{
        SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME, TRANSPORT_IDENTITY_HOST_KEY_ONLY_CUSTODY_TIER,
        TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER, TransportIdentityPersistentState,
        TransportIdentityProvisioningError, TransportIdentityProvisioningPolicy,
        TransportIdentityRecoveryError, classify_transport_identity_persistent_state,
        established_policy_from_dropin_payload, render_transport_identity_dropin,
    };
    use prw_transport_identity_custody::derive_transport_identity_from_pkcs8_v1_der;

    #[test]
    fn persistent_state_requires_a_complete_artifact_pair() {
        assert_eq!(
            classify_transport_identity_persistent_state(false, false),
            Ok(TransportIdentityPersistentState::Absent)
        );
        assert_eq!(
            classify_transport_identity_persistent_state(true, true),
            Ok(TransportIdentityPersistentState::Established)
        );
        assert_eq!(
            classify_transport_identity_persistent_state(true, false),
            Err(TransportIdentityRecoveryError::PartialState)
        );
        assert_eq!(
            classify_transport_identity_persistent_state(false, true),
            Err(TransportIdentityRecoveryError::PartialState)
        );
    }

    #[test]
    fn generated_p256_key_derives_nonzero_transport_identity() {
        let generated =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable transport key");
        let identity = derive_transport_identity_from_pkcs8_v1_der(generated.as_ref())
            .expect("derive transport identity");
        assert_ne!(identity.as_bytes(), &[0_u8; 32]);
    }

    #[test]
    fn established_binding_selects_only_exact_persisted_canonical_policy() {
        let encrypted_path = Path::new(
            "/home/owner/.local/state/private-remote-workspace/credentials/transport-identity-private-key-v1.cred",
        );

        for policy in [
            TransportIdentityProvisioningPolicy::Preferred,
            TransportIdentityProvisioningPolicy::HostKeyOnly,
        ] {
            let payload = render_transport_identity_dropin(encrypted_path, policy.custody_tier())
                .expect("canonical established binding");
            assert_eq!(
                established_policy_from_dropin_payload(&payload, encrypted_path),
                Ok(policy)
            );
        }

        let unknown = format!(
            "# PRW_TRANSPORT_CUSTODY_TIER=UNKNOWN\n[Service]\nLoadCredentialEncrypted={SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME}:{}\n",
            encrypted_path.display()
        );
        assert_eq!(
            established_policy_from_dropin_payload(unknown.as_bytes(), encrypted_path),
            Err(TransportIdentityRecoveryError::CustodyPolicyMismatch)
        );

        let preferred = render_transport_identity_dropin(
            Path::new("/different/transport.cred"),
            TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER,
        )
        .expect("other canonical path");
        assert_eq!(
            established_policy_from_dropin_payload(&preferred, encrypted_path),
            Err(TransportIdentityRecoveryError::CustodyPolicyMismatch)
        );
    }

    #[test]
    fn transport_dropin_binds_exact_credential_and_selected_custody_tier() {
        let encrypted_path = Path::new(
            "/home/gersi365/.local/state/private-remote-workspace/credentials/transport-identity-private-key-v1.cred",
        );

        for custody_tier in [
            TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER,
            TRANSPORT_IDENTITY_HOST_KEY_ONLY_CUSTODY_TIER,
        ] {
            let rendered = render_transport_identity_dropin(encrypted_path, custody_tier)
                .expect("render fixed binding");
            let expected = format!(
                "# PRW_TRANSPORT_CUSTODY_TIER={custody_tier}\n[Service]\nLoadCredentialEncrypted={SYSTEMD_TRANSPORT_IDENTITY_CREDENTIAL_NAME}:{}\n",
                encrypted_path.display()
            );
            assert_eq!(rendered, expected.into_bytes());
        }
    }

    #[test]
    fn custody_policy_controls_only_explicit_host_key_override() {
        assert!(!TransportIdentityProvisioningPolicy::Preferred.uses_host_key_only_override());
        assert!(TransportIdentityProvisioningPolicy::HostKeyOnly.uses_host_key_only_override());
    }

    #[test]
    fn transport_dropin_rejects_relative_unsafe_or_unknown_policy() {
        assert_eq!(
            render_transport_identity_dropin(
                Path::new("relative/transport.cred"),
                TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER,
            ),
            Err(TransportIdentityProvisioningError::InvalidCredentialBinding)
        );
        assert_eq!(
            render_transport_identity_dropin(
                Path::new("/tmp/unsafe path.cred"),
                TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER,
            ),
            Err(TransportIdentityProvisioningError::InvalidCredentialBinding)
        );
        assert_eq!(
            render_transport_identity_dropin(
                Path::new("/tmp/unsafe%path.cred"),
                TRANSPORT_IDENTITY_PREFERRED_CUSTODY_TIER,
            ),
            Err(TransportIdentityProvisioningError::InvalidCredentialBinding)
        );
        assert_eq!(
            render_transport_identity_dropin(Path::new("/tmp/safe.cred"), "UNKNOWN"),
            Err(TransportIdentityProvisioningError::InvalidCredentialBinding)
        );
    }
}
