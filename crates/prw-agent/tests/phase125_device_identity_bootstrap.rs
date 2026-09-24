#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{self, Command},
    sync::atomic::{AtomicU64, Ordering},
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair},
};
use prw_device_identity_custody::SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME;

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct TestRuntimeRoot {
    path: PathBuf,
}

impl TestRuntimeRoot {
    fn new() -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "prw-phase125-device-identity-bootstrap-{}-{id}",
            process::id()
        ));
        fs::create_dir(&path).expect("create isolated Phase 125 runtime root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure isolated runtime root");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestRuntimeRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct TestCredentialDirectory {
    path: PathBuf,
}

impl TestCredentialDirectory {
    fn new() -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "prw-phase125-device-identity-credential-{}-{id}",
            process::id()
        ));
        fs::create_dir(&path).expect("create isolated Phase 125 credential directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure isolated credential directory");

        let key =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .expect("generate disposable Phase 125 device identity");
        let credential = path.join(SYSTEMD_DEVICE_IDENTITY_CREDENTIAL_NAME);
        fs::write(&credential, key.as_ref()).expect("write disposable device identity credential");
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o400))
            .expect("secure disposable device identity credential");

        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestCredentialDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn missing_systemd_identity_fails_before_runtime_socket_creation() {
    let runtime = TestRuntimeRoot::new();
    let output = Command::new(env!("CARGO_BIN_EXE_prw-agent"))
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env_remove("CREDENTIALS_DIRECTORY")
        .output()
        .expect("execute Phase 125 Agent bootstrap");

    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).expect("bounded Agent stderr is UTF-8"),
        "prw-agent event=startup_failure kind=device_identity exit=failure signal_mask_restore=not_applicable\n"
    );
    assert!(!runtime.path().join("private-remote-workspace").exists());
}

#[test]
fn valid_identity_reaches_startup_authority_before_execution_mode_or_runtime() {
    let runtime = TestRuntimeRoot::new();
    let credential = TestCredentialDirectory::new();
    let output = Command::new(env!("CARGO_BIN_EXE_prw-agent"))
        .env("XDG_RUNTIME_DIR", runtime.path())
        .env("XDG_STATE_HOME", runtime.path())
        .env("CREDENTIALS_DIRECTORY", credential.path())
        .env_remove("PRW_AGENT_EXECUTION_MODE")
        .output()
        .expect("execute startup-authority-gated Agent bootstrap");

    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).expect("bounded Agent stderr is UTF-8"),
        "prw-agent event=startup_failure kind=startup_authority stage=setup_intent_classification exit=failure signal_mask_restore=not_applicable\n"
    );
    assert!(!runtime.path().join("private-remote-workspace").exists());
}
