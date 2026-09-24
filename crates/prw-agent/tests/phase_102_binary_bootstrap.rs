#![cfg(target_os = "linux")]

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use prw_agent::linux_bootstrap::{
    LinuxAgentExecutionModeSourceError, PRW_AGENT_EXECUTION_MODE_ENV,
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

const SUBPROCESS_ENV: &str = "PRW_PHASE_102_RUNTIME_FACADE_SUBPROCESS";
const TEST_NAME: &str = "runtime_facade_failure_contract_is_proven_in_isolated_subprocesses";

const CASE_MISSING_EXECUTION_MODE: &str = "missing_execution_mode";
const CASE_INVALID_EXECUTION_MODE: &str = "invalid_execution_mode";
const CASE_MISSING_RUNTIME_ROOT: &str = "missing_runtime_root";
const CASE_WRONG_MODE_RUNTIME_ROOT: &str = "wrong_mode_runtime_root";

struct TempRuntimeRoot {
    path: PathBuf,
}

impl TempRuntimeRoot {
    fn new(label: &str, mode: u32) -> Self {
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "prw-phase-102-runtime-facade-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("Phase 102 temporary runtime root creates");
        fs::set_permissions(&path, Permissions::from_mode(mode))
            .expect("Phase 102 temporary runtime root mode sets");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempRuntimeRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_isolated_case(
    case: &str,
    runtime_root: Option<&Path>,
    execution_mode: Option<&str>,
) -> Output {
    let executable = std::env::current_exe().expect("Phase 102 test executable resolves");
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg(TEST_NAME)
        .arg("--nocapture")
        .env(SUBPROCESS_ENV, case);

    match runtime_root {
        Some(root) => {
            command.env("XDG_RUNTIME_DIR", root);
        }
        None => {
            command.env_remove("XDG_RUNTIME_DIR");
        }
    }

    match execution_mode {
        Some(mode) => {
            command.env(PRW_AGENT_EXECUTION_MODE_ENV, mode);
        }
        None => {
            command.env_remove(PRW_AGENT_EXECUTION_MODE_ENV);
        }
    }

    command
        .output()
        .expect("Phase 102 isolated runtime-facade subprocess starts")
}

fn assert_subprocess_success(case: &str, output: &Output) {
    assert!(
        output.status.success(),
        "Phase 102 isolated case {case:?} failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn run_subprocess_case(case: &str) {
    match case {
        CASE_MISSING_EXECUTION_MODE => {
            assert_eq!(
                prw_agent::linux_bootstrap::load_linux_agent_execution_mode_from_env(),
                Err(LinuxAgentExecutionModeSourceError::Missing)
            );
        }
        CASE_INVALID_EXECUTION_MODE => {
            assert_eq!(
                prw_agent::linux_bootstrap::load_linux_agent_execution_mode_from_env(),
                Err(LinuxAgentExecutionModeSourceError::InvalidValue)
            );
        }
        CASE_MISSING_RUNTIME_ROOT | CASE_WRONG_MODE_RUNTIME_ROOT => {
            let failure = prw_agent::linux_bootstrap::run()
                .expect_err("invalid runtime-root custody must fail before runtime starts");
            assert_eq!(failure.kind().token(), "runtime_root");
            assert_eq!(failure.signal_mask_restore().token(), "restored");
        }
        unexpected => panic!("unexpected Phase 102 subprocess case: {unexpected}"),
    }
}

#[test]
fn runtime_facade_failure_contract_is_proven_in_isolated_subprocesses() {
    if let Some(case) = std::env::var_os(SUBPROCESS_ENV) {
        run_subprocess_case(
            case.to_str()
                .expect("Phase 102 subprocess case is canonical UTF-8"),
        );
        return;
    }

    let secure_root = TempRuntimeRoot::new("secure", 0o700);
    let missing_execution_mode =
        run_isolated_case(CASE_MISSING_EXECUTION_MODE, Some(secure_root.path()), None);
    assert_subprocess_success(CASE_MISSING_EXECUTION_MODE, &missing_execution_mode);

    let invalid_execution_mode = run_isolated_case(
        CASE_INVALID_EXECUTION_MODE,
        Some(secure_root.path()),
        Some("invalid"),
    );
    assert_subprocess_success(CASE_INVALID_EXECUTION_MODE, &invalid_execution_mode);

    let missing_runtime_root =
        run_isolated_case(CASE_MISSING_RUNTIME_ROOT, None, Some("local_only"));
    assert_subprocess_success(CASE_MISSING_RUNTIME_ROOT, &missing_runtime_root);

    let wrong_mode_root = TempRuntimeRoot::new("wrong-mode", 0o755);
    let wrong_mode_runtime_root = run_isolated_case(
        CASE_WRONG_MODE_RUNTIME_ROOT,
        Some(wrong_mode_root.path()),
        Some("local_only"),
    );
    assert_subprocess_success(CASE_WRONG_MODE_RUNTIME_ROOT, &wrong_mode_runtime_root);

    assert!(
        fs::read_dir(wrong_mode_root.path())
            .expect("wrong-mode temporary root remains readable")
            .next()
            .is_none(),
        "runtime-root failure must not create Agent runtime state"
    );
}
