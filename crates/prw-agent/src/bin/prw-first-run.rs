//! Thin executable boundary for the explicit `prw-first-run` setup-intent authoring tool.

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    prw_agent::prw_first_run::run_from_env_args()
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("prw-first-run result=failure error=unsupported_platform");
    ExitCode::FAILURE
}
