#![cfg(target_os = "linux")]

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    prw_agent_package_reconciliation::run_cli(env::args_os())
}
