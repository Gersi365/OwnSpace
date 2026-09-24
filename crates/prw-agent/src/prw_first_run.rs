//! Command-line interface for the dedicated `prw-first-run` setup-intent authoring tool.
//!
//! C03e-ZI materializes only the explicit setup-intent authoring grammar.
//! It does not invoke first-run bootstrap, Agent startup, systemd, `SQLite`,
//! certificate issuance, networking, installer logic, or Desktop logic.

use std::{ffi::OsString, process::ExitCode};

use crate::{
    owner_first_run_setup_intent::{
        OwnerFirstRunSetupIntentError, OwnerFirstRunSetupIntentWriteOutcome,
        ensure_owner_first_run_transport_custody_intent_from_env,
    },
    owner_first_setup_custody_policy_orchestration::OwnerFirstSetupTransportCustodySelection,
};

const TRANSPORT_CUSTODY_COMMAND: &str = "transport-custody";
const PREFERRED_DEFAULT_TOKEN: &str = "preferred-default";
const EXPLICIT_HOST_KEY_ONLY_FALLBACK_TOKEN: &str = "explicit-host-key-only-fallback";
const USAGE: &str =
    "usage: prw-first-run transport-custody <preferred-default|explicit-host-key-only-fallback>";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrwFirstRunCliError {
    InvalidArguments,
    Writer(OwnerFirstRunSetupIntentError),
}

/// Runs the dedicated first-run setup-intent authoring command.
///
/// The command accepts only the exact C03e-ZI grammar and then delegates
/// persistence to the existing create-once PRW-D083 writer. It does not invoke
/// bootstrap/runtime activation.
///
/// # Exit status
///
/// Returns success only when the requested canonical intent was created or
/// already existed exactly. Invalid input and writer failure return failure.
#[must_use]
pub fn run_from_env_args() -> ExitCode {
    match execute_with_writer(
        std::env::args_os().skip(1),
        ensure_owner_first_run_transport_custody_intent_from_env,
    ) {
        Ok(outcome) => {
            println!(
                "prw-first-run command=transport-custody intent={} result={}",
                selection_token(outcome.selection()),
                if outcome.was_created() {
                    "created"
                } else {
                    "existing"
                }
            );
            ExitCode::SUCCESS
        }
        Err(PrwFirstRunCliError::InvalidArguments) => {
            eprintln!("prw-first-run result=failure error=invalid_arguments");
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
        Err(PrwFirstRunCliError::Writer(error)) => {
            eprintln!("prw-first-run result=failure error={error}");
            ExitCode::FAILURE
        }
    }
}

fn execute_with_writer<I, F>(
    args: I,
    writer: F,
) -> Result<OwnerFirstRunSetupIntentWriteOutcome, PrwFirstRunCliError>
where
    I: IntoIterator<Item = OsString>,
    F: FnOnce(
        OwnerFirstSetupTransportCustodySelection,
    ) -> Result<OwnerFirstRunSetupIntentWriteOutcome, OwnerFirstRunSetupIntentError>,
{
    let selection = parse_transport_custody_selection(args)?;
    writer(selection).map_err(PrwFirstRunCliError::Writer)
}

fn parse_transport_custody_selection<I>(
    args: I,
) -> Result<OwnerFirstSetupTransportCustodySelection, PrwFirstRunCliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let command = args.next().ok_or(PrwFirstRunCliError::InvalidArguments)?;
    let selection = args.next().ok_or(PrwFirstRunCliError::InvalidArguments)?;

    if args.next().is_some() || command.to_str() != Some(TRANSPORT_CUSTODY_COMMAND) {
        return Err(PrwFirstRunCliError::InvalidArguments);
    }

    match selection.to_str() {
        Some(PREFERRED_DEFAULT_TOKEN) => {
            Ok(OwnerFirstSetupTransportCustodySelection::PreferredDefault)
        }
        Some(EXPLICIT_HOST_KEY_ONLY_FALLBACK_TOKEN) => {
            Ok(OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback)
        }
        _ => Err(PrwFirstRunCliError::InvalidArguments),
    }
}

const fn selection_token(selection: OwnerFirstSetupTransportCustodySelection) -> &'static str {
    match selection {
        OwnerFirstSetupTransportCustodySelection::PreferredDefault => PREFERRED_DEFAULT_TOKEN,
        OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback => {
            EXPLICIT_HOST_KEY_ONLY_FALLBACK_TOKEN
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{
        PrwFirstRunCliError, execute_with_writer, parse_transport_custody_selection,
        selection_token,
    };
    use crate::{
        owner_first_run_setup_intent::OwnerFirstRunSetupIntentWriteOutcome,
        owner_first_setup_custody_policy_orchestration::OwnerFirstSetupTransportCustodySelection,
    };

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn exact_grammar_maps_to_existing_typed_selections() {
        for (token, expected) in [
            (
                "preferred-default",
                OwnerFirstSetupTransportCustodySelection::PreferredDefault,
            ),
            (
                "explicit-host-key-only-fallback",
                OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback,
            ),
        ] {
            assert_eq!(
                parse_transport_custody_selection(args(&["transport-custody", token])),
                Ok(expected)
            );
            assert_eq!(selection_token(expected), token);
        }
    }

    #[test]
    fn invalid_or_ambiguous_grammar_fails_before_writer_dispatch() {
        for invalid in [
            args(&[]),
            args(&["transport-custody"]),
            args(&["preferred-default"]),
            args(&["transport-custody", "host-key-only"]),
            args(&["transport-custody", "HOST-KEY-ONLY"]),
            args(&["transport-custody", "preferred-default", "extra"]),
        ] {
            let result = execute_with_writer(invalid, |_| {
                panic!("writer must not run for invalid grammar")
            });
            assert_eq!(result, Err(PrwFirstRunCliError::InvalidArguments));
        }
    }

    #[test]
    fn exact_explicit_fallback_reaches_writer_without_policy_reinterpretation() {
        let expected = OwnerFirstSetupTransportCustodySelection::ExplicitHostKeyOnlyFallback;
        let mut observed = None;

        let outcome = execute_with_writer(
            args(&["transport-custody", "explicit-host-key-only-fallback"]),
            |selection| {
                observed = Some(selection);
                Ok(OwnerFirstRunSetupIntentWriteOutcome::Existing(selection))
            },
        )
        .expect("exact grammar dispatches");

        assert_eq!(observed, Some(expected));
        assert_eq!(
            outcome,
            OwnerFirstRunSetupIntentWriteOutcome::Existing(expected)
        );
    }
}
