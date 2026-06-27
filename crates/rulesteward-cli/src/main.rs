//! `rulesteward` - top-level CLI binary.
//!
//! Thin shell: parse argv via clap, dispatch to the matching
//! `commands::<ns>::run`, convert any `anyhow::Error` to an exit code
//! via `report()`, and use that as the process exit code.
//!
//! Clap's default exit code on parse errors is `2`. Spec §9.4
//! reserves `2` for "errors found in policy" (real lint findings),
//! so we remap usage errors to `EXIT_TOOL_FAILURE` (3). Help and
//! version requests still exit `0`.

use clap::Parser;

use rulesteward_cli::cli::{Cli, TopCommand};
use rulesteward_cli::commands;
use rulesteward_cli::exit_code::EXIT_TOOL_FAILURE;

fn main() {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // `use_stderr()` is true for genuine usage errors (unknown
            // flag, missing required arg, etc.) and false for help /
            // version output. Help → exit 0; usage error → exit 3.
            let usage_error = e.use_stderr();
            e.print()
                .expect("failed to write clap error to stderr/stdout");
            std::process::exit(if usage_error { EXIT_TOOL_FAILURE } else { 0 });
        }
    };

    let code = match cli.command {
        TopCommand::Fapolicyd(cmd) => report(commands::fapolicyd::run(cmd)),
        TopCommand::Selinux(cmd) => report(commands::selinux::run(cmd)),
        TopCommand::Auditd(cmd) => report(commands::auditd::run(cmd)),
        TopCommand::Sshd(cmd) => report(commands::sshd::run(cmd)),
        TopCommand::Sysctl(cmd) => report(commands::sysctl::run(cmd)),
        TopCommand::Completions(args) => report(commands::completions::run(&args)),
        TopCommand::Mangen(args) => report(commands::mangen::run(&args)),
    };
    std::process::exit(code);
}

/// Convert a command's `anyhow::Result<i32>` to a process exit code.
///
/// On `Ok(code)` the command's own exit code is honored. On `Err(e)`
/// the cause chain is printed to stderr as a single line in
/// `"error: head: cause1: cause2"` form (via the `{e:#}`
/// alternate-format flag - not the multi-line `Caused by:` block
/// that `{e:?}` produces), and the process exits with
/// `EXIT_TOOL_FAILURE` (3).
fn report(result: anyhow::Result<i32>) -> i32 {
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            EXIT_TOOL_FAILURE
        }
    }
}
