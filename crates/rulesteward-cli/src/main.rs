//! `rulesteward` — top-level CLI binary.
//!
//! Thin shell: parse argv via clap, dispatch to the matching
//! `commands::<ns>::run`, and use the returned `i32` as the
//! process exit code.
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
            e.print().expect("clap error printer");
            std::process::exit(if usage_error { EXIT_TOOL_FAILURE } else { 0 });
        }
    };

    let code = match cli.command {
        TopCommand::Fapolicyd(cmd) => commands::fapolicyd::run(cmd),
        TopCommand::Selinux(cmd) => commands::selinux::run(cmd),
        TopCommand::Auditd(cmd) => commands::auditd::run(cmd),
    };
    std::process::exit(code);
}
