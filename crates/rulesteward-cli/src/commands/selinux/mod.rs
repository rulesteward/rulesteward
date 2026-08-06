//! Body of `rulesteward selinux <subcommand>`.
//!
//! Dispatch across the three selinux verbs: `triage` (P0.3-P5), `lint`
//! (#520, se-W01/se-W02), and `doctor` (#520, the 5-check scorecard).
//! `triage.rs` keeps its own `pub fn run(cmd: SelinuxCommand) ->
//! anyhow::Result<i32>` signature, with an exhaustive-match arm
//! (`Lint`/`Doctor` -> `unreachable!()`) so it type-checks against every
//! variant of the enum. That arm is never reached in practice because this
//! dispatcher re-wraps the extracted `TriageArgs` into a fresh
//! `SelinuxCommand::Triage` before calling it, rather than editing that
//! otherwise-frozen file.

mod doctor;
mod lint;
mod triage;

use crate::cli::SelinuxCommand;
use rulesteward_core::Framework;

/// `--profile` carries a `Vec<Diagnostic>` seam only through `lint`; `triage`
/// and `doctor` have no findings surface, so the globally-accepted flag is
/// inert for them (mirrors the fapolicyd/sysctl dispatch doc comments).
pub fn run(cmd: SelinuxCommand, profile: Option<Framework>) -> anyhow::Result<i32> {
    match cmd {
        SelinuxCommand::Triage(args) => triage::run(SelinuxCommand::Triage(args)),
        SelinuxCommand::Lint(args) => Ok(lint::run_lint(&args, profile)),
        SelinuxCommand::Doctor(args) => Ok(doctor::run(&args)),
    }
}
