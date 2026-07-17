//! Body of `rulesteward selinux <subcommand>`.
//!
//! Dispatch across the three selinux verbs: `triage` (P0.3-P5, unchanged),
//! `lint` (#520, se-W01/se-W02), and `doctor` (#520, the 5-check scorecard).
//! `triage.rs` was moved BYTE-IDENTICAL from the former single-file
//! `commands/selinux.rs` when this module became a directory (session 9d lane
//! 2b); it keeps its own `pub fn run(cmd: SelinuxCommand) -> anyhow::Result<i32>`
//! matching only the `Triage` arm, so this dispatcher re-wraps the extracted
//! `TriageArgs` into a fresh `SelinuxCommand::Triage` rather than editing that
//! frozen file.

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
