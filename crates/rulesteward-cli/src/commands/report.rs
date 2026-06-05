//! `rulesteward fapolicyd report` body.
//!
//! Phase-0 STUB: the arg contract (`ReportArgs`) is frozen here; the actual
//! exception-register build + drift logic is implemented in the `feat-report`
//! pipeline. This `todo!()` body type-checks and keeps the dispatch wiring
//! frozen so the pipeline edits only this file (plus `register.rs`, which only
//! report touches).

/// Run the report subcommand. (Stub - filled by the `feat-report` pipeline.)
///
/// By-value `args` mirrors the sibling command `run` convention (`explain::run`)
/// and the frozen dispatch wiring; the stub does not yet consume it, so the
/// pass-by-value lint is allowed until the pipeline fills the body.
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: crate::cli::ReportArgs) -> anyhow::Result<i32> {
    let _ = args;
    todo!("report: implemented in the feat-report pipeline")
}
