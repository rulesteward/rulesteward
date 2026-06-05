//! `rulesteward fapolicyd simulate` body.
//!
//! Phase-0 STUB: the arg contract (`SimulateArgs`) is frozen here; the actual
//! workload-replay logic is implemented in the `feat-simulate` pipeline. This
//! `todo!()` body type-checks and keeps the dispatch wiring frozen so the
//! pipeline edits only this file.

/// Run the simulate subcommand. (Stub - filled by the `feat-simulate` pipeline.)
///
/// By-value `args` mirrors the sibling command `run` convention (`explain::run`)
/// and the frozen dispatch wiring; the stub does not yet consume it, so the
/// pass-by-value lint is allowed until the pipeline fills the body.
#[allow(clippy::needless_pass_by_value)]
pub fn run(args: crate::cli::SimulateArgs) -> anyhow::Result<i32> {
    let _ = args;
    todo!("simulate: implemented in the feat-simulate pipeline")
}
