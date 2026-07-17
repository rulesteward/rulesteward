//! `rulesteward selinux doctor` - composite `SELinux` deployment health check
//! (#520).
//!
//! # Architecture
//!
//! Mirrors `commands::doctor` (fapolicyd's, PR #133/#173): all environment
//! I/O (`getenforce`, `sestatus`, `rpm -q`, the faillock locator, `ls -Zd`) is
//! routed through the [`model::SelinuxProbe`] trait. The 5 check functions in
//! `checks.rs` contain ONLY classification logic over plain data, so they are
//! fully unit-testable with a `FakeProbe` without touching the real OS. The
//! real [`probe::LiveSelinuxProbe`] shells out and is NOT unit-tested
//! directly - it is exercised by the live VM smoke test and the graceful-
//! degradation e2e test.
//!
//! Reuses the shared doctor surface generalized in the Phase-0 foundation:
//! `crate::commands::doctor::{CheckResult, CheckStatus, worst_exit_code}` and
//! `crate::commands::doctor::render::{render_human, render_json}`.

mod checks;
mod model;
mod probe;

use crate::cli::SelinuxDoctorArgs;
use crate::commands::doctor::render::{render_human, render_json};
use crate::commands::doctor::worst_exit_code;
use crate::commands::target_probe::{LiveTargetProbe, resolve_doctor_target};

/// Schema version for the `selinux-doctor-report` kind.
const SELINUX_DOCTOR_SCHEMA_VERSION: u32 = 1;

/// Run the `selinux doctor` subcommand.
pub(super) fn run(args: &SelinuxDoctorArgs) -> i32 {
    // Doctor semantics (epic #251): an omitted --target defaults to
    // auto-detect (doctor always examines the host it runs on); a failed or
    // unresolvable auto-detect resolves to None silently, and THIS caller
    // owns the one-line stderr note, per the Phase-0 foundation's convention.
    let target = resolve_doctor_target(args.target, &LiveTargetProbe).map(Into::into);
    if target.is_none() {
        eprintln!("selinux doctor: running checks without STIG control attachment");
    }

    let probe = probe::LiveSelinuxProbe;
    let results = checks::run_checks(&probe, target);

    let output = match args.format {
        crate::cli::HumanJsonFormat::Human => render_human("selinux doctor report", &results),
        crate::cli::HumanJsonFormat::Json => render_json(
            "selinux-doctor-report",
            SELINUX_DOCTOR_SCHEMA_VERSION,
            &results,
        ),
    };
    print!("{output}");

    worst_exit_code(&results)
}
