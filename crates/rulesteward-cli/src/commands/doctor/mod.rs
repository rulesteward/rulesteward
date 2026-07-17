//! `rulesteward fapolicyd doctor` -- composite deployment health check.
//!
//! # Architecture
//!
//! All environment I/O (systemctl, uname, auditctl, fapolicyd-cli, rpm,
//! statvfs, config-file reads) is routed through the [`SystemProbe`] trait.
//! The 14 check functions contain ONLY classification logic over plain data, so
//! they are fully unit-testable with `FakeProbe` without touching the real OS.
//! The real [`LiveProbe`] shells out and is NOT unit-tested directly -- it is
//! exercised by the live VM smoke test and the graceful-degradation e2e test.
//!
//! Dependency injection via a trait object (`&dyn SystemProbe`) keeps `run_checks`
//! decoupled from the OS: swap in `FakeProbe` in tests, `LiveProbe` in production.
//!
//! `--target` -> STIG control attachment (#519): `run()` resolves the doctor
//! target (`target_probe::resolve_doctor_target` - omitted defaults to
//! `auto`, doctor always examines the host it runs on) and, when it resolves,
//! builds `FapolicydStigRefs::for_target` and threads it through
//! `run_checks`. An unresolvable `auto` (or a non-EL host) degrades to `stig:
//! None` - byte-identical to pre-#519 output - with a one-line stderr note,
//! never an error (read-only tool).

use std::path::Path;

use crate::cli::{DoctorArgs, HumanJsonFormat};
use crate::commands::target_probe::{LiveTargetProbe, resolve_doctor_target};

mod checks;
mod model;
mod probe;
pub(crate) mod render;

pub use checks::run_checks;
pub use model::{
    CheckResult, CheckStatus, CommandOutcome, DenialStats, FapolicydConf, FsSpace, LintCounts,
    ServiceState, SystemProbe, worst_exit_code,
};
pub use probe::{LiveProbe, parse_fanotify_denials};

use model::FapolicydStigRefs;
use render::{render_human, render_json};

const DEFAULT_RULES_DIR: &str = "/etc/fapolicyd/rules.d/";

/// Schema version for the `doctor-report` kind.
/// Bumps only on a breaking change (field removal, rename, retype); the
/// additive `controls` field (omitted when empty) did NOT bump it, matching
/// the `Diagnostic.controls` precedent.
const DOCTOR_SCHEMA_VERSION: u32 = 1;

/// Run the `fapolicyd doctor` subcommand.
pub fn run(args: &DoctorArgs) -> anyhow::Result<i32> {
    let rules_dir = args
        .rules_dir
        .as_deref()
        .unwrap_or_else(|| Path::new(DEFAULT_RULES_DIR));

    let probe = LiveProbe;

    // Check #9 reuses the container-check classifier (#134). Build its report
    // from a live ContainerProbe and pass it in as plain data so `run_checks`
    // stays pure over `SystemProbe` (and OS-free in unit tests).
    let container_probe = crate::commands::container_check::LiveContainerProbe;
    let container_report =
        crate::commands::container_check::classify(&container_probe, rules_dir, false);

    // #519: resolve the doctor's STIG benchmark target and build the
    // per-family ControlRef projections (see the module doc).
    let resolved_target = resolve_doctor_target(args.target, &LiveTargetProbe);
    let stig = resolved_target.map(|t| FapolicydStigRefs::for_target(t.into()));
    if stig.is_none() {
        eprintln!(
            "fapolicyd doctor: running checks without STIG control attachment \
             (--target could not be resolved)"
        );
    }

    let results = run_checks(&probe, rules_dir, Some(&container_report), stig.as_ref());

    let output = match args.format {
        HumanJsonFormat::Human => render_human("fapolicyd doctor report", &results),
        HumanJsonFormat::Json => render_json("doctor-report", DOCTOR_SCHEMA_VERSION, &results),
    };

    print!("{output}");

    Ok(worst_exit_code(&results))
}
