//! `rulesteward fapolicyd doctor` -- composite deployment health check.
//!
//! # Architecture
//!
//! All environment I/O (systemctl, uname, auditctl, fapolicyd-cli, rpm,
//! statvfs, config-file reads) is routed through the [`SystemProbe`] trait.
//! The 13 check functions contain ONLY classification logic over plain data, so
//! they are fully unit-testable with `FakeProbe` without touching the real OS.
//! The real [`LiveProbe`] shells out and is NOT unit-tested directly -- it is
//! exercised by the live VM smoke test and the graceful-degradation e2e test.
//!
//! Dependency injection via a trait object (`&dyn SystemProbe`) keeps `run_checks`
//! decoupled from the OS: swap in `FakeProbe` in tests, `LiveProbe` in production.

use std::path::Path;

use crate::cli::{DoctorArgs, HumanJsonFormat};

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

    let results = run_checks(&probe, rules_dir, Some(&container_report));

    let output = match args.format {
        HumanJsonFormat::Human => render_human("fapolicyd doctor report", &results),
        HumanJsonFormat::Json => render_json("doctor-report", DOCTOR_SCHEMA_VERSION, &results),
    };

    print!("{output}");

    Ok(worst_exit_code(&results))
}
