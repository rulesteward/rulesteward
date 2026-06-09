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
mod render;

pub use checks::{run_checks, worst_exit_code};
pub use model::{
    CheckResult, CheckStatus, CommandOutcome, DenialStats, FapolicydConf, FsSpace, LintCounts,
    ServiceState, SystemProbe,
};
pub use probe::{LiveProbe, parse_fanotify_denials};

use render::{render_human, render_json};

const DEFAULT_RULES_DIR: &str = "/etc/fapolicyd/rules.d/";

/// Run the `fapolicyd doctor` subcommand.
pub fn run(args: &DoctorArgs) -> anyhow::Result<i32> {
    let rules_dir = args
        .rules_dir
        .as_deref()
        .unwrap_or_else(|| Path::new(DEFAULT_RULES_DIR));

    let probe = LiveProbe;
    let results = run_checks(&probe, rules_dir);

    let output = match args.format {
        HumanJsonFormat::Human => render_human(&results),
        HumanJsonFormat::Json => render_json(&results),
    };

    print!("{output}");

    Ok(worst_exit_code(&results))
}
