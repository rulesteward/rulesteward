//! `rulesteward fapolicyd container-check` -- container-runtime risk detection.
//!
//! # Architecture
//!
//! All environment I/O (which/systemctl/test/rpm/ausearch/fapolicyd-cli, config
//! and rules reads) is routed through the [`ContainerProbe`] trait. The
//! classifier in [`checks`] contains ONLY logic over plain data, so it is fully
//! unit-testable with `FakeProbe` and no real OS access. The real
//! [`LiveContainerProbe`] shells out and is NOT unit-tested directly -- it is
//! exercised by the graceful-degradation e2e test and live VM smoke.
//!
//! Spec: section 6.1, lines 391-425. Tracking: #175 (also closes #134, the
//! doctor check #9 rewire that reuses this classifier).

use std::path::Path;

use crate::cli::{ContainerCheckArgs, HumanJsonFormat};

mod checks;
mod model;
mod probe;
mod render;

pub use checks::{Report, classify, exit_code, worst_severity};
pub use model::{ContainerProbe, Finding, RhcosStatus, Severity};
pub use probe::LiveContainerProbe;

const DEFAULT_RULES_DIR: &str = "/etc/fapolicyd/rules.d/";

/// Run the `fapolicyd container-check` subcommand.
pub fn run(args: &ContainerCheckArgs) -> anyhow::Result<i32> {
    let rules_dir = args
        .rules_dir
        .as_deref()
        .unwrap_or_else(|| Path::new(DEFAULT_RULES_DIR));

    let probe = LiveContainerProbe;
    let report = classify(&probe, rules_dir, args.deep);

    let output = match args.format {
        HumanJsonFormat::Human => render::render_human(&report),
        HumanJsonFormat::Json => render::render_json(&report),
    };

    print!("{output}");

    Ok(exit_code(&report))
}
