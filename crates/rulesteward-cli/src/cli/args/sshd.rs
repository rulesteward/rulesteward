use clap::Parser;
use std::path::PathBuf;

use crate::cli::{HumanJsonFormat, TargetSelector};

/// Arguments for `rulesteward sshd lint` (#149).
#[derive(Debug, Parser)]
pub struct SshdLintArgs {
    /// The `sshd_config` file to lint (defaults to `/etc/ssh/sshd_config`)
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Output format (human | json; SARIF and CSV are not offered for this verb
    /// per the locked output contracts CC-3/CC-4).
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,

    /// Target OS baseline (auto|rhel8|rhel9|rhel10) for the version-aware lints.
    /// Selects which OpenSSH keyword set the version-aware passes (sshd-E01,
    /// sshd-E04, sshd-W01..W04) validate against (rhel8 = 8.0p1, rhel9 / rhel10 =
    /// 9.9p1). `auto` detects the baseline from the host's /etc/os-release, falling
    /// back (with a warning) to the version-agnostic dialect when detection fails.
    /// With no --target, the most-permissive (newest) dialect is used, so sshd-E01
    /// flags only keywords unknown to every supported version and sshd-E04 leans
    /// false-negative.
    #[arg(long, value_enum)]
    pub target: Option<TargetSelector>,
}
