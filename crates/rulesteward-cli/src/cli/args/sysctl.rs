use clap::Parser;
use std::path::PathBuf;

use crate::cli::{OutputFormat, TargetSelector};

/// Arguments for `rulesteward sysctl lint` (#150, #335, #420).
#[derive(Debug, Parser)]
pub struct SysctlLintArgs {
    /// The `sysctl.d`/`sysctl.conf` file to lint (defaults to `/etc/sysctl.conf`).
    /// Mutually exclusive with `--system`.
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Scan the standard `sysctl.d` search-path directories (`/etc/sysctl.d`,
    /// `/run/sysctl.d`, `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d`) plus
    /// `/etc/sysctl.conf`, instead of a single `<path>` (issue #420). Models the
    /// grounded same-basename directory masking + global lexicographic merge and
    /// adds the cross-directory `sysctld-W03` pass to F01/W01/W02/W04. Mutually
    /// exclusive with the positional `<path>`.
    #[arg(long, conflicts_with = "path")]
    pub system: bool,

    /// Prepend PREFIX to every standard search directory and to
    /// `/etc/sysctl.conf` / the `99-sysctl.conf` symlink (hermetic testing, or
    /// linting an image/chroot). Requires `--system`.
    #[arg(long, value_name = "PREFIX", requires = "system")]
    pub root: Option<PathBuf>,

    /// Output format (human | json | sarif; CSV is not offered for this verb
    /// per the locked output contract CC-3). SARIF is findings-only here:
    /// `--sarif-include-pass` coverage attestation stays fapolicyd-only (CC-4).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Target RHEL release for the version-aware hardening baselines
    /// (auto|rhel8|rhel9|rhel10). Enables BOTH `sysctld-W02` (STIG) and
    /// `sysctld-W04` (CIS Benchmark): a baseline-required kernel-hardening key that
    /// is unset across the effective config, or set to a value the baseline does not
    /// accept, is flagged against the selected release. `auto` detects the release
    /// from the host's /etc/os-release, falling back (with a warning) to
    /// version-agnostic when detection fails. With no `--target`, neither W02 nor W04
    /// runs (version-agnostic: only sysctld-F01 / sysctld-W01, plus sysctld-W03 in
    /// `--system` mode, which does not depend on `--target`).
    #[arg(long, value_enum)]
    pub target: Option<TargetSelector>,
}
