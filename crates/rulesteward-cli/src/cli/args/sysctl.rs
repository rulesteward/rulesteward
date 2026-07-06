use clap::Parser;
use std::path::PathBuf;

use crate::cli::{HumanJsonFormat, TargetSelector};

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
    /// adds the cross-directory `sysctld-W03` pass to F01/W01/W02. Mutually
    /// exclusive with the positional `<path>`.
    #[arg(long, conflicts_with = "path")]
    pub system: bool,

    /// Prepend PREFIX to every standard search directory and to
    /// `/etc/sysctl.conf` / the `99-sysctl.conf` symlink (hermetic testing, or
    /// linting an image/chroot). Requires `--system`.
    #[arg(long, value_name = "PREFIX", requires = "system")]
    pub root: Option<PathBuf>,

    /// Output format (human | json; SARIF and CSV are not offered for this verb
    /// per the locked output contracts CC-3/CC-4).
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,

    /// Target RHEL release for the STIG hardening baseline (auto|rhel8|rhel9|rhel10).
    /// Enables the version-aware `sysctld-W02` check: a STIG-required kernel-hardening
    /// key that is unset across the effective config, or set to an insecure value, is
    /// flagged against the selected release's baseline. `auto` detects the release from
    /// the host's /etc/os-release, falling back (with a warning) to version-agnostic
    /// when detection fails. With no `--target`, W02 does not run (version-agnostic:
    /// only sysctld-F01 / sysctld-W01).
    #[arg(long, value_enum)]
    pub target: Option<TargetSelector>,
}
