use clap::Parser;
use std::path::PathBuf;

use crate::cli::{HumanJsonFormat, OutputFormat, TargetSelector};

/// Arguments for `rulesteward selinux triage` (#94).
///
/// Triages `SELinux` AVC denials. The `--emit-te` flag activates te-emit mode
/// (emits a self-contained base-module `.te`) instead of a triage report.
/// te-emit is NOT a separate verb; it is a mode flag on triage.
///
/// At least one of `--audit-log` or `--record` must be supplied; this is
/// validated by the triage command at run time, not by clap, so neither
/// field is `required`.
#[derive(Debug, Parser)]
pub struct TriageArgs {
    /// Scan a full audit log for AVCs.
    #[arg(long, value_name = "FILE")]
    pub audit_log: Option<PathBuf>,

    /// A single AVC record file (mutually exclusive with --audit-log).
    ///
    /// At least one of --record or --audit-log must be supplied (validated at
    /// run time, not by clap; the command errors if neither is present).
    #[arg(long, value_name = "FILE", conflicts_with = "audit_log")]
    pub record: Option<PathBuf>,

    /// Time window to scan (e.g. 1h, 2d).
    #[arg(long, value_name = "WINDOW")]
    pub since: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,

    /// Emit a self-contained base-module .te instead of a triage report.
    #[arg(long)]
    pub emit_te: bool,

    /// Module name for the emitted .te (used with --emit-te).
    #[arg(long, value_name = "NAME")]
    pub module_name: Option<String>,

    /// Write output to FILE instead of stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Binary `SELinux` policy file to replay denials against (read-only).
    ///
    /// When supplied, each AVC denial is authoritatively categorized by
    /// replaying it against this policy via libsepol
    /// (`sepol_compute_av_reason_buffer`). The authoritative verdict overrides
    /// the record-only floor classifier when present; the floor is the fallback
    /// when `--policy` is not supplied or when a context in the denial is not
    /// defined in the supplied policy (cross-host / cross-version mismatch).
    ///
    /// A `--policy` that cannot be LOADED is a hard error (exit 2): the run does
    /// NOT silently fall back to the floor, since the operator explicitly asked
    /// for authoritative analysis.
    ///
    /// Gated on the `authoritative-categorizer` feature (default-ON, #124): the
    /// flag only exists in the libsepol-backed default build. In the clean
    /// Apache-2.0-only `--no-default-features` build there is no authoritative
    /// path, so the flag is absent and `triage` runs floor-only.
    #[cfg(feature = "authoritative-categorizer")]
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,
}

/// Arguments for `rulesteward selinux lint` (#520).
///
/// Lints `/etc/selinux/config` (or a supplied file) for STIG
/// boot-configuration gaps: `se-W01` (`SELINUX=` not enforcing at boot;
/// requires `--target rhel9|rhel10`) and `se-W02` (`SELINUXTYPE=` not
/// targeted; requires `--target rhel8`). An omitted `--target` stays
/// version-agnostic (no findings) - mirrors `sysctl lint`'s `sysctld-W02`
/// gating shape.
#[derive(Debug, Parser)]
pub struct SelinuxLintArgs {
    /// Path to the `SELinux` config file to lint (defaults to
    /// `/etc/selinux/config`).
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Output format (human | json | sarif; findings-only:
    /// `--sarif-include-pass` coverage attestation stays fapolicyd-only (CC-4)).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Target RHEL release for the version-aware STIG baseline
    /// (auto|rhel8|rhel9|rhel10). Omit `--target` to lint version-agnostically
    /// (no `se-W01`/`se-W02` findings).
    #[arg(long, value_enum)]
    pub target: Option<TargetSelector>,
}

/// Arguments for `rulesteward selinux doctor` (#520).
///
/// Runs 5 read-only `SELinux` deployment health checks and reports a
/// pass/warn/fail scorecard.
#[derive(Debug, Parser)]
pub struct SelinuxDoctorArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = HumanJsonFormat::Human)]
    pub format: HumanJsonFormat,

    /// Target RHEL release for STIG control attachment
    /// (auto|rhel8|rhel9|rhel10). Defaults to auto-detect (doctor examines
    /// the host it runs on); a failed or unresolvable auto-detect degrades
    /// silently to running the checks without control attachment.
    #[arg(long, value_enum)]
    pub target: Option<TargetSelector>,
}
