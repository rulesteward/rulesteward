use clap::Parser;
use std::path::PathBuf;

use crate::cli::HumanJsonFormat;

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
