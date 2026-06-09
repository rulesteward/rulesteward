//! Doctor check result model and the `SystemProbe` dependency-injection seam.
//!
//! Plain data only: the status/result types, the probe-input structs, and the
//! `SystemProbe` trait. The live OS implementation lives in the `probe`
//! submodule; the pure classification logic in `checks`.

use std::path::Path;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Check result model (spec §6.1 + locked design decision #2)
// ---------------------------------------------------------------------------

/// The status of a single doctor check.
///
/// `Fail > Warn > Ok` for exit-code escalation.
/// `Skip` and `Unknown` are informational only and never escalate the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Skip,
    Unknown,
}

/// The result of a single doctor check.
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// Short machine-readable name for this check.
    pub name: &'static str,
    /// Pass/warn/fail/skip/unknown verdict.
    pub status: CheckStatus,
    /// Human-readable detail describing what was observed.
    pub detail: String,
    /// Remediation hint shown for Warn / Fail; None for Ok / Skip / Unknown.
    pub remediation: Option<String>,
}

// ---------------------------------------------------------------------------
// Probe input types -- plain data structs returned by SystemProbe methods
// ---------------------------------------------------------------------------

/// Fapolicyd service state from systemctl.
#[derive(Debug, Clone)]
pub struct ServiceState {
    pub running: bool,
    pub enabled: bool,
    /// If Some, the mode string (e.g. "enforcing" or "permissive").
    pub mode: Option<String>,
}

/// Outcome of running a command (fapolicyd-cli --check-*).
#[derive(Debug, Clone)]
pub struct CommandOutcome {
    pub success: bool,
    pub message: String,
}

/// Lint result counts from `rulesteward fapolicyd lint`.
#[derive(Debug, Clone)]
pub struct LintCounts {
    pub errors: u32,
    pub warnings: u32,
}

/// Free-space information for a path.
#[derive(Debug, Clone)]
pub struct FsSpace {
    /// Bytes available to unprivileged users.
    pub bytes_free: u64,
}

/// Denial statistics for the recent-denial-rate check.
#[derive(Debug, Clone)]
pub struct DenialStats {
    pub count_24h: u64,
    pub count_7d: u64,
    /// Top denied subject+object pairs (subject path, object path, count).
    pub top_denied: Vec<(String, String, u64)>,
}

/// Contents of fapolicyd.conf relevant to misconfiguration checks.
#[derive(Debug, Clone)]
pub struct FapolicydConf {
    /// True if `permissive=1` is set.
    pub permissive_set: bool,
    /// True if any rule file contains `sha256hash=`.
    pub deprecated_sha256hash: bool,
    /// True if both `/etc/fapolicyd/fapolicyd.rules` AND `rules.d/` exist.
    pub both_layouts_present: bool,
}

// ---------------------------------------------------------------------------
// SystemProbe trait -- dependency-injection seam (design decision #1)
// ---------------------------------------------------------------------------

/// Trait for all environment I/O used by the doctor checks.
///
/// Each method returns plain data (structs / Result). The 13 check functions
/// contain ONLY classification logic over that data, making them testable with
/// `FakeProbe` without any real OS access. The real [`LiveProbe`](super::probe::LiveProbe) shells out.
pub trait SystemProbe {
    /// Query the fapolicyd systemd service status.
    fn service_state(&self) -> Result<ServiceState, String>;

    /// Return the kernel release string (from `uname -r`).
    fn kernel_release(&self) -> Result<String, String>;

    /// Return the count of loaded audit syscall rules.
    fn audit_rule_count(&self) -> Result<u32, String>;

    /// Run `fapolicyd-cli --check-config`.
    fn check_config(&self) -> Result<CommandOutcome, String>;

    /// Run `rulesteward fapolicyd lint` on the given rules dir.
    fn lint_rules(&self, rules_dir: &Path) -> Result<LintCounts, String>;

    /// Run `fapolicyd-cli --check-trustdb`.
    fn check_trustdb(&self) -> Result<CommandOutcome, String>;

    /// Run `fapolicyd-cli --check-watch_fs`.
    fn check_watch_fs(&self) -> Result<CommandOutcome, String>;

    /// Run `fapolicyd-cli --check-ignore_mounts` (v1.4+); return None if not
    /// supported by the installed version.
    fn check_ignore_mounts(&self) -> Result<Option<CommandOutcome>, String>;

    /// Check whether the `rpm-plugin-fapolicyd` RPM package is installed.
    fn rpm_plugin_installed(&self) -> Result<bool, String>;

    /// Return free bytes in /var/lib/fapolicyd/.
    fn fapolicyd_db_space(&self) -> Result<FsSpace, String>;

    /// Return denial statistics from the audit log.
    fn denial_stats(&self) -> Result<DenialStats, String>;

    /// Parse /etc/fapolicyd/fapolicyd.conf and the rules dir for misconfiguration flags.
    fn fapolicyd_conf(&self, rules_dir: &Path) -> Result<FapolicydConf, String>;
}
