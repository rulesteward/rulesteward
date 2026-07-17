//! Doctor check result model and the `SystemProbe` dependency-injection seam.
//!
//! Plain data only: the status/result types, the probe-input structs, and the
//! `SystemProbe` trait. The live OS implementation lives in the `probe`
//! submodule; the pure classification logic in `checks`.

use std::path::Path;

use rulesteward_core::ControlRef;
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
    /// Typed compliance controls this check evaluates evidence for (attached
    /// whenever the benchmark target is resolved, regardless of status: on the
    /// doctor surface a check IS the control's assessment, so a compliant host
    /// must still report its coverage). Omitted from JSON when empty, so the
    /// field is additive under the tolerant-reader contract (same as
    /// `Diagnostic.controls`: no schemaVersion bump).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub controls: Vec<ControlRef>,
}

impl CheckResult {
    /// A passing check. No remediation (per the status/remediation convention).
    pub fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Ok,
            detail: detail.into(),
            remediation: None,
            controls: Vec::new(),
        }
    }

    /// A warning check, carrying a remediation hint.
    pub fn warn(
        name: &'static str,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status: CheckStatus::Warn,
            detail: detail.into(),
            remediation: Some(remediation.into()),
            controls: Vec::new(),
        }
    }

    /// A failing check, carrying a remediation hint.
    pub fn fail(
        name: &'static str,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status: CheckStatus::Fail,
            detail: detail.into(),
            remediation: Some(remediation.into()),
            controls: Vec::new(),
        }
    }

    /// A skipped check: not applicable here. Informational, never escalates the
    /// exit code; no remediation.
    pub fn skip(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Skip,
            detail: detail.into(),
            remediation: None,
            controls: Vec::new(),
        }
    }

    /// An indeterminate check: the probe failed. Informational, never escalates
    /// the exit code; no remediation.
    pub fn unknown(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Unknown,
            detail: detail.into(),
            remediation: None,
            controls: Vec::new(),
        }
    }

    /// Attach typed compliance controls, mirroring `Diagnostic::with_controls`.
    #[must_use]
    pub fn with_controls(mut self, controls: Vec<ControlRef>) -> Self {
        self.controls = controls;
        self
    }
}

// ---------------------------------------------------------------------------
// Exit code computation (worst-status-wins, design decision #3)
// ---------------------------------------------------------------------------

/// Compute the overall exit code from a list of check results.
///
/// Any `Fail` -> `EXIT_ERRORS` (2); else any `Warn` -> `EXIT_WARNINGS` (1);
/// else `EXIT_CLEAN` (0). `Skip` and `Unknown` never escalate.
///
/// Lives on the model (not in the fapolicyd `checks` module) because it is
/// pure over the result types and every backend's doctor verb shares it.
#[must_use]
pub fn worst_exit_code(results: &[CheckResult]) -> i32 {
    use crate::exit_code::{EXIT_CLEAN, EXIT_ERRORS, EXIT_WARNINGS};

    if results.iter().any(|r| r.status == CheckStatus::Fail) {
        return EXIT_ERRORS;
    }
    if results.iter().any(|r| r.status == CheckStatus::Warn) {
        return EXIT_WARNINGS;
    }
    EXIT_CLEAN
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

#[cfg(test)]
mod tests {
    use rulesteward_core::{ControlRef, Framework};

    use super::{CheckResult, CheckStatus, worst_exit_code};
    use crate::exit_code::{EXIT_CLEAN, EXIT_ERRORS, EXIT_WARNINGS};

    fn result(status: CheckStatus) -> CheckResult {
        CheckResult {
            name: "test",
            status,
            detail: String::new(),
            remediation: None,
            controls: Vec::new(),
        }
    }

    #[test]
    fn worst_exit_code_all_ok_is_clean() {
        assert_eq!(
            worst_exit_code(&[result(CheckStatus::Ok), result(CheckStatus::Ok)]),
            EXIT_CLEAN
        );
    }

    #[test]
    fn worst_exit_code_warn_only_is_warnings() {
        assert_eq!(
            worst_exit_code(&[result(CheckStatus::Ok), result(CheckStatus::Warn)]),
            EXIT_WARNINGS
        );
    }

    #[test]
    fn worst_exit_code_fail_overrides_warn() {
        assert_eq!(
            worst_exit_code(&[
                result(CheckStatus::Warn),
                result(CheckStatus::Fail),
                result(CheckStatus::Ok)
            ]),
            EXIT_ERRORS
        );
    }

    #[test]
    fn worst_exit_code_skip_unknown_do_not_escalate() {
        // Skip and Unknown alone must not escalate above clean.
        assert_eq!(
            worst_exit_code(&[result(CheckStatus::Skip), result(CheckStatus::Unknown)]),
            EXIT_CLEAN
        );
    }

    #[test]
    fn with_controls_sets_controls_and_constructors_default_empty() {
        // Every constructor starts with no controls; the builder attaches them.
        let plain = CheckResult::ok("svc", "running");
        assert!(plain.controls.is_empty(), "constructors default to empty");

        let attached =
            CheckResult::warn("misconfiguration", "permissive", "fix it").with_controls(vec![
                ControlRef::new(Framework::Stig, "RHEL-09-433016").with_alias("V-270180"),
            ]);
        assert_eq!(attached.controls.len(), 1);
        assert_eq!(attached.controls[0].id, "RHEL-09-433016");
        assert_eq!(attached.controls[0].alias.as_deref(), Some("V-270180"));
        // The builder must not disturb the underlying result fields.
        assert_eq!(attached.status, CheckStatus::Warn);
        assert_eq!(attached.remediation.as_deref(), Some("fix it"));
    }

    #[test]
    fn controls_omitted_from_json_when_empty_present_when_set() {
        // Additive field contract (same as Diagnostic.controls): empty vec is
        // omitted entirely so existing doctor-report consumers see no new key.
        let plain = serde_json::to_value(CheckResult::ok("svc", "running")).unwrap();
        assert!(
            plain.get("controls").is_none(),
            "empty controls must be omitted from JSON, got {plain}"
        );

        let attached = serde_json::to_value(
            CheckResult::ok("svc", "running")
                .with_controls(vec![ControlRef::new(Framework::Stig, "RHEL-08-040136")]),
        )
        .unwrap();
        assert_eq!(attached["controls"][0]["id"], "RHEL-08-040136");
        assert_eq!(attached["controls"][0]["framework"], "stig");
    }

    #[test]
    fn constructors_set_status_detail_and_remediation() {
        let ok = CheckResult::ok("svc", "running");
        assert_eq!(ok.name, "svc");
        assert_eq!(ok.status, CheckStatus::Ok);
        assert_eq!(ok.detail, "running");
        assert_eq!(ok.remediation, None);

        let warn = CheckResult::warn("svc", "degraded", "restart it");
        assert_eq!(warn.status, CheckStatus::Warn);
        assert_eq!(warn.remediation.as_deref(), Some("restart it"));

        let fail = CheckResult::fail("svc", "down", "start it");
        assert_eq!(fail.status, CheckStatus::Fail);
        assert_eq!(fail.remediation.as_deref(), Some("start it"));

        let skip = CheckResult::skip("svc", "n/a");
        assert_eq!(skip.status, CheckStatus::Skip);
        assert_eq!(skip.remediation, None);

        let unknown = CheckResult::unknown("svc", "probe failed");
        assert_eq!(unknown.status, CheckStatus::Unknown);
        assert_eq!(unknown.remediation, None);
    }
}
