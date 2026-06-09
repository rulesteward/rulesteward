//! The 13 pure check-classification functions plus the doctor orchestration.
//!
//! Each `check_*` fn takes a `&dyn SystemProbe` and classifies its plain-data
//! return into a `CheckResult` (no I/O here -- that lives behind the trait in
//! `probe`). `run_checks` drives all 13; `worst_exit_code` folds the verdicts.

use std::fmt::Write as _;
use std::path::Path;

use super::model::{CheckResult, CheckStatus, CommandOutcome, SystemProbe};
use crate::exit_code::{EXIT_CLEAN, EXIT_ERRORS, EXIT_WARNINGS};

// ---------------------------------------------------------------------------
// The 13 check functions (pure classification over probe data)
// ---------------------------------------------------------------------------

/// Check 1: fapolicyd service status.
///
/// Fail if not running; Warn if permissive; Ok if running + enforcing.
fn check_service(probe: &dyn SystemProbe) -> CheckResult {
    match probe.service_state() {
        Err(e) => CheckResult {
            name: "service-status",
            status: CheckStatus::Unknown,
            detail: format!("could not query service state: {e}"),
            remediation: None,
        },
        Ok(state) => {
            if !state.running {
                return CheckResult {
                    name: "service-status",
                    status: CheckStatus::Fail,
                    detail: "fapolicyd is not running".to_string(),
                    remediation: Some("systemctl start fapolicyd".to_string()),
                };
            }
            let mode = state.mode.as_deref().unwrap_or("enforcing");
            if mode == "permissive" {
                CheckResult {
                    name: "service-status",
                    status: CheckStatus::Warn,
                    detail: "fapolicyd is running in permissive mode (permissive=1)".to_string(),
                    remediation: Some(
                        "Set permissive=0 in /etc/fapolicyd/fapolicyd.conf and restart the service"
                            .to_string(),
                    ),
                }
            } else {
                // Surface the ACTUAL mode string rather than hard-coding
                // "enforcing": `read_fapolicyd_mode` defaults an absent
                // permissive= key to "enforcing", but if a future probe ever
                // returns some other value we report it verbatim instead of
                // mislabeling it as enforcing.
                CheckResult {
                    name: "service-status",
                    status: CheckStatus::Ok,
                    detail: format!(
                        "fapolicyd is running, enabled={}, mode={mode}",
                        state.enabled
                    ),
                    remediation: None,
                }
            }
        }
    }
}

/// Check 2: kernel version (fanotify >= 4.20; full FANOTIFY field set >= 6.3).
///
/// Fail < 4.20; Warn >= 4.20 but < 6.3; Ok >= 6.3.
fn check_kernel(probe: &dyn SystemProbe) -> CheckResult {
    match probe.kernel_release() {
        Err(e) => CheckResult {
            name: "kernel-version",
            status: CheckStatus::Unknown,
            detail: format!("could not query kernel release: {e}"),
            remediation: None,
        },
        Ok(release) => {
            match parse_kernel_version(&release) {
                None => CheckResult {
                    name: "kernel-version",
                    status: CheckStatus::Unknown,
                    detail: format!("could not parse kernel version from: {release:?}"),
                    remediation: None,
                },
                Some((major, minor)) => {
                    // Compare as (major, minor) tuples.
                    if (major, minor) < (4, 20) {
                        CheckResult {
                            name: "kernel-version",
                            status: CheckStatus::Fail,
                            detail: format!(
                                "kernel {release} is below 4.20 (fanotify requires >= 4.20)"
                            ),
                            remediation: Some("Upgrade to kernel >= 4.20".to_string()),
                        }
                    } else if (major, minor) < (6, 3) {
                        CheckResult {
                            name: "kernel-version",
                            status: CheckStatus::Warn,
                            detail: format!(
                                "kernel {release} supports fanotify but lacks the full \
                                 FANOTIFY field set (requires >= 6.3)"
                            ),
                            remediation: Some(
                                "Upgrade to kernel >= 6.3 for the full FANOTIFY field set"
                                    .to_string(),
                            ),
                        }
                    } else {
                        CheckResult {
                            name: "kernel-version",
                            status: CheckStatus::Ok,
                            detail: format!(
                                "kernel {release} supports fanotify and the full FANOTIFY field set"
                            ),
                            remediation: None,
                        }
                    }
                }
            }
        }
    }
}

/// Parse "major.minor[.patch...]" from a kernel release string.
///
/// Returns `Some((major, minor))` on success, `None` if unparseable.
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    // Kernel release strings look like "6.3.0-0.rc1.20230326git.el9" -- split on
    // the first non-numeric/non-dot char, then take major.minor.
    let version_part = release
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()?;
    let mut parts = version_part.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Check 3: at least one audit syscall rule loaded (#78).
///
/// Fail if count == 0; Ok otherwise.
fn check_audit_rules(probe: &dyn SystemProbe) -> CheckResult {
    match probe.audit_rule_count() {
        Err(e) => CheckResult {
            name: "audit-syscall-rules",
            status: CheckStatus::Unknown,
            detail: format!("could not query auditctl rules: {e}"),
            remediation: None,
        },
        Ok(0) => CheckResult {
            name: "audit-syscall-rules",
            status: CheckStatus::Fail,
            detail: "no audit syscall rules loaded; fapolicyd FANOTIFY events may be invisible"
                .to_string(),
            remediation: Some(
                "auditctl -a always,exit -F arch=b64 -S all -k fapolicyd".to_string(),
            ),
        },
        Ok(count) => CheckResult {
            name: "audit-syscall-rules",
            status: CheckStatus::Ok,
            detail: format!("{count} audit rule(s) loaded"),
            remediation: None,
        },
    }
}

/// Check 4: `fapolicyd-cli --check-config`.
fn check_config_cmd(probe: &dyn SystemProbe) -> CheckResult {
    match probe.check_config() {
        Err(e) => CheckResult {
            name: "config-check",
            status: CheckStatus::Unknown,
            detail: format!("could not run fapolicyd-cli --check-config: {e}"),
            remediation: None,
        },
        Ok(outcome) => {
            if outcome.success {
                CheckResult {
                    name: "config-check",
                    status: CheckStatus::Ok,
                    detail: if outcome.message.is_empty() {
                        "fapolicyd-cli --check-config passed".to_string()
                    } else {
                        outcome.message.clone()
                    },
                    remediation: None,
                }
            } else {
                CheckResult {
                    name: "config-check",
                    status: CheckStatus::Fail,
                    detail: format!("fapolicyd-cli --check-config failed: {}", outcome.message),
                    remediation: Some(
                        "Review /etc/fapolicyd/fapolicyd.conf for syntax errors".to_string(),
                    ),
                }
            }
        }
    }
}

/// Check 5: `rulesteward fapolicyd lint /etc/fapolicyd/rules.d/`.
fn check_lint(probe: &dyn SystemProbe, rules_dir: &Path) -> CheckResult {
    match probe.lint_rules(rules_dir) {
        Err(e) => CheckResult {
            name: "rules-lint",
            status: CheckStatus::Unknown,
            detail: format!("lint probe failed: {e}"),
            remediation: None,
        },
        Ok(counts) => {
            if counts.errors > 0 {
                CheckResult {
                    name: "rules-lint",
                    status: CheckStatus::Fail,
                    detail: format!(
                        "lint found {} error(s) and {} warning(s) in {}",
                        counts.errors,
                        counts.warnings,
                        rules_dir.display()
                    ),
                    remediation: Some(format!(
                        "Run `rulesteward fapolicyd lint {}` to see full details",
                        rules_dir.display()
                    )),
                }
            } else if counts.warnings > 0 {
                CheckResult {
                    name: "rules-lint",
                    status: CheckStatus::Warn,
                    detail: format!(
                        "lint found {} warning(s) in {}",
                        counts.warnings,
                        rules_dir.display()
                    ),
                    remediation: Some(format!(
                        "Run `rulesteward fapolicyd lint {}` for details",
                        rules_dir.display()
                    )),
                }
            } else {
                CheckResult {
                    name: "rules-lint",
                    status: CheckStatus::Ok,
                    detail: format!("no lint issues in {}", rules_dir.display()),
                    remediation: None,
                }
            }
        }
    }
}

/// Check 6: `fapolicyd-cli --check-trustdb`.
fn check_trustdb_cmd(probe: &dyn SystemProbe) -> CheckResult {
    match probe.check_trustdb() {
        Err(e) => CheckResult {
            name: "trustdb-check",
            status: CheckStatus::Unknown,
            detail: format!("could not run fapolicyd-cli --check-trustdb: {e}"),
            remediation: None,
        },
        Ok(outcome) => cmd_outcome_to_result("trustdb-check", &outcome, "trust DB is consistent"),
    }
}

/// Check 7: `fapolicyd-cli --check-watch_fs`.
fn check_watch_fs_cmd(probe: &dyn SystemProbe) -> CheckResult {
    match probe.check_watch_fs() {
        Err(e) => CheckResult {
            name: "watch-fs-check",
            status: CheckStatus::Unknown,
            detail: format!("could not run fapolicyd-cli --check-watch_fs: {e}"),
            remediation: None,
        },
        Ok(outcome) => cmd_outcome_to_result(
            "watch-fs-check",
            &outcome,
            "watch_fs configuration is consistent",
        ),
    }
}

/// Check 8: `fapolicyd-cli --check-ignore_mounts` (v1.4+ only).
///
/// Skip with note if the installed fapolicyd predates 1.4.
fn check_ignore_mounts_cmd(probe: &dyn SystemProbe) -> CheckResult {
    match probe.check_ignore_mounts() {
        Err(e) => CheckResult {
            name: "ignore-mounts-check",
            status: CheckStatus::Unknown,
            detail: format!("could not run fapolicyd-cli --check-ignore_mounts: {e}"),
            remediation: None,
        },
        Ok(None) => CheckResult {
            name: "ignore-mounts-check",
            status: CheckStatus::Skip,
            detail:
                "--check-ignore_mounts not supported by this fapolicyd version (requires >= 1.4)"
                    .to_string(),
            remediation: None,
        },
        Ok(Some(outcome)) => cmd_outcome_to_result(
            "ignore-mounts-check",
            &outcome,
            "ignore_mounts configuration is consistent",
        ),
    }
}

/// Check 9: container-check (stub -- Skip with note per design decision #4).
fn check_container(_probe: &dyn SystemProbe) -> CheckResult {
    // Design decision #4: container-check subcommand is not yet implemented.
    // This check emits Skip so it appears in the report without implying
    // the deployment is unhealthy.
    CheckResult {
        name: "container-check",
        status: CheckStatus::Skip,
        detail: "container-check not yet implemented (tracked separately)".to_string(),
        remediation: None,
    }
}

/// Check 10: `rpm-plugin-fapolicyd` installed.
///
/// Ok if present; Warn if absent (live RPM trust-DB update path missing).
fn check_rpm_plugin(probe: &dyn SystemProbe) -> CheckResult {
    match probe.rpm_plugin_installed() {
        Err(e) => CheckResult {
            name: "rpm-plugin",
            status: CheckStatus::Unknown,
            detail: format!("could not query rpm-plugin-fapolicyd: {e}"),
            remediation: None,
        },
        Ok(true) => CheckResult {
            name: "rpm-plugin",
            status: CheckStatus::Ok,
            detail: "rpm-plugin-fapolicyd is installed".to_string(),
            remediation: None,
        },
        Ok(false) => CheckResult {
            name: "rpm-plugin",
            status: CheckStatus::Warn,
            detail:
                "rpm-plugin-fapolicyd is not installed; RPM trust-DB updates will not be automatic"
                    .to_string(),
            remediation: Some("dnf install rpm-plugin-fapolicyd".to_string()),
        },
    }
}

// Thresholds for the free-space check (decision #11 + spec §6.1 check 11).
// LMDB pre-allocates ~100 MiB; warn below 128 MiB, fail below 100 MiB.
const WARN_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB
const FAIL_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB

/// Check 11: free space in /var/lib/fapolicyd/ (LMDB pre-allocates ~100 MiB).
fn check_disk_space(probe: &dyn SystemProbe) -> CheckResult {
    match probe.fapolicyd_db_space() {
        Err(e) => CheckResult {
            name: "disk-space",
            status: CheckStatus::Unknown,
            detail: format!("could not query /var/lib/fapolicyd/ free space: {e}"),
            remediation: None,
        },
        Ok(space) => {
            let mib = space.bytes_free / (1024 * 1024);
            if space.bytes_free < FAIL_BYTES {
                CheckResult {
                    name: "disk-space",
                    status: CheckStatus::Fail,
                    detail: format!(
                        "/var/lib/fapolicyd/ has only {mib} MiB free (< 100 MiB threshold)"
                    ),
                    remediation: Some(
                        "Free space on the /var/lib/fapolicyd partition; LMDB needs >= 100 MiB"
                            .to_string(),
                    ),
                }
            } else if space.bytes_free < WARN_BYTES {
                CheckResult {
                    name: "disk-space",
                    status: CheckStatus::Warn,
                    detail: format!(
                        "/var/lib/fapolicyd/ has {mib} MiB free (< 128 MiB warning threshold)"
                    ),
                    remediation: Some(
                        "Consider freeing space; LMDB pre-allocates ~100 MiB".to_string(),
                    ),
                }
            } else {
                CheckResult {
                    name: "disk-space",
                    status: CheckStatus::Ok,
                    detail: format!("/var/lib/fapolicyd/ has {mib} MiB free"),
                    remediation: None,
                }
            }
        }
    }
}

/// Check 12: recent denial rate (24h / 7d) + top-10 denied subj/obj.
///
/// Informational only: always Ok, surfacing the 24h/7d counts (and top-10 denied
/// subj/obj when present) in the detail. Spec §6.1 defines no spike threshold.
fn check_denial_rate(probe: &dyn SystemProbe) -> CheckResult {
    match probe.denial_stats() {
        Err(e) => CheckResult {
            name: "denial-rate",
            status: CheckStatus::Unknown,
            detail: format!("could not query denial statistics: {e}"),
            remediation: None,
        },
        Ok(stats) => {
            let mut detail = format!(
                "denials: {} in past 24h, {} in past 7d",
                stats.count_24h, stats.count_7d
            );
            if !stats.top_denied.is_empty() {
                detail.push_str("; top denied: ");
                for (subj, obj, count) in stats.top_denied.iter().take(10) {
                    let _ = write!(detail, "[{subj} -> {obj} x{count}]");
                }
            }
            CheckResult {
                name: "denial-rate",
                status: CheckStatus::Ok,
                detail,
                remediation: None,
            }
        }
    }
}

/// Check 13: misconfiguration warnings.
///
/// Each condition that is true -> Warn with specific detail. All false -> Ok.
fn check_misconfig(probe: &dyn SystemProbe, rules_dir: &Path) -> CheckResult {
    match probe.fapolicyd_conf(rules_dir) {
        Err(e) => CheckResult {
            name: "misconfiguration",
            status: CheckStatus::Unknown,
            detail: format!("could not read fapolicyd configuration: {e}"),
            remediation: None,
        },
        Ok(conf) => {
            let mut issues: Vec<String> = Vec::new();
            if conf.permissive_set {
                issues.push("`permissive=1` is set in fapolicyd.conf".to_string());
            }
            if conf.deprecated_sha256hash {
                issues.push(
                    "deprecated `sha256hash=` attribute found in rules (use `filehash=` instead)"
                        .to_string(),
                );
            }
            if conf.both_layouts_present {
                issues.push(
                    "both legacy fapolicyd.rules AND rules.d/ are present (fapd-F02)".to_string(),
                );
            }
            if issues.is_empty() {
                CheckResult {
                    name: "misconfiguration",
                    status: CheckStatus::Ok,
                    detail: "no misconfiguration detected".to_string(),
                    remediation: None,
                }
            } else {
                CheckResult {
                    name: "misconfiguration",
                    status: CheckStatus::Warn,
                    detail: issues.join("; "),
                    remediation: Some(
                        "Review the listed configuration items and correct them".to_string(),
                    ),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

/// Convert a `CommandOutcome` to a `CheckResult` for simple pass/fail checks.
fn cmd_outcome_to_result(
    name: &'static str,
    outcome: &CommandOutcome,
    ok_detail: &'static str,
) -> CheckResult {
    if outcome.success {
        CheckResult {
            name,
            status: CheckStatus::Ok,
            detail: ok_detail.to_string(),
            remediation: None,
        }
    } else {
        CheckResult {
            name,
            status: CheckStatus::Fail,
            detail: format!("failed: {}", outcome.message),
            remediation: Some(format!("Investigate the {name} failure")),
        }
    }
}

// ---------------------------------------------------------------------------
// run_checks -- drives all 13 checks via &dyn SystemProbe
// ---------------------------------------------------------------------------

/// Run all 13 doctor checks, returning a Vec of results in declaration order.
pub fn run_checks(probe: &dyn SystemProbe, rules_dir: &Path) -> Vec<CheckResult> {
    vec![
        check_service(probe),
        check_kernel(probe),
        check_audit_rules(probe),
        check_config_cmd(probe),
        check_lint(probe, rules_dir),
        check_trustdb_cmd(probe),
        check_watch_fs_cmd(probe),
        check_ignore_mounts_cmd(probe),
        check_container(probe),
        check_rpm_plugin(probe),
        check_disk_space(probe),
        check_denial_rate(probe),
        check_misconfig(probe, rules_dir),
    ]
}

// ---------------------------------------------------------------------------
// Exit code computation (worst-status-wins, design decision #3)
// ---------------------------------------------------------------------------

/// Compute the overall exit code from a list of check results.
///
/// Any `Fail` -> `EXIT_ERRORS` (2); else any `Warn` -> `EXIT_WARNINGS` (1);
/// else `EXIT_CLEAN` (0). `Skip` and `Unknown` never escalate.
#[must_use]
pub fn worst_exit_code(results: &[CheckResult]) -> i32 {
    if results.iter().any(|r| r.status == CheckStatus::Fail) {
        return EXIT_ERRORS;
    }
    if results.iter().any(|r| r.status == CheckStatus::Warn) {
        return EXIT_WARNINGS;
    }
    EXIT_CLEAN
}

#[cfg(test)]
mod tests {
    use super::super::model::{DenialStats, FapolicydConf, FsSpace, LintCounts, ServiceState};
    use super::*;
    use std::path::PathBuf;

    // -------------------------------------------------------------------------
    // FakeProbe -- the test double for SystemProbe
    //
    // Fields default to Err("not configured") so individual tests need only
    // override the probe methods relevant to the check under test.
    // -------------------------------------------------------------------------

    /// Configurable fake probe for unit tests.
    ///
    /// Each field holds the value that the corresponding probe method returns.
    /// `None` means "return Err('not configured')" -- any check that hits an
    /// un-configured field becomes `CheckStatus::Unknown`.
    #[derive(Default)]
    struct FakeProbe {
        service: Option<ServiceState>,
        kernel: Option<String>,
        audit_count: Option<u32>,
        config: Option<CommandOutcome>,
        lint: Option<LintCounts>,
        trustdb: Option<CommandOutcome>,
        watch_fs: Option<CommandOutcome>,
        // Three-state on purpose: outer None = "not configured" (probe Errs);
        // Some(None) = pre-v1.4 (check_ignore_mounts returns Ok(None) -> Skip);
        // Some(Some(_)) = supported with an outcome. Mirrors the method's
        // `Result<Option<CommandOutcome>, String>` return, hence Option<Option<_>>.
        #[allow(clippy::option_option)]
        ignore_mounts: Option<Option<CommandOutcome>>,
        rpm_plugin: Option<bool>,
        fs_space: Option<FsSpace>,
        denials: Option<DenialStats>,
        conf: Option<FapolicydConf>,
    }

    impl SystemProbe for FakeProbe {
        fn service_state(&self) -> Result<ServiceState, String> {
            self.service
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn kernel_release(&self) -> Result<String, String> {
            self.kernel
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn audit_rule_count(&self) -> Result<u32, String> {
            self.audit_count.ok_or_else(|| "not configured".to_string())
        }
        fn check_config(&self) -> Result<CommandOutcome, String> {
            self.config
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn lint_rules(&self, _rules_dir: &Path) -> Result<LintCounts, String> {
            self.lint
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn check_trustdb(&self) -> Result<CommandOutcome, String> {
            self.trustdb
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn check_watch_fs(&self) -> Result<CommandOutcome, String> {
            self.watch_fs
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn check_ignore_mounts(&self) -> Result<Option<CommandOutcome>, String> {
            self.ignore_mounts
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn rpm_plugin_installed(&self) -> Result<bool, String> {
            self.rpm_plugin.ok_or_else(|| "not configured".to_string())
        }
        fn fapolicyd_db_space(&self) -> Result<FsSpace, String> {
            self.fs_space
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn denial_stats(&self) -> Result<DenialStats, String> {
            self.denials
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
        fn fapolicyd_conf(&self, _rules_dir: &Path) -> Result<FapolicydConf, String> {
            self.conf
                .clone()
                .ok_or_else(|| "not configured".to_string())
        }
    }

    fn fake_path() -> PathBuf {
        PathBuf::from("/fake/rules.d")
    }
    // -------------------------------------------------------------------------
    // Check 1: service status
    // -------------------------------------------------------------------------

    #[test]
    fn check_service_not_running_is_fail() {
        let probe = FakeProbe {
            service: Some(ServiceState {
                running: false,
                enabled: false,
                mode: None,
            }),
            ..Default::default()
        };
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.detail.contains("not running"), "{}", result.detail);
        assert!(result.remediation.is_some());
    }

    #[test]
    fn check_service_running_enforcing_is_ok() {
        let probe = FakeProbe {
            service: Some(ServiceState {
                running: true,
                enabled: true,
                mode: Some("enforcing".to_string()),
            }),
            ..Default::default()
        };
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(result.remediation.is_none());
        // The Ok detail must report the ACTUAL mode, not a hard-coded literal.
        assert!(
            result.detail.contains("mode=enforcing"),
            "enforcing detail: {}",
            result.detail
        );
    }

    #[test]
    fn check_service_running_unknown_mode_is_reported_verbatim() {
        // A non-permissive mode string that is NOT "enforcing" must be surfaced
        // verbatim in the detail (Ok), never mislabeled as "mode=enforcing".
        // Kills a mutant that hard-codes the mode label in the Ok branch.
        let probe = FakeProbe {
            service: Some(ServiceState {
                running: true,
                enabled: true,
                mode: Some("disabled".to_string()),
            }),
            ..Default::default()
        };
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(
            result.detail.contains("mode=disabled"),
            "detail must report the real mode verbatim, got: {}",
            result.detail
        );
        assert!(
            !result.detail.contains("mode=enforcing"),
            "detail must NOT falsely claim enforcing for an arbitrary mode: {}",
            result.detail
        );
    }

    #[test]
    fn check_service_permissive_is_warn() {
        let probe = FakeProbe {
            service: Some(ServiceState {
                running: true,
                enabled: true,
                mode: Some("permissive".to_string()),
            }),
            ..Default::default()
        };
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("permissive"), "{}", result.detail);
        assert!(result.remediation.is_some());
    }

    #[test]
    fn check_service_probe_error_is_unknown() {
        let probe = FakeProbe::default(); // no service configured
        let result = check_service(&probe);
        assert_eq!(result.status, CheckStatus::Unknown);
        assert!(result.remediation.is_none());
    }

    // -------------------------------------------------------------------------
    // Check 2: kernel version
    // -------------------------------------------------------------------------

    #[test]
    fn check_kernel_below_4_20_is_fail() {
        let probe = FakeProbe {
            kernel: Some("4.18.0-513.el8.x86_64".to_string()),
            ..Default::default()
        };
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.detail.contains("4.20"), "{}", result.detail);
    }

    #[test]
    fn check_kernel_4_20_to_6_2_is_warn() {
        let probe = FakeProbe {
            kernel: Some("5.14.0-427.el9.x86_64".to_string()),
            ..Default::default()
        };
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
        assert!(result.detail.contains("6.3"), "{}", result.detail);
    }

    #[test]
    fn check_kernel_6_3_plus_is_ok() {
        let probe = FakeProbe {
            kernel: Some("6.3.0-0.rc1.el10.x86_64".to_string()),
            ..Default::default()
        };
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Ok, "{}", result.detail);
    }

    #[test]
    fn check_kernel_exact_4_20_is_warn_not_fail() {
        // 4.20 meets the fanotify floor but is below 6.3 -> Warn, not Fail.
        let probe = FakeProbe {
            kernel: Some("4.20.0".to_string()),
            ..Default::default()
        };
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Warn, "{}", result.detail);
    }

    #[test]
    fn check_kernel_probe_error_is_unknown() {
        let probe = FakeProbe::default();
        let result = check_kernel(&probe);
        assert_eq!(result.status, CheckStatus::Unknown);
    }

    // -------------------------------------------------------------------------
    // Check 3: audit syscall rules
    // -------------------------------------------------------------------------

    #[test]
    fn check_audit_rules_zero_is_fail_with_remediation() {
        let probe = FakeProbe {
            audit_count: Some(0),
            ..Default::default()
        };
        let result = check_audit_rules(&probe);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result
                .remediation
                .as_deref()
                .unwrap_or("")
                .contains("auditctl"),
            "{:?}",
            result.remediation
        );
    }

    #[test]
    fn check_audit_rules_nonzero_is_ok() {
        let probe = FakeProbe {
            audit_count: Some(5),
            ..Default::default()
        };
        let result = check_audit_rules(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(result.detail.contains('5'), "{}", result.detail);
    }

    #[test]
    fn check_audit_rules_probe_error_is_unknown() {
        let probe = FakeProbe::default();
        let result = check_audit_rules(&probe);
        assert_eq!(result.status, CheckStatus::Unknown);
    }

    // -------------------------------------------------------------------------
    // Check 4: config check
    // -------------------------------------------------------------------------

    #[test]
    fn check_config_success_is_ok() {
        let probe = FakeProbe {
            config: Some(CommandOutcome {
                success: true,
                message: "config ok".to_string(),
            }),
            ..Default::default()
        };
        let result = check_config_cmd(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
    }

    #[test]
    fn check_config_failure_is_fail() {
        let probe = FakeProbe {
            config: Some(CommandOutcome {
                success: false,
                message: "syntax error on line 5".to_string(),
            }),
            ..Default::default()
        };
        let result = check_config_cmd(&probe);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.detail.contains("syntax error"), "{}", result.detail);
    }

    // -------------------------------------------------------------------------
    // Check 5: lint
    // -------------------------------------------------------------------------

    #[test]
    fn check_lint_errors_is_fail() {
        let probe = FakeProbe {
            lint: Some(LintCounts {
                errors: 2,
                warnings: 1,
            }),
            ..Default::default()
        };
        let result = check_lint(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.detail.contains('2'), "{}", result.detail);
    }

    #[test]
    fn check_lint_warnings_only_is_warn() {
        let probe = FakeProbe {
            lint: Some(LintCounts {
                errors: 0,
                warnings: 3,
            }),
            ..Default::default()
        };
        let result = check_lint(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
    }

    #[test]
    fn check_lint_clean_is_ok() {
        let probe = FakeProbe {
            lint: Some(LintCounts {
                errors: 0,
                warnings: 0,
            }),
            ..Default::default()
        };
        let result = check_lint(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Ok);
    }

    // -------------------------------------------------------------------------
    // Check 8: ignore_mounts (Skip when unsupported)
    // -------------------------------------------------------------------------

    #[test]
    fn check_ignore_mounts_skip_when_pre_v1_4() {
        let probe = FakeProbe {
            ignore_mounts: Some(None), // None = pre-v1.4 not supported
            ..Default::default()
        };
        let result = check_ignore_mounts_cmd(&probe);
        assert_eq!(result.status, CheckStatus::Skip);
        assert!(
            result.detail.contains("1.4"),
            "detail should mention v1.4 requirement: {}",
            result.detail
        );
    }

    #[test]
    fn check_ignore_mounts_success_is_ok() {
        let probe = FakeProbe {
            ignore_mounts: Some(Some(CommandOutcome {
                success: true,
                message: String::new(),
            })),
            ..Default::default()
        };
        let result = check_ignore_mounts_cmd(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
    }

    // -------------------------------------------------------------------------
    // Check 9: container-check always Skip (design decision #4)
    // -------------------------------------------------------------------------

    #[test]
    fn check_container_is_always_skip() {
        let probe = FakeProbe::default();
        let result = check_container(&probe);
        assert_eq!(result.status, CheckStatus::Skip);
        assert!(
            result.detail.contains("not yet implemented"),
            "{}",
            result.detail
        );
    }

    // -------------------------------------------------------------------------
    // Check 10: rpm-plugin
    // -------------------------------------------------------------------------

    #[test]
    fn check_rpm_plugin_present_is_ok() {
        let probe = FakeProbe {
            rpm_plugin: Some(true),
            ..Default::default()
        };
        assert_eq!(check_rpm_plugin(&probe).status, CheckStatus::Ok);
    }

    #[test]
    fn check_rpm_plugin_absent_is_warn() {
        let probe = FakeProbe {
            rpm_plugin: Some(false),
            ..Default::default()
        };
        let result = check_rpm_plugin(&probe);
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.remediation.is_some());
    }

    // -------------------------------------------------------------------------
    // Check 11: disk space
    // -------------------------------------------------------------------------

    #[test]
    fn check_disk_space_plenty_is_ok() {
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: 512 * 1024 * 1024, // 512 MiB
            }),
            ..Default::default()
        };
        assert_eq!(check_disk_space(&probe).status, CheckStatus::Ok);
    }

    #[test]
    fn check_disk_space_below_128_mib_is_warn() {
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: 120 * 1024 * 1024, // 120 MiB -- between FAIL and WARN threshold
            }),
            ..Default::default()
        };
        assert_eq!(check_disk_space(&probe).status, CheckStatus::Warn);
    }

    #[test]
    fn check_disk_space_below_100_mib_is_fail() {
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: 50 * 1024 * 1024, // 50 MiB
            }),
            ..Default::default()
        };
        assert_eq!(check_disk_space(&probe).status, CheckStatus::Fail);
    }

    // -------------------------------------------------------------------------
    // Check 12: denial rate (informational)
    // -------------------------------------------------------------------------

    #[test]
    fn check_denial_rate_zero_is_ok() {
        let probe = FakeProbe {
            denials: Some(DenialStats {
                count_24h: 0,
                count_7d: 0,
                top_denied: Vec::new(),
            }),
            ..Default::default()
        };
        let result = check_denial_rate(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(result.detail.contains("24h"), "{}", result.detail);
    }

    #[test]
    fn check_denial_rate_nonzero_is_ok_with_count_in_detail() {
        let probe = FakeProbe {
            denials: Some(DenialStats {
                count_24h: 42,
                count_7d: 300,
                top_denied: Vec::new(),
            }),
            ..Default::default()
        };
        let result = check_denial_rate(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(result.detail.contains("42"), "{}", result.detail);
    }

    // -------------------------------------------------------------------------
    // Check 13: misconfiguration
    // -------------------------------------------------------------------------

    #[test]
    fn check_misconfig_clean_is_ok() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: false,
                deprecated_sha256hash: false,
                both_layouts_present: false,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_misconfig(&probe, &fake_path()).status,
            CheckStatus::Ok
        );
    }

    #[test]
    fn check_misconfig_permissive_flag_is_warn() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: true,
                deprecated_sha256hash: false,
                both_layouts_present: false,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("permissive"), "{}", result.detail);
    }

    #[test]
    fn check_misconfig_deprecated_sha256hash_is_warn() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: false,
                deprecated_sha256hash: true,
                both_layouts_present: false,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("sha256hash"), "{}", result.detail);
    }

    #[test]
    fn check_misconfig_both_layouts_is_warn() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: false,
                deprecated_sha256hash: false,
                both_layouts_present: true,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("fapd-F02"), "{}", result.detail);
    }

    #[test]
    fn check_misconfig_multiple_issues_combined_in_detail() {
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: true,
                deprecated_sha256hash: true,
                both_layouts_present: false,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        // Both issues should appear in the detail.
        assert!(result.detail.contains("permissive"), "{}", result.detail);
        assert!(result.detail.contains("sha256hash"), "{}", result.detail);
    }

    #[test]
    fn check_misconfig_all_three_independent_and_unmasked() {
        // All three sub-conditions true: EACH must appear in the detail.
        // Pins sub-condition independence -- kills a mutant that makes any one
        // condition contingent on the others being absent (e.g. only pushing
        // `both_layouts` when no other issue is present), which the
        // single-condition + permissive+sha256hash tests cannot detect.
        let probe = FakeProbe {
            conf: Some(FapolicydConf {
                permissive_set: true,
                deprecated_sha256hash: true,
                both_layouts_present: true,
            }),
            ..Default::default()
        };
        let result = check_misconfig(&probe, &fake_path());
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.detail.contains("permissive"), "{}", result.detail);
        assert!(result.detail.contains("sha256hash"), "{}", result.detail);
        assert!(
            result.detail.contains("fapd-F02"),
            "both-layouts (fapd-F02) must not be masked by the other two: {}",
            result.detail
        );
    }

    // -------------------------------------------------------------------------
    // worst_exit_code
    // -------------------------------------------------------------------------

    fn result(status: CheckStatus) -> CheckResult {
        CheckResult {
            name: "test",
            status,
            detail: String::new(),
            remediation: None,
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

    // -------------------------------------------------------------------------
    // run_checks emits 13 checks
    // -------------------------------------------------------------------------

    #[test]
    fn run_checks_returns_exactly_13_results() {
        // All probe methods unconfigured -- every check returns Unknown or Skip.
        let probe = FakeProbe::default();
        let results = run_checks(&probe, &fake_path());
        assert_eq!(results.len(), 13, "doctor must run exactly 13 checks");
    }

    #[test]
    fn run_checks_container_check_is_skip_regardless_of_probe() {
        // Container-check (#9, index 8) is always Skip (design decision #4).
        let probe = FakeProbe::default();
        let results = run_checks(&probe, &fake_path());
        let cc = &results[8];
        assert_eq!(
            cc.name, "container-check",
            "index 8 must be container-check"
        );
        assert_eq!(cc.status, CheckStatus::Skip, "container-check must be Skip");
    }
    // -------------------------------------------------------------------------
    // parse_kernel_version
    // -------------------------------------------------------------------------

    #[test]
    fn parse_kernel_version_standard_el_release_strings() {
        assert_eq!(
            parse_kernel_version("6.3.0-0.rc1.el10.x86_64"),
            Some((6, 3))
        );
        assert_eq!(parse_kernel_version("5.14.0-427.el9.x86_64"), Some((5, 14)));
        assert_eq!(parse_kernel_version("4.18.0-513.el8.x86_64"), Some((4, 18)));
    }

    #[test]
    fn parse_kernel_version_plain_strings() {
        assert_eq!(parse_kernel_version("6.3.1"), Some((6, 3)));
        assert_eq!(parse_kernel_version("4.20.0"), Some((4, 20)));
        assert_eq!(parse_kernel_version("4.19.0"), Some((4, 19)));
    }

    #[test]
    fn parse_kernel_version_garbage_returns_none() {
        assert_eq!(parse_kernel_version("not-a-kernel"), None);
        assert_eq!(parse_kernel_version(""), None);
    }
    // -------------------------------------------------------------------------
    // JOB 1B: check_disk_space boundary tests
    //
    // Kills survivors on the `< FAIL_BYTES` / `< WARN_BYTES` boundaries
    // (`<` vs `<=` / `==` / `>`) and the `bytes_free / (1024*1024)` arithmetic.
    // -------------------------------------------------------------------------

    #[test]
    fn check_disk_space_exactly_fail_bytes_is_warn_not_fail() {
        // bytes_free == FAIL_BYTES (100 MiB exactly) is NOT below FAIL_BYTES,
        // so it must be Warn (between FAIL and WARN thresholds), not Fail.
        // Kills a `< -> <=` mutant on the first branch.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: FAIL_BYTES,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_disk_space(&probe).status,
            CheckStatus::Warn,
            "exactly FAIL_BYTES must be Warn, not Fail"
        );
    }

    #[test]
    fn check_disk_space_one_byte_below_fail_bytes_is_fail() {
        // bytes_free == FAIL_BYTES - 1 is strictly below FAIL_BYTES -> Fail.
        // Kills a `< -> ==` or `< -> >` mutant on the first branch.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: FAIL_BYTES - 1,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_disk_space(&probe).status,
            CheckStatus::Fail,
            "FAIL_BYTES-1 must be Fail"
        );
    }

    #[test]
    fn check_disk_space_exactly_warn_bytes_is_ok_not_warn() {
        // bytes_free == WARN_BYTES (128 MiB exactly) is NOT below WARN_BYTES,
        // so it must be Ok, not Warn.
        // Kills a `< -> <=` mutant on the second branch.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: WARN_BYTES,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_disk_space(&probe).status,
            CheckStatus::Ok,
            "exactly WARN_BYTES must be Ok, not Warn"
        );
    }

    #[test]
    fn check_disk_space_one_byte_below_warn_bytes_is_warn() {
        // WARN_BYTES - 1 is strictly below WARN_BYTES but above FAIL_BYTES -> Warn.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: WARN_BYTES - 1,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_disk_space(&probe).status,
            CheckStatus::Warn,
            "WARN_BYTES-1 must be Warn"
        );
    }

    #[test]
    fn check_disk_space_detail_reports_correct_mib() {
        // 200 MiB exactly: detail must say "200 MiB".
        //
        // Pins the `/ (1024 * 1024)` arithmetic.  Two tricky mutants:
        //   - `replace / with *`:  bytes * 1048576 = 219902325555200 -> "219902325555200 MiB"
        //     which contains the substring "200 MiB" -- so `contains("200 MiB")` is too weak.
        //     We assert `contains(" 200 MiB")` (leading space) AND that the value parses to
        //     exactly 200 to force both mutations to fail.
        //   - `replace * with /`:  bytes / (1024/1024) = bytes / 1 = 209715200 -> not 200.
        let probe = FakeProbe {
            fs_space: Some(FsSpace {
                bytes_free: 200 * 1024 * 1024,
            }),
            ..Default::default()
        };
        let result = check_disk_space(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        // Leading-space prefix prevents "219902325555200 MiB" from matching " 200 MiB".
        assert!(
            result.detail.contains(" 200 MiB"),
            "detail must report exactly 200 MiB (with leading space), got: {}",
            result.detail
        );
        // Additionally assert the numeric value parses to 200 from the detail.
        let mib_val: u64 = result
            .detail
            .split_whitespace()
            .find_map(|tok| tok.parse().ok())
            .expect("detail must contain a parseable MiB number");
        assert_eq!(
            mib_val, 200,
            "MiB value in detail must be exactly 200, got {mib_val}"
        );
    }
    // -------------------------------------------------------------------------
    // JOB 1C: check_denial_rate top_denied section
    //
    // Kills the `delete !` survivor on `!stats.top_denied.is_empty()`.
    // Without the `!`, the top-denied section would be appended when the list
    // IS empty and omitted when it is NOT empty -- both assertions below would
    // fail.
    // -------------------------------------------------------------------------

    #[test]
    fn check_denial_rate_nonempty_top_denied_includes_top_section() {
        let probe = FakeProbe {
            denials: Some(DenialStats {
                count_24h: 5,
                count_7d: 50,
                top_denied: vec![
                    ("/usr/bin/python3".to_string(), "/etc/shadow".to_string(), 3),
                    ("/usr/bin/bash".to_string(), "/tmp/secret".to_string(), 2),
                ],
            }),
            ..Default::default()
        };
        let result = check_denial_rate(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(
            result.detail.contains("top denied:"),
            "non-empty top_denied must include 'top denied:' in detail: {}",
            result.detail
        );
        assert!(
            result.detail.contains("/usr/bin/python3"),
            "detail must include the top subject: {}",
            result.detail
        );
        assert!(
            result.detail.contains("/etc/shadow"),
            "detail must include the top object: {}",
            result.detail
        );
    }

    #[test]
    fn check_denial_rate_empty_top_denied_excludes_top_section() {
        // When top_denied is empty the "top denied:" section must be absent.
        // A `delete !` mutant would incorrectly append it even for an empty list.
        let probe = FakeProbe {
            denials: Some(DenialStats {
                count_24h: 0,
                count_7d: 0,
                top_denied: Vec::new(),
            }),
            ..Default::default()
        };
        let result = check_denial_rate(&probe);
        assert_eq!(result.status, CheckStatus::Ok);
        assert!(
            !result.detail.contains("top denied:"),
            "empty top_denied must NOT include 'top denied:' in detail: {}",
            result.detail
        );
    }
}
