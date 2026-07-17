//! The 5 pure check-classification functions for `rulesteward selinux doctor`
//! (#520). Each takes a `&dyn SelinuxProbe` and classifies its plain-data
//! return into a `CheckResult` - no I/O here (that lives behind the trait in
//! `probe`). `run_checks` drives all 5; the shared
//! `crate::commands::doctor::worst_exit_code` folds the verdicts.

use rulesteward_core::ControlRef;
use rulesteward_selinux::TargetVersion;
use rulesteward_selinux::stig::{ControlFamily, control_refs};

use super::model::SelinuxProbe;
use crate::commands::doctor::CheckResult;

/// Controls attached whenever `target` resolves (regardless of the check's
/// status); empty when it does not, mirroring the Phase-0 doc comment
/// (`CheckResult::controls`): "Controls attach whenever target resolves,
/// regardless of status."
fn controls_for(family: ControlFamily, target: Option<TargetVersion>) -> Vec<ControlRef> {
    match target {
        Some(t) => control_refs(family, t),
        None => Vec::new(),
    }
}

/// Check 1: `selinux-enforcing` - `getenforce` reports `Enforcing`.
pub(super) fn check_enforcing(
    probe: &dyn SelinuxProbe,
    target: Option<TargetVersion>,
) -> CheckResult {
    let controls = controls_for(ControlFamily::Enforcing, target);
    match probe.enforce_status() {
        Ok(mode) if mode == "Enforcing" => {
            CheckResult::ok("selinux-enforcing", "SELinux is Enforcing").with_controls(controls)
        }
        Ok(mode) => CheckResult::fail(
            "selinux-enforcing",
            format!("SELinux is {mode}, not Enforcing"),
            "run `setenforce 1` (immediate) and set SELINUX=enforcing in \
             /etc/selinux/config (persistent across reboot)",
        )
        .with_controls(controls),
        Err(e) => CheckResult::unknown(
            "selinux-enforcing",
            format!("could not determine SELinux enforcement status: {e}"),
        )
        .with_controls(controls),
    }
}

/// Check 2: `selinux-policy` - the loaded policy is `targeted`.
pub(super) fn check_policy(probe: &dyn SelinuxProbe, target: Option<TargetVersion>) -> CheckResult {
    let controls = controls_for(ControlFamily::PolicyType, target);
    match probe.loaded_policy_name() {
        Ok(Some(name)) if name == "targeted" => {
            CheckResult::ok("selinux-policy", format!("loaded policy is {name}"))
                .with_controls(controls)
        }
        Ok(Some(name)) => CheckResult::fail(
            "selinux-policy",
            format!("loaded policy is {name}, not targeted"),
            "set SELINUXTYPE=targeted in /etc/selinux/config and reboot",
        )
        .with_controls(controls),
        Ok(None) => CheckResult::fail(
            "selinux-policy",
            "no policy loaded (SELinux disabled)",
            "enable SELinux: set SELINUX=enforcing and SELINUXTYPE=targeted \
             in /etc/selinux/config, then reboot",
        )
        .with_controls(controls),
        Err(e) => CheckResult::unknown(
            "selinux-policy",
            format!("could not determine the loaded SELinux policy: {e}"),
        )
        .with_controls(controls),
    }
}

/// Check 3: `policycoreutils-package` installed.
pub(super) fn check_policycoreutils_package(
    probe: &dyn SelinuxProbe,
    target: Option<TargetVersion>,
) -> CheckResult {
    let controls = controls_for(ControlFamily::Policycoreutils, target);
    match probe.package_installed("policycoreutils") {
        Ok(true) => CheckResult::ok("policycoreutils-package", "policycoreutils is installed")
            .with_controls(controls),
        Ok(false) => CheckResult::fail(
            "policycoreutils-package",
            "policycoreutils is not installed",
            "dnf install policycoreutils",
        )
        .with_controls(controls),
        Err(e) => CheckResult::unknown(
            "policycoreutils-package",
            format!("could not query the policycoreutils package status: {e}"),
        )
        .with_controls(controls),
    }
}

/// Check 4: `policycoreutils-python-package` installed. Runs on EVERY target
/// (unlike se-W02, this is a doctor check, not a config-file lint), but the
/// controls attach ONLY at Rhel9/Rhel10 - `stig::control_refs` naturally
/// returns an empty vec for `Rhel8` (no row exists there, G7-confirmed), so
/// this needs no special-casing beyond calling `controls_for` uniformly.
pub(super) fn check_policycoreutils_python_package(
    probe: &dyn SelinuxProbe,
    target: Option<TargetVersion>,
) -> CheckResult {
    let controls = controls_for(ControlFamily::PolicycoreutilsPython, target);
    match probe.package_installed("policycoreutils-python-utils") {
        Ok(true) => CheckResult::ok(
            "policycoreutils-python-package",
            "policycoreutils-python-utils is installed",
        )
        .with_controls(controls),
        Ok(false) => CheckResult::fail(
            "policycoreutils-python-package",
            "policycoreutils-python-utils is not installed",
            "dnf install policycoreutils-python-utils",
        )
        .with_controls(controls),
        Err(e) => CheckResult::unknown(
            "policycoreutils-python-package",
            format!("could not query the policycoreutils-python-utils package status: {e}"),
        )
        .with_controls(controls),
    }
}

/// Check 5: `faillock-dir-context` - the faillock tally directory carries the
/// `faillog_t` `SELinux` type.
pub(super) fn check_faillock_dir_context(
    probe: &dyn SelinuxProbe,
    target: Option<TargetVersion>,
) -> CheckResult {
    let controls = controls_for(ControlFamily::FaillockDirContext, target);

    let dir = match probe.faillock_dir() {
        Ok(Some(dir)) => dir,
        Ok(None) => {
            return CheckResult::skip(
                "faillock-dir-context",
                "not applicable: SELinux is not enforcing a targeted \
                 policy, pam_faillock is not present in the auth stack, or \
                 no nondefault tally directory is configured (the STIG \
                 check targets nondefault directories)",
            )
            .with_controls(controls);
        }
        Err(e) => {
            return CheckResult::unknown(
                "faillock-dir-context",
                format!("could not locate the faillock tally directory: {e}"),
            )
            .with_controls(controls);
        }
    };

    match probe.dir_context_type(&dir) {
        Ok(Some(ty)) if ty == "faillog_t" => CheckResult::ok(
            "faillock-dir-context",
            format!("{} has SELinux type faillog_t", dir.display()),
        )
        .with_controls(controls),
        Ok(Some(ty)) => CheckResult::fail(
            "faillock-dir-context",
            format!("{} has SELinux type {ty}, not faillog_t", dir.display()),
            format!(
                "semanage fcontext -a -t faillog_t \"{}(/.*)?\" && restorecon -R -v {}",
                dir.display(),
                dir.display()
            ),
        )
        .with_controls(controls),
        Ok(None) => CheckResult::unknown(
            "faillock-dir-context",
            format!("{} does not exist", dir.display()),
        )
        .with_controls(controls),
        Err(e) => CheckResult::unknown(
            "faillock-dir-context",
            format!(
                "could not determine the SELinux context of {}: {e}",
                dir.display()
            ),
        )
        .with_controls(controls),
    }
}

/// Run all 5 selinux doctor checks in a fixed, pinned order.
#[must_use]
pub(super) fn run_checks(
    probe: &dyn SelinuxProbe,
    target: Option<TargetVersion>,
) -> Vec<CheckResult> {
    vec![
        check_enforcing(probe, target),
        check_policy(probe, target),
        check_policycoreutils_package(probe, target),
        check_policycoreutils_python_package(probe, target),
        check_faillock_dir_context(probe, target),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::doctor::CheckStatus;
    use rulesteward_core::Framework;
    use std::path::{Path, PathBuf};

    /// A fully-controllable fake probe: every method returns a canned value.
    struct FakeProbe {
        enforce: Result<String, String>,
        policy: Result<Option<String>, String>,
        package: Result<bool, String>,
        faillock_dir: Result<Option<PathBuf>, String>,
        dir_context: Result<Option<String>, String>,
    }

    impl SelinuxProbe for FakeProbe {
        fn enforce_status(&self) -> Result<String, String> {
            self.enforce.clone()
        }
        fn loaded_policy_name(&self) -> Result<Option<String>, String> {
            self.policy.clone()
        }
        fn package_installed(&self, _name: &str) -> Result<bool, String> {
            self.package.clone()
        }
        fn faillock_dir(&self) -> Result<Option<PathBuf>, String> {
            self.faillock_dir.clone()
        }
        fn dir_context_type(&self, _dir: &Path) -> Result<Option<String>, String> {
            self.dir_context.clone()
        }
    }

    impl Default for FakeProbe {
        fn default() -> Self {
            FakeProbe {
                enforce: Ok("Enforcing".to_string()),
                policy: Ok(Some("targeted".to_string())),
                package: Ok(true),
                faillock_dir: Ok(Some(PathBuf::from("/var/log/faillock"))),
                dir_context: Ok(Some("faillog_t".to_string())),
            }
        }
    }

    // -------------------------------------------------------------------
    // Check 1: selinux-enforcing
    // -------------------------------------------------------------------

    #[test]
    fn enforcing_is_ok() {
        let probe = FakeProbe::default();
        let r = check_enforcing(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(r.status, CheckStatus::Ok);
    }

    #[test]
    fn permissive_and_disabled_are_fail_with_setenforce_remediation() {
        for mode in ["Permissive", "Disabled"] {
            let probe = FakeProbe {
                enforce: Ok(mode.to_string()),
                ..FakeProbe::default()
            };
            let r = check_enforcing(&probe, Some(TargetVersion::Rhel9));
            assert_eq!(r.status, CheckStatus::Fail, "{mode} must be Fail");
            let rem = r.remediation.as_deref().unwrap_or("");
            assert!(rem.contains("setenforce 1"), "remediation={rem}");
            assert!(rem.contains("/etc/selinux/config"), "remediation={rem}");
            // Controls attach whenever the target resolves, REGARDLESS of
            // status (Phase-0 `CheckResult::controls` doc): the failing arm is
            // the compliance case that most needs its STIG id. Kills a
            // happy-path impl that only calls `.with_controls` on Ok.
            assert_eq!(
                r.controls.len(),
                1,
                "{mode}: Fail at a resolved target must still carry the \
                 Enforcing control"
            );
            assert_eq!(r.controls[0].framework, Framework::Stig);
            assert_eq!(r.controls[0].id, "RHEL-09-431010");
            assert_eq!(r.controls[0].alias.as_deref(), Some("V-258078"));
        }
    }

    #[test]
    fn enforce_probe_error_is_unknown() {
        let probe = FakeProbe {
            enforce: Err("getenforce not found".to_string()),
            ..FakeProbe::default()
        };
        let r = check_enforcing(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(r.status, CheckStatus::Unknown);
    }

    #[test]
    fn unknown_status_still_attaches_controls_at_resolved_target() {
        // Contract (Phase-0 `CheckResult::controls` doc): "attached whenever
        // the benchmark target is resolved, regardless of status" - Unknown
        // included. An impl that attaches controls only when the probe
        // succeeds drops the STIG ref exactly when the operator most needs to
        // know which control went unassessed.
        let probe = FakeProbe {
            enforce: Err("getenforce not found".to_string()),
            ..FakeProbe::default()
        };
        let r = check_enforcing(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(r.status, CheckStatus::Unknown);
        assert_eq!(
            r.controls.len(),
            1,
            "Unknown at a resolved target must still carry the Enforcing \
             control"
        );
        assert_eq!(r.controls[0].framework, Framework::Stig);
        assert_eq!(r.controls[0].id, "RHEL-09-431010");
        assert_eq!(r.controls[0].alias.as_deref(), Some("V-258078"));
    }

    #[test]
    fn enforcing_attaches_controls_at_every_target() {
        let probe = FakeProbe::default();
        for (target, expected_id) in [
            (TargetVersion::Rhel8, "RHEL-08-010170"),
            (TargetVersion::Rhel9, "RHEL-09-431010"),
            (TargetVersion::Rhel10, "RHEL-10-700420"),
        ] {
            let r = check_enforcing(&probe, Some(target));
            assert_eq!(r.controls.len(), 1, "{target:?}");
            assert_eq!(r.controls[0].framework, Framework::Stig);
            assert_eq!(r.controls[0].id, expected_id);
        }
    }

    // -------------------------------------------------------------------
    // Check 2: selinux-policy
    // -------------------------------------------------------------------

    #[test]
    fn targeted_policy_is_ok() {
        let probe = FakeProbe::default();
        let r = check_policy(&probe, Some(TargetVersion::Rhel8));
        assert_eq!(r.status, CheckStatus::Ok);
    }

    #[test]
    fn non_targeted_policy_is_fail() {
        let probe = FakeProbe {
            policy: Ok(Some("mls".to_string())),
            ..FakeProbe::default()
        };
        let r = check_policy(&probe, Some(TargetVersion::Rhel8));
        assert_eq!(r.status, CheckStatus::Fail);
        // Controls attach regardless of status (Phase-0 contract): the
        // wrong-policy Fail must still cite the PolicyType control it fails.
        assert_eq!(
            r.controls.len(),
            1,
            "Fail at a resolved target must still carry the PolicyType control"
        );
        assert_eq!(r.controls[0].framework, Framework::Stig);
        assert_eq!(r.controls[0].id, "RHEL-08-010450");
        assert_eq!(r.controls[0].alias.as_deref(), Some("V-230282"));
    }

    #[test]
    fn no_policy_loaded_is_fail_not_unknown() {
        // SELinux disabled (sestatus omits the "Loaded policy name" line
        // entirely, G5.2) is a REAL finding, not an indeterminate probe
        // failure.
        let probe = FakeProbe {
            policy: Ok(None),
            ..FakeProbe::default()
        };
        let r = check_policy(&probe, Some(TargetVersion::Rhel8));
        assert_eq!(r.status, CheckStatus::Fail);
        assert!(
            r.detail.to_lowercase().contains("disabled"),
            "detail={}",
            r.detail
        );
    }

    #[test]
    fn policy_probe_error_is_unknown() {
        let probe = FakeProbe {
            policy: Err("sestatus not found".to_string()),
            ..FakeProbe::default()
        };
        let r = check_policy(&probe, Some(TargetVersion::Rhel8));
        assert_eq!(r.status, CheckStatus::Unknown);
    }

    #[test]
    fn policy_attaches_policy_type_control() {
        let probe = FakeProbe::default();
        let r = check_policy(&probe, Some(TargetVersion::Rhel8));
        assert_eq!(r.controls.len(), 1);
        assert_eq!(r.controls[0].id, "RHEL-08-010450");
    }

    // -------------------------------------------------------------------
    // Check 3: policycoreutils-package
    // -------------------------------------------------------------------

    #[test]
    fn policycoreutils_installed_is_ok_absent_is_fail() {
        let installed = FakeProbe {
            package: Ok(true),
            ..FakeProbe::default()
        };
        assert_eq!(
            check_policycoreutils_package(&installed, Some(TargetVersion::Rhel9)).status,
            CheckStatus::Ok
        );

        let absent = FakeProbe {
            package: Ok(false),
            ..FakeProbe::default()
        };
        let r = check_policycoreutils_package(&absent, Some(TargetVersion::Rhel9));
        assert_eq!(r.status, CheckStatus::Fail);
        assert!(
            r.remediation
                .as_deref()
                .unwrap_or("")
                .contains("dnf install policycoreutils")
        );
    }

    #[test]
    fn policycoreutils_probe_error_is_unknown() {
        let probe = FakeProbe {
            package: Err("rpm not found".to_string()),
            ..FakeProbe::default()
        };
        let r = check_policycoreutils_package(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(r.status, CheckStatus::Unknown);
    }

    // -------------------------------------------------------------------
    // Check 4: policycoreutils-python-package
    // -------------------------------------------------------------------

    #[test]
    fn policycoreutils_python_shares_the_same_status_arms() {
        let installed = FakeProbe {
            package: Ok(true),
            ..FakeProbe::default()
        };
        assert_eq!(
            check_policycoreutils_python_package(&installed, Some(TargetVersion::Rhel9)).status,
            CheckStatus::Ok
        );
        let absent = FakeProbe {
            package: Ok(false),
            ..FakeProbe::default()
        };
        assert_eq!(
            check_policycoreutils_python_package(&absent, Some(TargetVersion::Rhel9)).status,
            CheckStatus::Fail
        );
    }

    #[test]
    fn policycoreutils_python_controls_empty_at_rhel8_present_at_rhel9_rhel10() {
        let probe = FakeProbe::default();
        let rhel8 = check_policycoreutils_python_package(&probe, Some(TargetVersion::Rhel8));
        assert!(
            rhel8.controls.is_empty(),
            "no policycoreutils-python-utils control exists at Rhel8 (G7)"
        );
        let rhel9 = check_policycoreutils_python_package(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(rhel9.controls.len(), 1);
        assert_eq!(rhel9.controls[0].id, "RHEL-09-431030");
        let rhel10 = check_policycoreutils_python_package(&probe, Some(TargetVersion::Rhel10));
        assert_eq!(rhel10.controls[0].id, "RHEL-10-200580");
    }

    // -------------------------------------------------------------------
    // Check 5: faillock-dir-context
    // -------------------------------------------------------------------

    #[test]
    fn faillock_locator_none_is_skip() {
        let probe = FakeProbe {
            faillock_dir: Ok(None),
            ..FakeProbe::default()
        };
        let r = check_faillock_dir_context(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(
            r.status,
            CheckStatus::Skip,
            "an NA locator must be Skip, never Fail"
        );
        assert!(r.detail.to_lowercase().contains("not applicable"));
    }

    #[test]
    fn faillock_skip_still_attaches_both_rhel8_controls_at_resolved_target() {
        // Contract (Phase-0 `CheckResult::controls` doc): "attached whenever
        // the benchmark target is resolved, regardless of status" - Skip
        // included. A not-applicable faillock dir must still report WHICH
        // controls this check assesses: BOTH RHEL 8 rows (the >=8.2 and <8.2
        // variants, G6/G8). Kills a happy-path impl that skips `.with_controls`
        // on the Skip arm.
        let probe = FakeProbe {
            faillock_dir: Ok(None),
            ..FakeProbe::default()
        };
        let r = check_faillock_dir_context(&probe, Some(TargetVersion::Rhel8));
        assert_eq!(r.status, CheckStatus::Skip);
        let ids: Vec<(&str, &str)> = r
            .controls
            .iter()
            .map(|c| (c.id.as_str(), c.alias.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(
            ids,
            vec![
                ("RHEL-08-020027", "V-250315"),
                ("RHEL-08-020028", "V-250316"),
            ],
            "Skip at a resolved Rhel8 target must still carry BOTH \
             FaillockDirContext controls"
        );
        for c in &r.controls {
            assert_eq!(c.framework, Framework::Stig);
        }
    }

    #[test]
    fn faillock_faillog_t_is_ok() {
        let probe = FakeProbe::default();
        let r = check_faillock_dir_context(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(r.status, CheckStatus::Ok);
    }

    #[test]
    fn faillock_wrong_type_is_fail_with_semanage_and_restorecon_remediation() {
        let probe = FakeProbe {
            dir_context: Ok(Some("container_file_t".to_string())),
            ..FakeProbe::default()
        };
        let r = check_faillock_dir_context(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(r.status, CheckStatus::Fail);
        let rem = r.remediation.as_deref().unwrap_or("");
        assert!(rem.contains("semanage fcontext"), "remediation={rem}");
        assert!(rem.contains("restorecon"), "remediation={rem}");
    }

    #[test]
    fn faillock_dir_absent_is_unknown() {
        // Locator found a dir path, but the dir itself does not exist on disk.
        let probe = FakeProbe {
            dir_context: Ok(None),
            ..FakeProbe::default()
        };
        let r = check_faillock_dir_context(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(r.status, CheckStatus::Unknown);
    }

    #[test]
    fn faillock_probe_error_is_unknown() {
        let locator_err = FakeProbe {
            faillock_dir: Err("cannot read faillock.conf".to_string()),
            ..FakeProbe::default()
        };
        assert_eq!(
            check_faillock_dir_context(&locator_err, Some(TargetVersion::Rhel9)).status,
            CheckStatus::Unknown
        );
        let context_err = FakeProbe {
            dir_context: Err("ls not found".to_string()),
            ..FakeProbe::default()
        };
        assert_eq!(
            check_faillock_dir_context(&context_err, Some(TargetVersion::Rhel9)).status,
            CheckStatus::Unknown
        );
    }

    #[test]
    fn faillock_attaches_two_refs_at_rhel8() {
        let probe = FakeProbe::default();
        let r = check_faillock_dir_context(&probe, Some(TargetVersion::Rhel8));
        assert_eq!(
            r.controls.len(),
            2,
            "RHEL 8 carries a >=8.2 AND a <8.2 faillock control"
        );
    }

    // -------------------------------------------------------------------
    // run_checks: exactly 5, in a pinned order
    // -------------------------------------------------------------------

    #[test]
    fn run_checks_produces_exactly_five_in_pinned_order() {
        let probe = FakeProbe::default();
        let results = run_checks(&probe, Some(TargetVersion::Rhel9));
        assert_eq!(results.len(), 5, "selinux doctor must run exactly 5 checks");
        let names: Vec<&str> = results.iter().map(|r| r.name).collect();
        assert_eq!(
            names,
            vec![
                "selinux-enforcing",
                "selinux-policy",
                "policycoreutils-package",
                "policycoreutils-python-package",
                "faillock-dir-context",
            ]
        );
    }

    #[test]
    fn run_checks_with_no_target_attaches_no_controls() {
        let probe = FakeProbe::default();
        let results = run_checks(&probe, None);
        assert_eq!(results.len(), 5);
        for r in &results {
            assert!(
                r.controls.is_empty(),
                "{}: no target resolved -> no control attachment",
                r.name
            );
        }
    }
}
