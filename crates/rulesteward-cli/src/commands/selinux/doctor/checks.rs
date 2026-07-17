//! The 5 pure check-classification functions for `rulesteward selinux doctor`
//! (#520). Each takes a `&dyn SelinuxProbe` and classifies its plain-data
//! return into a `CheckResult` - no I/O here (that lives behind the trait in
//! `probe`). `run_checks` drives all 5; the shared
//! `crate::commands::doctor::worst_exit_code` folds the verdicts.

use std::path::Path;

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
    let _ = (
        probe.enforce_status(),
        controls_for(ControlFamily::Enforcing, target),
    );
    todo!(
        "selinux-enforcing: Enforcing->Ok; Permissive/Disabled->Fail \
         (remediation mentions `setenforce 1` + /etc/selinux/config \
         persistence); Err->Unknown; attach \
         controls_for(ControlFamily::Enforcing, target) at every target \
         (G5.1)"
    )
}

/// Check 2: `selinux-policy` - the loaded policy is `targeted`.
pub(super) fn check_policy(probe: &dyn SelinuxProbe, target: Option<TargetVersion>) -> CheckResult {
    let _ = (
        probe.loaded_policy_name(),
        controls_for(ControlFamily::PolicyType, target),
    );
    todo!(
        "selinux-policy: Some(\"targeted\")->Ok; Some(other)->Fail; \
         None->Fail(\"no policy loaded (SELinux disabled)\"); Err->Unknown; \
         attach controls_for(ControlFamily::PolicyType, target) (G5.2)"
    )
}

/// Check 3: `policycoreutils-package` installed.
pub(super) fn check_policycoreutils_package(
    probe: &dyn SelinuxProbe,
    target: Option<TargetVersion>,
) -> CheckResult {
    let _ = (
        probe.package_installed("policycoreutils"),
        controls_for(ControlFamily::Policycoreutils, target),
    );
    todo!(
        "policycoreutils-package: true->Ok; false->Fail(\"dnf install \
         policycoreutils\"); Err->Unknown; attach \
         controls_for(ControlFamily::Policycoreutils, target)"
    )
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
    let _ = (
        probe.package_installed("policycoreutils-python-utils"),
        controls_for(ControlFamily::PolicycoreutilsPython, target),
    );
    todo!(
        "policycoreutils-python-package: SAME arms as check 3; attach \
         controls_for(ControlFamily::PolicycoreutilsPython, target) - empty \
         at Rhel8 by construction (no table row), non-empty at Rhel9/Rhel10"
    )
}

/// Check 5: `faillock-dir-context` - the faillock tally directory carries the
/// `faillog_t` `SELinux` type.
pub(super) fn check_faillock_dir_context(
    probe: &dyn SelinuxProbe,
    target: Option<TargetVersion>,
) -> CheckResult {
    let _ = (
        probe.faillock_dir(),
        probe.dir_context_type(Path::new("/")),
        controls_for(ControlFamily::FaillockDirContext, target),
    );
    todo!(
        "faillock-dir-context: locator Ok(None)->Skip(\"not applicable\"); \
         Some(dir)+Ok(Some(\"faillog_t\"))->Ok; Ok(Some(other))->Fail \
         (remediation mentions `semanage fcontext` + `restorecon`); \
         Ok(None) dir-absent->Unknown; Err (either probe call)->Unknown; \
         attach controls_for(ControlFamily::FaillockDirContext, target) - \
         TWO refs at Rhel8 (G6)"
    )
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
