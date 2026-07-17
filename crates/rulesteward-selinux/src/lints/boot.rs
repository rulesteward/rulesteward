//! `se-W01` / `se-W02` - the `SELinux` boot-configuration STIG checks (#520).
//!
//! Both read the already-parsed [`SelinuxConfig`] (never raw text directly -
//! see [`crate::config`] for the per-key parse semantics) and are gated on a
//! resolved `--target`:
//!
//! * `se-W01` - `SELINUX=` is not `enforcing` in `/etc/selinux/config`. Fires
//!   ONLY at `--target rhel9|rhel10` (grounding F4: the config-file check-content
//!   for the boot-enforcing STIG requirement exists only in the RHEL 9/RHEL 10
//!   XCCDF text; RHEL 8's equivalent control is runtime-only - see
//!   `crate::stig::ControlFamily::Enforcing`'s RHEL 8 row, which is consumed by
//!   the selinux DOCTOR check instead).
//! * `se-W02` - `SELINUXTYPE=` is not `targeted` in `/etc/selinux/config`. Fires
//!   ONLY at `--target rhel8` (grounding F5: the config-file check-content for
//!   the targeted-policy STIG requirement exists only in the RHEL 8 XCCDF text;
//!   RHEL 9/RHEL 10's equivalent control is runtime-only). A MISSING
//!   `SELINUXTYPE=` line fires here even though libselinux itself would
//!   silently default to `targeted` at runtime (grounding G4 item 12) - the
//!   STIG check-content is explicit: "If no results are returned ... this is
//!   a finding" (SV-230282), so the STIG text wins on the lint surface, not
//!   libselinux's runtime default.
//!
//! Both are `Severity::Warning`. A missing key anchors at the file (span
//! `0..0`, line `0`, no `source_id` - the same "unanchored" convention as
//! `parse_error_diagnostic`'s file-level branch); a present-but-wrong key
//! anchors at its real line/span via [`rulesteward_core::anchored`].

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity, anchored};

use crate::config::SelinuxConfig;
use crate::stig::{ControlFamily, control_refs};
use crate::version::TargetVersion;

/// True when `value` is a case-insensitive PREFIX match of `"enforcing"`
/// (the same libselinux prefix-match semantics `config::parse_selinux_config`
/// models for the `SELINUX=` value - G4 Q7/Q9).
fn is_enforcing_value(value: &str) -> bool {
    value
        .get(..9)
        .is_some_and(|p| p.eq_ignore_ascii_case("enforcing"))
}

/// `se-W01`: `SELINUX=` is not `enforcing`. Fires only when `target` is
/// `Some(Rhel9)` or `Some(Rhel10)`; silent at `Rhel8` and at `None`.
#[must_use]
pub fn check_enforcing(
    config: &SelinuxConfig,
    target: Option<TargetVersion>,
    file: &Path,
) -> Vec<Diagnostic> {
    let Some(t) = target else {
        return Vec::new();
    };
    if !matches!(t, TargetVersion::Rhel9 | TargetVersion::Rhel10) {
        return Vec::new();
    }

    let controls = control_refs(ControlFamily::Enforcing, t);
    match &config.selinux {
        None => vec![
            Diagnostic::new(
                Severity::Warning,
                "se-W01",
                0..0,
                "SELinux is not configured to be enforcing at boot: SELINUX= \
                 is missing, commented out, or unrecognized in \
                 /etc/selinux/config",
                file.to_path_buf(),
                0,
                0,
            )
            .with_controls(controls),
        ],
        Some(cv) => {
            if is_enforcing_value(&cv.value) {
                Vec::new()
            } else {
                vec![
                    anchored(
                        Severity::Warning,
                        "se-W01",
                        cv.span.clone(),
                        format!(
                            "SELinux is not configured to be enforcing at boot: \
                             SELINUX={} in /etc/selinux/config",
                            cv.value
                        ),
                        file.to_path_buf(),
                        cv.line,
                    )
                    .with_controls(controls),
                ]
            }
        }
    }
}

/// `se-W02`: `SELINUXTYPE=` is not `targeted`. Fires only when `target` is
/// `Some(Rhel8)`; silent at `Rhel9`/`Rhel10` and at `None`.
#[must_use]
pub fn check_policy_type(
    config: &SelinuxConfig,
    target: Option<TargetVersion>,
    file: &Path,
) -> Vec<Diagnostic> {
    if target != Some(TargetVersion::Rhel8) {
        return Vec::new();
    }

    let controls = control_refs(ControlFamily::PolicyType, TargetVersion::Rhel8);
    match &config.selinuxtype {
        None => vec![
            Diagnostic::new(
                Severity::Warning,
                "se-W02",
                0..0,
                "SELinux is not configured to use the targeted policy: \
                 SELINUXTYPE= is missing in /etc/selinux/config",
                file.to_path_buf(),
                0,
                0,
            )
            .with_controls(controls),
        ],
        Some(cv) => {
            if cv.value == "targeted" {
                Vec::new()
            } else {
                vec![
                    anchored(
                        Severity::Warning,
                        "se-W02",
                        cv.span.clone(),
                        format!(
                            "SELinux is not configured to use the targeted \
                             policy: SELINUXTYPE={} in /etc/selinux/config",
                            cv.value
                        ),
                        file.to_path_buf(),
                        cv.line,
                    )
                    .with_controls(controls),
                ]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigValue;
    use rulesteward_core::{Framework, Severity};
    use std::path::PathBuf;

    fn file() -> PathBuf {
        PathBuf::from("/etc/selinux/config")
    }

    fn cv(value: &str, line: usize, span: std::ops::Range<usize>) -> ConfigValue {
        ConfigValue {
            value: value.to_string(),
            line,
            span,
        }
    }

    // -------------------------------------------------------------------
    // se-W01 (check_enforcing)
    // -------------------------------------------------------------------

    #[test]
    fn w01_missing_key_fires_with_file_level_anchor_at_rhel9() {
        let config = SelinuxConfig {
            selinux: None,
            selinuxtype: None,
        };
        let diags = check_enforcing(&config, Some(TargetVersion::Rhel9), &file());
        assert_eq!(diags.len(), 1, "a missing SELINUX= key must fire se-W01");
        let d = &diags[0];
        assert_eq!(d.code, "se-W01");
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.line, 0, "a missing key has no source line -> file-level");
        assert_eq!(d.span, 0..0, "a missing key has no byte range -> 0..0");
    }

    #[test]
    fn w01_permissive_value_fires_anchored_at_the_real_line() {
        let config = SelinuxConfig {
            selinux: Some(cv("permissive", 5, 10..29)),
            selinuxtype: None,
        };
        let diags = check_enforcing(&config, Some(TargetVersion::Rhel9), &file());
        assert_eq!(diags.len(), 1, "permissive must fire se-W01");
        let d = &diags[0];
        assert_eq!(d.code, "se-W01");
        assert_eq!(d.line, 5, "must anchor at the real assignment's line");
        assert_eq!(d.span, 10..29, "must anchor at the real assignment's span");
    }

    #[test]
    fn w01_disabled_value_fires_at_rhel10() {
        let config = SelinuxConfig {
            selinux: Some(cv("disabled", 3, 0..17)),
            selinuxtype: None,
        };
        let diags = check_enforcing(&config, Some(TargetVersion::Rhel10), &file());
        assert_eq!(diags.len(), 1, "disabled must fire se-W01");
    }

    #[test]
    fn w01_enforcing_value_is_clean() {
        let config = SelinuxConfig {
            selinux: Some(cv("enforcing", 1, 0..17)),
            selinuxtype: None,
        };
        assert!(
            check_enforcing(&config, Some(TargetVersion::Rhel9), &file()).is_empty(),
            "SELINUX=enforcing must not fire se-W01"
        );
    }

    #[test]
    fn w01_case_insensitive_enforcing_value_is_clean() {
        let config = SelinuxConfig {
            selinux: Some(cv("ENFORCING", 1, 0..17)),
            selinuxtype: None,
        };
        assert!(
            check_enforcing(&config, Some(TargetVersion::Rhel9), &file()).is_empty(),
            "the enforcing-value comparison is case-insensitive (G4 Q3)"
        );
    }

    #[test]
    fn w01_prefix_quirk_enforcingxyz_is_clean() {
        // G4 Q7/Q9: libselinux's own recognized-value comparison is a 9-byte
        // PREFIX match, so `enforcingXYZ` is treated as ENFORCING upstream.
        // A lint claiming libselinux fidelity must accept it (a stricter
        // "must be exactly `enforcing`" impl would be a documented
        // over-broad-FP risk the grounding doc explicitly flags).
        let config = SelinuxConfig {
            selinux: Some(cv("enforcingXYZ", 1, 0..20)),
            selinuxtype: None,
        };
        assert!(
            check_enforcing(&config, Some(TargetVersion::Rhel9), &file()).is_empty(),
            "enforcingXYZ is a recognized-as-enforcing PREFIX match (G4); \
             must not fire se-W01"
        );
    }

    #[test]
    fn w01_is_silent_at_rhel8() {
        let config = SelinuxConfig {
            selinux: Some(cv("permissive", 1, 0..18)),
            selinuxtype: None,
        };
        assert!(
            check_enforcing(&config, Some(TargetVersion::Rhel8), &file()).is_empty(),
            "se-W01's config-file check-content exists only in the rhel9/10 \
             XCCDF text (grounding F4); it must be silent at rhel8 even for a \
             clearly-non-enforcing value"
        );
    }

    #[test]
    fn w01_is_silent_with_no_target() {
        let config = SelinuxConfig {
            selinux: None,
            selinuxtype: None,
        };
        assert!(
            check_enforcing(&config, None, &file()).is_empty(),
            "an omitted --target must stay version-agnostic: se-W01 never \
             fires without a resolved target"
        );
    }

    #[test]
    fn w01_attaches_the_enforcing_control_for_the_firing_target() {
        let missing = SelinuxConfig {
            selinux: None,
            selinuxtype: None,
        };
        let rhel9 = check_enforcing(&missing, Some(TargetVersion::Rhel9), &file());
        assert_eq!(rhel9.len(), 1);
        assert_eq!(rhel9[0].controls.len(), 1);
        assert_eq!(rhel9[0].controls[0].framework, Framework::Stig);
        assert_eq!(rhel9[0].controls[0].id, "RHEL-09-431010");
        assert_eq!(rhel9[0].controls[0].alias.as_deref(), Some("V-258078"));

        let rhel10 = check_enforcing(&missing, Some(TargetVersion::Rhel10), &file());
        assert_eq!(rhel10.len(), 1);
        assert_eq!(rhel10[0].controls[0].id, "RHEL-10-700420");
        assert_eq!(rhel10[0].controls[0].alias.as_deref(), Some("V-281251"));
    }

    // -------------------------------------------------------------------
    // se-W02 (check_policy_type)
    // -------------------------------------------------------------------

    #[test]
    fn w02_missing_key_fires_with_file_level_anchor_at_rhel8() {
        let config = SelinuxConfig {
            selinux: None,
            selinuxtype: None,
        };
        let diags = check_policy_type(&config, Some(TargetVersion::Rhel8), &file());
        assert_eq!(
            diags.len(),
            1,
            "a missing SELINUXTYPE= key must fire se-W02, even though \
             libselinux itself would default to targeted at runtime (the \
             STIG check-content wording wins on the lint surface, G4 item 12 \
             / grounding F5)"
        );
        let d = &diags[0];
        assert_eq!(d.code, "se-W02");
        assert_eq!(d.severity, Severity::Warning);
        assert_eq!(d.line, 0);
        assert_eq!(d.span, 0..0);
    }

    #[test]
    fn w02_mls_value_fires_anchored_at_the_real_line() {
        let config = SelinuxConfig {
            selinux: None,
            selinuxtype: Some(cv("mls", 4, 20..35)),
        };
        let diags = check_policy_type(&config, Some(TargetVersion::Rhel8), &file());
        assert_eq!(diags.len(), 1, "SELINUXTYPE=mls must fire se-W02");
        let d = &diags[0];
        assert_eq!(d.line, 4);
        assert_eq!(d.span, 20..35);
    }

    #[test]
    fn w02_targeted_value_is_clean() {
        let config = SelinuxConfig {
            selinux: None,
            selinuxtype: Some(cv("targeted", 4, 0..21)),
        };
        assert!(
            check_policy_type(&config, Some(TargetVersion::Rhel8), &file()).is_empty(),
            "SELINUXTYPE=targeted must not fire se-W02"
        );
    }

    #[test]
    fn w02_is_silent_at_rhel9_and_rhel10() {
        let config = SelinuxConfig {
            selinux: None,
            selinuxtype: Some(cv("mls", 1, 0..16)),
        };
        for target in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            assert!(
                check_policy_type(&config, Some(target), &file()).is_empty(),
                "se-W02's config-file check-content exists only in the rhel8 \
                 XCCDF text (grounding F5); it must be silent at {target:?} \
                 even for a clearly-wrong value"
            );
        }
    }

    #[test]
    fn w02_is_silent_with_no_target() {
        let config = SelinuxConfig {
            selinux: None,
            selinuxtype: None,
        };
        assert!(
            check_policy_type(&config, None, &file()).is_empty(),
            "an omitted --target must stay version-agnostic: se-W02 never \
             fires without a resolved target"
        );
    }

    #[test]
    fn w02_attaches_the_policy_type_control() {
        let missing = SelinuxConfig {
            selinux: None,
            selinuxtype: None,
        };
        let diags = check_policy_type(&missing, Some(TargetVersion::Rhel8), &file());
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].controls.len(), 1);
        assert_eq!(diags[0].controls[0].framework, Framework::Stig);
        assert_eq!(diags[0].controls[0].id, "RHEL-08-010450");
        assert_eq!(diags[0].controls[0].alias.as_deref(), Some("V-230282"));
    }

    // -------------------------------------------------------------------
    // Adequacy-bar guard: se-W01 must never fire at rhel8, and vice versa,
    // even given the SAME misconfigured input for both checks at once.
    // -------------------------------------------------------------------

    #[test]
    fn cross_gating_holds_for_the_same_misconfigured_file_at_every_target() {
        let config = SelinuxConfig {
            selinux: Some(cv("permissive", 1, 0..18)),
            selinuxtype: Some(cv("mls", 2, 19..34)),
        };
        // Rhel8: only se-W02 may fire.
        assert!(!check_policy_type(&config, Some(TargetVersion::Rhel8), &file()).is_empty());
        assert!(check_enforcing(&config, Some(TargetVersion::Rhel8), &file()).is_empty());
        // Rhel9/Rhel10: only se-W01 may fire.
        for target in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            assert!(!check_enforcing(&config, Some(target), &file()).is_empty());
            assert!(check_policy_type(&config, Some(target), &file()).is_empty());
        }
        // No target: neither fires.
        assert!(check_enforcing(&config, None, &file()).is_empty());
        assert!(check_policy_type(&config, None, &file()).is_empty());
    }
}
