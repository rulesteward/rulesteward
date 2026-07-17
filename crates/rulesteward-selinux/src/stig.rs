//! `SELinux` STIG control-family table (issue #520).
//!
//! Every id/alias pair below is transcribed VERBATIM from
//! `grounding/g7-g8-xccdf-vnumbers.md` (extracted from the pinned DISA XCCDF
//! zips: RHEL 8 STIG V2R4, RHEL 9 STIG V2R7, RHEL 10 STIG V1R1) - no
//! hand-invented ids (per the session's "Aliases are DISA V-numbers,
//! tool-derived" rule). The grounded rows (family, target -> `stig_id` /
//! `v_number`), fenced so rustdoc/clippy treat it as literal text, not prose:
//!
//! ```text
//! family                 target   stig_id          v_number
//! Enforcing              Rhel8    RHEL-08-010170   V-230240
//! Enforcing              Rhel9    RHEL-09-431010   V-258078
//! Enforcing              Rhel10   RHEL-10-700420   V-281251
//! PolicyType             Rhel8    RHEL-08-010450   V-230282
//! PolicyType             Rhel9    RHEL-09-431015   V-258079
//! PolicyType             Rhel10   RHEL-10-700400   V-281249
//! Policycoreutils        Rhel8    RHEL-08-010171   V-230241
//! Policycoreutils        Rhel9    RHEL-09-431025   V-258081
//! Policycoreutils        Rhel10   RHEL-10-200570   V-280966
//! PolicycoreutilsPython  Rhel9    RHEL-09-431030   V-258082
//! PolicycoreutilsPython  Rhel10   RHEL-10-200580   V-280967
//! FaillockDirContext     Rhel8    RHEL-08-020027   V-250315
//! FaillockDirContext     Rhel8    RHEL-08-020028   V-250316
//! FaillockDirContext     Rhel9    RHEL-09-431020   V-258080
//! FaillockDirContext     Rhel10   RHEL-10-700430   V-281252
//! ```
//!
//! `PolicycoreutilsPython` has NO `Rhel8` row (G7-confirmed: the RHEL 8 V2R4
//! XCCDF has zero occurrences of `policycoreutils-python-utils` anywhere).
//! `FaillockDirContext` carries TWO rows at `Rhel8` (a >=8.2 variant and a
//! <8.2 variant; RHEL 9/RHEL 10 carry one each).
//!
//! Consumed by BOTH `crate::lints::boot` (se-W01/se-W02) and
//! `rulesteward-cli`'s selinux doctor checks; also imported by
//! `tools/selinux-stig-update` for the drift-check gate (mirroring
//! `rulesteward_sysctld::catalog::stig_baseline`'s consumer shape).

use rulesteward_core::ControlRef;

use crate::version::TargetVersion;

/// A STIG control family this crate maps: which STIG requirement a given
/// se-W01/se-W02 lint finding, or selinux-doctor check, enforces evidence for.
/// See the module doc comment's table for the exact grounded id/alias per
/// (family, target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFamily {
    /// "must use a Linux Security Module configured to enforce limits on
    /// system services" (`SELinux` enforcing at boot / at runtime).
    Enforcing,
    /// "must enable the `SELinux` targeted policy".
    PolicyType,
    /// "must have policycoreutils package installed".
    Policycoreutils,
    /// "must have policycoreutils-python-utils package installed". NO RHEL 8
    /// row exists.
    PolicycoreutilsPython,
    /// "must configure `SELinux` context type to allow the use of a
    /// non-default faillock tally directory". RHEL 8 carries TWO rows.
    FaillockDirContext,
}

/// Project the grounded control rows for `family` at `target` into typed
/// [`ControlRef`]s (framework = Stig, id = the Rule/stig id, alias = the DISA
/// Group/V-number). Returns an empty vec when the family has no row at
/// `target` (e.g. `PolicycoreutilsPython` at `Rhel8`); returns more than one
/// entry when the family has multiple rows at `target` (e.g.
/// `FaillockDirContext` at `Rhel8`).
#[must_use]
pub fn control_refs(family: ControlFamily, target: TargetVersion) -> Vec<ControlRef> {
    let _ = (family, target);
    todo!(
        "return the grounded ControlRef{{framework: Stig, id: stig_id, alias: \
         v_number}} row(s) for (family, target) per the module doc comment's \
         table; see grounding/g7-g8-xccdf-vnumbers.md for the primary source"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::Framework;

    fn ids(refs: &[ControlRef]) -> Vec<(&str, &str)> {
        refs.iter()
            .map(|r| (r.id.as_str(), r.alias.as_deref().unwrap_or("")))
            .collect()
    }

    #[test]
    fn enforcing_exact_ids_per_target() {
        assert_eq!(
            ids(&control_refs(
                ControlFamily::Enforcing,
                TargetVersion::Rhel8
            )),
            vec![("RHEL-08-010170", "V-230240")]
        );
        assert_eq!(
            ids(&control_refs(
                ControlFamily::Enforcing,
                TargetVersion::Rhel9
            )),
            vec![("RHEL-09-431010", "V-258078")]
        );
        assert_eq!(
            ids(&control_refs(
                ControlFamily::Enforcing,
                TargetVersion::Rhel10
            )),
            vec![("RHEL-10-700420", "V-281251")]
        );
    }

    #[test]
    fn policy_type_exact_ids_per_target() {
        assert_eq!(
            ids(&control_refs(
                ControlFamily::PolicyType,
                TargetVersion::Rhel8
            )),
            vec![("RHEL-08-010450", "V-230282")]
        );
        assert_eq!(
            ids(&control_refs(
                ControlFamily::PolicyType,
                TargetVersion::Rhel9
            )),
            vec![("RHEL-09-431015", "V-258079")]
        );
        assert_eq!(
            ids(&control_refs(
                ControlFamily::PolicyType,
                TargetVersion::Rhel10
            )),
            vec![("RHEL-10-700400", "V-281249")]
        );
    }

    #[test]
    fn policycoreutils_exact_ids_per_target() {
        assert_eq!(
            ids(&control_refs(
                ControlFamily::Policycoreutils,
                TargetVersion::Rhel8
            )),
            vec![("RHEL-08-010171", "V-230241")]
        );
        assert_eq!(
            ids(&control_refs(
                ControlFamily::Policycoreutils,
                TargetVersion::Rhel9
            )),
            vec![("RHEL-09-431025", "V-258081")]
        );
        assert_eq!(
            ids(&control_refs(
                ControlFamily::Policycoreutils,
                TargetVersion::Rhel10
            )),
            vec![("RHEL-10-200570", "V-280966")]
        );
    }

    #[test]
    fn policycoreutils_python_has_no_rhel8_row() {
        assert!(
            control_refs(ControlFamily::PolicycoreutilsPython, TargetVersion::Rhel8).is_empty(),
            "G7-confirmed: RHEL 8 V2R4 has NO policycoreutils-python-utils \
             control; a wrong impl that copies the Policycoreutils row to \
             every target would fail this"
        );
    }

    #[test]
    fn policycoreutils_python_exact_ids_at_rhel9_and_rhel10() {
        assert_eq!(
            ids(&control_refs(
                ControlFamily::PolicycoreutilsPython,
                TargetVersion::Rhel9
            )),
            vec![("RHEL-09-431030", "V-258082")]
        );
        assert_eq!(
            ids(&control_refs(
                ControlFamily::PolicycoreutilsPython,
                TargetVersion::Rhel10
            )),
            vec![("RHEL-10-200580", "V-280967")]
        );
    }

    #[test]
    fn faillock_dir_context_rhel8_returns_two_refs() {
        let refs = control_refs(ControlFamily::FaillockDirContext, TargetVersion::Rhel8);
        assert_eq!(
            ids(&refs),
            vec![
                ("RHEL-08-020027", "V-250315"),
                ("RHEL-08-020028", "V-250316"),
            ],
            "RHEL 8 carries a >=8.2 variant AND a <8.2 variant of the faillock \
             control - both must be returned, not just one"
        );
    }

    #[test]
    fn faillock_dir_context_exact_ids_at_rhel9_and_rhel10() {
        assert_eq!(
            ids(&control_refs(
                ControlFamily::FaillockDirContext,
                TargetVersion::Rhel9
            )),
            vec![("RHEL-09-431020", "V-258080")]
        );
        assert_eq!(
            ids(&control_refs(
                ControlFamily::FaillockDirContext,
                TargetVersion::Rhel10
            )),
            vec![("RHEL-10-700430", "V-281252")]
        );
    }

    #[test]
    fn every_ref_is_tagged_stig_framework() {
        for (family, target) in [
            (ControlFamily::Enforcing, TargetVersion::Rhel9),
            (ControlFamily::PolicyType, TargetVersion::Rhel8),
            (ControlFamily::Policycoreutils, TargetVersion::Rhel10),
            (ControlFamily::FaillockDirContext, TargetVersion::Rhel8),
        ] {
            for r in control_refs(family, target) {
                assert_eq!(r.framework, Framework::Stig);
            }
        }
    }
}
