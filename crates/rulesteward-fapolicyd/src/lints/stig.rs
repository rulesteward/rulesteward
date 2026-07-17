//! fapolicyd STIG control table (#519): the 3 host-state control families
//! fapolicyd maps to a DISA STIG benchmark - package installed, service
//! enabled, and the deny-all/permit-by-exception rule policy - projected per
//! RHEL target. fapolicyd has ZERO pure rules.d/-content STIG controls (the
//! #518 exhaustive sweep found none); every control here is host-state, which
//! is why the doctor verb (not the lint verb) is the primary control-attachment
//! surface (`FapolicydStigRefs` in
//! `crates/rulesteward-cli/src/commands/doctor/model.rs`). fapd-W13 (deny-all)
//! and fapd-W14 (permissive) also attach the [`ControlFamily::DenyAll`] row
//! (deny-all is BOTH a doctor host-state check AND a lint-observable ruleset
//! property).
//!
//! Grounded verbatim in the pinned DISA XCCDF (RHEL 8 V2R4 / RHEL 9 V2R7 /
//! RHEL 10 V1R1), extracted 2026-07-16 into
//! `/mnt/side-projects/9d-v0_8-wave2b/grounding/g7-g8-xccdf-vnumbers.md`
//! section 2 (raw `<Group>` fixtures under `grounding/xccdf/RHEL-0{8,9,10}-*.xml`).
//! All nine rows are DISA severity `medium` (confirmed against the XCCDF
//! `severity` attribute on every one of the 9 Rule elements); the two
//! non-medium severities the wider #518 classification found
//! (RHEL-09-431010 high, RHEL-08-010171 low) belong to selinux lane 2b, not
//! fapolicyd.

use rulesteward_core::{ControlRef, Framework};

use crate::version::TargetVersion;

/// The three host-state control families fapolicyd's DISA STIG controls map
/// to. There is exactly one [`StigControl`] row per family per
/// [`TargetVersion`] (9 rows total: 3 families x 3 targets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFamily {
    /// The fapolicyd package/module is installed.
    Installed,
    /// The fapolicyd service is enabled (persists across reboot).
    Enabled,
    /// The rule policy employs a deny-all, permit-by-exception default.
    DenyAll,
}

/// DISA STIG severity tier (the XCCDF Rule `severity` attribute) - distinct
/// from [`rulesteward_core::Severity`] (`RuleSteward`'s own F/E/W/S/C/X finding
/// tier): this is the EXTERNAL framework's classification, not ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StigSeverity {
    Low,
    Medium,
    High,
}

/// One fapolicyd DISA STIG control, grounded verbatim in the pinned XCCDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StigControl {
    /// Which host-state family this control belongs to.
    pub family: ControlFamily,
    /// The canonical STIG/Rule id (DISA XCCDF `<version>`, e.g. `"RHEL-08-040135"`).
    pub stig_id: &'static str,
    /// The DISA Group/Vuln id (XCCDF `<Group id>`, e.g. `"V-230523"`).
    pub v_number: &'static str,
    /// DISA severity tier (the XCCDF Rule `severity` attribute).
    pub severity: StigSeverity,
    /// The DISA Rule `<title>` text, verbatim.
    pub title: &'static str,
}

/// The 3 fapolicyd STIG controls (Installed/Enabled/DenyAll) for `target`,
/// grounded verbatim in the pinned DISA XCCDF for that RHEL release.
///
/// Implementer note: source the exact `stig_id`/`v_number`/`severity`/`title`
/// values from `/mnt/side-projects/9d-v0_8-wave2b/grounding/g7-g8-xccdf-vnumbers.md`
/// section 2 (cross-checked against the raw `grounding/xccdf/*.xml` fixtures) -
/// never hand-invent a V-number (session `.wolf/cerebrum.md` standing rule).
#[must_use]
pub fn stig_controls(target: TargetVersion) -> &'static [StigControl] {
    const RHEL8: &[StigControl] = &[
        StigControl {
            family: ControlFamily::Installed,
            stig_id: "RHEL-08-040135",
            v_number: "V-230523",
            severity: StigSeverity::Medium,
            title: "The RHEL 8 fapolicy module must be installed.",
        },
        StigControl {
            family: ControlFamily::Enabled,
            stig_id: "RHEL-08-040136",
            v_number: "V-244545",
            severity: StigSeverity::Medium,
            title: "The RHEL 8 fapolicy module must be enabled.",
        },
        StigControl {
            family: ControlFamily::DenyAll,
            stig_id: "RHEL-08-040137",
            v_number: "V-244546",
            severity: StigSeverity::Medium,
            title: "The RHEL 8 fapolicy module must be configured to employ a deny-all, \
                    permit-by-exception policy to allow the execution of authorized \
                    software programs.",
        },
    ];
    const RHEL9: &[StigControl] = &[
        StigControl {
            family: ControlFamily::Installed,
            stig_id: "RHEL-09-433010",
            v_number: "V-258089",
            severity: StigSeverity::Medium,
            title: "RHEL 9 fapolicy module must be installed.",
        },
        StigControl {
            family: ControlFamily::Enabled,
            stig_id: "RHEL-09-433015",
            v_number: "V-258090",
            severity: StigSeverity::Medium,
            title: "RHEL 9 fapolicy module must be enabled.",
        },
        StigControl {
            family: ControlFamily::DenyAll,
            stig_id: "RHEL-09-433016",
            v_number: "V-270180",
            severity: StigSeverity::Medium,
            title: "The RHEL 9 fapolicy module must be configured to employ a deny-all, \
                    permit-by-exception policy to allow the execution of authorized \
                    software programs.",
        },
    ];
    const RHEL10: &[StigControl] = &[
        StigControl {
            family: ControlFamily::Installed,
            stig_id: "RHEL-10-200600",
            v_number: "V-280969",
            severity: StigSeverity::Medium,
            title: "RHEL 10 must have the \"fapolicy\" module installed.",
        },
        StigControl {
            family: ControlFamily::Enabled,
            stig_id: "RHEL-10-200601",
            v_number: "V-280970",
            severity: StigSeverity::Medium,
            title: "RHEL 10 must enable the \"fapolicy\" module.",
        },
        StigControl {
            family: ControlFamily::DenyAll,
            stig_id: "RHEL-10-200602",
            v_number: "V-280971",
            severity: StigSeverity::Medium,
            title: "RHEL 10 must be configured to employ a deny-all, permit-by-exception \
                    policy to allow the execution of authorized software programs.",
        },
    ];
    match target {
        TargetVersion::Rhel8 => RHEL8,
        TargetVersion::Rhel9 => RHEL9,
        TargetVersion::Rhel10 => RHEL10,
    }
}

/// The typed [`ControlRef`]s a check for `family` should attach when running
/// against `target`: `id` = the STIG Rule id, `alias` = the DISA V-number
/// (mirrors the `sshd-W01`/`sshd-W02` `ControlRef::new(...).with_alias(...)`
/// convention in `rulesteward-sshd/src/lints/stig.rs`). Exactly one control per
/// family per target, so this always returns a single-element `Vec` for any
/// [`TargetVersion`] (never empty, never > 1 - `stig_controls` guarantees one
/// row per family per target).
#[must_use]
pub fn control_refs(family: ControlFamily, target: TargetVersion) -> Vec<ControlRef> {
    stig_controls(target)
        .iter()
        .filter(|c| c.family == family)
        .map(|c| ControlRef::new(Framework::Stig, c.stig_id).with_alias(c.v_number))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_core::Framework;

    fn find(rows: &[StigControl], family: ControlFamily) -> StigControl {
        *rows
            .iter()
            .find(|c| c.family == family)
            .unwrap_or_else(|| panic!("missing {family:?} row in {rows:?}"))
    }

    // ---------------------------------------------------------------------
    // Exact row content, grounded verbatim in G7/G8 (section 2 table).
    // ---------------------------------------------------------------------

    #[test]
    fn rhel8_rows_match_the_pinned_xccdf_exactly() {
        let rows = stig_controls(TargetVersion::Rhel8);
        assert_eq!(rows.len(), 3, "exactly 3 rows per target, got {rows:?}");
        for row in rows {
            assert_eq!(
                row.severity,
                StigSeverity::Medium,
                "all 9 fapolicyd rows are medium (G7/G8 section 2): {row:?}"
            );
        }

        let installed = find(rows, ControlFamily::Installed);
        assert_eq!(installed.stig_id, "RHEL-08-040135");
        assert_eq!(installed.v_number, "V-230523");
        assert_eq!(
            installed.title,
            "The RHEL 8 fapolicy module must be installed."
        );

        let enabled = find(rows, ControlFamily::Enabled);
        assert_eq!(enabled.stig_id, "RHEL-08-040136");
        assert_eq!(enabled.v_number, "V-244545");
        assert_eq!(enabled.title, "The RHEL 8 fapolicy module must be enabled.");

        let deny_all = find(rows, ControlFamily::DenyAll);
        assert_eq!(deny_all.stig_id, "RHEL-08-040137");
        assert_eq!(deny_all.v_number, "V-244546");
        assert_eq!(
            deny_all.title,
            "The RHEL 8 fapolicy module must be configured to employ a deny-all, \
             permit-by-exception policy to allow the execution of authorized \
             software programs."
        );
    }

    #[test]
    fn rhel9_rows_match_the_pinned_xccdf_exactly() {
        let rows = stig_controls(TargetVersion::Rhel9);
        assert_eq!(rows.len(), 3, "exactly 3 rows per target, got {rows:?}");

        let installed = find(rows, ControlFamily::Installed);
        assert_eq!(installed.stig_id, "RHEL-09-433010");
        assert_eq!(installed.v_number, "V-258089");
        assert_eq!(installed.title, "RHEL 9 fapolicy module must be installed.");

        let enabled = find(rows, ControlFamily::Enabled);
        assert_eq!(enabled.stig_id, "RHEL-09-433015");
        assert_eq!(enabled.v_number, "V-258090");
        assert_eq!(enabled.title, "RHEL 9 fapolicy module must be enabled.");

        let deny_all = find(rows, ControlFamily::DenyAll);
        assert_eq!(deny_all.stig_id, "RHEL-09-433016");
        assert_eq!(deny_all.v_number, "V-270180");
        assert_eq!(
            deny_all.title,
            "The RHEL 9 fapolicy module must be configured to employ a deny-all, \
             permit-by-exception policy to allow the execution of authorized \
             software programs."
        );
    }

    #[test]
    fn rhel10_rows_match_the_pinned_xccdf_exactly() {
        let rows = stig_controls(TargetVersion::Rhel10);
        assert_eq!(rows.len(), 3, "exactly 3 rows per target, got {rows:?}");

        let installed = find(rows, ControlFamily::Installed);
        assert_eq!(installed.stig_id, "RHEL-10-200600");
        assert_eq!(installed.v_number, "V-280969");
        assert_eq!(
            installed.title,
            "RHEL 10 must have the \"fapolicy\" module installed."
        );

        let enabled = find(rows, ControlFamily::Enabled);
        assert_eq!(enabled.stig_id, "RHEL-10-200601");
        assert_eq!(enabled.v_number, "V-280970");
        assert_eq!(
            enabled.title,
            "RHEL 10 must enable the \"fapolicy\" module."
        );

        let deny_all = find(rows, ControlFamily::DenyAll);
        assert_eq!(deny_all.stig_id, "RHEL-10-200602");
        assert_eq!(deny_all.v_number, "V-280971");
        assert_eq!(
            deny_all.title,
            "RHEL 10 must be configured to employ a deny-all, permit-by-exception \
             policy to allow the execution of authorized software programs."
        );
    }

    #[test]
    fn every_target_has_exactly_one_row_per_family() {
        // Adversarial pin: kills a wrong impl that returns 3 rows of the SAME
        // family (e.g. copy-paste-forgot-to-change-family), which would still
        // satisfy `rows.len() == 3` above but leave `find()` ambiguous/wrong.
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            let rows = stig_controls(target);
            for family in [
                ControlFamily::Installed,
                ControlFamily::Enabled,
                ControlFamily::DenyAll,
            ] {
                let matches = rows.iter().filter(|c| c.family == family).count();
                assert_eq!(
                    matches, 1,
                    "{family:?} must appear exactly once for {target:?}, got {matches} in {rows:?}"
                );
            }
        }
    }

    #[test]
    fn stig_ids_are_unique_within_a_target() {
        // A wrong impl that duplicates one row across two families (same
        // stig_id/v_number) would pass the per-family-count test above only if
        // the family tag itself were also duplicated; this catches the
        // sibling defect of a genuinely-duplicated id/alias pair.
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            let rows = stig_controls(target);
            let mut ids: Vec<&str> = rows.iter().map(|r| r.stig_id).collect();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(
                ids.len(),
                3,
                "stig_id must be unique within {target:?}, got {rows:?}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // control_refs projection
    // ---------------------------------------------------------------------

    #[test]
    fn control_refs_builds_stig_ref_with_id_and_alias() {
        for (target, family, expect_id, expect_alias) in [
            (
                TargetVersion::Rhel8,
                ControlFamily::Installed,
                "RHEL-08-040135",
                "V-230523",
            ),
            (
                TargetVersion::Rhel9,
                ControlFamily::Enabled,
                "RHEL-09-433015",
                "V-258090",
            ),
            (
                TargetVersion::Rhel10,
                ControlFamily::DenyAll,
                "RHEL-10-200602",
                "V-280971",
            ),
        ] {
            let refs = control_refs(family, target);
            assert_eq!(
                refs.len(),
                1,
                "exactly one control per family/target, got {refs:?}"
            );
            assert_eq!(refs[0].framework, Framework::Stig);
            assert_eq!(refs[0].id, expect_id);
            assert_eq!(refs[0].alias.as_deref(), Some(expect_alias));
        }
    }

    #[test]
    fn control_refs_differ_by_family_for_the_same_target() {
        // Kills a wrong impl that ignores `family` and always returns the
        // same row (e.g. always DenyAll) for a given target.
        let target = TargetVersion::Rhel9;
        let installed = control_refs(ControlFamily::Installed, target);
        let enabled = control_refs(ControlFamily::Enabled, target);
        let deny_all = control_refs(ControlFamily::DenyAll, target);
        assert_ne!(installed[0].id, enabled[0].id);
        assert_ne!(installed[0].id, deny_all[0].id);
        assert_ne!(enabled[0].id, deny_all[0].id);
    }

    #[test]
    fn control_refs_differ_by_target_for_the_same_family() {
        // Kills a wrong impl that ignores `target` and always returns the
        // same row for a given family.
        let family = ControlFamily::DenyAll;
        let r8 = control_refs(family, TargetVersion::Rhel8);
        let r9 = control_refs(family, TargetVersion::Rhel9);
        let r10 = control_refs(family, TargetVersion::Rhel10);
        assert_ne!(r8[0].id, r9[0].id);
        assert_ne!(r9[0].id, r10[0].id);
        assert_ne!(r8[0].id, r10[0].id);
    }
}
