//! The owned comparison shape ([`DerivedControl`]) plus the two sides fed to
//! the drift diff: the DISA-XCCDF-derived table (built in [`crate::xccdf`])
//! and the shipped `rulesteward_fapolicyd` STIG-control projection
//! ([`code_table`]).
//!
//! Unlike `tools/auditd-stig-update`'s `DerivedRule` (one row per REQUIRED
//! RULES.D LINE, since one audit requirement can span several config lines),
//! one [`DerivedControl`] row here is one REQUIREMENT/Group: #519's fapolicyd
//! table has exactly 3 rows per RHEL target
//! (`ControlFamily::{Installed,Enabled,DenyAll}`, one per family), and each
//! DISA Group maps to exactly one family.

use rulesteward_fapolicyd::TargetVersion;
use rulesteward_fapolicyd::lints::stig::{ControlFamily, stig_controls};

/// One derived fapolicyd STIG control: which family it belongs to, DISA's
/// Group V-number, and the RHEL STIG control id. Diffed as a plain set
/// (see [`diff_controls`]): with only 3 rows per product there is no need
/// for a narrower per-requirement key or an `Ord` impl on [`ControlFamily`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedControl {
    /// Which of the 3 host-state families this control maps to.
    pub family: ControlFamily,
    /// DISA `<Group id="V-NNNNNN">`.
    pub v_number: String,
    /// The RHEL STIG control id (`RHEL-XX-NNNNNN`).
    pub stig_id: String,
}

/// The shipped `rulesteward_fapolicyd` STIG control table for `target`,
/// projected into the comparison shape. This is the "code" side of the drift
/// diff. Infallible: the shipped table is `&'static str` data.
#[must_use]
pub fn code_table(target: TargetVersion) -> Vec<DerivedControl> {
    stig_controls(target)
        .iter()
        .map(|c| DerivedControl {
            family: c.family,
            v_number: c.v_number.to_string(),
            stig_id: c.stig_id.to_string(),
        })
        .collect()
}

/// Human-readable diff of an `upstream`-derived table against the shipped
/// `code` table. A plain linear set difference (small n per product, so no
/// `BTreeSet`/`Ord` needed): `-` a row in code but absent in the derived DISA
/// set (DISA dropped/changed it); `+` a row DISA now requires that the
/// shipped table does not have yet. Empty result == no drift.
#[must_use]
pub fn diff_controls(upstream: &[DerivedControl], code: &[DerivedControl]) -> Vec<String> {
    let mut out = Vec::new();
    for row in code {
        if !upstream.contains(row) {
            out.push(format!(
                "- {:?} {} ({})  (in code, absent in the DISA XCCDF)",
                row.family, row.v_number, row.stig_id
            ));
        }
    }
    for row in upstream {
        if !code.contains(row) {
            out.push(format!(
                "+ {:?} {} ({})  (new in the DISA XCCDF)",
                row.family, row.v_number, row.stig_id
            ));
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(family: ControlFamily, v: &str, stig: &str) -> DerivedControl {
        DerivedControl {
            family,
            v_number: v.to_string(),
            stig_id: stig.to_string(),
        }
    }

    #[test]
    fn code_table_projects_exactly_three_rows_per_target() {
        for target in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            let rows = code_table(target);
            assert_eq!(rows.len(), 3, "{target:?}: {rows:?}");
        }
    }

    #[test]
    fn code_table_rhel9_matches_the_shipped_table_content() {
        let rows = code_table(TargetVersion::Rhel9);
        assert!(
            rows.iter()
                .any(|r| r.family == ControlFamily::DenyAll && r.stig_id == "RHEL-09-433016")
        );
    }

    #[test]
    fn diff_empty_when_identical() {
        let code = vec![row(ControlFamily::Installed, "V-1", "RHEL-09-000010")];
        assert!(diff_controls(&code, &code).is_empty());
    }

    #[test]
    fn diff_reports_added_and_removed_rows() {
        let code = vec![
            row(ControlFamily::Installed, "V-1", "RHEL-09-000010"),
            row(ControlFamily::Enabled, "V-2", "RHEL-09-000020"),
        ];
        let upstream = vec![
            row(ControlFamily::Installed, "V-1", "RHEL-09-000010"),
            row(ControlFamily::DenyAll, "V-3", "RHEL-09-000030"),
        ];
        let d = diff_controls(&upstream, &code);
        assert!(d.iter().any(|l| l.starts_with("- ") && l.contains("V-2")));
        assert!(d.iter().any(|l| l.starts_with("+ ") && l.contains("V-3")));
        assert_eq!(d.len(), 2, "{d:?}");
    }

    #[test]
    fn diff_a_changed_family_on_the_same_v_number_shows_as_remove_plus_add() {
        // Same v_number/stig_id but a different family has no narrower key
        // than the whole row, so it surfaces as one "-" and one "+".
        let code = vec![row(ControlFamily::Enabled, "V-1", "RHEL-09-000010")];
        let upstream = vec![row(ControlFamily::Installed, "V-1", "RHEL-09-000010")];
        let d = diff_controls(&upstream, &code);
        assert_eq!(d.len(), 2, "{d:?}");
    }
}
