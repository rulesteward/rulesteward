//! The owned comparison shape ([`DerivedControl`]) plus the two sides fed to
//! the drift diff: the DISA-XCCDF-derived, family-classified table (built in
//! [`crate::xccdf`]) and the shipped `rulesteward_selinux::stig` projection
//! ([`code_table`]).
//!
//! Unlike `tools/auditd-stig-update`'s `DerivedRule` (one row per required
//! `rules.d` LINE), one [`DerivedControl`] row is one (family, target)
//! REQUIREMENT: the selinux STIG surface this crate maps is a small, fixed set
//! of 5 control families (`Enforcing`/`PolicyType`/`Policycoreutils`/
//! `PolicycoreutilsPython`/`FaillockDirContext`), each with at most a
//! handful of rows per RHEL product (`FaillockDirContext` carries two at
//! `rhel8`). `Family` mirrors `rulesteward_selinux::stig::ControlFamily`
//! locally so this comparison shape can derive `Ord` (needed for the
//! set-based diff below); `ControlFamily` itself does not derive `Ord`.

use rulesteward_selinux::TargetVersion;
use rulesteward_selinux::stig::{ControlFamily, control_refs};

/// Local mirror of `rulesteward_selinux::stig::ControlFamily`, with `Ord`
/// derived so [`DerivedControl`] can be diffed via a `BTreeSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    Enforcing,
    PolicyType,
    Policycoreutils,
    PolicycoreutilsPython,
    FaillockDirContext,
}

impl Family {
    /// Every family, in a fixed order (used to build [`code_table`]).
    const ALL: [Family; 5] = [
        Family::Enforcing,
        Family::PolicyType,
        Family::Policycoreutils,
        Family::PolicycoreutilsPython,
        Family::FaillockDirContext,
    ];

    /// Project this local mirror onto the crate's own `ControlFamily`.
    #[must_use]
    pub fn to_domain(self) -> ControlFamily {
        match self {
            Family::Enforcing => ControlFamily::Enforcing,
            Family::PolicyType => ControlFamily::PolicyType,
            Family::Policycoreutils => ControlFamily::Policycoreutils,
            Family::PolicycoreutilsPython => ControlFamily::PolicycoreutilsPython,
            Family::FaillockDirContext => ControlFamily::FaillockDirContext,
        }
    }
}

/// One derived control row: which family it belongs to, DISA's Group
/// V-number, and the RHEL STIG control id. Diffed as a plain set against the
/// shipped projection: there is no narrower per-family key that stays unique
/// across a whole product's table (`FaillockDirContext` legitimately carries
/// two rows at `rhel8`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DerivedControl {
    pub family: Family,
    /// DISA `<Group id="V-NNNNNN">` (the alias in `stig.rs`'s `ControlRef`).
    pub v_number: String,
    /// The RHEL STIG control id (`RHEL-XX-NNNNNN`, the canonical `ControlRef::id`).
    pub stig_id: String,
}

/// The shipped `rulesteward_selinux::stig` control table for `target`,
/// projected into the comparison shape. This is the "code" side of the drift
/// diff. Infallible: the shipped table is match-arm data, not something that
/// can fail to project (unlike parsing a live/fixture XCCDF).
#[must_use]
pub fn code_table(target: TargetVersion) -> Vec<DerivedControl> {
    Family::ALL
        .iter()
        .flat_map(|&family| {
            control_refs(family.to_domain(), target)
                .into_iter()
                .map(move |r| DerivedControl {
                    family,
                    v_number: r.alias.unwrap_or_default(),
                    stig_id: r.id,
                })
        })
        .collect()
}

/// Human-readable diff of an `upstream`-derived table against the shipped
/// `code` table. Every [`DerivedControl`] row (family/v_number/stig_id
/// triple) is its own identity, so this is a plain set difference, not a
/// keyed "changed" diff. Empty result == no drift.
///
/// `-` a row in code but absent in the derived DISA set (DISA dropped/changed
/// it); `+` a row DISA now requires that the shipped table does not have yet.
#[must_use]
pub fn diff_controls(upstream: &[DerivedControl], code: &[DerivedControl]) -> Vec<String> {
    use std::collections::BTreeSet;

    let uset: BTreeSet<&DerivedControl> = upstream.iter().collect();
    let cset: BTreeSet<&DerivedControl> = code.iter().collect();

    let mut out = Vec::new();
    for row in cset.difference(&uset) {
        out.push(format!(
            "- {:?} {} ({})  (in code, absent in the DISA XCCDF)",
            row.family, row.v_number, row.stig_id
        ));
    }
    for row in uset.difference(&cset) {
        out.push(format!(
            "+ {:?} {} ({})  (new in the DISA XCCDF)",
            row.family, row.v_number, row.stig_id
        ));
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(family: Family, v: &str, stig: &str) -> DerivedControl {
        DerivedControl {
            family,
            v_number: v.to_string(),
            stig_id: stig.to_string(),
        }
    }

    #[test]
    fn code_table_projects_the_shipped_table_exactly() {
        // Parity pin on the PROJECTION MECHANISM: rhel9 has one row per
        // family (5 total); rhel8 also has 5 (FaillockDirContext carries
        // two, but PolicycoreutilsPython has none, netting out the same).
        let rhel9 = code_table(TargetVersion::Rhel9);
        assert_eq!(rhel9.len(), 5, "{rhel9:?}");
        assert!(
            rhel9
                .iter()
                .any(|r| r.family == Family::Enforcing && r.stig_id == "RHEL-09-431010")
        );

        let rhel8 = code_table(TargetVersion::Rhel8);
        assert_eq!(rhel8.len(), 5, "{rhel8:?}");
        assert!(
            !rhel8
                .iter()
                .any(|r| r.family == Family::PolicycoreutilsPython),
            "RHEL 8 has no policycoreutils-python-utils control (G7): {rhel8:?}"
        );
        assert_eq!(
            rhel8
                .iter()
                .filter(|r| r.family == Family::FaillockDirContext)
                .count(),
            2,
            "RHEL 8 carries both faillock variants: {rhel8:?}"
        );
    }

    #[test]
    fn diff_empty_when_identical() {
        let code = vec![row(Family::Enforcing, "V-1", "RHEL-09-000010")];
        assert!(diff_controls(&code, &code).is_empty());
    }

    #[test]
    fn diff_reports_added_and_removed_rows() {
        let code = vec![
            row(Family::Enforcing, "V-1", "RHEL-09-000010"),
            row(Family::PolicyType, "V-9", "RHEL-09-000090"),
        ];
        let upstream = vec![
            row(Family::Enforcing, "V-1", "RHEL-09-000010"),
            row(Family::Policycoreutils, "V-2", "RHEL-09-000020"),
        ];
        let d = diff_controls(&upstream, &code);
        assert!(d.iter().any(|l| l.starts_with("- PolicyType V-9")), "{d:?}");
        assert!(
            d.iter().any(|l| l.starts_with("+ Policycoreutils V-2")),
            "{d:?}"
        );
        assert_eq!(d.len(), 2, "V-1 unchanged must not appear: {d:?}");
    }
}
