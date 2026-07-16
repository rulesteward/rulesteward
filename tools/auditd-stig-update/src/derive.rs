//! The owned comparison shape ([`DerivedRule`]) plus the two sides fed to the
//! drift diff: the DISA-XCCDF-derived table (built in [`crate::xccdf`]) and the
//! shipped `rulesteward_auditd` projection ([`code_table`]).
//!
//! Unlike `tools/sshd-stig-update`'s `DerivedControl` (one row per sshd_config
//! DIRECTIVE, unique-keyword-per-Rule), one [`DerivedRule`] row is one REQUIRED
//! RULES.D LINE, not one requirement/Group: the grounding doc (P2, session
//! 7c-v0_6-wave3, Part B.5.8/C.5) proves a single audit key can legitimately be
//! shared by several DISTINCT DISA Rules (e.g. `identity` on 7 separate watch
//! requirements in rhel9), and a single requirement can require MULTIPLE lines
//! (an arch=b32/b64 pair, a 2x2 Cartesian product, or multiple watched paths) --
//! so there is no per-requirement key that stays unique across a whole product's
//! table. `v_number`/`stig_id` are carried per LINE (several lines can share the
//! same pair when they come from one multi-line requirement) so drift output and
//! au-W06 diagnostics can still name the owning STIG control.

use rulesteward_auditd::TargetVersion;
use rulesteward_auditd::lints::stig_required::stig_baseline;

/// One derived required-rule row: DISA's Group V-number, the RHEL STIG control
/// id, and the canonical required `rules.d` line text (auditd rules.d syntax,
/// extraction source = check-content per the grounding doc Part B.4). Diffed
/// as plain text against the shipped projection: two spellings that a real
/// rules.d file's PARSER would treat as equivalent (field order, `-k` vs
/// `-F key=`) are NOT folded here -- that folding is au-W06's MATCHER's job
/// (`crates/rulesteward-auditd/src/lints/stig_required.rs`), which compares a
/// real parsed ruleset against this same shipped table by parsing each side
/// via `rulesteward_auditd::parser`. This diff only asks "does the shipped
/// table's LITERAL text match what DISA's XCCDF currently says", so a
/// human-introduced re-ordering during a hand-paste would legitimately show as
/// drift here (a feature, not a bug: `derive`'s paste-ready output should be
/// pasted verbatim, not hand-edited).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DerivedRule {
    /// DISA `<Group id="V-NNNNNN">` (mirrors the sshd tool's `v_number`).
    pub v_number: String,
    /// The RHEL STIG control id (`RHEL-XX-NNNNNN`), shown in au-W06 messages.
    pub stig_id: String,
    /// The canonical required rules.d line, exactly as extracted from
    /// check-content (see [`crate::xccdf`]'s module doc for the selector/algorithm).
    pub line: String,
}

/// The shipped `rulesteward_auditd` au-W06 required-rules table for `target`,
/// projected into the comparison shape. This is the "code" side of the drift
/// diff. Infallible: the shipped table is `&'static str` data, not something
/// that can fail to project (unlike parsing a live/fixture XCCDF).
#[must_use]
pub fn code_table(target: TargetVersion) -> Vec<DerivedRule> {
    stig_baseline(target)
        .iter()
        .map(|e| DerivedRule {
            v_number: e.v_number.to_string(),
            stig_id: e.stig_id.to_string(),
            line: e.line.to_string(),
        })
        .collect()
}

/// Human-readable diff of an `upstream`-derived table against the shipped `code`
/// table. Every [`DerivedRule`] row (v_number/stig_id/line triple) is its own
/// identity (see the module doc: there is no narrower per-requirement key that
/// stays unique across a whole product), so this is a plain set difference, not
/// a keyed "changed" diff like the sshd tool's `diff_controls`. Empty result ==
/// no drift.
///
/// `-` a row in code but absent in the derived DISA set (DISA dropped/changed
/// it); `+` a row DISA now requires that the shipped table does not have yet.
#[must_use]
pub fn diff_rules(upstream: &[DerivedRule], code: &[DerivedRule]) -> Vec<String> {
    use std::collections::BTreeSet;

    let uset: BTreeSet<&DerivedRule> = upstream.iter().collect();
    let cset: BTreeSet<&DerivedRule> = code.iter().collect();

    let mut out = Vec::new();
    for row in cset.difference(&uset) {
        out.push(format!(
            "- {} ({}): {}  (in code, absent in the DISA XCCDF)",
            row.v_number, row.stig_id, row.line
        ));
    }
    for row in uset.difference(&cset) {
        out.push(format!(
            "+ {} ({}): {}  (new in the DISA XCCDF)",
            row.v_number, row.stig_id, row.line
        ));
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(v: &str, stig: &str, line: &str) -> DerivedRule {
        DerivedRule {
            v_number: v.to_string(),
            stig_id: stig.to_string(),
            line: line.to_string(),
        }
    }

    #[test]
    fn code_table_projects_the_populated_shipped_tables() {
        // The shipped RHEL*_REQUIRED tables are now populated (issue #474); this
        // is a parity pin on the PROJECTION MECHANISM, not a content oracle -- the
        // lengths mirror the frozen per-product line counts pinned by
        // `xccdf.rs`'s `rhelN_fixture_reproduces_code_table_exactly` /
        // `rhelN_known_answer_counts` tests, and each spot-check id is one this
        // test-author independently confirmed present in the shipped table.
        //
        // UPDATED (#523, session 9b-v0_8-wave2 lane 2e): counts bumped from
        // 61/67/75 to 62/69/77 (one new Control-shaped deepening entry on
        // RHEL8, two each on RHEL9/RHEL10 -- see `xccdf.rs`'s known-answer
        // tests for the full grounding). RED today.
        let rhel8 = code_table(TargetVersion::Rhel8);
        let rhel9 = code_table(TargetVersion::Rhel9);
        let rhel10 = code_table(TargetVersion::Rhel10);
        assert_eq!(rhel8.len(), 62, "{rhel8:?}");
        assert_eq!(rhel9.len(), 69, "{rhel9:?}");
        assert_eq!(rhel10.len(), 77, "{rhel10:?}");
        assert!(
            rhel8.iter().any(|r| r.stig_id == "RHEL-08-030000"),
            "{rhel8:?}"
        );
        assert!(
            rhel8.iter().any(|r| r.stig_id == "RHEL-08-030121"),
            "{rhel8:?}"
        );
        assert!(
            rhel9.iter().any(|r| r.stig_id == "RHEL-09-654010"),
            "{rhel9:?}"
        );
        assert!(
            rhel9.iter().any(|r| r.stig_id == "RHEL-09-654265"),
            "{rhel9:?}"
        );
        assert!(
            rhel9.iter().any(|r| r.stig_id == "RHEL-09-654275"),
            "{rhel9:?}"
        );
        assert!(
            rhel10.iter().any(|r| r.stig_id == "RHEL-10-500300"),
            "{rhel10:?}"
        );
        assert!(
            rhel10.iter().any(|r| r.stig_id == "RHEL-10-500035"),
            "{rhel10:?}"
        );
        assert!(
            rhel10.iter().any(|r| r.stig_id == "RHEL-10-900100"),
            "{rhel10:?}"
        );
    }

    #[test]
    fn diff_empty_when_identical() {
        let code = vec![row(
            "V-1",
            "RHEL-09-000010",
            "-w /etc/passwd -p wa -k identity",
        )];
        assert!(diff_rules(&code, &code).is_empty());
    }

    #[test]
    fn diff_reports_added_and_removed_rows() {
        let code = vec![
            row("V-1", "RHEL-09-000010", "-w /etc/passwd -p wa -k identity"),
            row("V-9", "RHEL-09-000090", "-w /etc/shadow -p wa -k identity"),
        ];
        let upstream = vec![
            // V-1 unchanged.
            row("V-1", "RHEL-09-000010", "-w /etc/passwd -p wa -k identity"),
            // V-9 dropped; V-2 is new.
            row("V-2", "RHEL-09-000020", "-w /etc/group -p wa -k identity"),
        ];
        let d = diff_rules(&upstream, &code);
        assert!(d.iter().any(|l| l.starts_with("- V-9")), "{d:?}");
        assert!(d.iter().any(|l| l.starts_with("+ V-2")), "{d:?}");
        assert!(!d.iter().any(|l| l.contains("V-1")), "{d:?}");
        assert_eq!(d.len(), 2, "V-1 unchanged must not appear: {d:?}");
    }

    #[test]
    fn diff_a_changed_line_on_the_same_v_number_shows_as_remove_plus_add() {
        // A row's LINE changing (same v_number/stig_id, different text) has no
        // narrower key than the whole row (module doc), so it surfaces as one
        // "-" (the old line) and one "+" (the new line), not a "~ changed" line.
        let code = vec![row(
            "V-1",
            "RHEL-09-000010",
            "-w /etc/passwd -p wa -k identity",
        )];
        let upstream = vec![row(
            "V-1",
            "RHEL-09-000010",
            "-w /etc/passwd -p rwa -k identity",
        )];
        let d = diff_rules(&upstream, &code);
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(
            d.iter()
                .any(|l| l.starts_with("- V-1") && l.contains("-p wa"))
        );
        assert!(
            d.iter()
                .any(|l| l.starts_with("+ V-1") && l.contains("-p rwa"))
        );
    }

    #[test]
    fn diff_multiple_rows_sharing_one_v_number_and_stig_id_are_independent() {
        // Grounding B.5.1/C.5: a b32/b64 pair shares one V-number; removing ONLY
        // the b64 half must surface exactly one "-" line, not two, and must not
        // touch the untouched b32 half.
        let code = vec![
            row(
                "V-1",
                "RHEL-09-654015",
                "-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=-1 -F key=perm_mod",
            ),
            row(
                "V-1",
                "RHEL-09-654015",
                "-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=-1 -F key=perm_mod",
            ),
        ];
        let upstream = vec![code[0].clone()]; // b64 line dropped upstream
        let d = diff_rules(&upstream, &code);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].starts_with("- V-1") && d[0].contains("arch=b64"));
    }
}
