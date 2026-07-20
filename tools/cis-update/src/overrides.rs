//! Targeted corrections for verbatim upstream artifacts in the pinned CaC CIS
//! controls files, applied immediately after parse on BOTH the check and derive
//! paths (via [`crate::controls::parse_corrected`]) so the derived output, the
//! drift gate, and the shipped per-backend tables always agree.
//!
//! Every entry cites the artifact at the pin. Application is IDEMPOTENT: a row
//! upstream has since fixed no-ops, so `check --latest` keeps working across an
//! upstream fix and the entry can be retired at the next pin bump.

use crate::controls::CisControl;

/// The correction an [`Override`] applies.
enum Fix {
    /// Strip a stray suffix glued to the end of the title (upstream copy
    /// artifact); no-op when the title does not end with it.
    StripTitleSuffix(&'static str),
    /// Replace a malformed control id (upstream typo); the match key is the
    /// UPSTREAM (pre-correction) id, so a fixed upstream row no longer matches.
    ReplaceId(&'static str),
}

/// One targeted correction, keyed by (product, upstream id) and GUARDED by a
/// mapped rule name so an upstream renumber can never mis-correct a different
/// control that later reuses the id.
struct Override {
    product: &'static str,
    /// The control id AS IT APPEARS UPSTREAM (pre-correction).
    id: &'static str,
    /// A rule the control must map for the fix to apply (identity guard).
    rule: &'static str,
    fix: Fix,
}

/// Grounded 2026-07-19 against `products/rhel8/controls/cis_rhel8.yml` at
/// 519b5fe8ce338cfa25d53065bcb3759aafe8d36d: line 2696's title ends
/// `(Automated)894` (stray benchmark footnote suffix), and line 2889's
/// `6.6.3.18` is the file's ONLY `6.6.x` id, sitting exactly where `6.3.3.18`
/// is missing between the present `6.3.3.17` and `6.3.3.19` - an upstream typo.
const OVERRIDES: [Override; 2] = [
    Override {
        product: "rhel8",
        id: "6.3.3.1",
        rule: "audit_rules_sysadmin_actions",
        fix: Fix::StripTitleSuffix("894"),
    },
    Override {
        product: "rhel8",
        id: "6.6.3.18",
        rule: "audit_rules_privileged_commands_usermod",
        fix: Fix::ReplaceId("6.3.3.18"),
    },
];

/// Apply every matching override for `product` in place. Rows that do not match
/// an entry's (product, id, rule) key - including rows upstream has since
/// fixed - are left untouched.
pub fn apply(product: &str, controls: &mut [CisControl]) {
    for ov in &OVERRIDES {
        if ov.product != product {
            continue;
        }
        for c in controls.iter_mut() {
            if c.id != ov.id || !c.rules.iter().any(|r| r == ov.rule) {
                continue;
            }
            match ov.fix {
                Fix::StripTitleSuffix(suffix) => {
                    if let Some(stripped) = c.title.strip_suffix(suffix) {
                        c.title = stripped.to_string();
                    }
                }
                Fix::ReplaceId(corrected) => c.id = corrected.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::apply;
    use crate::controls::{CisControl, Status, parse_corrected};

    fn control(id: &str, title: &str, rule: &str) -> CisControl {
        CisControl {
            id: id.to_string(),
            title: title.to_string(),
            levels: vec!["l2_server".to_string()],
            status: Status::Automated,
            rules: vec![rule.to_string()],
            selections: Vec::new(),
        }
    }

    const SYSADMIN_TITLE_UPSTREAM: &str =
        "Ensure changes to system administration scope (sudoers) is collected (Automated)894";
    const SYSADMIN_TITLE_FIXED: &str =
        "Ensure changes to system administration scope (sudoers) is collected (Automated)";

    fn artifact_rows() -> Vec<CisControl> {
        vec![
            control(
                "6.3.3.1",
                SYSADMIN_TITLE_UPSTREAM,
                "audit_rules_sysadmin_actions",
            ),
            control(
                "6.6.3.18",
                "Ensure successful and unsuccessful attempts to use the usermod command are collected (Automated)",
                "audit_rules_privileged_commands_usermod",
            ),
        ]
    }

    #[test]
    fn rhel8_sysadmin_actions_title_suffix_stripped() {
        let mut rows = artifact_rows();
        apply("rhel8", &mut rows);
        assert_eq!(rows[0].title, SYSADMIN_TITLE_FIXED);
        assert_eq!(rows[0].id, "6.3.3.1", "id untouched by the title fix");
    }

    #[test]
    fn rhel8_usermod_id_corrected() {
        let mut rows = artifact_rows();
        apply("rhel8", &mut rows);
        assert_eq!(rows[1].id, "6.3.3.18");
        assert!(
            rows[1].title.ends_with("(Automated)"),
            "title untouched by the id fix: {}",
            rows[1].title
        );
    }

    #[test]
    fn apply_is_idempotent_and_noops_on_fixed_upstream() {
        let mut rows = artifact_rows();
        apply("rhel8", &mut rows);
        let once = rows.clone();
        // Double application (and equivalently: an upstream that has already
        // fixed both artifacts) must change nothing.
        apply("rhel8", &mut rows);
        assert_eq!(rows, once);
    }

    #[test]
    fn other_products_are_untouched() {
        let mut rows = artifact_rows();
        apply("rhel9", &mut rows);
        assert_eq!(rows, artifact_rows());
    }

    #[test]
    fn rule_guard_blocks_a_reused_id_on_a_different_control() {
        // Same product + id, but the control maps a DIFFERENT rule: the guard
        // must block the fix (an upstream renumber could reuse the id).
        let mut rows = vec![control(
            "6.6.3.18",
            "Ensure some unrelated control (Automated)",
            "audit_rules_login_events_lastlog",
        )];
        apply("rhel8", &mut rows);
        assert_eq!(
            rows[0].id, "6.6.3.18",
            "guard mismatch leaves the row alone"
        );
    }

    /// The choke point main.rs uses: parse + overrides in one call.
    #[test]
    fn parse_corrected_applies_overrides_after_parse() {
        let fixture = format!(
            "policy: 'CIS Red Hat Enterprise Linux 8 Benchmark'\n\
             version: '4.0.0'\n\
             controls:\n\
             \x20   - id: 6.3.3.1\n\
             \x20     title: {SYSADMIN_TITLE_UPSTREAM}\n\
             \x20     levels:\n\
             \x20         - l2_server\n\
             \x20     status: automated\n\
             \x20     rules:\n\
             \x20         - audit_rules_sysadmin_actions\n\
             \x20   - id: 6.6.3.18\n\
             \x20     title: Ensure usermod attempts are collected (Automated)\n\
             \x20     levels:\n\
             \x20         - l2_server\n\
             \x20     status: automated\n\
             \x20     rules:\n\
             \x20         - audit_rules_privileged_commands_usermod\n"
        );
        let (_, controls) = parse_corrected("rhel8", &fixture).unwrap();
        assert_eq!(controls[0].title, SYSADMIN_TITLE_FIXED);
        assert_eq!(controls[1].id, "6.3.3.18");
    }
}
