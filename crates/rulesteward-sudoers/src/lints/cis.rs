//! Per-product CIS Benchmark control table for the sudoers family (#526, v0.8
//! Wave 3 lane 3b). Mirrors the `TargetVersion` / `pub fn X_baseline` shape
//! established by `rulesteward_sysctld::lints::baseline` (sysctld-W02) and
//! `rulesteward_sshd::lints::stig` (`TargetVersion` in `lints::mod`), so each
//! domain crate stays clap-free (the CLI maps its `--target` value-enum into
//! this via a `From` impl at the wiring site, orchestrator-owned, not this
//! lane).
//!
//! This is the backend's FIRST `pub cis_baseline`-style accessor: the smallest
//! of the four Wave-3 CIS lanes (5 controls, uniform across all three
//! products), and the single source [`crate::lints::stig`]'s two pre-existing
//! `Framework::Cis` `ControlRef`s (the `use_pty` / I/O-logging citations) draw
//! their renumbered ids and CaC titles from -- see the RENUMBER note below.
//!
//! # Grounding
//!
//! Transcribed VERBATIM from `tools/cis-update derive` at
//! ComplianceAsCode/content pin `519b5fe8ce338cfa25d53065bcb3759aafe8d36d`
//! (`cis-refs.toml`). Per product: 5 controls / 5 rule mappings / 0
//! selections. Ids and CaC rule-name mappings are IDENTICAL across rhel8 (CIS
//! v4.0.0) / rhel9 (CIS v2.0.0) / rhel10 (CIS v1.0.1); only the 5.2.6 TITLE
//! text diverges (rhel8/rhel10 share one phrasing, rhel9 uses different
//! wording for the same id + rule mapping).
//!
//! # License discipline
//!
//! Ids + CaC titles ONLY (verbatim, including the upstream `"(Automated)"`
//! suffix -- matches `tools/cis-update`'s own `CisControl::title` field
//! convention: "CaC-carried title, verbatim"). NEVER CIS benchmark prose.
//!
//! # Anchor renumber (#526, LOCKED post-A0 2026-07-18)
//!
//! `lints::stig`'s two PRE-EXISTING `Framework::Cis` refs cited the stale
//! `"1.3.2"` / `"1.3.3"` ids -- an older CIS benchmark generation's
//! numbering, surviving in ComplianceAsCode only as `cis@sle12` / `cis@sle15`
//! rule references. The pinned-commit ground truth (this module) is
//! `sudo_add_use_pty` -> `"5.2.2"`, `sudo_custom_logfile` -> `"5.2.3"`,
//! uniform across all three products. `lints::stig`'s renumbered refs also
//! gain the CaC title via `.with_name(..)` (an output change, test-pinned in
//! `lints::stig`'s test module).
//!
//! Only TWO of the five controls in this table (5.2.2 / 5.2.3) are wired into
//! a live `Diagnostic` today; 5.2.4 / 5.2.5 / 5.2.6 exist here for table
//! completeness (this accessor is the drift-check source of truth
//! `tools/cis-update` compares against the full upstream family) even though
//! no `sudo-` finding attaches them yet.

// "CaC" (ComplianceAsCode) and "use_pty" appear as plain terms throughout this
// module's docs; wrapping every mention in backticks would bury the signal.
#![allow(clippy::doc_markdown)]

/// RHEL release whose CIS control table to select. Clap-free (mirrors
/// `rulesteward_sysctld::lints::baseline::TargetVersion` /
/// `rulesteward_sshd::lints::mod::TargetVersion`) so this crate stays
/// clap-free too.
///
/// This is the sudoers crate's FIRST `TargetVersion` (the sudo-W04 STIG
/// findings are version-agnostic, per `lints::mod`'s module doc, so no prior
/// `--target` rail existed). Defined here (this module is the sole consumer
/// today) and re-exported at `lints::TargetVersion` + the crate root
/// (`lib.rs`), matching the auditd (`stig_required.rs:46` ->
/// `lints::mod::TargetVersion`) / sysctld (`baseline.rs:35` ->
/// `lints::mod::TargetVersion`) convention -- never buried under
/// `lints::cis::TargetVersion` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetVersion {
    Rhel8,
    Rhel9,
    Rhel10,
}

/// A stable, public view of one CIS control entry: id, verbatim CaC title,
/// and the ComplianceAsCode rule name it maps to (`rules:` in the upstream
/// controls file). Exists so external tooling (`tools/cis-update`'s drift
/// checker) can diff the shipped table against ComplianceAsCode by IMPORTING
/// it, instead of parsing this source file -- mirrors
/// `rulesteward_sysctld::lints::baseline::StigEntry`.
///
/// Named `CisControl` (not `CisEntry`) per the barrier dedup reconciliation
/// (#524 arbiter ruling, round 3): the entry-struct name is standardized as
/// `CisControl` across all four Wave-3 CIS lanes (the struct itself stays
/// per-crate; only the name unifies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CisControl {
    /// The CIS control id (e.g. `"5.2.2"`).
    pub id: &'static str,
    /// The CaC-carried title, verbatim (includes the upstream `"(Automated)"`
    /// suffix).
    pub title: &'static str,
    /// The ComplianceAsCode rule name this control maps to (e.g.
    /// `"sudo_add_use_pty"`).
    pub rule: &'static str,
}

/// The grounded CIS control table for `target`: the 5 sudoers-family
/// controls (5.2.2-5.2.6), in ascending-id order. See the module doc for the
/// grounding pin and the renumber this table backs.
///
/// Returns a static slice (not `Vec`), per the barrier dedup reconciliation
/// (#524 arbiter ruling, round 3): accessor symmetry with the sibling
/// backends' `pub fn X_baseline(target) -> &'static [Y]` shape (e.g.
/// `rulesteward_auditd::lints::cis::cis_baseline`).
#[must_use]
pub fn cis_baseline(_target: TargetVersion) -> &'static [CisControl] {
    todo!("cis-3b (#526): per-product CIS control table, see module doc")
}

#[cfg(test)]
mod tests {
    use super::{CisControl, TargetVersion, cis_baseline};

    const ALL_TARGETS: [TargetVersion; 3] = [
        TargetVersion::Rhel8,
        TargetVersion::Rhel9,
        TargetVersion::Rhel10,
    ];

    /// The 5 grounded CIS anchor ids, in ascending order, IDENTICAL across all
    /// three products (`tools/cis-update derive` at ComplianceAsCode/content
    /// pin `519b5fe8ce338cfa25d53065bcb3759aafe8d36d`; #526 A0 grounding: "5
    /// controls, 5 rule mappings, 0 selections", uniform).
    const ANCHOR_IDS: [&str; 5] = ["5.2.2", "5.2.3", "5.2.4", "5.2.5", "5.2.6"];

    /// The grounded CaC rule name each anchor id maps to, in the SAME order as
    /// [`ANCHOR_IDS`] (position-paired) -- UNIFORM across all three products.
    const ANCHOR_RULES: [&str; 5] = [
        "sudo_add_use_pty",
        "sudo_custom_logfile",
        "sudo_remove_nopasswd",
        "sudo_remove_no_authenticate",
        "sudo_require_reauthentication",
    ];

    fn ids(entries: &[CisControl]) -> Vec<&str> {
        entries.iter().map(|e| e.id).collect()
    }

    fn rules(entries: &[CisControl]) -> Vec<&str> {
        entries.iter().map(|e| e.rule).collect()
    }

    /// Each of the three products carries EXACTLY the 5 grounded controls, in
    /// ascending-id order (matching the project-wide sorted-catalog
    /// convention, e.g. `lints::catalog::SUDO_CODES`), with the SAME
    /// id<->rule pairing. A wrong impl that drops, reorders, or duplicates a
    /// row fails this test; `assert_eq!` on the full positional vectors is
    /// what makes the id<->rule PAIRING (not just membership) load-bearing.
    #[test]
    fn cis_baseline_carries_all_five_grounded_anchors_per_product() {
        for target in ALL_TARGETS {
            let entries = cis_baseline(target);
            assert_eq!(
                ids(entries),
                ANCHOR_IDS.to_vec(),
                "{target:?} must carry exactly the 5 grounded ids in ascending order; \
                 got {entries:?}"
            );
            assert_eq!(
                rules(entries),
                ANCHOR_RULES.to_vec(),
                "{target:?}'s rule-name mapping must match the grounded (id, rule) \
                 pairing (same position as ANCHOR_IDS); got {entries:?}"
            );
        }
    }

    /// The two LOCKED anchor pairs the sudo-W04 renumber (#526, LOCKED post-A0
    /// 2026-07-18) draws from: `sudo_add_use_pty` -> `"5.2.2"`,
    /// `sudo_custom_logfile` -> `"5.2.3"`. This is the pinned-CaC ground truth
    /// that supersedes the STALE `"1.3.2"`/`"1.3.3"` issue-#526 text and the
    /// pre-existing `sudo-W04` hardcoded ids. Order-independent (`.find` by
    /// rule name) so it stays meaningful even if `cis_baseline`'s return
    /// order ever changes for an unrelated reason.
    #[test]
    fn locked_anchor_pair_use_pty_and_logfile() {
        for target in ALL_TARGETS {
            let entries = cis_baseline(target);
            let use_pty = entries
                .iter()
                .find(|e| e.rule == "sudo_add_use_pty")
                .unwrap_or_else(|| panic!("{target:?} table must contain sudo_add_use_pty"));
            assert_eq!(
                use_pty.id, "5.2.2",
                "{target:?}: sudo_add_use_pty must anchor at 5.2.2"
            );
            let logfile = entries
                .iter()
                .find(|e| e.rule == "sudo_custom_logfile")
                .unwrap_or_else(|| panic!("{target:?} table must contain sudo_custom_logfile"));
            assert_eq!(
                logfile.id, "5.2.3",
                "{target:?}: sudo_custom_logfile must anchor at 5.2.3"
            );
        }
    }

    /// The 5.2.2 / 5.2.3 titles `lints::stig`'s renumber actually attaches via
    /// `.with_name(..)` are VERBATIM CaC text (upstream `"(Automated)"` suffix
    /// included, matching `tools/cis-update`'s own `CisControl::title`
    /// convention) and are PRODUCT-INVARIANT (byte-identical across rhel8 /
    /// rhel9 / rhel10 in the grounding derive) -- `lints::stig` can draw
    /// either title from this table without needing a per-target selection.
    #[test]
    fn use_pty_and_logfile_titles_are_verbatim_and_product_invariant() {
        for target in ALL_TARGETS {
            let entries = cis_baseline(target);
            let use_pty = entries
                .iter()
                .find(|e| e.id == "5.2.2")
                .unwrap_or_else(|| panic!("{target:?} table must contain 5.2.2"));
            assert_eq!(use_pty.title, "Ensure sudo commands use pty (Automated)");
            let logfile = entries
                .iter()
                .find(|e| e.id == "5.2.3")
                .unwrap_or_else(|| panic!("{target:?} table must contain 5.2.3"));
            assert_eq!(logfile.title, "Ensure sudo log file exists (Automated)");
        }
    }

    /// 5.2.4 (`sudo_remove_nopasswd`) and 5.2.5 (`sudo_remove_no_authenticate`)
    /// titles: verbatim CaC text, PRODUCT-INVARIANT (the grounding derive
    /// shows byte-identical text for these two ids across all three
    /// products). Neither is wired into a live `Diagnostic` yet (see module
    /// doc); this test pins the TABLE data independent of that.
    #[test]
    fn nopasswd_and_no_authenticate_titles_are_verbatim_and_product_invariant() {
        for target in ALL_TARGETS {
            let entries = cis_baseline(target);
            let nopasswd = entries
                .iter()
                .find(|e| e.id == "5.2.4")
                .unwrap_or_else(|| panic!("{target:?} table must contain 5.2.4"));
            assert_eq!(
                nopasswd.title,
                "Ensure users must provide password for escalation (Automated)"
            );
            let no_auth = entries
                .iter()
                .find(|e| e.id == "5.2.5")
                .unwrap_or_else(|| panic!("{target:?} table must contain 5.2.5"));
            assert_eq!(
                no_auth.title,
                "Ensure re-authentication for privilege escalation is not disabled \
                 globally (Automated)"
            );
        }
    }

    /// 5.2.6 (`sudo_require_reauthentication`) is the ONE control whose title
    /// DIVERGES by product (#526 grounding): rhel8 (CIS v4.0.0) and rhel10
    /// (CIS v1.0.1) share one phrasing; rhel9 (CIS v2.0.0) uses different
    /// wording for the SAME id + rule mapping. A wrong impl that reuses one
    /// title string for every product would pass a single-target title check
    /// but fail this cross-product comparison.
    #[test]
    fn timestamp_timeout_title_diverges_on_rhel9_only() {
        let title_for = |target: TargetVersion| -> String {
            cis_baseline(target)
                .iter()
                .find(|e| e.id == "5.2.6")
                .unwrap_or_else(|| panic!("{target:?} table must contain 5.2.6"))
                .title
                .to_string()
        };

        let rhel8_title = title_for(TargetVersion::Rhel8);
        let rhel9_title = title_for(TargetVersion::Rhel9);
        let rhel10_title = title_for(TargetVersion::Rhel10);

        assert_eq!(
            rhel8_title, "Ensure sudo timestamp_timeout is configured (Automated)",
            "rhel8's 5.2.6 title"
        );
        assert_eq!(
            rhel10_title, rhel8_title,
            "rhel10 shares rhel8's 5.2.6 title (both differ from rhel9)"
        );
        assert_eq!(
            rhel9_title, "Ensure sudo authentication timeout is configured correctly (Automated)",
            "rhel9's 5.2.6 title text diverges from rhel8/rhel10 -- same id, same rule, \
             different CaC wording"
        );
        assert_ne!(
            rhel8_title, rhel9_title,
            "the rhel8/rhel9 5.2.6 titles must NOT collapse to the same string"
        );
    }
}
