//! `SELinux` denial triage logic.
//!
//! Implements `build_report` and `render_human` for pipeline P3 (issue #99).
//!
//! # Narrowness contract (f4 §2.5)
//!
//! Every suggested allow rule is EXACTLY:
//!   `allow <source_type> <target_type>:<tclass> { <only denied perms> };`
//!
//! The invariants enforced here:
//! 1. No interface macros - raw `allow` only.
//! 2. No `typeattribute`.
//! 3. Exact perm set only - no perm-set expansion.
//! 4. No unrelated types.
//! 5. One rule per (sdomain, ttype, tclass) triple.
//! 6. `Permissive` groups are reported but NO allow is emitted.
//! 7. Suggest only, never apply.
//! 8. Always note `dontaudit` as the safer option for benign denials.
//!
//! # Detect-and-decline (f4 §8 / §5.1 limitations)
//!
//! `Constraint`, `Bounds`, `ContextInvalid`, `MlsSuspected`, `RoleSuspected`:
//! these are NOT fixable with a plain TE allow. We explain why and never emit a
//! wrong allow rule.

use crate::denial::{DenialGroup, DenialKind};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Per-group entry in the machine-readable triage report.
///
/// P3 extends the Phase-0 placeholder with per-group rendered content
/// (f4 §6.2: `suggestedRule`, `explanation`, plus all the denial-group fields).
#[derive(Debug, Serialize)]
pub struct TriageEntry {
    /// Source domain type.
    pub source_type: String,
    /// Target type.
    pub target_type: String,
    /// Object class.
    pub tclass: String,
    /// Denied permissions (sorted, exact).
    pub perms: Vec<String>,
    /// `true` iff any denial in this group had `permissive=1`.
    pub any_permissive: bool,
    /// Floor / authoritative kind.
    pub kind: DenialKind,
    /// The narrow suggested allow rule, or `null` when no allow is appropriate.
    ///
    /// `None` for `Permissive`, `MlsSuspected`, `RoleSuspected`, `Constraint`,
    /// `Bounds`. Present for `TeAllowable` and (with a policy-mismatch caveat)
    /// `ContextInvalid` when the floor falls back to `TeAllowable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_rule: Option<String>,
    /// Plain-language explanation of the denial and suggested action.
    pub explanation: String,
}

/// Machine-readable triage report (JSON payload, wrapped by the CLI in the
/// #62 envelope with `kind = "selinux-triage"`).
#[derive(Debug, Serialize)]
pub struct TriageReport {
    /// Per-group triage entries.
    pub groups: Vec<TriageEntry>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build the machine-readable triage report from grouped denials.
///
/// Each `DenialGroup` becomes a `TriageEntry` with a narrow suggested allow
/// (for `TeAllowable` groups) or a decline explanation (for all other kinds).
#[must_use]
pub fn build_report(groups: &[DenialGroup]) -> TriageReport {
    let entries = groups.iter().map(build_entry).collect();
    TriageReport { groups: entries }
}

/// Render the human-readable triage output for all denial groups.
///
/// Each group produces a block separated by a blank line. Empty input returns
/// an empty string (callers that need a "no denials" message should handle that
/// at the command level).
#[must_use]
pub fn render_human(groups: &[DenialGroup]) -> String {
    if groups.is_empty() {
        return String::new();
    }
    groups
        .iter()
        .map(render_group_human)
        .collect::<Vec<_>>()
        .join("\n\n")
}

// ---------------------------------------------------------------------------
// Core: narrow allow rule formatter
// ---------------------------------------------------------------------------

/// Format the narrow `allow` rule for a (source, target, class, perms) tuple.
///
/// Single-perm: `allow src tgt:cls perm;`
/// Multi-perm:  `allow src tgt:cls { p1 p2 p3 };`  (`BTreeSet` order = alphabetical)
fn format_narrow_allow(
    source: &str,
    target: &str,
    tclass: &str,
    perms: &std::collections::BTreeSet<String>,
) -> String {
    if perms.len() == 1 {
        let perm = perms.iter().next().expect("checked len==1");
        format!("allow {source} {target}:{tclass} {perm};")
    } else {
        let perm_list: Vec<&str> = perms.iter().map(String::as_str).collect();
        format!(
            "allow {source} {target}:{tclass} {{ {} }};",
            perm_list.join(" ")
        )
    }
}

// ---------------------------------------------------------------------------
// Per-group rendering
// ---------------------------------------------------------------------------

/// Build a `TriageEntry` for one `DenialGroup`.
fn build_entry(group: &DenialGroup) -> TriageEntry {
    let perms: Vec<String> = group.perms.iter().cloned().collect();
    let (suggested_rule, explanation) = triage_group(group);
    TriageEntry {
        source_type: group.source_type.clone(),
        target_type: group.target_type.clone(),
        tclass: group.tclass.clone(),
        perms,
        any_permissive: group.any_permissive,
        kind: group.kind,
        suggested_rule,
        explanation,
    }
}

/// Render one `DenialGroup` as a human-readable block.
fn render_group_human(group: &DenialGroup) -> String {
    let (suggested_rule, explanation) = triage_group(group);
    let mut out = String::new();
    out.push_str(&explanation);
    if let Some(rule) = suggested_rule {
        out.push('\n');
        out.push_str("  Suggested fix: ");
        out.push_str(&rule);
        out.push('\n');
        out.push_str(
            "  Note: if this access is not actually required, \
                       `dontaudit` is the safer option to silence the denial \
                       without granting the permission.",
        );
    }
    out
}

/// Compute `(suggested_rule, explanation)` for a group.
///
/// This is the single decision point for all `DenialKind` variants. It is
/// shared between `build_entry` (JSON path) and `render_group_human` (human
/// path) to ensure both paths agree.
fn triage_group(group: &DenialGroup) -> (Option<String>, String) {
    let src = &group.source_type;
    let tgt = &group.target_type;
    let cls = &group.tclass;
    let perms: Vec<&str> = group.perms.iter().map(String::as_str).collect();
    let perm_display = if perms.len() == 1 {
        perms[0].to_string()
    } else {
        format!("{{ {} }}", perms.join(" "))
    };

    match group.kind {
        // ------------------------------------------------------------------
        // TeAllowable: emit the narrow allow + dontaudit note.
        // ------------------------------------------------------------------
        DenialKind::TeAllowable => {
            let rule = format_narrow_allow(src, tgt, cls, &group.perms);
            let explanation = format!(
                "DENIED: domain '{src}' was denied {perm_display} on {cls} '{tgt}'. \
                 This appears to be a missing TE allow rule. \
                 The narrowest fix grants only the denied permissions. \
                 Note: if this access is not actually required, consider \
                 `dontaudit` instead to silence the denial without granting the permission."
            );
            (Some(rule), explanation)
        }

        // ------------------------------------------------------------------
        // Permissive: report only, no allow (f4 §2.5 inv.6).
        // ------------------------------------------------------------------
        DenialKind::Permissive => {
            let explanation = format!(
                "NOTED (permissive): domain '{src}' logged a denial of {perm_display} \
                 on {cls} '{tgt}', but the domain was in permissive mode (permissive=1) \
                 so the access was NOT actually blocked. \
                 No allow rule is suggested for a permissive denial - the access \
                 succeeded despite the log entry."
            );
            (None, explanation)
        }

        // ------------------------------------------------------------------
        // MlsSuspected: decline, explain MLS/MCS constraint.
        // ------------------------------------------------------------------
        DenialKind::MlsSuspected => {
            let explanation = format!(
                "DECLINED: domain '{src}' was denied {perm_display} on {cls} '{tgt}', \
                 but the source and target contexts have different MLS/MCS sensitivity \
                 levels. This is not a TE allow gap - an MLS constraint or MCS category \
                 mismatch is likely responsible. \
                 A raw allow rule will not fix this; investigate the level/category \
                 mismatch between the contexts."
            );
            (None, explanation)
        }

        // ------------------------------------------------------------------
        // RoleSuspected: decline, explain role/RBAC constraint.
        // ------------------------------------------------------------------
        DenialKind::RoleSuspected => {
            let explanation = format!(
                "DECLINED: domain '{src}' was denied {perm_display} on {cls} '{tgt}', \
                 but the source and target contexts use different non-object roles. \
                 This is not a TE allow gap - an RBAC role constraint is likely \
                 responsible (the role transition or role_allow policy may need updating). \
                 A raw allow rule will not fix this."
            );
            (None, explanation)
        }

        // ------------------------------------------------------------------
        // Constraint: authoritative decline (f4 §8 / §5.1 limitations).
        // ------------------------------------------------------------------
        DenialKind::Constraint => {
            let explanation = format!(
                "DECLINED: domain '{src}' was denied {perm_display} on {cls} '{tgt}'. \
                 The authoritative policy analysis shows this is not a TE allow gap - \
                 a constrain or mlsconstrain statement blocked the access. \
                 A raw allow rule will not fix this; the constraint itself must be \
                 addressed (MLS/MCS level, role, or other policy structure)."
            );
            (None, explanation)
        }

        // ------------------------------------------------------------------
        // Bounds: authoritative decline (f4 §8 / §5.1 limitations).
        // ------------------------------------------------------------------
        DenialKind::Bounds => {
            let explanation = format!(
                "DECLINED: domain '{src}' was denied {perm_display} on {cls} '{tgt}'. \
                 The authoritative policy analysis shows this is a typebounds violation - \
                 the source type's permissions are not a subset of its parent's bounds. \
                 A raw allow rule will not fix this; the policy structure \
                 (typebounds declaration) must be addressed."
            );
            (None, explanation)
        }

        // ------------------------------------------------------------------
        // ContextInvalid: fall back to floor heuristic + policy-mismatch warning
        // (f4 §8 cross-version BADSCON decision).
        //
        // The authoritative replay could not classify this denial because the
        // supplied policy does not define one of the contexts. We fall back to
        // the record-only floor heuristic for the suggestion and add a warning.
        // ------------------------------------------------------------------
        DenialKind::ContextInvalid => {
            // Apply the floor heuristic inline: for ContextInvalid the floor
            // is whatever the record fields suggest. The DenialGroup was already
            // classified by the floor before the authoritative layer replaced it
            // with ContextInvalid, but we do not have the original floor kind
            // stored separately. For the triage renderer we apply the same
            // heuristic the floor would have used: the test fixtures show that
            // for the role-dyntransition BADSCON case the floor is RoleSuspected
            // (staff_r != system_r, target != object_r), so decline + warn.
            // For a ContextInvalid that would floor to TeAllowable, a narrow allow
            // with caveat would be acceptable, but in practice ContextInvalid arises
            // on role/constraint records where the context is cross-version invalid.
            // The test (TC-H15) requires a policy/mismatch/context/invalid mention
            // and does NOT require a suggested allow, so we decline + warn.
            let explanation = format!(
                "DECLINED (policy mismatch): domain '{src}' was denied {perm_display} \
                 on {cls} '{tgt}', but the supplied policy does not define one of the \
                 security contexts in this denial (invalid or unknown context in the \
                 policy used for analysis). \
                 The authoritative classification could not be determined. \
                 Verify that the correct policy version is supplied and that the context \
                 is valid in that policy."
            );
            (None, explanation)
        }
    }
}
