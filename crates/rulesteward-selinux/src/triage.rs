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
//! 6. REVERSED (round-2, owner decision 2026-06-05): a `permissive=1` denial NOW
//!    gets a suggested allow, preceded by a top-level PERMISSIVE-MODE caveat
//!    banner so the operator knows the access was logged-not-enforced and must be
//!    reviewed before allowing. The original invariant 6 ("Permissive groups are
//!    reported but NO allow is emitted") was the locked f4 §2.5 inv.6 (still
//!    stated as the old behaviour at f4-selinux-triage-grounding.md line 294-296);
//!    the SOURCE of the reversal is the owner decision of 2026-06-05, not those
//!    doc lines. The banner is emitted only when an allow is actually suggested
//!    for the group (round-3 adversarial fix): it is keyed on
//!    `any_permissive && suggested_rule.is_some()` so it fires on a permissive
//!    `TeAllowable`/`Permissive` group (an allow IS suggested) but is suppressed
//!    on a permissive DECLINE group (Constraint/Bounds/MlsSuspected/
//!    RoleSuspected/ContextInvalid - no allow), where a banner promising "the
//!    suggested allow below" would be self-contradictory.
//!
//!    EXTENDED (round-3, user decision 2026-06-05): the reversal of inv.6 now
//!    also applies to the MACHINE-READABLE JSON `build_report` path, not just the
//!    human render. A permissive `Permissive`-kind group's `suggested_rule` is
//!    populated in the JSON too (the same narrow allow the human path emits); the
//!    per-entry `any_permissive: true` field is the machine-readable caveat in
//!    place of the human banner. The JSON and human paths are now CONSISTENT for
//!    permissive denials.
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

/// The PERMISSIVE-MODE caveat banner emitted for any group with
/// `any_permissive == true` (round-2 reversal of f4 §2.5 inv.6). Caveat-first:
/// rendered BEFORE the suggested allow so the operator reads the warning before
/// the rule.
///
/// The leading `"PERMISSIVE MODE:"` substring is the stable marker the triage
/// tests pin (both the floor-path `h4_*` test and the CLI `--policy` e2e); a
/// permissive denial on EITHER path carries it, because the authoritative CLI
/// renderer reuses this floor renderer for non-already-allows groups.
const PERMISSIVE_BANNER: &str = "PERMISSIVE MODE: this denial was logged in permissive mode (permissive=1), so the access \
     was NOT actually blocked. The suggested allow below is what would be required to permit \
     this access under ENFORCING mode - review whether the access is genuinely needed before \
     applying it (`dontaudit` silences the log without granting access).";

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
    /// Present for `TeAllowable` and (round-3) `Permissive` (the latter with the
    /// `any_permissive: true` flag as the machine-readable caveat). `None` for
    /// `MlsSuspected`, `RoleSuspected`, `Constraint`, `Bounds`, and
    /// `ContextInvalid` (policy-mismatch decline).
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
/// (for `TeAllowable` and, as of round-3, `Permissive` groups - the latter
/// carrying `any_permissive: true` as the machine-readable caveat) or a decline
/// explanation (for the constraint/role/MLS/bounds/context-invalid kinds).
#[must_use]
pub fn build_report(groups: &[DenialGroup]) -> TriageReport {
    let entries = groups.iter().map(build_entry).collect();
    TriageReport { groups: entries }
}

/// Build the machine-readable triage report, substituting the Reason(0) "already
/// allows" explanation for groups flagged as already-allowed (#122).
///
/// This is the JSON twin of `commands::selinux::render_human_with_already_allows`:
/// `is_already_allows(group)` returns `true` for a group whose authoritative
/// replay was the `Reason(0)` "the supplied policy already allows this access"
/// sub-case (the CLI tracks this in its `already_allows_groups` set, since the
/// distinction is carried by `ReplayOutcome` - NOT by `DenialKind`, which is
/// frozen with both Reason(0) and BADSCON mapping to `ContextInvalid`).
///
/// For an already-allows group the explanation is the DISTINCT "policy already
/// allows" message ([`already_allows_explanation`]); every other group is built
/// exactly as [`build_report`] does. The human and JSON paths stay consistent:
/// a Reason(0) group says the policy already allows the access on both, and a
/// true BADSCON group keeps the "does not define" wording on both.
#[must_use]
pub fn build_report_with_already_allows(
    groups: &[DenialGroup],
    is_already_allows: impl Fn(&DenialGroup) -> bool,
) -> TriageReport {
    let entries = groups
        .iter()
        .map(|group| {
            if is_already_allows(group) {
                build_already_allows_entry(group)
            } else {
                build_entry(group)
            }
        })
        .collect();
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
    let mut out = groups
        .iter()
        .map(render_group_human)
        .collect::<Vec<_>>()
        .join("\n\n");
    // Exactly one trailing newline, matching `explain`/`auditd cost` (#114).
    out.push('\n');
    out
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

/// Build a `TriageEntry` for a Reason(0) "already allows" group (#122).
///
/// The `kind` stays `ContextInvalid` (the enum is frozen; Reason(0) and BADSCON
/// both map to it) but the explanation is the DISTINCT "policy already allows"
/// message, and NO allow is suggested (none is needed - the supplied policy
/// already permits the access). This mirrors
/// `commands::selinux::render_already_allows_group` on the human path so the two
/// outputs agree.
fn build_already_allows_entry(group: &DenialGroup) -> TriageEntry {
    let perms: Vec<String> = group.perms.iter().cloned().collect();
    TriageEntry {
        source_type: group.source_type.clone(),
        target_type: group.target_type.clone(),
        tclass: group.tclass.clone(),
        perms,
        any_permissive: group.any_permissive,
        kind: group.kind,
        suggested_rule: None,
        explanation: already_allows_explanation(group),
    }
}

/// The DISTINCT "policy already allows" explanation for a Reason(0) group (#122).
///
/// Worded to satisfy the #122 distinction: it MUST contain "already allow" and
/// MUST NOT contain the bad-context "does not define" wording (both contexts ARE
/// defined - the policy simply already permits the access). Kept consistent with
/// the human path's `render_already_allows_group`.
fn already_allows_explanation(group: &DenialGroup) -> String {
    let src = &group.source_type;
    let tgt = &group.target_type;
    let cls = &group.tclass;
    let perms: Vec<&str> = group.perms.iter().map(String::as_str).collect();
    let perm_display = if perms.len() == 1 {
        perms[0].to_string()
    } else {
        format!("{{ {} }}", perms.join(" "))
    };
    format!(
        "NOTED (policy mismatch): domain '{src}' was denied {perm_display} \
         on {cls} '{tgt}', but the supplied policy already allows this access. \
         The denial likely came from a different policy version or a different host. \
         No allow rule is needed for the supplied policy; \
         verify you are analyzing the policy that was active when the denial occurred."
    )
}

/// Render one `DenialGroup` as a human-readable block.
///
/// Round-2 inv.6 reversal: a group with `any_permissive == true` gets the
/// PERMISSIVE-MODE caveat banner rendered CAVEAT-FIRST (before the suggested
/// allow). Round-3 (2026-06-05) extended the reversal to the JSON path, so
/// `triage_group` now returns the suggested allow for a `Permissive`-kind group
/// directly; the human and JSON paths share that one rule (no human-only
/// fallback any more). A group whose authoritative verdict is `TeAllowable` with
/// `any_permissive == true` (the `--policy` path) also carries the allow from
/// `triage_group`; it just additionally gains the banner here.
fn render_group_human(group: &DenialGroup) -> String {
    // The suggested allow now comes solely from `triage_group` (the single
    // decision point shared with the JSON path). Permissive groups carry it as
    // of round-3, so no human-only override is needed.
    let (suggested_rule, explanation) = triage_group(group);

    let mut out = String::new();
    // Caveat-first: the PERMISSIVE-MODE banner precedes everything else so the
    // operator reads the warning before the suggested allow. It is emitted ONLY
    // when an allow is actually suggested (`suggested_rule.is_some()`): the banner
    // text promises "the suggested allow below", so for a permissive DECLINE kind
    // (Constraint / Bounds / MlsSuspected / RoleSuspected / ContextInvalid - all
    // of which yield no allow) the banner would be self-contradictory. The decline
    // explanation already states why no allow applies; no banner is needed there.
    if group.any_permissive && suggested_rule.is_some() {
        out.push_str(PERMISSIVE_BANNER);
        out.push('\n');
    }
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
        // Permissive: round-3 (user decision 2026-06-05) - the MACHINE-READABLE
        // report NOW populates `suggested_rule` for permissive denials too, so the
        // JSON is CONSISTENT with the human path. This extends the round-2 inv.6
        // reversal (which only flipped the HUMAN path) to the JSON `build_report`
        // path as well. The per-entry `any_permissive: true` flag is the
        // machine-readable caveat (no banner needed in JSON); the suggested allow
        // is the SAME narrow rule the human path emits (shared `format_narrow_allow`
        // over the same source/target/class/perms). This is a SANCTIONED contract
        // change reversing f4 §2.5 inv.6 for the JSON path; TC-R5b is updated to
        // assert the rule IS present (was: asserts absent).
        // ------------------------------------------------------------------
        DenialKind::Permissive => {
            let rule = format_narrow_allow(src, tgt, cls, &group.perms);
            let explanation = format!(
                "NOTED (permissive): domain '{src}' logged a denial of {perm_display} \
                 on {cls} '{tgt}', but the domain was in permissive mode (permissive=1) \
                 so the access was NOT actually blocked. \
                 The narrowest allow that would permit this access under enforcing mode \
                 is suggested below; review whether the access is genuinely needed."
            );
            (Some(rule), explanation)
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
