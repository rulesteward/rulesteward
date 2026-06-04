//! fapolicyd rule explanation: maps a kernel FANOTIFY denial to the responsible
//! rule, or replays the evaluation when the record lacks a rule number.
//!
//! Grounding: f1 §3.4 / §4.2 / §5.1 / §5.2.
//!
//! Two resolution paths:
//! - **Era2** (`fan_type=1`): decode `fan_info` (hex) -> decimal -> 1-based
//!   rule index; look up and return the rule. High confidence.
//! - **Era1** (`fan_type=0`): no rule number in the record. Replay the §1
//!   evaluation via the frozen `evaluate()` core over the SYSCALL/PATH facts
//!   recovered from the `AuditEvent`, and return the first matching `deny*`
//!   rule as best-effort, labeled `matched_by: "replay"`.
//!
//! Filled by pipeline P1 (issue #74).

use std::fmt::Write as _;

use serde::Serialize;

use crate::ast::{Decision, Perm, Rule};
use crate::evaluate::{Source, evaluate};
use crate::facts::{AccessFacts, SetTable, Trust};
use crate::fanotify::{AuditEvent, TrustVal};

// ---------------------------------------------------------------------------
// ExplainError
// ---------------------------------------------------------------------------

/// Typed error from `explain_event`.
///
/// Both variants correspond to exit code 2 (f1 §4.2: "exit 2 on an
/// unparseable record OR a rule number the supplied ruleset lacks").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExplainError {
    /// The record references a rule number that does not exist in the supplied
    /// ruleset.
    ///
    /// f1 §4.2: "do NOT guess; message: record references rule N, ruleset has M".
    #[error("record references rule {rule_ref}, ruleset has {ruleset_len}")]
    RuleOutOfRange {
        /// 1-based rule number from the FANOTIFY record.
        rule_ref: u32,
        /// Number of rules in the supplied ruleset.
        ruleset_len: usize,
    },
    /// The replay fallback found no matching `deny*` rule in the ruleset.
    ///
    /// This can happen when the ruleset passed to `explain` does not match
    /// the generation that produced the denial (f1 §4.2 limitation note).
    #[error("replay found no matching deny rule; ruleset may not match the denial generation")]
    ReplayNoMatch,
}

// ---------------------------------------------------------------------------
// MatchedBy
// ---------------------------------------------------------------------------

/// How the responsible rule was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchedBy {
    /// Era2: the rule number was directly encoded in the FANOTIFY record
    /// (`fan_type=1`, `fan_info` hex decoded).
    RuleNumber,
    /// Era1 fallback: no rule number in the record; the rule was found by
    /// replaying the §1 evaluation algorithm over the recovered access facts.
    Replay,
}

// ---------------------------------------------------------------------------
// ExplainResult
// ---------------------------------------------------------------------------

/// The result of explaining a FANOTIFY denial.
///
/// Serializes to the `explain` JSON payload (kind="explain", `schema_version=1`)
/// per f1 §4.2 and issue #62 envelope contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExplainResult {
    /// The decision: `"deny"` for any `deny*` variant.
    pub decision: String,
    /// 1-based rule number from the record (Era2) or from the replay match
    /// (Era1). `None` only when the replay path is used and `matched_rule` is
    /// available from `Verdict`.
    pub rule_number: Option<u32>,
    /// The full rule text as it appears in the ruleset, e.g.
    /// `"deny_audit perm=execute all : all"`.
    pub rule_text: String,
    /// How the rule was identified.
    pub matched_by: MatchedBy,
    /// Subject executable path (from SYSCALL `exe=`), if available.
    pub exe: Option<String>,
    /// Object path (from PATH `name=`), if available.
    pub path: Option<String>,
    /// Permission attempted (from SYSCALL), if available.
    pub perm: Option<String>,
    /// PID of the accessing process, if available.
    pub pid: Option<i32>,
    /// Audit UID of the accessing process, if available.
    pub auid: Option<u32>,
    /// Trust status of the subject.
    pub subj_trust: String,
    /// Trust status of the object.
    pub obj_trust: String,
    /// When `matched_by=replay` and there was a `PossibleMatch` rule that
    /// preceded the decisive one, this carries the uncertainty reason
    /// (forwarded from `Verdict::uncertain`).
    pub uncertain: Option<String>,
}

// ---------------------------------------------------------------------------
// Rule text formatter (public for testing)
// ---------------------------------------------------------------------------

/// Format a `Rule` as its canonical text representation for display.
///
/// Used in `ExplainResult::rule_text` and human output. The format mirrors
/// fapolicyd's own representation: `<decision>[:perm] <subject-attrs> : <object-attrs>`.
#[must_use]
pub fn rule_text(rule: &Rule) -> String {
    // Use the Display impl from format.rs which already does the right thing.
    rule.to_string()
}

// ---------------------------------------------------------------------------
// Decision helpers
// ---------------------------------------------------------------------------

/// Return `true` if `decision` is any deny variant (`Deny`, `DenyAudit`,
/// `DenySyslog`, `DenyLog`).
///
/// Used by the replay path to find the first matching `deny*` rule.
#[must_use]
pub fn is_deny_decision(decision: Decision) -> bool {
    matches!(
        decision,
        Decision::Deny | Decision::DenyAudit | Decision::DenySyslog | Decision::DenyLog
    )
}

// ---------------------------------------------------------------------------
// Internal: build AccessFacts from AuditEvent
// ---------------------------------------------------------------------------

fn trust_val_to_trust(tv: TrustVal) -> Trust {
    match tv {
        TrustVal::Yes => Trust::Yes,
        TrustVal::No => Trust::No,
        TrustVal::Unknown => Trust::Unknown,
    }
}

fn facts_from_event(event: &AuditEvent) -> AccessFacts {
    let perm = event.perm.unwrap_or(Perm::Open);
    let mut facts = AccessFacts::new(perm);
    facts.exe.clone_from(&event.exe);
    facts.path.clone_from(&event.path);
    facts.auid = event.auid;
    facts.subj_trust = trust_val_to_trust(event.fanotify.subj_trust);
    facts.obj_trust = trust_val_to_trust(event.fanotify.obj_trust);
    facts
}

// ---------------------------------------------------------------------------
// Core explain function
// ---------------------------------------------------------------------------

/// Explain a FANOTIFY denial by mapping it to the responsible rule.
///
/// # Arguments
///
/// * `event` - The parsed `AuditEvent` (FANOTIFY record + companion facts).
/// * `rules` - The load-ordered ruleset (only `Entry::Rule` items; use
///   `entries.iter().filter_map(|e| if let Entry::Rule(r) = e { Some(r) }
///   else { None }).collect::<Vec<_>>()` to build this slice).
/// * `sets` - The `%set` table built from the same entries.
///
/// # Resolution paths
///
/// - **Era2** (`event.fanotify.fan_type == 1`): decode `fan_info` (already
///   stored as decimal in `FanotifyRecord::fan_info` after hex parse) as the
///   1-based rule index. Look up `rules[rule_number - 1]`. If the index is
///   out of range, return `ExplainError::RuleOutOfRange`.
/// - **Era1** (`event.fanotify.fan_type == 0`): build an `AccessFacts` from
///   the `AuditEvent`'s `exe`, `path`, `perm`, `auid` fields, then call the
///   frozen `evaluate()` from `crate::evaluate`. Return the first matching
///   `deny*` verdict, labeled `matched_by: Replay`. Return
///   `ExplainError::ReplayNoMatch` if the evaluation falls through or matches
///   an allow rule.
///
/// # Errors
///
/// Returns `ExplainError::RuleOutOfRange` (Era2) or `ExplainError::ReplayNoMatch`
/// (Era1, no deny match found).
pub fn explain_event(
    event: &AuditEvent,
    rules: &[&Rule],
    sets: &SetTable,
) -> Result<ExplainResult, ExplainError> {
    let perm_label = event.perm.map(|p| format!("{p}"));

    if event.fanotify.fan_type == 1 {
        // Era2: direct rule lookup by 1-based index.
        let rule_ref = event.fanotify.fan_info;
        let idx = rule_ref as usize;
        if idx == 0 || idx > rules.len() {
            return Err(ExplainError::RuleOutOfRange {
                rule_ref,
                ruleset_len: rules.len(),
            });
        }
        let rule = rules[idx - 1];
        Ok(ExplainResult {
            decision: format!("{}", rule.decision),
            rule_number: Some(rule_ref),
            rule_text: rule_text(rule),
            matched_by: MatchedBy::RuleNumber,
            exe: event.exe.clone(),
            path: event.path.clone(),
            perm: perm_label,
            pid: event.pid,
            auid: event.auid,
            subj_trust: event.fanotify.subj_trust.label().to_string(),
            obj_trust: event.fanotify.obj_trust.label().to_string(),
            uncertain: None,
        })
    } else {
        // Era1: replay via the frozen evaluate() core.
        // The spec says "report the first matching deny* rule". evaluate() returns
        // first-match-wins which may be an allow. We must walk past allows to find
        // the first deny.
        //
        // Strategy: build facts once, then iterate rules owned, calling evaluate()
        // on progressively-shorter slices until we find a deny match, OR use a
        // single-rule evaluation per rule to find the first deny.
        let facts = facts_from_event(event);

        // Walk rules one by one (evaluate() with a single-element slice), looking
        // for the first rule that decisively matches AND is a deny variant.
        // This correctly handles the mixed [allow, deny] case per f1 §3.4.
        let mut uncertain: Option<String> = None;
        for (idx, &rule) in rules.iter().enumerate() {
            let rule_num = idx + 1; // 1-based
            // rule_num is a usize but ruleset sizes are bounded well within u32.
            #[allow(clippy::cast_possible_truncation)]
            let rule_num_u32 = rule_num as u32;
            let verdict = evaluate(std::slice::from_ref(rule), sets, &facts);
            if verdict.source == Source::Rule && is_deny_decision(verdict.decision) {
                // Found the first deny match.
                return Ok(ExplainResult {
                    decision: format!("{}", verdict.decision),
                    rule_number: Some(rule_num_u32),
                    rule_text: rule_text(rule),
                    matched_by: MatchedBy::Replay,
                    exe: event.exe.clone(),
                    path: event.path.clone(),
                    perm: perm_label,
                    pid: event.pid,
                    auid: event.auid,
                    subj_trust: event.fanotify.subj_trust.label().to_string(),
                    obj_trust: event.fanotify.obj_trust.label().to_string(),
                    uncertain,
                });
            }
            // Capture uncertain reason from PossibleMatch (Source::Fallthrough with uncertain set).
            // evaluate() on a single rule: if the rule has a NotEvaluable field, verdict.uncertain
            // is set and source is Fallthrough (no decisive match). Carry the first such reason.
            if uncertain.is_none()
                && let Some(u) = verdict.uncertain
            {
                // Re-frame to reference the correct rule number.
                // evaluate() formats it as "possible match at rule 1: ..." (single-rule slice).
                // Replace "rule 1" with "rule N" for the actual position.
                let reframed = u.replacen("rule 1", &format!("rule {rule_num}"), 1);
                uncertain = Some(reframed);
            }
        }

        // No deny match found.
        Err(ExplainError::ReplayNoMatch)
    }
}

// ---------------------------------------------------------------------------
// Human output formatter
// ---------------------------------------------------------------------------

/// Render an `ExplainResult` as a human-readable string.
///
/// Format (f1 §4.2):
/// ```text
/// DENIED: <exe> (pid <N>, auid <M>) tried to <perm> <path>. Matched rule <N>:
///   "<rule_text>". subject trust=<label>, object trust=<label>.
/// ```
///
/// When `matched_by=replay`, a second line is appended:
/// ```text
///   (rule number not in record; matched by replay)
/// ```
///
/// When `uncertain` is `Some`, a third line is appended:
/// ```text
///   (uncertain: <reason>)
/// ```
#[must_use]
pub fn render_human(result: &ExplainResult) -> String {
    let exe = result.exe.as_deref().unwrap_or("<unknown>");
    let path = result.path.as_deref().unwrap_or("<unknown>");
    let perm = result.perm.as_deref().unwrap_or("access");

    let pid_part = match result.pid {
        Some(p) => format!("pid {p}"),
        None => "pid unknown".to_string(),
    };
    let auid_part = match result.auid {
        Some(a) => format!(", auid {a}"),
        None => String::new(),
    };

    let rule_num_part = match result.rule_number {
        Some(n) => format!("rule {n}"),
        None => "unknown rule".to_string(),
    };

    let mut out = format!(
        "DENIED: {exe} ({pid_part}{auid_part}) tried to {perm} {path}. Matched {rule_num_part}:\n  \"{}\". subject trust={}, object trust={}.",
        result.rule_text, result.subj_trust, result.obj_trust,
    );

    if result.matched_by == MatchedBy::Replay {
        out.push_str("\n  (rule number not in record; matched by replay)");
    }

    if let Some(ref reason) = result.uncertain {
        let _ = write!(out, "\n  (uncertain: {reason})");
    }

    out
}
