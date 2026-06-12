//! Ordering and reachability lints over the concatenated `rules.d/` stream.
//!
//! Pipeline P2 (#193):
//! * au-W02 - shadowed rule: an earlier rule (in EFFECTIVE load order,
//!   including `-A` prepend head-insertion) structurally subsumes a later rule
//!   on the same filter list. v1 subsumption is STRUCTURAL-only (owner
//!   decision D4): same filter list, syscall superset, field-predicate subset
//!   with exact predicate equality; no interval arithmetic. Pairs that are
//!   exactly canonical-equal are au-W01 (P1) and MUST be skipped here (owner
//!   decision D2: skip when `canonical_key(a) == canonical_key(b)`).
//! * au-E01 - unreachable rule after the `-e 2` lock: any rule appearing
//!   after the lock line in the concatenated lexical stream never loads
//!   (`auditctl(8)`: `-e 2` makes the config immutable until reboot).
//! * au-W03 - exclude/never suppression conflict: an `exclude`-list (msgtype)
//!   or `never`-action rule suppresses events an `always` rule intends to
//!   record.
//! * au-W04 (stretch, owner decision D6) - `-D` after non-control rules
//!   discards previously loaded rules; the standard layout (`-D` at the top
//!   of the first file) must not fire.

use rulesteward_core::Diagnostic;

use crate::ast::LocatedRule;

/// au-W02 shadow/subsumption pass.
///
/// Body is pipeline P2's; the signature is Phase-0 frozen.
#[must_use]
pub fn w02(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let _ = rules;
    todo!("pipeline P2 (#193): au-W02 shadow/subsumption")
}

/// au-E01 post-lock unreachable-rule pass.
///
/// Body is pipeline P2's; the signature is Phase-0 frozen.
#[must_use]
pub fn e01(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let _ = rules;
    todo!("pipeline P2 (#193): au-E01 rules after -e 2 lock")
}

/// au-W03 exclude/never suppression-conflict pass.
///
/// Body is pipeline P2's; the signature is Phase-0 frozen.
#[must_use]
pub fn w03(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let _ = rules;
    todo!("pipeline P2 (#193): au-W03 suppression conflict")
}
