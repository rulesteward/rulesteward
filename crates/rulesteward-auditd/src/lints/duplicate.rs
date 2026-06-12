//! au-W01: duplicate rule - normalized-equal across the concatenated
//! `rules.d/` stream (same or different files).
//!
//! Pipeline P1 (#193). Equality is [`super::normalize::canonical_key`]
//! equality: field order, syscall order, `-a` vs `-A`, and `-p` letter order
//! do not distinguish rules; the `-k` key DOES (a key-differing pair is P2's
//! au-W02 shadow case per owner decision D2, never au-W01).
//!
//! Emission convention: N occurrences of one canonical rule yield N-1
//! findings, each anchored at the LATER occurrence in load order with the
//! first occurrence's `file:line` named in the message.

use rulesteward_core::Diagnostic;

use crate::ast::LocatedRule;

/// au-W01 duplicate-rule pass over the concatenated load-order stream.
///
/// Body is pipeline P1's; the signature is Phase-0 frozen.
#[must_use]
pub fn w01(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let _ = rules;
    todo!("pipeline P1 (#193): au-W01 duplicate detection")
}
