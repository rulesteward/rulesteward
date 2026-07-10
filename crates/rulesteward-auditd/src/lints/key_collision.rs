//! au-W05: key collision - the same audit key (`-k <key>` / `-F key=<key>`)
//! is attached to unrelated rules, making key-based reporting (`ausearch -k`,
//! `aureport --key`) return mixed, unrelated events (issue #473).
//!
//! Phase-0 stub (session 7c): registration is frozen; the collision predicate
//! is NOT. It must be grounded against real ausearch/aureport consumer
//! behavior (pinned audit-userspace source) and signed off by the operator
//! BEFORE any tests or implementation land: the naive "shared key + provably
//! disjoint traffic" predicate is refuted by DISA STIG practice, which
//! REQUIRES one key across many mutually-disjoint rules (e.g. `-k identity`
//! across several watches).

use rulesteward_core::Diagnostic;

use super::LintOptions;
use crate::ast::LocatedRule;

/// au-W05 key-collision pass. Phase-0 stub, filled by pipeline P4 (#473)
/// after the predicate sign-off: returns no diagnostics, so dispatcher
/// output is byte-identical until the pass lands.
#[must_use]
pub fn w05(_rules: &[LocatedRule], _opts: LintOptions) -> Vec<Diagnostic> {
    Vec::new()
}
