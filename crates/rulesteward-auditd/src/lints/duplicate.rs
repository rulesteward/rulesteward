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
//!
//! # Severity boundary
//!
//! * **au-E03 (Error)** -- later rule is structurally identical to the
//!   first occurrence, EXCLUDING the prepend flag (same field order, same syscall
//!   order). The prepend flag is excluded because `auditctl -R` loads rules in
//!   sequence, and the kernel clears `AUDIT_FILTER_PREPEND` after the first rule
//!   is inserted (`kernel/auditfilter.c:1003`, audit 3bfa048), so at compare time
//!   both rules have the same flags. `auditctl -R` aborts on `EEXIST`
//!   (`auditctl.c:1680-1686`, audit 3bfa048): every rule after the duplicate
//!   silently fails to load.
//! * **au-W01 (Warning)** -- `canonical_key`-equal but NOT structurally identical
//!   (field order swapped, syscall order swapped, `-a` vs `-A`, or prepend differs).
//!   The kernel does NOT `EEXIST` on these; they load but are redundant waste.

use std::collections::HashMap;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{AuditRule, LocatedRule};
use crate::lints::normalize::canonical_key;

/// Check if two AuditRules are structurally identical for EEXIST duplicate detection.
/// The comparison assumes the first rule's prepend bit is cleared by the kernel
/// (kernel/auditfilter.c:1003, audit 3bfa048) and compares it as-is against the
/// second rule's prepend bit.
///
/// # Arguments
/// - `first`: the earlier rule in load order (its prepend bit is treated as cleared)
/// - `later`: the later rule in load order (its prepend bit is kept as-is)
fn rules_eexist_equal(first: &AuditRule, later: &AuditRule) -> bool {
    match (first, later) {
        (
            AuditRule::Syscall {
                list: list_a,
                action: action_a,
                syscalls: syscalls_a,
                fields: fields_a,
                field_compares: field_compares_a,
                prepend: _, // first rule's prepend is cleared by kernel
                key: key_a,
            },
            AuditRule::Syscall {
                list: list_b,
                action: action_b,
                syscalls: syscalls_b,
                fields: fields_b,
                field_compares: field_compares_b,
                prepend: prepend_b, // later rule's prepend is kept as-is
                key: key_b,
            },
        ) => {
            // For EEXIST comparison:
            // - All fields must be equal except prepend
            // - The later rule's prepend must be false (i.e., -a not -A)
            //   because the kernel only EXISTs if both have the same flags value.
            //   The first rule's prepend was cleared to false, so the later rule
            //   must also be false to match.
            list_a == list_b
                && action_a == action_b
                && syscalls_a == syscalls_b
                && fields_a == fields_b
                && field_compares_a == field_compares_b
                && key_a == key_b
                && !prepend_b // later rule must also be -a (not -A)
        }
        _ => first == later,
    }
}

/// au-W01 / au-E03 duplicate-rule pass over the concatenated load-order stream.
///
/// Body is pipeline P1's; the signature is Phase-0 frozen.
#[must_use]
pub fn w01(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    // Map from canonical key to the first occurrence of that rule.
    let mut first_seen: HashMap<_, &LocatedRule> = HashMap::new();
    let mut diags = Vec::new();

    for located in rules {
        let key = canonical_key(&located.rule);

        match first_seen.get(&key) {
            None => {
                // First time we see this canonical rule; record it.
                first_seen.insert(key, located);
            }
            Some(first) => {
                // Later occurrence: classify severity by structural equality (excluding prepend).
                // au-E03: structurally identical (rules_eexist_equal is true, excluding prepend)
                //   -> auditctl -R aborts (EEXIST, auditctl.c:1680-1686).
                // au-W01: canonical-equal but NOT structurally identical (field-order
                //   swapped, syscall-order swapped, -a vs -A, or prepend differs)
                //   -> kernel does not EEXIST; loads but is redundant waste.
                let (sev, code, msg) = if rules_eexist_equal(&first.rule, &located.rule) {
                    let msg = format!(
                        "load-aborting duplicate of {first_file}:{first_line}: \
                        structurally identical rule causes auditctl -R to abort, \
                        so every later rule silently fails to load \
                        (auditctl.c:1680-1686, audit 3bfa048)",
                        first_file = first.file.display(),
                        first_line = first.line,
                    );
                    (Severity::Error, "au-E03", msg)
                } else {
                    let msg = format!(
                        "duplicate of {first_file}:{first_line}: \
                        normalized-equal to an earlier rule in the rules.d/ load order",
                        first_file = first.file.display(),
                        first_line = first.line,
                    );
                    (Severity::Warning, "au-W01", msg)
                };

                diags.push(super::anchored(
                    sev,
                    code,
                    located.span.clone(),
                    msg,
                    located.file.clone(),
                    located.line,
                ));
            }
        }
    }

    diags
}
