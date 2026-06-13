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
//! * **au-E03 (Error)** -- the later rule is a LOAD-ABORTING duplicate: the
//!   kernel `EEXIST`s on it, so `auditctl -R` aborts and every rule after it
//!   silently fails to load (`auditctl.c:1680-1686`, audit 3bfa048: on a rule
//!   error `if (ignore == 0) { fclose(f); return -1; }`). The kernel compares
//!   the SYSCALL set as a commutative bitmask (libaudit ORs each `-S` name into
//!   `rule->mask`, `lib/libaudit.c:1021-1025`), so a `-S`-order-swapped OR
//!   repetition-varying set is the SAME kernel rule and EEXISTs. Fields are
//!   compared POSITIONALLY by the kernel, so field order DOES matter. The
//!   prepend flag is excluded from the compare because the kernel clears
//!   `AUDIT_FILTER_PREPEND` after the first rule is inserted
//!   (`kernel/auditfilter.c:1003`); a later `-A` (prepend) rule is therefore
//!   NOT an EEXIST (it carries the prepend bit the stored rule lacks).
//! * **au-W01 (Warning)** -- `canonical_key`-equal but NOT load-aborting
//!   (field order swapped, `-a` vs `-A`, or `-p` letter order). The kernel does
//!   NOT `EEXIST` on these; they load but are redundant waste.

use std::collections::HashMap;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{AuditRule, LocatedRule};
use crate::lints::normalize::canonical_key;

/// Check if two `AuditRule`s are a load-aborting (`EEXIST`) duplicate pair.
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
            // - syscalls compare as a SORTED-DEDUPED SET: the kernel stores them
            //   as a commutative bitmask (libaudit.c:1021-1025), so order and
            //   repetition do not distinguish them at load -- a swapped/repeated
            //   `-S` set is the SAME kernel rule and EEXISTs (au-E03).
            // - fields/field_compares compare POSITIONALLY (the kernel compares
            //   them in order), so a field-order swap is NOT an EEXIST (au-W01).
            // - the later rule's prepend must be false (-a not -A): the kernel
            //   clears the first rule's prepend bit after insertion, so a later
            //   -A carries a prepend bit the stored rule lacks and does not EEXIST.
            let syscalls_eq = {
                let mut a: Vec<&str> = syscalls_a.iter().map(String::as_str).collect();
                let mut b: Vec<&str> = syscalls_b.iter().map(String::as_str).collect();
                a.sort_unstable();
                a.dedup();
                b.sort_unstable();
                b.dedup();
                a == b
            };
            list_a == list_b
                && action_a == action_b
                && syscalls_eq
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
