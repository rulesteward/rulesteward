//! Shared rule canonicalization (Phase-0 frozen; consumed by P1 au-W01 and
//! P2 au-W02 per owner decision D2).
//!
//! Two rules are "the same rule" when their canonical keys are equal:
//! * `-F` predicate ORDER does not distinguish (libaudit ANDs all pairs).
//! * `-S` syscall ORDER and repetition do not distinguish (libaudit ORs the
//!   names into one syscall bitmask, so `a,b == b,a` and `a,a == a`).
//! * `-a` vs `-A` does NOT distinguish content: prepend changes effective
//!   POSITION (provenance), not what the rule matches. Position is P2's
//!   business, never part of content identity.
//! * `-p` letter order does not distinguish (`PermBits` is order-free by
//!   construction).
//! * The `-k` key DOES distinguish: a predicate-equal pair whose keys differ
//!   is P2's shadow case (the later key never fires), not a P1 duplicate.
//! * Values are FOLDED by field type (#220, was the D5 false-negative): on a
//!   uid/gid field the spellings `auid!=-1`, `auid!=4294967295`, and
//!   `auid!=unset` denote the same kernel sentinel and share one key; concrete
//!   numerics decimal-normalize. Folding is [`crate::lints::value::canonical_value`]
//!   and never crosses field types (a concrete `pid=4294967295` or a signed
//!   `exit=-1` is NOT the uid sentinel).

use crate::ast::{AuditRule, PermBits};
use crate::lints::field_type::field_type;
use crate::lints::value::canonical_value;

/// Opaque canonical identity of a rule's CONTENT (not its position).
///
/// Internally an unambiguous string encoding: every free-form component
/// (paths, values, keys, syscall names) is embedded via `Debug` formatting,
/// whose quoting/escaping makes a crafted value unable to forge a separator,
/// and the variant tag prefix keeps the three rule shapes disjoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalKey(String);

/// The canonical content key of `rule`. See the module doc for what does and
/// does not distinguish two rules (D2/D5 boundaries).
#[must_use]
pub fn canonical_key(rule: &AuditRule) -> CanonicalKey {
    match rule {
        AuditRule::Control(c) => CanonicalKey(format!("control|{c:?}")),

        AuditRule::Watch {
            path,
            perms,
            key,
            // Derived from the path's trailing slash; the path already
            // carries it, so it adds nothing to identity.
            is_dir: _,
        } => CanonicalKey(format!("watch|{path:?}|{}|{key:?}", perm_letters(perms))),

        AuditRule::Syscall {
            list,
            action,
            syscalls,
            fields,
            field_compares,
            // Position (effective load order), not content: P2's business.
            prepend: _,
            key,
        } => {
            let mut sc: Vec<&str> = syscalls.iter().map(String::as_str).collect();
            sc.sort_unstable();
            sc.dedup();

            let mut fs: Vec<String> = fields
                .iter()
                .map(|f| {
                    // Fold the value by field type (#220) so equivalent uid/gid
                    // sentinel spellings share one key. Op and field stay verbatim.
                    let v = canonical_value(field_type(&f.field), &f.value);
                    format!("{:?} {:?} {:?}", f.field, f.op, v)
                })
                .collect();
            fs.sort_unstable();

            let mut cs: Vec<String> = field_compares
                .iter()
                .map(|c| format!("{:?} {:?} {:?}", c.left, c.op, c.right))
                .collect();
            cs.sort_unstable();

            CanonicalKey(format!(
                "syscall|{list:?}|{action:?}|{sc:?}|{fs:?}|{cs:?}|{key:?}"
            ))
        }
    }
}

/// Canonical `rwxa`-ordered permission letters (order-free by construction:
/// `-p wa` and `-p aw` parse to the same `PermBits`).
fn perm_letters(perms: &PermBits) -> String {
    let mut s = String::new();
    if perms.read {
        s.push('r');
    }
    if perms.write {
        s.push('w');
    }
    if perms.exec {
        s.push('x');
    }
    if perms.attr {
        s.push('a');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::canonical_key;
    use crate::ast::AuditRule;
    use crate::parser::parse_rules_str;

    /// Parse exactly one rule line (test fixture helper).
    fn rule(line: &str) -> AuditRule {
        let mut rules = parse_rules_str(line)
            .unwrap_or_else(|e| panic!("fixture {line:?} must parse, got {e:?}"));
        assert_eq!(rules.len(), 1, "fixture {line:?} must be a single rule");
        rules.remove(0)
    }

    #[test]
    fn field_order_swap_is_equal() {
        let a = rule("-a always,exit -S execve -F auid>=1000 -F uid=0 -k x");
        let b = rule("-a always,exit -S execve -F uid=0 -F auid>=1000 -k x");
        assert_eq!(
            canonical_key(&a),
            canonical_key(&b),
            "-F predicate order must not distinguish rules"
        );
    }

    #[test]
    fn syscall_order_swap_is_equal() {
        let a = rule("-a always,exit -S open -S close -k x");
        let b = rule("-a always,exit -S close -S open -k x");
        assert_eq!(
            canonical_key(&a),
            canonical_key(&b),
            "-S order must not distinguish rules (libaudit builds one bitmask)"
        );
    }

    #[test]
    fn repeated_syscall_entry_is_equal_to_single() {
        let a = rule("-a always,exit -S open -S open -k x");
        let b = rule("-a always,exit -S open -k x");
        assert_eq!(
            canonical_key(&a),
            canonical_key(&b),
            "a repeated -S name is the same bitmask bit; dedup before compare"
        );
    }

    #[test]
    fn prepend_flag_is_excluded_from_identity() {
        let a = rule("-a always,exit -S execve -k x");
        let b = rule("-A always,exit -S execve -k x");
        assert_eq!(
            canonical_key(&a),
            canonical_key(&b),
            "-a vs -A is position (provenance), not content identity"
        );
    }

    #[test]
    fn key_difference_distinguishes() {
        let a = rule("-a always,exit -S execve -k first");
        let b = rule("-a always,exit -S execve -k second");
        let c = rule("-a always,exit -S execve");
        assert_ne!(
            canonical_key(&a),
            canonical_key(&b),
            "differing -k keys are distinct rules (the pair is P2's shadow case)"
        );
        assert_ne!(
            canonical_key(&a),
            canonical_key(&c),
            "keyed vs keyless must be distinct"
        );
    }

    #[test]
    fn action_distinguishes() {
        let a = rule("-a always,exit -S mount -k m");
        let b = rule("-a never,exit -S mount -k m");
        assert_ne!(
            canonical_key(&a),
            canonical_key(&b),
            "always vs never are different rules"
        );
    }

    #[test]
    fn watch_vs_syscall_never_equal() {
        let w = rule("-w /etc/passwd -p wa -k identity");
        let s = rule("-a always,exit -S open -k identity");
        assert_ne!(canonical_key(&w), canonical_key(&s));
    }

    #[test]
    fn watch_perm_letter_order_is_equal() {
        let a = rule("-w /etc/passwd -p wa -k identity");
        let b = rule("-w /etc/passwd -p aw -k identity");
        assert_eq!(
            canonical_key(&a),
            canonical_key(&b),
            "-p letter order must not distinguish watches"
        );
    }

    #[test]
    fn watch_path_and_key_distinguish() {
        let a = rule("-w /etc/passwd -p wa -k identity");
        let b = rule("-w /etc/shadow -p wa -k identity");
        let c = rule("-w /etc/passwd -p wa -k other");
        assert_ne!(canonical_key(&a), canonical_key(&b));
        assert_ne!(canonical_key(&a), canonical_key(&c));
    }

    #[test]
    fn control_rules_compare_by_content() {
        assert_eq!(
            canonical_key(&rule("-b 8192")),
            canonical_key(&rule("-b 8192"))
        );
        assert_ne!(
            canonical_key(&rule("-b 8192")),
            canonical_key(&rule("-b 4096"))
        );
        assert_ne!(canonical_key(&rule("-e 2")), canonical_key(&rule("-e 1")));
    }

    #[test]
    fn uid_sentinel_spellings_fold_220() {
        // #220 (was D5): on a uid/gid field, -1 / 4294967295 / unset denote the
        // same kernel sentinel and now fold to one canonical key.
        let a = rule("-a always,exit -S execve -F auid!=-1 -k x");
        let b = rule("-a always,exit -S execve -F auid!=4294967295 -k x");
        let c = rule("-a always,exit -S execve -F auid!=unset -k x");
        assert_eq!(
            canonical_key(&a),
            canonical_key(&b),
            "auid!=-1 == auid!=4294967295"
        );
        assert_eq!(
            canonical_key(&a),
            canonical_key(&c),
            "auid!=-1 == auid!=unset"
        );
    }

    #[test]
    fn gid_sentinel_spellings_fold_220() {
        let a = rule("-a always,exit -S execve -F gid!=-1 -k x");
        let b = rule("-a always,exit -S execve -F gid!=4294967295 -k x");
        assert_eq!(canonical_key(&a), canonical_key(&b));
    }

    #[test]
    fn big_value_does_not_fold_on_non_uid_fields_220() {
        // pid is unsigned Numeric: 4294967295 is a concrete pid, NOT the
        // sentinel. exit is signed: -1 and 4294967295 are different values. A
        // naive impl that folded 4294967295/-1 globally would wrongly merge.
        let pid_big = rule("-a always,exit -S execve -F pid=4294967295 -k x");
        let pid_one = rule("-a always,exit -S execve -F pid=1 -k x");
        assert_ne!(canonical_key(&pid_big), canonical_key(&pid_one));
        let exit_m1 = rule("-a always,exit -S execve -F exit=-1 -k x");
        let exit_big = rule("-a always,exit -S execve -F exit=4294967295 -k x");
        assert_ne!(
            canonical_key(&exit_m1),
            canonical_key(&exit_big),
            "exit is signed; -1 and 4294967295 are different values"
        );
    }

    #[test]
    fn sentinel_fold_is_per_field_220() {
        // Folding is per (field, value): different fields never collapse.
        let a = rule("-a always,exit -S execve -F auid!=-1 -k x");
        let b = rule("-a always,exit -S execve -F euid!=-1 -k x");
        assert_ne!(canonical_key(&a), canonical_key(&b));
    }

    #[test]
    fn concrete_uid_not_folded_with_sentinel_220() {
        // auid=0 (root) is a concrete uid, not the unset sentinel.
        let a = rule("-a always,exit -S execve -F auid=0 -k x");
        let b = rule("-a always,exit -S execve -F auid=unset -k x");
        assert_ne!(canonical_key(&a), canonical_key(&b));
    }

    #[test]
    fn op_is_preserved_under_folding_220() {
        // Folding rewrites only the value, never the operator.
        let ge_m1 = rule("-a always,exit -S execve -F auid>=-1 -k x");
        let ge_big = rule("-a always,exit -S execve -F auid>=4294967295 -k x");
        assert_eq!(
            canonical_key(&ge_m1),
            canonical_key(&ge_big),
            "value folds, op kept"
        );
        let ge_unset = rule("-a always,exit -S execve -F auid>=unset -k x");
        let le_unset = rule("-a always,exit -S execve -F auid<=unset -k x");
        assert_ne!(
            canonical_key(&ge_unset),
            canonical_key(&le_unset),
            "op distinguishes"
        );
    }

    #[test]
    fn field_compare_order_swap_is_equal() {
        let a = rule("-a always,exit -S execve -C uid!=euid -C gid!=egid -k x");
        let b = rule("-a always,exit -S execve -C gid!=egid -C uid!=euid -k x");
        assert_eq!(
            canonical_key(&a),
            canonical_key(&b),
            "-C comparison order must not distinguish rules"
        );
    }

    #[test]
    fn key_is_usable_in_hash_maps() {
        use std::collections::HashMap;
        let mut seen: HashMap<_, usize> = HashMap::new();
        seen.insert(canonical_key(&rule("-w /etc/passwd -p wa -k id")), 1);
        assert_eq!(
            seen.get(&canonical_key(&rule("-w /etc/passwd -p aw -k id"))),
            Some(&1),
            "CanonicalKey must be Eq + Hash so passes can bucket by it"
        );
    }
}
