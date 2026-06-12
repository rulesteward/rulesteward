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
//! * Values compare VERBATIM (owner decision D5): `auid!=-1`,
//!   `auid!=4294967295`, and `auid!=unset` are spelled differently and stay
//!   distinct in v1, a documented false-negative class (folding them needs
//!   the field-type table, a Phase-0 dependency cycle).

use crate::ast::{AuditRule, PermBits};

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
                .map(|f| format!("{:?} {:?} {:?}", f.field, f.op, f.value))
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
    fn values_compare_verbatim_d5() {
        // Owner decision D5: -1 / 4294967295 / unset are NOT folded in v1.
        // This pins the documented false-negative class; the integration gate
        // files the follow-up issue.
        let a = rule("-a always,exit -S execve -F auid!=-1 -k x");
        let b = rule("-a always,exit -S execve -F auid!=4294967295 -k x");
        assert_ne!(
            canonical_key(&a),
            canonical_key(&b),
            "values are verbatim in v1 (D5); folding is a tracked follow-up"
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
