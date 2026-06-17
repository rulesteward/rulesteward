//! au-W04 missing-ABI coverage pass (issue #261).
//!
//! Audit syscall rules are PER-ABI. `-a always,exit -F arch=b64 -S execve`
//! audits only 64-bit `execve`; the same syscall from a 32-bit process (the b32
//! ABI) is UNAUDITED. The b32 ABI is live on rhel8/9/10
//! (`CONFIG_IA32_EMULATION=y`, default-enabled, verified on the Rocky VMs
//! 2026-06-16), so this check is version-INDEPENDENT and needs no `--target`.
//! CIS / DISA-STIG rulesets ship every syscall rule as a matched b32+b64 pair;
//! a lone-ABI rule is a silent coverage gap.
//!
//! Scope (owner-ratified, #261):
//! * Only `exit`-list, non-`never` syscall rules with `-S` and a single-ABI pin
//!   are CHECKED; companion search is within the Exit list, same action.
//! * SYMMETRIC: a lone `arch=b64` warns "32-bit unaudited", a lone `arch=b32`
//!   warns "64-bit unaudited".
//! * A rule with NO `arch` field matches all ABIs (not a gap; counts as a
//!   companion for either ABI).
//!
//! The ABI classifier deliberately does NOT share `bands.rs`'s `is_32bit_arch`
//! /`classify_rule` arch handling: that pass answers a different question (an
//! Eq-`b32`-ONLY volume demotion that excludes `Ne` and `b64`), so a shared
//! helper would conflate two semantics. This classifier recognises both Eq and
//! Ne on `b32`/`b64`; machine-name values (`x86_64`/`i386`) stay out of scope
//! exactly as in `bands.rs` (and the arch-alias note in `value.rs`).

use rulesteward_core::{Diagnostic, Severity};

use super::anchored;
use crate::ast::{Action, AuditField, AuditRule, CompareOp, FieldFilter, FilterList, LocatedRule};

/// One of the two syscall ABIs an `arch` pin can select.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Abi {
    B32,
    B64,
}

impl Abi {
    /// The ABI a rule pinned to `self` leaves unaudited (and the one a companion
    /// must cover).
    fn opposite(self) -> Self {
        match self {
            Abi::B32 => Abi::B64,
            Abi::B64 => Abi::B32,
        }
    }
}

/// The ABI coverage a rule provides.
#[derive(Clone, Copy)]
enum Coverage {
    /// No `arch` field, or an unclassifiable pin (machine-name value, a
    /// non-Eq/Ne operator, or 2+ `arch` fields): conservatively covers BOTH
    /// ABIs so it never causes a false positive and is never itself checked.
    Both,
    /// A single classifiable ABI pin.
    One(Abi),
}

/// Classify which ABI(s) a rule's `-F arch=...` field selects.
fn classify(fields: &[FieldFilter]) -> Coverage {
    // Exactly one `arch` field can be a single-ABI pin; 0 or 2+ => Both.
    let mut arch = fields.iter().filter(|f| f.field == AuditField::Arch);
    let (Some(f), None) = (arch.next(), arch.next()) else {
        return Coverage::Both;
    };
    // auditctl matches the ABI token case-insensitively (libaudit
    // `audit_determine_machine` -> `strcasecmp("b64"/"b32", arch)`), so `B64`
    // is the same b64 pin as `b64`. Fold case before matching.
    let value = f.value.to_ascii_lowercase();
    match (&f.op, value.as_str()) {
        (CompareOp::Eq, "b64") | (CompareOp::Ne, "b32") => Coverage::One(Abi::B64),
        (CompareOp::Eq, "b32") | (CompareOp::Ne, "b64") => Coverage::One(Abi::B32),
        // machine-name value (x86_64/i386) or a non-equality operator: unclassifiable.
        _ => Coverage::Both,
    }
}

/// Whether `cov` covers the `target` ABI (Both covers everything; a single pin
/// covers only its own ABI).
fn covers(cov: Coverage, target: Abi) -> bool {
    match cov {
        Coverage::Both => true,
        Coverage::One(abi) => abi == target,
    }
}

/// Whether some Exit-list, same-`action` rule audits syscall `s` on the
/// `opposite` ABI. A companion with no `-S` (empty syscall set) is a wildcard
/// that audits every syscall on its ABI. `-F`/`-C` narrowing, `-k` key, and
/// `-a`/`-A` ordering are irrelevant to ABI coverage and are ignored. The
/// checked rule itself is naturally excluded: its own ABI is never the opposite.
fn syscall_covered(s: &str, opposite: Abi, action: &Action, rules: &[LocatedRule]) -> bool {
    rules.iter().any(|c| {
        let AuditRule::Syscall {
            list,
            action: c_action,
            syscalls,
            fields,
            ..
        } = &c.rule
        else {
            return false;
        };
        *list == FilterList::Exit
            && c_action == action
            && covers(classify(fields), opposite)
            && (syscalls.is_empty() || syscalls.iter().any(|x| x.as_str() == s))
    })
}

/// Build the operator-facing warning naming the unaudited syscalls and the fix.
fn message(pinned: Abi, uncovered: &[&str]) -> String {
    let list = uncovered.join(", ");
    let (pinned_bits, unaudited_bits, fix) = match pinned {
        Abi::B64 => ("64-bit", "32-bit", "b32"),
        Abi::B32 => ("32-bit", "64-bit", "b64"),
    };
    format!(
        "syscall rule pins the {pinned_bits} ABI; {unaudited_bits} invocations of \
         {list} are unaudited - add a matching -F arch={fix} rule"
    )
}

/// au-W04 -- a syscall rule pins one ABI with no companion on the opposite ABI.
#[must_use]
pub fn w04(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for r in rules {
        let AuditRule::Syscall {
            list,
            action,
            syscalls,
            fields,
            ..
        } = &r.rule
        else {
            continue;
        };
        if *list != FilterList::Exit {
            continue; // only exit-list rules are checked (decision 4)
        }
        if *action == Action::Never {
            continue; // never is suppressive, not additive
        }
        if syscalls.is_empty() {
            continue; // wildcard rule: the uncovered set is unnameable
        }
        let Coverage::One(abi) = classify(fields) else {
            continue; // unpinned or unclassifiable: not a single-ABI gap
        };
        let opposite = abi.opposite();

        let mut uncovered: Vec<&str> = Vec::new();
        for s in syscalls {
            if !syscall_covered(s, opposite, action, rules) {
                uncovered.push(s.as_str());
            }
        }
        uncovered.sort_unstable();
        uncovered.dedup();
        if uncovered.is_empty() {
            continue;
        }

        diags.push(anchored(
            Severity::Warning,
            "au-W04",
            r.span.clone(),
            message(abi, &uncovered),
            r.file.clone(),
            r.line,
        ));
    }
    diags
}
