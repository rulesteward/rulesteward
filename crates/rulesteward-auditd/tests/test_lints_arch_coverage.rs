//! RED barrier tests for au-W04 (missing-ABI coverage, Warning) -- issue #261.
//!
//! Emitted by `lints::arch_coverage::w04(&[LocatedRule])`. A syscall audit rule
//! is PER-ABI: `-a always,exit -F arch=b64 -S execve` audits only 64-bit
//! `execve`; the same syscall from a 32-bit process (the b32 ABI) is UNAUDITED.
//! The b32 ABI is live on rhel8/9/10 (`CONFIG_IA32_EMULATION=y`, default-enabled,
//! primary-source verified on the Rocky VMs 2026-06-16), so the check is
//! version-INDEPENDENT and needs no `--target`. CIS / DISA-STIG rulesets ship
//! every syscall rule as a matched b32+b64 pair; a lone-ABI rule is a silent gap.
//!
//! # Locked decisions (owner-ratified, issue #261)
//! * Code = `au-W04` (revived; the old `-D`-after-load au-W04 was cut, D6).
//! * SYMMETRIC: a lone `arch=b64` warns "32-bit unaudited"; a lone `arch=b32`
//!   warns "64-bit unaudited".
//! * Companion must share the EXACT same action (an `always` rule needs an
//!   `always` companion; a `possible` companion does not satisfy it).
//! * Only `exit`-list rules are CHECKED; companion search is within the Exit list.
//!
//! # ABI classification (mirrors bands.rs:206-208's Eq/Ne handling)
//! * no `arch` field          -> covers BOTH ABIs (not a gap; counts as companion)
//! * `arch=b64` | `arch!=b32` -> selects b64
//! * `arch=b32` | `arch!=b64` -> selects b32
//! * anything else (machine-name `x86_64`/`i386`, non-Eq/Ne op, 2+ arch fields)
//!   -> UNCLASSIFIABLE: conservatively covers BOTH (never a false positive) and
//!   is never itself checked (documented v1 false-negative, matching value.rs:566).
//!
//! # Grounding
//! * `arch` selects the syscall ABI; rules match per-arch: auditctl(8),
//!   audit.rules(7).
//! * b32 ABI live on rhel8/9/10 (kernel `CONFIG_IA32_EMULATION=y`), issue #261 table.

use std::path::Path;

use rulesteward_auditd::lints::arch_coverage::w04;
use rulesteward_auditd::lints::catalog::AU_CODES;
use rulesteward_auditd::parse_rules_str_located;
use rulesteward_core::Severity;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a single-file fixture (rule per physical line, 1-based line numbers).
fn parse(input: &str) -> Vec<rulesteward_auditd::LocatedRule> {
    parse_rules_str_located(input, Path::new("10-arch.rules")).expect("fixture must parse")
}

// ===========================================================================
// T1 -- lone arch=b64 pin fires au-W04 (32-bit ABI unaudited)
// ===========================================================================
#[test]
fn t1_lone_b64_pin_fires_w04_naming_the_syscall() {
    let rules = parse("-a always,exit -F arch=b64 -S execve -k exec\n");
    let diags = w04(&rules);

    assert_eq!(diags.len(), 1, "a lone b64 pin is a gap, got {diags:?}");
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning, "au-W04 is a Warning");
    assert_eq!(d.code, "au-W04");
    assert_eq!(d.line, 1, "anchored at the offending rule");
    assert_eq!(d.column, 1, "auditd convention: column is always 1");
    assert!(
        d.message.contains("execve"),
        "message must name the unaudited syscall, got {:?}",
        d.message
    );
    assert!(
        d.message.contains("32-bit"),
        "a b64 pin leaves the 32-bit ABI unaudited, got {:?}",
        d.message
    );
    assert!(
        d.message.contains("-F arch=b32"),
        "message must name the fix (-F arch=b32), got {:?}",
        d.message
    );
}

// ===========================================================================
// T2 -- a matched b64+b32 pair is clean (the CIS/STIG idiom)
// ===========================================================================
#[test]
fn t2_matched_b64_b32_pair_is_clean() {
    let rules = parse(concat!(
        "-a always,exit -F arch=b64 -S execve -k exec\n",
        "-a always,exit -F arch=b32 -S execve -k exec\n",
    ));
    assert!(
        w04(&rules).is_empty(),
        "a matched pair covers both ABIs -- no gap"
    );
}

// ===========================================================================
// T3 -- a syscall rule with NO arch field matches all ABIs (not a gap)
// ===========================================================================
#[test]
fn t3_unpinned_rule_is_not_a_gap() {
    let rules = parse("-a always,exit -S execve -F auid>=1000 -k exec\n");
    assert!(
        w04(&rules).is_empty(),
        "no arch field => matches all ABIs => never warned"
    );
}

// ===========================================================================
// T4 -- lone arch=b32 pin fires (64-bit unaudited): symmetry
// ===========================================================================
#[test]
fn t4_lone_b32_pin_fires_symmetric_direction() {
    let rules = parse("-a always,exit -F arch=b32 -S execve -k exec\n");
    let diags = w04(&rules);

    assert_eq!(diags.len(), 1, "a lone b32 pin is a gap too (symmetry)");
    let d = &diags[0];
    assert_eq!(d.code, "au-W04");
    assert!(
        d.message.contains("64-bit"),
        "a b32 pin leaves the 64-bit ABI unaudited, got {:?}",
        d.message
    );
    assert!(
        d.message.contains("-F arch=b64"),
        "the fix for a b32 pin is -F arch=b64, got {:?}",
        d.message
    );
}

// ===========================================================================
// T5 -- arch!=b32 (Ne) is a b64 pin by exclusion -> fires
// Kills an operator-blind `value == "b32"` mutation that ignores Ne.
// ===========================================================================
#[test]
fn t5_ne_b32_is_a_b64_pin_and_fires() {
    let rules = parse("-a always,exit -F arch!=b32 -S execve -k exec\n");
    let diags = w04(&rules);

    assert_eq!(
        diags.len(),
        1,
        "arch!=b32 selects b64 by exclusion -> 32-bit gap"
    );
    assert!(
        diags[0].message.contains("-F arch=b32"),
        "Ne b32 == b64 pin -> fix is -F arch=b32, got {:?}",
        diags[0].message
    );
}

// ===========================================================================
// T6 -- arch!=b32 paired with arch=b32 is clean (Ne recognized both ways)
// ===========================================================================
#[test]
fn t6_ne_b32_paired_with_eq_b32_is_clean() {
    let rules = parse(concat!(
        "-a always,exit -F arch!=b32 -S execve -k exec\n",
        "-a always,exit -F arch=b32 -S execve -k exec\n",
    ));
    assert!(
        w04(&rules).is_empty(),
        "Ne-b32 (=b64) + Eq-b32 covers both ABIs"
    );
}

// ===========================================================================
// T7 -- a task-list b32 rule is NOT an Exit-list companion (decision 4)
// ===========================================================================
#[test]
fn t7_task_list_is_not_an_exit_companion() {
    let rules = parse(concat!(
        "-a always,exit -F arch=b64 -S execve -k exec\n",
        "-a always,task -F arch=b32 -S execve -k exec\n",
    ));
    let diags = w04(&rules);

    assert_eq!(
        diags.len(),
        1,
        "the exit b64 rule has no EXIT-list b32 companion (task != exit), got {diags:?}"
    );
    assert_eq!(
        diags[0].line, 1,
        "only the exit rule is checked and uncovered"
    );
}

// ===========================================================================
// T8 -- a -C field-compare on one side does not block the companion match
// ===========================================================================
#[test]
fn t8_field_compares_do_not_block_companion() {
    let rules = parse(concat!(
        "-a always,exit -F arch=b64 -S execve -C uid!=euid -k exec\n",
        "-a always,exit -F arch=b32 -S execve -k exec\n",
    ));
    assert!(
        w04(&rules).is_empty(),
        "coverage is per (list, action, ABI, syscall); -C narrowing is irrelevant"
    );
}

// ===========================================================================
// T9 -- syscall-set membership is order-insensitive
// ===========================================================================
#[test]
fn t9_companion_match_is_order_insensitive() {
    let rules = parse(concat!(
        "-a always,exit -F arch=b64 -S settimeofday -S clock_settime -k time\n",
        "-a always,exit -F arch=b32 -S clock_settime -S settimeofday -k time\n",
    ));
    assert!(
        w04(&rules).is_empty(),
        "both syscalls are covered regardless of -S order"
    );
}

// ===========================================================================
// T10 -- one diagnostic per rule, listing all uncovered syscalls sorted+deduped
// ===========================================================================
#[test]
fn t10_one_diag_lists_uncovered_syscalls_sorted_deduped() {
    // read appears twice (dedup); input order is unsorted (sort).
    let rules = parse("-a always,exit -F arch=b64 -S read -S open -S read -S close -k io\n");
    let diags = w04(&rules);

    assert_eq!(
        diags.len(),
        1,
        "ONE diagnostic for the rule, not one per syscall"
    );
    assert!(
        diags[0].message.contains("close, open, read"),
        "uncovered syscalls must be sorted + deduped, got {:?}",
        diags[0].message
    );
}

// ===========================================================================
// T11 -- an empty-syscall (-S-less) opposite-ABI rule is a wildcard companion
// ===========================================================================
#[test]
fn t11_empty_syscall_companion_covers_all() {
    let rules = parse(concat!(
        "-a always,exit -F arch=b64 -S execve -k exec\n",
        "-a always,exit -F arch=b32 -F auid>=1000 -k allb32\n",
    ));
    assert!(
        w04(&rules).is_empty(),
        "a b32 rule with no -S audits every b32 syscall -> covers execve"
    );
}

// ===========================================================================
// T12 -- a machine-name pin (x86_64) is unclassifiable -> never checked (FN)
// ===========================================================================
#[test]
fn t12_machine_name_pin_is_not_checked() {
    let rules = parse("-a always,exit -F arch=x86_64 -S execve -k exec\n");
    assert!(
        w04(&rules).is_empty(),
        "x86_64 is unclassifiable in v1 -> conservatively not checked (documented FN)"
    );
}

// ===========================================================================
// T13 -- a machine-name pin counts as covers-both for a real b32 rule's companion
// (the conservative direction that prevents a false positive)
// ===========================================================================
#[test]
fn t13_machine_name_companion_suppresses_false_positive() {
    let rules = parse(concat!(
        "-a always,exit -F arch=b32 -S execve -k exec\n",
        "-a always,exit -F arch=x86_64 -S execve -k exec\n",
    ));
    assert!(
        w04(&rules).is_empty(),
        "x86_64 read as covers-both -> the b32 rule's b64 side is covered"
    );
}

// ===========================================================================
// T14 -- exact-same-action: a `possible` companion does NOT cover an `always`
// rule (decision 3). With symmetry both rules are checked, so BOTH fire.
// ===========================================================================
#[test]
fn t14_mismatched_action_does_not_cover_both_directions() {
    let rules = parse(concat!(
        "-a always,exit -F arch=b64 -S execve -k exec\n",
        "-a possible,exit -F arch=b32 -S execve -k exec\n",
    ));
    let diags = w04(&rules);

    // The always-b64 rule needs an always-b32 companion (the possible-b32 rule
    // is the wrong action); the possible-b32 rule needs a possible-b64 companion
    // (the always-b64 rule is the wrong action). Exact-same-action => 2 gaps.
    assert_eq!(
        diags.len(),
        2,
        "exact-same-action: neither rule has a same-action companion, got {diags:?}"
    );
    let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
    assert!(
        lines.contains(&1) && lines.contains(&2),
        "one per checked rule"
    );
}

// ===========================================================================
// T15 -- a never-action rule is suppressive, not checked
// ===========================================================================
#[test]
fn t15_never_action_is_not_checked() {
    let rules = parse("-a never,exit -F arch=b64 -S execve -k exec\n");
    assert!(
        w04(&rules).is_empty(),
        "never is suppressive (not additive) -> no ABI-coverage gap to warn"
    );
}

// ===========================================================================
// T16 -- a -A (prepend) companion still covers (prepend is irrelevant to ABI)
// ===========================================================================
#[test]
fn t16_prepend_companion_still_covers() {
    let rules = parse(concat!(
        "-a always,exit -F arch=b64 -S execve -k exec\n",
        "-A always,exit -F arch=b32 -S execve -k exec\n",
    ));
    assert!(
        w04(&rules).is_empty(),
        "ordering (-a vs -A) does not change which ABI a rule audits"
    );
}

// ===========================================================================
// T17 -- catalog carries au-W04 as a Warning
// ===========================================================================
#[test]
fn t17_catalog_has_au_w04_warning() {
    let entry = AU_CODES
        .iter()
        .find(|c| c.code == "au-W04")
        .expect("au-W04 must be catalogued");
    assert_eq!(entry.severity, Severity::Warning, "au-W04 is a Warning");
    assert!(
        !entry.description.trim().is_empty(),
        "au-W04 needs an operator-facing description"
    );
}

// ===========================================================================
// T18 -- two independent uncovered rules => two diagnostics (one per rule)
// ===========================================================================
#[test]
fn t18_two_independent_gaps_two_diagnostics() {
    let rules = parse(concat!(
        "-a always,exit -F arch=b64 -S execve -k exec\n",
        "-a always,exit -F arch=b64 -S open -k io\n",
    ));
    let diags = w04(&rules);

    assert_eq!(
        diags.len(),
        2,
        "each lone-ABI rule is its own gap, got {diags:?}"
    );
    assert_eq!(diags[0].line, 1);
    assert_eq!(diags[1].line, 2);
}

// ===========================================================================
// T19 -- arch=B64 (uppercase) is a b64 pin: auditctl matches the ABI token
// case-insensitively (libaudit `strcasecmp("b64", arch)`), and the parser
// stores the value verbatim, so a case-blind impl would silently skip it.
// ===========================================================================
#[test]
fn t19_uppercase_b64_pin_fires() {
    let rules = parse("-a always,exit -F arch=B64 -S execve -k exec\n");
    let diags = w04(&rules);

    assert_eq!(
        diags.len(),
        1,
        "arch=B64 == arch=b64 (auditctl is case-insensitive) -> lone-b64 gap, got {diags:?}"
    );
    assert!(
        diags[0].message.contains("32-bit") && diags[0].message.contains("-F arch=b32"),
        "got {:?}",
        diags[0].message
    );
}

// ===========================================================================
// T20 -- arch=B32 (uppercase) symmetric: a b32 pin, 64-bit unaudited.
// ===========================================================================
#[test]
fn t20_uppercase_b32_pin_fires() {
    let rules = parse("-a always,exit -F arch=B32 -S execve -k exec\n");
    let diags = w04(&rules);

    assert_eq!(
        diags.len(),
        1,
        "arch=B32 == arch=b32 -> lone-b32 gap (symmetry), got {diags:?}"
    );
    assert!(
        diags[0].message.contains("64-bit") && diags[0].message.contains("-F arch=b64"),
        "got {:?}",
        diags[0].message
    );
}

// ===========================================================================
// T21 -- a mixed-case matched pair is clean: the companion match folds case
// too (a B64-checked rule finds its b32 companion and vice versa).
// ===========================================================================
#[test]
fn t21_mixed_case_matched_pair_is_clean() {
    let rules = parse(concat!(
        "-a always,exit -F arch=B64 -S execve -k exec\n",
        "-a always,exit -F arch=b32 -S execve -k exec\n",
    ));
    assert!(
        w04(&rules).is_empty(),
        "B64 + b32 cover both ABIs regardless of case"
    );
}

// ===========================================================================
// T22 -- au-W04 is wired into the lint() dispatcher (kills a dispatcher
// `lint -> vec![]` mutation the per-crate gate would otherwise miss, since
// the dispatcher's only other coverage is the cli-crate e2e tests).
// ===========================================================================
#[test]
fn t22_dispatcher_includes_au_w04() {
    use rulesteward_auditd::lints::lint;
    let rules = parse("-a always,exit -F arch=b64 -S execve -k exec\n");
    let diags = lint(&rules);
    assert!(
        diags.iter().any(|d| d.code == "au-W04"),
        "lint() must run the arch_coverage pass, got {diags:?}"
    );
}
