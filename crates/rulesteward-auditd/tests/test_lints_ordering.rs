//! RED barrier tests for au-W02 (shadow/subsumption), au-E01 (post-lock unreachable),
//! au-W03 (suppression conflict), and au-W04 (mid-stream -D) - issue #193, pipeline P2.
//!
//! # Grounding
//!
//! ## Kernel first-match semantics
//! The kernel evaluates syscall rules on each filter list in load order; the
//! FIRST matching rule wins and no further rules on that list are consulted.
//! Source: `man 7 audit.rules` "Rules are evaluated in load order"; f3
//! section 2.3 (f3-auditd-cost-grounding.md).
//!
//! ## -A (prepend) head-insertion: EFFECTIVE order differs from file order
//! `-A` sets `AUDIT_FILTER_PREPEND = 0x10` (kernel `linux/audit.h:185`),
//! which inserts the rule at the HEAD of the filter list rather than the tail.
//! Source: `audit-src/src/auditctl.c:864` (audit commit 3bfa048).
//! MULTIPLE -A rules net-REVERSE relative to each other: each prepend inserts
//! at the current head, so the LAST -A rule in file/stream order ends up FIRST
//! in effective order. Every w02 and w03 test that involves -A rules is written
//! against EFFECTIVE order, not file order.
//!
//! ## -e 2 immutability
//! `auditctl(8)` `-e 2` makes the audit configuration immutable until reboot;
//! subsequent `auditctl` invocations fail with EPERM. Any rule in the
//! concatenated stream that appears AFTER the first `-e 2` line (in lexical
//! order) never loads. au-E01 fires at those rules (`Severity::Error`).
//!
//! ## exclude/never suppression model
//! Source: f3-auditd-cost-grounding.md section 3.5 + flagtab.h:25-29
//! (audit 3bfa048). A `never`-action rule on the exit list suppresses
//! events for matching traffic; an `exclude`-list rule suppresses entire
//! record types by msgtype. au-W03 fires when such a rule (in EFFECTIVE
//! order) precedes and suppresses an `always` rule that intends to record
//! the same events.
//!
//! ## D2 (canonical-equal = au-W01, skip in w02)
//! A pair whose `canonical_key` values are EQUAL is a P1 au-W01 duplicate;
//! w02 MUST skip it. Source: owner decision D2, normalize.rs.
//!
//! ## Subsumption with interval arithmetic (#219, supersedes the v1 D4 pin)
//! Subsumption: same filter list+action, earlier rule's syscall set is a
//! SUPERSET (order-insensitive) of the later's, and every earlier field
//! predicate is IMPLIED BY a later predicate on the same field
//! (`value::implies`): exact match, a folded-equal value, a broader relational
//! threshold (`-F auid>=1000` DOES subsume `-F auid>=2000`), or a relational
//! range containing a later `=` point. Ne/bitmask/opaque operands match only
//! exactly, and the uid/gid sentinel never participates in interval math.
//! Source: #219 (was owner decision D4, v1 structural-only).
//!
//! ## Emission convention
//! au-W02, au-E01, au-W03, au-W04 emit at the SHADOWED/UNREACHABLE/SUPPRESSED
//! rule's file+line+span (column 1 by the `lints::anchored` convention). The
//! message cites the shadowing/lock/suppressing rule's `file:line`.

use std::path::Path;

use rulesteward_auditd::{
    lints::{
        LintOptions,
        ordering::{e01, w02, w03},
    },
    parse_rules_str_located, parse_target_located,
};
use rulesteward_core::Severity;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fixture_dir(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lints/ordering")
        .join(rel)
}

fn corpus_dir(scenario: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/auditd")
        .join(scenario)
}

// ---------------------------------------------------------------------------
// au-W02 shadow/subsumption tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 1: broad-early/narrow-late same filter list fires au-W02
//
// Fixtures: shadow-broad-early/
//   10-broad.rules  line 3: -a always,exit -S execve -k exec_all
//   50-narrow.rules line 6: -a always,exit -S execve -F 'auid>=1000' -k exec_user
//                           (5 comment lines precede the rule; parser counts all lines)
//
// D4 subsumption: broad rule syscall set {execve} is a SUPERSET of narrow's {execve};
// broad rule field predicate set {} (empty) is a SUBSET of narrow's {auid>=1000}.
// Grounding: kernel first-match -- execve always matches the broad rule first, so the
// narrow rule never fires. au-W02 fires at line 6 of 50-narrow.rules.
//
// Adversarial: a naive "did a broader rule appear first?" impl that only checks
// syscall-set containment (ignoring field predicates) would be wrong for cases where
// the broad rule also has more field predicates.
// ---------------------------------------------------------------------------
#[test]
fn w02_broad_early_narrow_late_fires() {
    let dir = fixture_dir("shadow-broad-early");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "expected 2 rules, got {rules:?}");

    let diags = w02(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 au-W02 expected for broad-early/narrow-late, got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning, "au-W02 must be Warning");
    assert_eq!(d.code, "au-W02", "code must be au-W02");
    // Anchored at the SHADOWED rule (50-narrow.rules).
    assert!(
        d.file.to_string_lossy().contains("50-narrow"),
        "must anchor at 50-narrow.rules, got file={:?}",
        d.file
    );
    // 50-narrow.rules has 5 comment lines before the rule (lines 1-5 are comments).
    // The parser (parse_target_located) counts comment and blank lines; rule is on line 6.
    assert_eq!(
        d.line, 6,
        "50-narrow.rules: rule is on line 6 (5 comment lines precede)"
    );
    assert_eq!(
        d.column, 1,
        "auditd anchoring convention: column is always 1"
    );
    // Message must cite the shadowing rule by its distinct filename token (10-broad.rules).
    // This cannot be satisfied by 50-narrow.rules' own filename, so it is a non-vacuous pin.
    assert!(
        d.message.contains("10-broad"),
        "message must cite 10-broad.rules, got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 2: canonical-equal pair does NOT fire au-W02 (D2 boundary)
//
// A pair whose canonical_key values are EQUAL is a P1 au-W01 duplicate.
// w02 MUST skip it. Source: owner decision D2.
//
// Adversarial: an impl that skips the D2 check would fire au-W02 on this pair,
// producing BOTH a W01 and a W02 for the same pair (double-reporting a simple dup).
// ---------------------------------------------------------------------------
#[test]
fn w02_canonical_equal_pair_does_not_fire() {
    // Two rules with identical content, identical key: canonical-equal (W01 territory).
    // w02 must return empty for this pair.
    let input = concat!(
        "-a always,exit -S execve -k exec_all\n",
        // Same rule repeated byte-for-byte: canonical_key equal -> W01, not W02.
        "-a always,exit -S execve -k exec_all\n",
    );
    let file = Path::new("10-same.rules");
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 2);

    let diags = w02(&rules, LintOptions::default());

    assert!(
        diags.is_empty(),
        "w02 must NOT fire on a canonical-equal pair (D2 boundary: that is W01 territory), \
         got {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: predicate-equal-but-key-differs DOES fire au-W02
//
// Same list/action/syscalls/fields, but different -k key => NOT canonical-equal
// (canonical_key includes the key). The LATER rule's key can never fire because
// first-match gives the earlier rule all the matching traffic.
// Grounding: normalize.rs:74 -- key is included in the canonical key.
// ---------------------------------------------------------------------------
#[test]
fn w02_predicate_equal_different_key_fires() {
    // Earlier: syscall rule with key "exec_audit" in "10-keydiff.rules"
    // Later: same predicates, different key "exec_priv" -- the later key never fires.
    // The shadowing rule is at 10-keydiff.rules:1; the shadowed rule is at
    // 10-keydiff.rules:2. The message must cite the shadowing file:line token
    // "10-keydiff.rules:1" (distinct from the anchored rule's own line "2").
    let input = concat!(
        "-a always,exit -S execve -F 'auid>=1000' -k exec_audit\n",
        "-a always,exit -S execve -F 'auid>=1000' -k exec_priv\n",
    );
    let file = Path::new("10-keydiff.rules");
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 2);

    let diags = w02(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "predicate-equal but key-differs must fire au-W02, got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning);
    assert_eq!(d.code, "au-W02");
    // Shadowed rule is the LATER one (second line, line 2 in the file).
    assert_eq!(d.file, file, "must anchor at the source file");
    assert_eq!(d.line, 2, "the later rule (line 2) is shadowed");
    assert_eq!(d.column, 1);
    // Message must cite the shadowing rule's file:line. The token "10-keydiff.rules:1"
    // cannot be produced by simply echoing the anchored rule's own filename or line
    // number alone, making this a non-vacuous pin.
    assert!(
        d.message.contains("10-keydiff.rules:1"),
        "message must cite 10-keydiff.rules:1 (the shadowing rule's distinct file:line token), \
         got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 4: cross-file shadow fires au-W02
//
// Fixtures: cross-file-shadow/
//   10-broad.rules  line 3: -a always,exit -S open -S close -F arch=b64 -k fs_access
//   50-narrow.rules line 6: -a always,exit -S open -F arch=b64 -F auid>=1000 -k fs_access_user
//                           (5 comment lines precede the rule in 50-narrow.rules)
//
// D4: broad has syscall superset {open, close} of narrow's {open}; broad's field
// predicates {arch=b64} are an EXACT subset of narrow's {arch=b64, auid>=1000}.
// au-W02 fires at 50-narrow.rules line 6; message cites 10-broad.rules:3.
// ---------------------------------------------------------------------------
#[test]
fn w02_cross_file_fires_at_later_file() {
    let dir = fixture_dir("cross-file-shadow");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "expected 2 rules, got {rules:?}");

    let diags = w02(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 au-W02 for cross-file shadow, got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning);
    assert_eq!(d.code, "au-W02");
    assert!(
        d.file.to_string_lossy().contains("50-narrow"),
        "must anchor at 50-narrow.rules, got {:?}",
        d.file
    );
    // 50-narrow.rules has 5 comment lines before the rule; parser counts all lines.
    assert_eq!(
        d.line, 6,
        "50-narrow.rules: rule is on line 6 (5 comment lines precede)"
    );
    assert_eq!(d.column, 1);
    // Message must cite the shadowing rule's distinct file:line token "10-broad.rules:3".
    // 10-broad.rules has 2 comment lines before its rule, which is on line 3.
    assert!(
        d.message.contains("10-broad.rules:3"),
        "message must cite 10-broad.rules:3 (the shadowing rule's distinct file:line token), \
         got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 5: late -A (prepend) rule in file order lands EARLY in effective order
//
// Fixtures: prepend-effective-order/
//   10-append-first.rules  line 4: -a always,exit -S execve -k exec_broad
//                                  (3 comment lines precede the rule)
//   50-prepend-last.rules  line 18: -A always,exit -S execve  (no key)
//                                   (17 comment lines precede the rule)
//
// Effective order (kernel's view):
//   [50-prepend -A rule, HEAD: syscall {execve}, no key]
//   [10-append -a rule, BACK: syscall {execve}, key exec_broad]
//
// Grounding: AUDIT_FILTER_PREPEND = 0x10 (kernel audit.h:185), set by
// auditctl.c:864 (audit-src 3bfa048). -A inserts at the HEAD of the exit
// list, so this rule overtakes the -a rule that was loaded earlier.
//
// D4 subsumption in EFFECTIVE order:
//   The -A rule (HEAD) syscall set {execve} is a superset of -a rule's {execve};
//   the -A rule's field predicates {} (empty) are a subset of -a rule's {} (empty).
//   Keys differ (one has exec_broad, one has no key) => NOT canonical-equal (D2).
//   => au-W02 fires at the -a rule in 10-append-first.rules (the later in EFFECTIVE
//      order, despite being EARLIER in file order).
//
// Adversarial: a FILE-ORDER-ONLY impl would either flag the -A rule (wrong) or
// see the -A rule as "later" and flag it -- but the -a rule is the one shadowed
// in EFFECTIVE order. Only an impl that tracks effective position fires correctly.
// ---------------------------------------------------------------------------
#[test]
fn w02_prepend_rule_file_late_effective_early_shadows_append_rule() {
    let dir = fixture_dir("prepend-effective-order");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "expected 2 rules, got {rules:?}");

    let diags = w02(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "au-W02 must fire exactly once: -A (file-order late, effective-order early) \
         shadows -a (file-order early, effective-order late), got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning);
    assert_eq!(d.code, "au-W02");
    // The SHADOWED rule is the -a rule in 10-append-first.rules (effective order: BACK).
    assert!(
        d.file.to_string_lossy().contains("10-append-first"),
        "must anchor at 10-append-first.rules (the -a rule, shadowed in effective order), \
         got file={:?}",
        d.file
    );
    // 10-append-first.rules has 3 comment lines before the rule; parser counts all lines.
    assert_eq!(
        d.line, 4,
        "10-append-first.rules: the rule is on line 4 (3 comment lines precede)"
    );
    assert_eq!(d.column, 1);
    // Message cites the SHADOWING rule's distinct file:line token "50-prepend-last.rules".
    // Since the files have clearly distinct names, this cannot be satisfied by the anchored
    // rule's own path "10-append-first".
    assert!(
        d.message.contains("50-prepend-last"),
        "message must cite 50-prepend-last.rules as the shadowing rule, got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 6: interval subsumption auid>=1000 subsumes auid>=2000 -> FIRES (#219)
//
// #219 (supersedes the v1 D4 pin): for a relational operator on a numeric/
// uid/gid field, a BROADER threshold subsumes a NARROWER one. `auid>=1000`
// matches a superset of `auid>=2000`'s traffic, so the later auid>=2000 rule
// is shadowed (kernel first-match). The reverse (narrow before broad) must NOT
// fire. Grounded by value::implies (interval containment).
// ---------------------------------------------------------------------------
#[test]
fn w02_interval_subsumption_fires_219() {
    let input = concat!(
        // Earlier: auid>=1000 (broad: all non-system users)
        "-a always,exit -S execve -F 'auid>=1000' -k exec_user\n",
        // Later: auid>=2000 (narrower threshold) -- shadowed by the broader rule.
        "-a always,exit -S execve -F 'auid>=2000' -k exec_highuid\n",
    );
    let file = Path::new("10-interval.rules");
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 2);

    let diags = w02(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "auid>=1000 must subsume auid>=2000 (#219 interval subsumption), got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.code, "au-W02");
    assert_eq!(d.severity, Severity::Warning);
    assert_eq!(d.line, 2, "the narrower later rule (line 2) is shadowed");
    assert!(
        d.message.contains("10-interval.rules:1"),
        "message must cite the broader rule, got {:?}",
        d.message
    );

    // Reverse order: a narrow earlier rule does NOT subsume a broad later one.
    let rev = concat!(
        "-a always,exit -S execve -F 'auid>=2000' -k exec_highuid\n",
        "-a always,exit -S execve -F 'auid>=1000' -k exec_user\n",
    );
    let rules_rev = parse_rules_str_located(rev, Path::new("10-rev.rules")).unwrap();
    assert!(
        w02(&rules_rev, LintOptions::default()).is_empty(),
        "auid>=2000 must NOT subsume auid>=1000 (narrow before broad)"
    );
}

// ---------------------------------------------------------------------------
// Test 6b: #219 interval-subsumption matrix (boundary, I2, fold, multi-field,
// signed exit). Each row is a wrong-impl tripwire from the design matrix.
// ---------------------------------------------------------------------------
#[test]
fn w02_gt_ge_boundary_fires_219() {
    // auid>1000 (>= 1001) subsumes auid>=2000.
    let input = concat!(
        "-a always,exit -S execve -F 'auid>1000' -k a\n",
        "-a always,exit -S execve -F 'auid>=2000' -k b\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-b.rules")).unwrap();
    assert_eq!(
        w02(&rules, LintOptions::default()).len(),
        1,
        "auid>1000 subsumes auid>=2000"
    );
}

#[test]
fn w02_eq_point_in_range_fires_219_i2() {
    // I2: auid>=1000 subsumes the single point auid=1500.
    let input = concat!(
        "-a always,exit -S execve -F 'auid>=1000' -k a\n",
        "-a always,exit -S execve -F 'auid=1500' -k b\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-i2.rules")).unwrap();
    assert_eq!(
        w02(&rules, LintOptions::default()).len(),
        1,
        "auid>=1000 subsumes auid=1500 (I2)"
    );

    // But auid=1500 (earlier) does NOT subsume auid>=1000 (later).
    let rev = concat!(
        "-a always,exit -S execve -F 'auid=1500' -k a\n",
        "-a always,exit -S execve -F 'auid>=1000' -k b\n",
    );
    let rr = parse_rules_str_located(rev, Path::new("10-i2r.rules")).unwrap();
    assert!(
        w02(&rr, LintOptions::default()).is_empty(),
        "an = point does not subsume a range"
    );
}

#[test]
fn w02_value_spelling_fold_fires_with_different_keys_219() {
    // auid!=-1 and auid!=4294967295 are the SAME predicate (folded). With
    // different keys they are not canonical-equal (W01), so the later is a W02
    // shadow. A verbatim-value impl would miss this.
    let input = concat!(
        "-a always,exit -S execve -F 'auid!=-1' -k a\n",
        "-a always,exit -S execve -F 'auid!=4294967295' -k b\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-fold.rules")).unwrap();
    let diags = w02(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "folded-equal predicate + different key -> W02, got {diags:?}"
    );
    assert_eq!(diags[0].line, 2);
}

#[test]
fn w02_multi_field_subsumption_219() {
    // Every earlier predicate must be witnessed: auid>=1000 -F uid=0 subsumes
    // auid>=2000 -F uid=0 (both predicates implied).
    let both = concat!(
        "-a always,exit -S execve -F 'auid>=1000' -F uid=0 -k a\n",
        "-a always,exit -S execve -F 'auid>=2000' -F uid=0 -k b\n",
    );
    let r = parse_rules_str_located(both, Path::new("10-mf.rules")).unwrap();
    assert_eq!(
        w02(&r, LintOptions::default()).len(),
        1,
        "both predicates witnessed -> shadow"
    );

    // If the later rule LACKS uid=0, the earlier uid=0 predicate is unwitnessed
    // (the later rule also matches uid!=0 traffic the earlier excludes) -> n/f.
    let missing = concat!(
        "-a always,exit -S execve -F 'auid>=1000' -F uid=0 -k a\n",
        "-a always,exit -S execve -F 'auid>=2000' -k b\n",
    );
    let r2 = parse_rules_str_located(missing, Path::new("10-mf2.rules")).unwrap();
    assert!(
        w02(&r2, LintOptions::default()).is_empty(),
        "earlier uid=0 has no witness in the later rule -> not subsumed"
    );
}

#[test]
fn w02_extra_later_predicate_does_not_block_219() {
    // A later rule that is NARROWER (extra constraint) is still shadowed by the
    // broader earlier rule: auid>=2000 subsumes auid>=2000 -F uid=0.
    let input = concat!(
        "-a always,exit -S execve -F 'auid>=2000' -k a\n",
        "-a always,exit -S execve -F 'auid>=2000' -F uid=0 -k b\n",
    );
    let r = parse_rules_str_located(input, Path::new("10-extra.rules")).unwrap();
    assert_eq!(
        w02(&r, LintOptions::default()).len(),
        1,
        "extra later predicate does not block subsumption"
    );
}

#[test]
fn w02_signed_exit_interval_219() {
    // exit is signed: exit>=-13 subsumes exit>=-5 (since -5 >= -13).
    let input = concat!(
        "-a always,exit -S execve -F 'exit>=-13' -k a\n",
        "-a always,exit -S execve -F 'exit>=-5' -k b\n",
    );
    let r = parse_rules_str_located(input, Path::new("10-sx.rules")).unwrap();
    assert_eq!(
        w02(&r, LintOptions::default()).len(),
        1,
        "exit>=-13 subsumes exit>=-5 (signed)"
    );

    // exit>=-13 does NOT subsume exit>=-20 (-20 < -13: later matches more).
    let wider = concat!(
        "-a always,exit -S execve -F 'exit>=-13' -k a\n",
        "-a always,exit -S execve -F 'exit>=-20' -k b\n",
    );
    let r2 = parse_rules_str_located(wider, Path::new("10-sx2.rules")).unwrap();
    assert!(
        w02(&r2, LintOptions::default()).is_empty(),
        "exit>=-13 does not subsume exit>=-20"
    );
}

#[test]
fn w02_sentinel_in_relational_is_conservative_219() {
    // auid>=0 (concrete 0) vs auid>=4294967295 (the unset sentinel): no interval
    // math on the sentinel -> conservative, must NOT fire.
    let input = concat!(
        "-a always,exit -S execve -F 'auid>=0' -k a\n",
        "-a always,exit -S execve -F 'auid>=4294967295' -k b\n",
    );
    let r = parse_rules_str_located(input, Path::new("10-sent.rules")).unwrap();
    assert!(
        w02(&r, LintOptions::default()).is_empty(),
        "concrete 0 vs sentinel must not fire (conservative)"
    );
}

// ---------------------------------------------------------------------------
// Test 7: different filter lists never interact for au-W02
//
// An exit-list rule and a task-list rule are on DIFFERENT filter lists;
// the kernel checks each list independently. A subsumption lint must only
// compare rules on THE SAME filter list.
// Grounding: flagtab.h:25-29 (audit 3bfa048) -- each list is independent.
// ---------------------------------------------------------------------------
#[test]
fn w02_different_filter_lists_do_not_interact() {
    let input = concat!(
        // exit-list rule (the common case)
        "-a always,exit -S execve -k exec_exit\n",
        // task-list rule: a completely separate filter applied at task creation
        "-a always,task -k task_create\n",
    );
    let file = Path::new("10-lists.rules");
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 2);

    let diags = w02(&rules, LintOptions::default());

    assert!(
        diags.is_empty(),
        "rules on different filter lists must not trigger w02 (they never interact), \
         got {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 8: earlier syscall SUPERSET shadows a later rule with subset syscalls
//
// Earlier: -S open -S close (syscall superset)
// Later:   -S open only (same fields, subset syscalls)
//
// D4: earlier rule's syscall set {open, close} is a SUPERSET of later's {open};
// earlier rule's field predicate set {} (empty) is a SUBSET of later's {} (empty).
// Keys differ ("fs_all" vs "fs_open") => NOT canonical-equal (D2).
// => au-W02 fires at the later rule.
//
// Adversarial: an impl that only checks whether the later syscall set is a
// SUPERSET of the earlier (backwards) would miss this.
// ---------------------------------------------------------------------------
#[test]
fn w02_earlier_syscall_superset_fires() {
    let input = concat!(
        "-a always,exit -S open -S close -k fs_all\n",
        // open only: a subset; the rule above matches all open calls first.
        "-a always,exit -S open -k fs_open\n",
    );
    let file = Path::new("10-superset.rules");
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 2);

    let diags = w02(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "earlier syscall-superset must fire au-W02 at the later narrower rule, got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning);
    assert_eq!(d.code, "au-W02");
    // Shadowed rule is the second one (line 2).
    assert_eq!(d.file, file, "diagnostic must anchor in the source file");
    assert_eq!(d.line, 2, "the narrower rule is on line 2 (shadowed)");
    assert_eq!(d.column, 1);
    // Message must cite the shadowing rule's distinct file:line token "10-superset.rules:1".
    // The token "10-superset.rules:1" is distinct from the anchored rule's own line "2",
    // so an impl that simply echoes the anchor file path cannot satisfy this assertion.
    assert!(
        d.message.contains("10-superset.rules:1"),
        "message must cite 10-superset.rules:1 (the syscall-superset rule's file:line token), \
         got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// au-E01 post-lock unreachable-rule tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 9: rule after -e 2 in the same file fires au-E01
//
// Fixtures: mid-stream-lock/10-rules.rules:
//   line 1:  # Base rules loaded before the lock.   (comment)
//   line 2:  -D
//   line 3:  -b 8192
//   line 4:  -a always,exit -S execve -F 'auid>=1000' -k exec_user
//   line 5:  -e 2                                   <- the lock
//   line 6:  # This rule appears after -e 2 ...     (comment)
//   line 7:  # grounding: auditctl(8)...             (comment)
//   line 8:  # subsequent auditctl...                (comment)
//   line 9:  # in the concatenated stream...         (comment)
//   line 10: -a always,exit -S mount -k mount_after_lock  <- au-E01 target
//
// Grounding: auditctl(8) -e 2 makes config immutable until reboot; any rule
// appearing after the lock in the concatenated stream never loads (au-E01, Error).
// The parser (parse_target_located) counts comment and blank lines; -e 2 is on
// line 5 and the unreachable rule is on line 10.
// ---------------------------------------------------------------------------
#[test]
fn e01_rule_after_lock_same_file_fires() {
    let dir = fixture_dir("mid-stream-lock");
    let rules = parse_target_located(&dir).expect("fixtures must parse");

    let diags = e01(&rules);

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 au-E01 for rule after -e 2 in the same file, got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(
        d.severity,
        Severity::Error,
        "au-E01 must be Error (not Warning)"
    );
    assert_eq!(d.code, "au-E01");
    assert_eq!(d.column, 1);
    // Anchored at the rule AFTER the lock (10-rules.rules).
    assert!(
        d.file.to_string_lossy().contains("10-rules"),
        "must anchor in 10-rules.rules, got {:?}",
        d.file
    );
    // The parser counts comment and blank lines. -e 2 is on line 5; there are 4
    // comment lines between the lock and the unreachable rule (lines 6-9); the
    // unreachable -S mount rule is on line 10.
    assert_eq!(
        d.line, 10,
        "the unreachable rule is on line 10 (after -e 2 on line 5, with 4 comment lines between)"
    );
    // Message must reference the lock so the operator knows why the rule is unreachable.
    assert!(
        d.message.to_lowercase().contains("-e 2")
            || d.message.to_lowercase().contains("lock")
            || d.message.to_lowercase().contains("immutable"),
        "message must explain the -e 2 lock, got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 10: rules in a lexically-LATER file than the file containing -e 2 fire
//
// Fixtures: cross-file-lock/
//   10-finalize.rules:
//     line 3: -a always,exit -S execve -k exec_before_lock
//     line 4: -e 2   <- the lock
//   50-after-lock.rules:
//     line 3: -a always,exit -S mount -k mount_unreachable  <- au-E01
//     line 4: -b 8192                                        <- au-E01 (control rule)
//
// Grounding: augenrules(8) lexical concat; -e 2 in 10-finalize.rules locks the
// config before any rule in 50-after-lock.rules can load.
// ---------------------------------------------------------------------------
#[test]
fn e01_rules_in_later_file_fire() {
    let dir = fixture_dir("cross-file-lock");
    let rules = parse_target_located(&dir).expect("fixtures must parse");

    let diags = e01(&rules);

    // Both rules in 50-after-lock.rules are unreachable.
    assert_eq!(
        diags.len(),
        2,
        "both rules in the post-lock file must fire au-E01, got {diags:?}"
    );
    for d in &diags {
        assert_eq!(d.severity, Severity::Error, "au-E01 is Error");
        assert_eq!(d.code, "au-E01");
        assert_eq!(d.column, 1);
        assert!(
            d.file.to_string_lossy().contains("50-after-lock"),
            "must anchor in 50-after-lock.rules, got {:?}",
            d.file
        );
    }
    // Message must cite the locking file.
    let msg0 = &diags[0].message;
    assert!(
        msg0.contains("10-finalize")
            || msg0.to_lowercase().contains("lock")
            || msg0.to_lowercase().contains("-e 2"),
        "message must cite the locking source, got {msg0:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 11: -e 2 as the very last line of the lexically-last file fires nothing
//
// Fixtures: standard-finalize/
//   10-rules.rules: -a always,exit -S execve -F 'auid>=1000' -k exec_user
//   99-finalize.rules: -b 8192 / -e 2  (lock is last line of last file)
//
// Grounding: the standard 99-finalize pattern. Nothing comes after the lock,
// so au-E01 fires nothing. This is the CORRECT deployment pattern.
// ---------------------------------------------------------------------------
#[test]
fn e01_standard_finalize_pattern_fires_nothing() {
    let dir = fixture_dir("standard-finalize");
    let rules = parse_target_located(&dir).expect("fixtures must parse");

    let diags = e01(&rules);

    assert!(
        diags.is_empty(),
        "standard 99-finalize pattern (-e 2 as last line of last file) must fire no \
         au-E01 diagnostics, got {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 12: a control rule (-b 8192) after the lock also fires au-E01
//
// Grounding: auditctl(8) -e 2 locks config immutable; any subsequent auditctl
// invocation fails with EPERM regardless of whether it is a data rule or a
// control rule. Control rules after the lock are unreachable too.
// ---------------------------------------------------------------------------
#[test]
fn e01_control_rule_after_lock_fires() {
    let input = concat!(
        "-e 2\n",
        // A control rule after the lock is also unreachable.
        "-b 8192\n",
    );
    let file = Path::new("10-control-after-lock.rules");
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 2);

    let diags = e01(&rules);

    assert_eq!(
        diags.len(),
        1,
        "a control rule after -e 2 must fire au-E01, got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Error);
    assert_eq!(d.code, "au-E01");
    assert_eq!(d.file, file);
    assert_eq!(d.line, 2, "the control rule is on line 2");
    assert_eq!(d.column, 1);
}

// ---------------------------------------------------------------------------
// Test 12b: NEGATIVE pin -- rules after -e 1 or -e 0 must NOT fire au-E01
//
// Grounding: auditctl(8): `-e 2` makes config IMMUTABLE (permanent lock until
// reboot); `-e 1` merely ENABLES audit (config remains mutable); `-e 0`
// DISABLES audit (config also remains mutable). Only -e 2 locks; subsequent
// auditctl invocations after -e 0 or -e 1 are NOT rejected with EPERM.
//
// Adversarial: an impl that treats any `-e N` as the lock (e.g., checking
// `-e` token presence without requiring N == 2) would incorrectly fire au-E01
// on rules that follow `-e 1` or `-e 0`. This test kills that wrong impl.
// ---------------------------------------------------------------------------
#[test]
fn e01_rule_after_e1_does_not_fire() {
    let input = concat!(
        // -e 1: enables audit, does NOT lock config (mutable after this).
        "-e 1\n",
        // A rule after -e 1 is perfectly reachable; au-E01 must NOT fire.
        "-a always,exit -S execve -k exec_user\n",
    );
    let file = Path::new("10-enable-not-lock.rules");
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 2);

    let diags = e01(&rules);

    assert!(
        diags.is_empty(),
        "-e 1 enables audit but does NOT lock the config; rules after -e 1 are \
         reachable and au-E01 must NOT fire, got {diags:?}"
    );
}

#[test]
fn e01_rule_after_e0_does_not_fire() {
    let input = concat!(
        // -e 0: disables audit, does NOT lock config (mutable after this).
        "-e 0\n",
        // A rule after -e 0 is perfectly reachable; au-E01 must NOT fire.
        "-b 8192\n",
    );
    let file = Path::new("10-disable-not-lock.rules");
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 2);

    let diags = e01(&rules);

    assert!(
        diags.is_empty(),
        "-e 0 disables audit but does NOT lock the config; rules after -e 0 are \
         reachable and au-E01 must NOT fire, got {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// au-W03 suppression conflict tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 13: exclude-list msgtype rule suppressing record types an always rule records
//
// Grounding: f3-auditd-cost-grounding.md section 3.5. An exclude-list rule with
// `msgtype=<N>` suppresses entire record types. If an always-action exit-list rule
// is present, the exclude rule may silently swallow the SYSCALL or other records
// that the always rule is supposed to produce. au-W03 fires at the ALWAYS rule.
// ---------------------------------------------------------------------------
#[test]
fn w03_exclude_msgtype_before_always_fires() {
    // A common operator mistake: suppress SYSCALL records globally via exclude-list,
    // then wonder why auditing stops working. The exclude fires at the kernel record-
    // filter stage, before the exit-list matching, so the syscall records are dropped.
    //
    // msgtype=1300 is AUDIT_SYSCALL per include/uapi/linux/audit.h (primary source).
    // Grounding: AUDIT_SYSCALL = 1300 (not 1309; 1309 = AUDIT_EXECVE, a distinct type).
    let input = concat!(
        // Suppress SYSCALL record type (msgtype=1300 = AUDIT_SYSCALL per linux/audit.h).
        "-a always,exclude -F msgtype=1300\n",
        // This always rule's events will never appear in the log because
        // the exclude filter above drops SYSCALL records globally.
        "-a always,exit -S execve -k exec_audit\n",
    );
    let file = Path::new("10-exclude-suppress.rules");
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 2);

    let diags = w03(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "exclude-list msgtype rule suppressing always rule must fire au-W03, got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning, "au-W03 is Warning");
    assert_eq!(d.code, "au-W03");
    assert_eq!(d.column, 1);
    // Anchored at the SUPPRESSED always rule (line 2).
    assert_eq!(d.file, file, "diagnostic must anchor in the source file");
    assert_eq!(d.line, 2, "the suppressed always rule is on line 2");
    // Message must cite the suppressing rule's distinct file:line token
    // "10-exclude-suppress.rules:1". This cannot be satisfied merely by echoing
    // the anchored rule's own filename or "exclude"/"msgtype" keywords; the
    // file:line token is the load-bearing citation that proves the impl found
    // the correct suppressing rule.
    assert!(
        d.message.contains("10-exclude-suppress.rules:1"),
        "message must cite 10-exclude-suppress.rules:1 (the suppressing exclude rule's \
         file:line token), got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 14a: never BEFORE always on exit list (same domain) fires au-W03
//
// Fixtures: never-suppress-before/audit.rules (9 comment/blank lines precede rules)
//   line 1:  # never-action BEFORE always ...   (comment)
//   line 2:  # grounding: ...                   (comment)
//   line 3:  # The never rule is first ...       (comment)
//   line 4:  # (suppressed rule), citing...      (comment)
//   line 5:  # ...                               (comment)
//   line 6:  #                                   (blank comment)
//   line 7:  # Effective order (kernel's view):  (comment)
//   line 8:  #   [never rule FIRST] ...          (comment)
//   line 9:  #   [always rule SECOND] ...        (comment)
//   line 10: -a never,exit -S execve -F uid=0 -k exec_root_suppress
//   line 11: -a always,exit -S execve -k exec_all
//
// Grounding: kernel first-match on the exit list. The never rule is FIRST in
// effective order (both use -a, so file order = effective order). For traffic
// matching uid=0 execve, the never rule fires first and suppresses; the always
// rule on line 11 never sees uid=0. au-W03 fires at the always rule (line 11),
// citing the never rule (line 10).
//
// Adversarial: this scenario is intentional in many deployments (suppress root,
// audit non-root). The lint fires as a WARNING to make the operator confirm the
// suppression is deliberate. It does not claim the always rule is fully dead --
// only that the never rule suppresses SOME of the traffic the always rule targets.
// ---------------------------------------------------------------------------
#[test]
fn w03_never_before_always_same_list_fires() {
    let dir = fixture_dir("never-suppress-before");
    let rules = parse_target_located(&dir).expect("fixtures must parse");

    let diags = w03(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "never-before-always on same exit list must fire au-W03, got {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning, "au-W03 is Warning");
    assert_eq!(d.code, "au-W03");
    assert_eq!(d.column, 1);
    // Anchored at the SUPPRESSED always rule.
    assert!(
        d.file.to_string_lossy().contains("never-suppress-before"),
        "must anchor in the fixture file, got {:?}",
        d.file
    );
    // The fixture has 9 comment lines before any rule (lines 1-9 are comments).
    // Parser counts all lines: never rule is on line 10, always rule is on line 11.
    assert_eq!(
        d.line, 11,
        "the always rule (suppressed) is on line 11 of audit.rules \
         (9 comment lines precede the rules; never rule on line 10)"
    );
    // Message must cite the suppressing never rule's distinct file:line token
    // "audit.rules:10". This is a non-vacuous pin: the cited line (10) differs
    // from the anchored line (11), so echoing the anchor's line cannot satisfy it.
    assert!(
        d.message.contains("audit.rules:10"),
        "message must cite audit.rules:10 (the suppressing never rule's file:line token), \
         got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 14b: never AFTER always (first-match: always wins) -- no au-W03
//
// Corpus: rocky9-never-below-always
//   Line 11: -a always,exit -S execve -k execve_all  (FIRST = wins)
//   Line 13: -a never,exit -S execve -F uid=0         (SECOND = inert)
//
// Grounding: f3 section 2.3 + corpus file comment. First-match means the always
// rule fires for all execve (including uid=0) before the never rule is consulted.
// The never rule is INERT (it never suppresses anything). au-W03 must NOT fire.
//
// This is a negative pin: w03 only fires when the SUPPRESSIVE rule precedes the
// ADDITIVE rule in effective order.
// ---------------------------------------------------------------------------
#[test]
fn w03_never_after_always_does_not_fire() {
    let corpus = corpus_dir("rocky9-never-below-always");
    let rules = parse_target_located(&corpus).expect("corpus must parse");

    let diags = w03(&rules, LintOptions::default());

    // The never rule is BELOW (after) the always rule -- it is inert, not suppressive.
    // au-W03 must NOT fire in this case.
    // Note: the corpus might also contain au-W02 findings if the rules overlap; we
    // only assert w03 is empty since w03 is position-sensitive (never BEFORE always).
    assert!(
        diags.is_empty(),
        "never-AFTER-always is inert; w03 must not fire (first-match: always wins), \
         got {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Clean-corpus negative tests
//
// The following well-known corpora must not generate any au-E01 or au-W04
// diagnostics, and their au-W02/au-W03 expectations are documented in comments.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Corpus negative: rocky9-stig-finalize
//
// Content (inspected 2026-06-12):
//   ## This file is automatically generated from /etc/audit/rules.d
//   -w /etc/passwd -p wa -k identity
//   -a always,exit -F arch=b64 -S execve -F 'auid>=1000' -F 'auid!=unset' -k exec
//   -e 2
//
// -e 2 is the last line: no rules follow the lock. au-E01 fires nothing.
// The watch and syscall rule are on different filter lists (filesystem vs exit)
// and have no subsumption relationship: au-W02 fires nothing.
// No never/exclude rules: au-W03 fires nothing.
// This is a single flat file, not a rules.d/: parse as a file, not a directory.
// ---------------------------------------------------------------------------
#[test]
fn corpus_rocky9_stig_finalize_no_e01_no_w04() {
    // Single-file corpus: parse as a file path, not a directory.
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/auditd/rocky9-stig-finalize/audit.rules");
    let rules = parse_target_located(&path).expect("corpus must parse");

    let e01_diags = e01(&rules);
    assert!(
        e01_diags.is_empty(),
        "rocky9-stig-finalize: -e 2 is last line, no au-E01 expected, got {e01_diags:?}"
    );

    // au-W02: the watch (-w) and syscall rule are on different filter lists.
    // No subsumption expected.
    let w02_diags = w02(&rules, LintOptions::default());
    assert!(
        w02_diags.is_empty(),
        "rocky9-stig-finalize: watch vs syscall are on different filter lists; \
         no au-W02 expected, got {w02_diags:?}"
    );

    // au-W03: no never/exclude rules in this corpus.
    let w03_diags = w03(&rules, LintOptions::default());
    assert!(
        w03_diags.is_empty(),
        "rocky9-stig-finalize: no never/exclude rules; no au-W03 expected, got {w03_diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Corpus negative: rocky9-never-below-always
//
// Content (inspected 2026-06-12): always FIRST, never SECOND (inert).
// See test 14b for the detailed reasoning. No e01/w04 expected.
// au-W03: the never rule is AFTER the always -- it is inert (already pinned in
// test 14b). au-W02: the always rule subsumes the never rule's subset traffic, but
// the always and never rules have different actions so they are NOT subsumption-
// comparable under D4 (subsumption applies to same-action rules that both fire).
// ---------------------------------------------------------------------------
#[test]
fn corpus_rocky9_never_below_always_no_e01() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/auditd/rocky9-never-below-always/audit.rules");
    let rules = parse_target_located(&path).expect("corpus must parse");

    let e01_diags = e01(&rules);
    assert!(
        e01_diags.is_empty(),
        "rocky9-never-below-always: no -e 2 in corpus; no au-E01 expected, got {e01_diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Corpus negative: rocky9-prepend-vs-append
//
// Content (inspected 2026-06-12):
//   -a always,exit -S execve -k execve_all         (append: goes to BACK)
//   -A exit,never -S execve -F uid=0               (prepend: goes to HEAD)
//
// Effective order: [never -A rule FIRST] -> [always -a rule SECOND]
// au-W03 fires at the always rule because the never rule is FIRST in effective order
// and suppresses uid=0 execve. This corpus is INTENTIONALLY the suppression scenario.
// We assert the TRUE expectation (au-W03 fires) rather than forcing zero.
// ---------------------------------------------------------------------------
#[test]
fn corpus_rocky9_prepend_vs_append_w03_fires_at_always_rule() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/auditd/rocky9-prepend-vs-append/audit.rules");
    let rules = parse_target_located(&path).expect("corpus must parse");

    // au-E01: no -e 2 in this corpus.
    let e01_diags = e01(&rules);
    assert!(
        e01_diags.is_empty(),
        "rocky9-prepend-vs-append: no -e 2; no au-E01 expected, got {e01_diags:?}"
    );

    // au-W03: the -A never rule is FIRST in effective order (prepended to HEAD),
    // suppressing the -a always rule which is SECOND. au-W03 fires at the always rule.
    // TRUE expectation: 1 au-W03 diagnostic.
    let w03_diags = w03(&rules, LintOptions::default());
    assert_eq!(
        w03_diags.len(),
        1,
        "rocky9-prepend-vs-append: -A never (effective HEAD) suppresses -a always \
         (effective BACK); au-W03 must fire at the always rule, got {w03_diags:?}"
    );
    let d = &w03_diags[0];
    assert_eq!(d.severity, Severity::Warning);
    assert_eq!(d.code, "au-W03");
    // The always rule is the first textual line (line 11 from the corpus file comments).
    // The always rule (-a) is on line 11 (counting from 1, after comments and blank lines).
    // Actual anchoring depends on the fixture content; assert it is the always rule.
    // We cannot assume exact line numbers from the comment-heavy corpus file, so just
    // assert the always rule is flagged (action-based check not possible without AST).
    // The w03 diagnostic is anchored at the SUPPRESSED always rule.
    assert_eq!(d.column, 1);
}

// ---------------------------------------------------------------------------
// Corpus negative: rocky10-rulesd-multifile
//
// Content (inspected 2026-06-12 - single flat audit.rules):
//   ## This file is automatically generated from /etc/audit/rules.d
//   -D
//   -b 8192
//   -w /etc/passwd -p wa -k identity
//   -a always,exit -F arch=b64 -S execve -F 'auid>=1000' -F 'auid!=unset' -k exec
//   -e 2
//
// -e 2 is the last rule: no au-E01 expected.
// -D is at the top (first non-comment rule): no mid-stream -D (no au-W04).
// No never/exclude rules: no au-W03.
// The watch and exit-list rule are on different filter lists: no au-W02.
// ---------------------------------------------------------------------------
#[test]
fn corpus_rocky10_rulesd_multifile_no_e01_no_w04() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/auditd/rocky10-rulesd-multifile/audit.rules");
    let rules = parse_target_located(&path).expect("corpus must parse");

    let e01_diags = e01(&rules);
    assert!(
        e01_diags.is_empty(),
        "rocky10-rulesd-multifile: -e 2 is last rule; no au-E01 expected, got {e01_diags:?}"
    );

    let w02_diags = w02(&rules, LintOptions::default());
    assert!(
        w02_diags.is_empty(),
        "rocky10-rulesd-multifile: watch vs exit-list rule, no subsumption expected, \
         got {w02_diags:?}"
    );

    let w03_diags = w03(&rules, LintOptions::default());
    assert!(
        w03_diags.is_empty(),
        "rocky10-rulesd-multifile: no never/exclude rules; no au-W03 expected, \
         got {w03_diags:?}"
    );
}

// ---------------------------------------------------------------------------
// #219: au-W03 interval-aware disjointness (W03 tightened)
//
// A never rule only suppresses an always rule when they can co-match. With
// interval reasoning a provably-disjoint never/always pair no longer fires
// au-W03 (removing a false positive), while overlapping pairs still fire.
// ---------------------------------------------------------------------------
#[test]
fn w03_disjoint_never_does_not_suppress_219() {
    // never uid=0 vs always uid>=1000: no shared uid value -> disjoint -> the
    // never cannot suppress the always -> no au-W03 (was a false positive).
    let input = concat!(
        "-a never,exit -S execve -F uid=0 -k root_sup\n",
        "-a always,exit -S execve -F 'uid>=1000' -k user_exec\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-w03d.rules")).unwrap();
    assert!(
        w03(&rules, LintOptions::default()).is_empty(),
        "disjoint never/always must not fire au-W03, got {:?}",
        w03(&rules, LintOptions::default())
    );
}

#[test]
fn w03_uid_name_vs_number_still_suppresses_219() {
    // uid=root and uid=0 denote the same user; the never rule DOES suppress the
    // always rule. The linter must not assume root != 0 (no passwd db), so the
    // alias-bearing Eq/Eq pair stays conservatively overlapping -> au-W03 fires.
    let input = concat!(
        "-a never,exit -S execve -F uid=root -k sup\n",
        "-a always,exit -S execve -F uid=0 -k rec\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-uidname.rules")).unwrap();
    assert_eq!(
        w03(&rules, LintOptions::default()).len(),
        1,
        "uid=root and uid=0 are the same user -> au-W03 fires, got {:?}",
        w03(&rules, LintOptions::default())
    );
}

#[test]
fn w03_overlapping_never_still_suppresses_219() {
    // never uid>=1000 vs always uid>=2000: overlapping ranges -> the never
    // suppresses the always -> au-W03 still fires.
    let input = concat!(
        "-a never,exit -S execve -F 'uid>=1000' -k sup\n",
        "-a always,exit -S execve -F 'uid>=2000' -k user_exec\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-w03o.rules")).unwrap();
    assert_eq!(
        w03(&rules, LintOptions::default()).len(),
        1,
        "overlapping never/always must still fire au-W03, got {:?}",
        w03(&rules, LintOptions::default())
    );
}

// ---------------------------------------------------------------------------
// #475 class 2: au-W03 -C inter-field-comparison contradiction disjointness
//
// Promotion (operator-locked, scope NARROWED by grounding, see the session
// 7c P3-class-2 grounding doc): a complementary `-C field=field` /
// `-C field!=field` pair on the SAME canonical field pair proves the two
// rules disjoint, but ONLY for the 16 PROCESS-vs-PROCESS AUDIT_COMPARE_*
// constants (libaudit.c's field1/field2 switch, rows 10-25 of the 25-row
// table; `AUDIT_MAX_FIELD_COMPARE` = 25, uapi_audit.h:211-243). The 9
// PROCESS-vs-OBJECT constants (*_TO_OBJ_UID / *_TO_OBJ_GID, rows 1-9) are
// EXCLUDED and MUST stay conservative (overlapping): the kernel dispatches
// them to `audit_compare_uid`/`audit_compare_gid` (auditsc.c:332-378), which
// existentially quantifies `=`/`!=` over `ctx->names_list` (ALL filesystem
// objects a syscall like rename(2)/link(2) touches, each with its own
// owning uid/gid) -- `=` and `!=` on the SAME pair can BOTH be true for one
// such event, so they are not true complements there.
//
// Legal `-C` syntax: only `=`/`!=` are valid operators (parser.rs:601-605;
// double-gated by libaudit.c:1099-1113 AND kernel auditfilter.c:408-413);
// every fixture below uses a legal field pair from the 25-row table so the
// parser accepts it as a REAL loadable rule (an illegal pair like `uid=uid`
// or `uid=egid` currently parses too in rulesteward today -- no cross-
// field-pair validation exists yet, a separate au-E04-family gap -- but
// using one here would test undefined/non-representative behavior, so none
// of the fixtures below use one).
//
// All rules below carry NO `-F` fields, only `-C`, so `field_disjoint` (the
// existing `-F`-only channel) is always false and `traffic_overlaps`'s
// verdict is driven ENTIRELY by whether the new `-C` channel recognizes the
// contradiction. Today (before the class-2 promotion) `-C` is completely
// ignored by `traffic_overlaps` (ordering.rs:144-156 never reads
// `field_compares`), so every pair below currently overlaps (au-W03 fires,
// 1 diag) regardless of what the `-C` clauses say. Tests asserting DISJOINT
// (0 diags, "_is_disjoint" names) are RED today; tests asserting the
// conservative/excluded NOT-disjoint verdict (1 diag, "_stays_conservative"
// / "_not_disjoint" names) are already GREEN today and MUST STAY GREEN
// after the promotion lands -- they are the soundness pins, in particular
// the two OBJECT-family tests below, which guard the single highest-risk
// false "provably disjoint" claim in this whole promotion.
// ---------------------------------------------------------------------------

#[test]
fn w03_c475_complementary_uid_euid_is_disjoint() {
    // RED. AUDIT_COMPARE_UID_TO_EUID (table row 11). `-C uid=euid` and
    // `-C uid!=euid` are exact logical complements for every event
    // (audit_uid_comparator, auditfilter.c:1229-1249, over a single scalar
    // cred->uid/cred->euid pair -- no names_list involved), so the two rules
    // can never co-match -> au-W03 must NOT fire.
    let input = concat!(
        "-a never,exit -S execve -C uid=euid -k c475_uid_euid_never\n",
        "-a always,exit -S execve -C uid!=euid -k c475_uid_euid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-uid-euid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C uid=euid vs -C uid!=euid are complements on AUDIT_COMPARE_UID_TO_EUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_auid_uid_is_disjoint() {
    // RED. AUDIT_COMPARE_UID_TO_AUID (table row 10).
    let input = concat!(
        "-a never,exit -S execve -C auid=uid -k c475_auid_uid_never\n",
        "-a always,exit -S execve -C auid!=uid -k c475_auid_uid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-auid-uid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C auid=uid vs -C auid!=uid are complements on AUDIT_COMPARE_UID_TO_AUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_gid_egid_is_disjoint() {
    // RED. AUDIT_COMPARE_GID_TO_EGID (table row 20), the GID-family twin of
    // audit_gid_comparator (auditfilter.c:1251-1271, byte-identical logic).
    let input = concat!(
        "-a never,exit -S execve -C gid=egid -k c475_gid_egid_never\n",
        "-a always,exit -S execve -C gid!=egid -k c475_gid_egid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-gid-egid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C gid=egid vs -C gid!=egid are complements on AUDIT_COMPARE_GID_TO_EGID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_operand_order_cross_spelling_contradictory_is_disjoint() {
    // RED. `-C uid=euid` and `-C euid!=uid` resolve to the SAME wire constant
    // (AUDIT_COMPARE_UID_TO_EUID) regardless of operand order: userspace
    // hard-codes both field1/field2 orderings to the same output constant
    // (libaudit.c:1274-1277 vs 1156-1159), and with opposite ops they are
    // still exact complements. A wrong impl that compares FieldComparison
    // operand-by-operand (left==left && right==right) without canonicalizing
    // order would MISS this and wrongly stay conservative.
    let input = concat!(
        "-a never,exit -S execve -C uid=euid -k c475_order_a_never\n",
        "-a always,exit -S execve -C euid!=uid -k c475_order_a_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-order-a.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C uid=euid vs -C euid!=uid canonicalize to the same pair with opposite \
         ops -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_operand_order_cross_spelling_same_op_not_disjoint() {
    // GREEN today and after. `-C uid=euid` and `-C euid=uid` are the
    // IDENTICAL rule spelled two ways (same wire constant, same op): not a
    // contradiction, they co-match every event that satisfies either. A
    // wrong impl that treats "operands swapped" alone as evidence of a
    // contradiction (confusing operand-order-difference with operator-
    // difference) would wrongly mark these disjoint -- a FALSE POSITIVE that
    // would silently drop a real au-W03 warning.
    let input = concat!(
        "-a never,exit -S execve -C uid=euid -k c475_order_b_never\n",
        "-a always,exit -S execve -C euid=uid -k c475_order_b_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-order-b.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C uid=euid vs -C euid=uid are the SAME rule spelled two ways (not a \
         contradiction) -> must stay overlapping -> au-W03 must still fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_same_op_same_pair_not_disjoint() {
    // GREEN today and after. An exact restatement is trivially
    // non-contradictory.
    let input = concat!(
        "-a never,exit -S execve -C uid=euid -k c475_restate_never\n",
        "-a always,exit -S execve -C uid=euid -k c475_restate_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-restate.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C uid=euid vs -C uid=euid (exact restatement) is not a contradiction \
         -> must stay overlapping -> au-W03 must still fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_different_safe_pairs_stay_conservative() {
    // GREEN today and after. UID-family and GID-family pairs share no
    // logical relationship: cross-pair reasoning is out of scope, so the
    // rules stay conservatively overlapping.
    let input = concat!(
        "-a never,exit -S execve -C uid=euid -k c475_crosspair_never\n",
        "-a always,exit -S execve -C gid!=egid -k c475_crosspair_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-crosspair.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C uid=euid vs -C gid!=egid share no safe canonical pair -> cross-pair \
         reasoning is out of scope -> au-W03 must still fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_object_family_uid_to_obj_uid_stays_conservative() {
    // GREEN today, and MUST STAY GREEN forever -- the critical soundness
    // guard. AUDIT_COMPARE_UID_TO_OBJ_UID (table row 1). The kernel
    // dispatches this constant to audit_compare_uid (auditsc.c:332-378),
    // which existentially quantifies over ctx->names_list (ALL filesystem
    // objects a syscall touches; e.g. rename(2)/link(2) can attach 2+ names
    // with DIFFERENT owning uids). For a cross-ownership rename, BOTH
    // `uid=obj_uid` and `uid!=obj_uid` can independently find a matching
    // name and return true -- they are NOT complements here. If a wrong
    // impl includes the 9 OBJECT constants in its canonical-pair table, this
    // test catches it: `traffic_overlaps` would wrongly return false, and
    // au-W03 (whose documented invariant is "anything not provably disjoint
    // stays conservatively overlapping", ordering.rs:141-143) would SILENTLY
    // STOP WARNING about a real suppression conflict that genuinely can
    // occur.
    let input = concat!(
        "-a never,exit -S rename -C uid=obj_uid -k c475_objuid_never\n",
        "-a always,exit -S rename -C uid!=obj_uid -k c475_objuid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-objuid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C uid=obj_uid vs -C uid!=obj_uid are NOT complements (existential over \
         names_list, auditsc.c:332-378) -> must stay conservatively overlapping -> \
         au-W03 must still fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_object_family_gid_to_obj_gid_stays_conservative() {
    // GREEN today, and MUST STAY GREEN forever. AUDIT_COMPARE_GID_TO_OBJ_GID
    // (table row 2), the GID-family twin of the UID case above (same
    // audit_compare_gid existential-over-names_list mechanism).
    let input = concat!(
        "-a never,exit -S rename -C gid=obj_gid -k c475_objgid_never\n",
        "-a always,exit -S rename -C gid!=obj_gid -k c475_objgid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-objgid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C gid=obj_gid vs -C gid!=obj_gid are NOT complements (existential over \
         names_list) -> must stay conservatively overlapping -> au-W03 must still \
         fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_c_vs_absent_c_stays_conservative() {
    // GREEN today and after. Rule B has no `-C` at all, so its matched-event
    // set is a superset of (or equal to) what it would be with the pair
    // constrained: A's `-C uid=euid` cannot prove disjointness from B's
    // absence of any constraint on that pair.
    let input = concat!(
        "-a never,exit -S execve -C uid=euid -k c475_absent_never\n",
        "-a always,exit -S execve -k c475_absent_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-absent.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C uid=euid vs no -C at all: absence cannot prove disjointness -> \
         au-W03 must still fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_multi_c_conjunction_shared_contradiction_is_disjoint() {
    // RED. Rule A carries TWO -C comparisons (`uid=euid` AND `gid=egid`);
    // rule B carries TWO DIFFERENT -C comparisons (`uid!=euid` AND
    // `sgid=fsgid`), sharing no pair with A's second clause. The kernel ANDs
    // every field in a rule (`audit_filter_rules`'s `if (!result) return 0`
    // loop, auditsc.c:481-751) -- a single false conjunct fails the WHOLE
    // rule -- so a contradiction on ANY one shared safe pair (uid/euid here)
    // is sufficient to prove the two rules' overall AND-conjunctions can
    // never both be true for one event, regardless of what else either rule
    // contains.
    let input = concat!(
        "-a never,exit -S execve -C uid=euid -C gid=egid -k c475_multi_never\n",
        "-a always,exit -S execve -C uid!=euid -C sgid=fsgid -k c475_multi_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-multi.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "rule A (-C uid=euid, -C gid=egid) and rule B (-C uid!=euid, -C sgid=fsgid) \
         share a contradictory pair (uid/euid) -> disjoint regardless of the other \
         conjuncts -> au-W03 must not fire, got {diags:?}"
    );
}

// --- object-family exclusion: FULL coverage of all 9 *_TO_OBJ_* constants ---
//
// The two OBJECT pins above (rows 1-2) plus the seven below pin ALL 9
// process-vs-object constants (uapi_audit.h:211-219, rows 1-9) as
// conservatively-overlapping. Pinning all 9 kills the LAZIEST unsound impl: a
// design that canonicalizes ANY field pair and then denylists only the two
// literals actually tested would pass a 2-of-9 subset but be silently unsound
// for the other 7 object pairs (e.g. `-C euid=obj_uid` vs `-C euid!=obj_uid`
// wrongly proven disjoint, dropping a real au-W03 warning). All 9 GREEN pins
// force the sound design (an allowlist of the 16 safe pairs, or a "contains
// obj_uid/obj_gid => exclude" rule). Every pin is GREEN now (the `-C` channel
// is inert today) and MUST STAY GREEN after the promotion. Each uses a legal
// pair (=/!= + a real field pair) on a syscall (rename) that genuinely
// attaches multiple names_list entries, so the existential-over-names_list
// co-satisfaction (auditsc.c:332-378) is real, not hypothetical.

#[test]
fn w03_c475_object_family_euid_to_obj_uid_stays_conservative() {
    // GREEN, must never flip. AUDIT_COMPARE_EUID_TO_OBJ_UID (uapi row 3).
    let input = concat!(
        "-a never,exit -S rename -C euid=obj_uid -k c475_euidobj_never\n",
        "-a always,exit -S rename -C euid!=obj_uid -k c475_euidobj_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-euidobj.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C euid=obj_uid vs -C euid!=obj_uid are NOT complements (existential over \
         names_list) -> must stay conservatively overlapping -> au-W03 must still \
         fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_object_family_egid_to_obj_gid_stays_conservative() {
    // GREEN, must never flip. AUDIT_COMPARE_EGID_TO_OBJ_GID (uapi row 4).
    let input = concat!(
        "-a never,exit -S rename -C egid=obj_gid -k c475_egidobj_never\n",
        "-a always,exit -S rename -C egid!=obj_gid -k c475_egidobj_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-egidobj.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C egid=obj_gid vs -C egid!=obj_gid are NOT complements (existential over \
         names_list) -> must stay conservatively overlapping -> au-W03 must still \
         fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_object_family_auid_to_obj_uid_stays_conservative() {
    // GREEN, must never flip. AUDIT_COMPARE_AUID_TO_OBJ_UID (uapi row 5).
    let input = concat!(
        "-a never,exit -S rename -C auid=obj_uid -k c475_auidobj_never\n",
        "-a always,exit -S rename -C auid!=obj_uid -k c475_auidobj_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-auidobj.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C auid=obj_uid vs -C auid!=obj_uid are NOT complements (existential over \
         names_list) -> must stay conservatively overlapping -> au-W03 must still \
         fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_object_family_suid_to_obj_uid_stays_conservative() {
    // GREEN, must never flip. AUDIT_COMPARE_SUID_TO_OBJ_UID (uapi row 6).
    let input = concat!(
        "-a never,exit -S rename -C suid=obj_uid -k c475_suidobj_never\n",
        "-a always,exit -S rename -C suid!=obj_uid -k c475_suidobj_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-suidobj.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C suid=obj_uid vs -C suid!=obj_uid are NOT complements (existential over \
         names_list) -> must stay conservatively overlapping -> au-W03 must still \
         fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_object_family_sgid_to_obj_gid_stays_conservative() {
    // GREEN, must never flip. AUDIT_COMPARE_SGID_TO_OBJ_GID (uapi row 7).
    let input = concat!(
        "-a never,exit -S rename -C sgid=obj_gid -k c475_sgidobj_never\n",
        "-a always,exit -S rename -C sgid!=obj_gid -k c475_sgidobj_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-sgidobj.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C sgid=obj_gid vs -C sgid!=obj_gid are NOT complements (existential over \
         names_list) -> must stay conservatively overlapping -> au-W03 must still \
         fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_object_family_fsuid_to_obj_uid_stays_conservative() {
    // GREEN, must never flip. AUDIT_COMPARE_FSUID_TO_OBJ_UID (uapi row 8).
    let input = concat!(
        "-a never,exit -S rename -C fsuid=obj_uid -k c475_fsuidobj_never\n",
        "-a always,exit -S rename -C fsuid!=obj_uid -k c475_fsuidobj_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-fsuidobj.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C fsuid=obj_uid vs -C fsuid!=obj_uid are NOT complements (existential over \
         names_list) -> must stay conservatively overlapping -> au-W03 must still \
         fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_object_family_fsgid_to_obj_gid_stays_conservative() {
    // GREEN, must never flip. AUDIT_COMPARE_FSGID_TO_OBJ_GID (uapi row 9).
    let input = concat!(
        "-a never,exit -S rename -C fsgid=obj_gid -k c475_fsgidobj_never\n",
        "-a always,exit -S rename -C fsgid!=obj_gid -k c475_fsgidobj_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-fsgidobj.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert_eq!(
        diags.len(),
        1,
        "-C fsgid=obj_gid vs -C fsgid!=obj_gid are NOT complements (existential over \
         names_list) -> must stay conservatively overlapping -> au-W03 must still \
         fire, got {diags:?}"
    );
}

// --- more SAFE-pair disjoint pins: force the full 16-pair table, not a 3-pair overfit ---
//
// The five RED disjoint-proving tests above exercise only 3 of the 16 safe
// process-vs-process pairs (UID_TO_EUID 11, UID_TO_AUID 10, GID_TO_EGID 20).
// These three more (rows 19, 24, 16) spread the coverage across the suid/fsuid,
// egid/sgid, and auid/euid sub-families so a 3-pair-allowlist impl cannot pass
// while under-delivering on the rest of the 16. All RED now (the `-C` channel
// is inert today) and must go GREEN with the sound 16-pair promotion.

#[test]
fn w03_c475_complementary_suid_fsuid_is_disjoint() {
    // RED. AUDIT_COMPARE_SUID_TO_FSUID (uapi row 19).
    let input = concat!(
        "-a never,exit -S execve -C suid=fsuid -k c475_suid_fsuid_never\n",
        "-a always,exit -S execve -C suid!=fsuid -k c475_suid_fsuid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-suid-fsuid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C suid=fsuid vs -C suid!=fsuid are complements on AUDIT_COMPARE_SUID_TO_FSUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_egid_sgid_is_disjoint() {
    // RED. AUDIT_COMPARE_EGID_TO_SGID (uapi row 24).
    let input = concat!(
        "-a never,exit -S execve -C egid=sgid -k c475_egid_sgid_never\n",
        "-a always,exit -S execve -C egid!=sgid -k c475_egid_sgid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-egid-sgid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C egid=sgid vs -C egid!=sgid are complements on AUDIT_COMPARE_EGID_TO_SGID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_auid_euid_is_disjoint() {
    // RED. AUDIT_COMPARE_AUID_TO_EUID (uapi row 16). Also cross-checks operand
    // canonicalization the other direction: spelled auid=euid, the userspace
    // constant is AUID_TO_EUID (libaudit.c AUID/EUID switch arm).
    let input = concat!(
        "-a never,exit -S execve -C auid=euid -k c475_auid_euid_never\n",
        "-a always,exit -S execve -C auid!=euid -k c475_auid_euid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-auid-euid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C auid=euid vs -C auid!=euid are complements on AUDIT_COMPARE_AUID_TO_EUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

// --- ALL 16 safe pairs pinned: kill every canonical_pair match-arm mutant (ATL) ---
//
// The mutation gate on the class-2 impl left 10 MISSED mutants, one per SAFE
// process-vs-process pair that had no disjoint-proving test (only 6 of 16 were
// pinned above). Each survivor is `delete match arm (X, Y)` in
// `canonical_pair`: dropping an arm makes it return None for that pair, so the
// promotion silently stops firing for it -- undetected without a test that
// exercises exactly that arm. The impl-aware adversary independently verified
// all 16 arms map CORRECTLY (0 mismatches vs an independent oracle), so these
// 10 are pure test-adequacy pins: GREEN against the current (correct) impl,
// each one killing its own arm's delete-mutant. With these plus the 6 above,
// all 16 safe pairs (uapi_audit.h:221-241, rows 10-25) are pinned. Every
// fixture uses a legal `=`/`!=` pair the parser accepts (parser.rs:626-674).

#[test]
fn w03_c475_complementary_uid_fsuid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_UID_TO_FSUID (uapi row 12).
    let input = concat!(
        "-a never,exit -S execve -C uid=fsuid -k c475_uid_fsuid_never\n",
        "-a always,exit -S execve -C uid!=fsuid -k c475_uid_fsuid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-uid-fsuid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C uid=fsuid vs -C uid!=fsuid are complements on AUDIT_COMPARE_UID_TO_FSUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_uid_suid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_UID_TO_SUID (uapi row 13).
    let input = concat!(
        "-a never,exit -S execve -C uid=suid -k c475_uid_suid_never\n",
        "-a always,exit -S execve -C uid!=suid -k c475_uid_suid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-uid-suid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C uid=suid vs -C uid!=suid are complements on AUDIT_COMPARE_UID_TO_SUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_auid_fsuid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_AUID_TO_FSUID (uapi row 14).
    let input = concat!(
        "-a never,exit -S execve -C auid=fsuid -k c475_auid_fsuid_never\n",
        "-a always,exit -S execve -C auid!=fsuid -k c475_auid_fsuid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-auid-fsuid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C auid=fsuid vs -C auid!=fsuid are complements on AUDIT_COMPARE_AUID_TO_FSUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_auid_suid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_AUID_TO_SUID (uapi row 15).
    let input = concat!(
        "-a never,exit -S execve -C auid=suid -k c475_auid_suid_never\n",
        "-a always,exit -S execve -C auid!=suid -k c475_auid_suid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-auid-suid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C auid=suid vs -C auid!=suid are complements on AUDIT_COMPARE_AUID_TO_SUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_euid_suid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_EUID_TO_SUID (uapi row 17).
    let input = concat!(
        "-a never,exit -S execve -C euid=suid -k c475_euid_suid_never\n",
        "-a always,exit -S execve -C euid!=suid -k c475_euid_suid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-euid-suid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C euid=suid vs -C euid!=suid are complements on AUDIT_COMPARE_EUID_TO_SUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_euid_fsuid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_EUID_TO_FSUID (uapi row 18).
    let input = concat!(
        "-a never,exit -S execve -C euid=fsuid -k c475_euid_fsuid_never\n",
        "-a always,exit -S execve -C euid!=fsuid -k c475_euid_fsuid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-euid-fsuid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C euid=fsuid vs -C euid!=fsuid are complements on AUDIT_COMPARE_EUID_TO_FSUID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_gid_fsgid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_GID_TO_FSGID (uapi row 21).
    let input = concat!(
        "-a never,exit -S execve -C gid=fsgid -k c475_gid_fsgid_never\n",
        "-a always,exit -S execve -C gid!=fsgid -k c475_gid_fsgid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-gid-fsgid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C gid=fsgid vs -C gid!=fsgid are complements on AUDIT_COMPARE_GID_TO_FSGID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_gid_sgid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_GID_TO_SGID (uapi row 22).
    let input = concat!(
        "-a never,exit -S execve -C gid=sgid -k c475_gid_sgid_never\n",
        "-a always,exit -S execve -C gid!=sgid -k c475_gid_sgid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-gid-sgid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C gid=sgid vs -C gid!=sgid are complements on AUDIT_COMPARE_GID_TO_SGID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_egid_fsgid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_EGID_TO_FSGID (uapi row 23).
    let input = concat!(
        "-a never,exit -S execve -C egid=fsgid -k c475_egid_fsgid_never\n",
        "-a always,exit -S execve -C egid!=fsgid -k c475_egid_fsgid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-egid-fsgid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C egid=fsgid vs -C egid!=fsgid are complements on AUDIT_COMPARE_EGID_TO_FSGID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

#[test]
fn w03_c475_complementary_sgid_fsgid_is_disjoint() {
    // GREEN. AUDIT_COMPARE_SGID_TO_FSGID (uapi row 25), the last of the 16.
    let input = concat!(
        "-a never,exit -S execve -C sgid=fsgid -k c475_sgid_fsgid_never\n",
        "-a always,exit -S execve -C sgid!=fsgid -k c475_sgid_fsgid_always\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-c475-sgid-fsgid.rules")).unwrap();
    assert_eq!(rules.len(), 2);
    let diags = w03(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "-C sgid=fsgid vs -C sgid!=fsgid are complements on AUDIT_COMPARE_SGID_TO_FSGID \
         -> provably disjoint -> au-W03 must not fire, got {diags:?}"
    );
}

// ===========================================================================
// STRETCH: au-W04 (-D mid-stream) tests -- clearly marked, cuttable at integration
// ===========================================================================
//
// Owner decision D6: au-W04 is a stretch lint. If the orchestrator cuts it at the
// integration gate, remove this section and remove au-W04 from catalog.rs.
// These tests use lints::ordering::w04 via direct call when it exists.

// au-W04 stretch: guarded by `#[cfg(any())]` (always-false) so the tests compile
// but never run until the orchestrator enables this block after the impl lands.
// To enable: change `any()` to `feature = "w04"` and add "w04" to Cargo.toml features.
#[cfg(any())]
mod w04_stretch {
    use super::*;
    use rulesteward_auditd::lints::ordering::w04;

    // -----------------------------------------------------------------------
    // W04-Test 15: -D after a loaded rule fires at the -D
    //
    // Fixtures: midstream-delete-all/
    //   10-some-rules.rules  line 3: -a always,exit ...  <- a real rule
    //   50-discard.rules     line 3: -D                  <- au-W04 target
    //
    // Grounding: auditctl(8) -D deletes ALL existing kernel audit rules.
    // When -D appears after rules that have already been loaded, those rules
    // are discarded. The standard pattern is -D at the top of the FIRST file.
    // au-W04 fires at this -D rule, naming the count of discarded rules.
    // -----------------------------------------------------------------------
    #[test]
    fn w04_midstream_delete_all_fires() {
        let dir = fixture_dir("midstream-delete-all");
        let rules = parse_target_located(&dir).expect("fixtures must parse");

        let diags = w04(&rules);

        assert_eq!(
            diags.len(),
            1,
            "-D after a loaded rule must fire au-W04 at the -D, got {diags:?}"
        );
        let d = &diags[0];
        assert_eq!(d.severity, Severity::Warning, "au-W04 is Warning");
        assert_eq!(d.code, "au-W04");
        assert_eq!(d.column, 1);
        // Anchored at the -D rule (50-discard.rules line 3).
        assert!(
            d.file.to_string_lossy().contains("50-discard"),
            "must anchor at 50-discard.rules, got {:?}",
            d.file
        );
        assert_eq!(d.line, 3, "50-discard.rules: -D is on line 3");
        // Message must mention how many rules are discarded (1 rule before this -D).
        assert!(
            d.message.contains('1'),
            "message must name the count of discarded rules (1), got {:?}",
            d.message
        );
    }

    // -----------------------------------------------------------------------
    // W04-Test 16: -D as the top of the FIRST file fires nothing
    //
    // The standard deployment pattern: -D at the very start (before any rules
    // are loaded) resets the kernel slate and is harmless. au-W04 must not fire.
    // Grounding: auditctl(8) -D at the top of the first file is the conventional
    // "start from a clean slate" pattern.
    // -----------------------------------------------------------------------
    #[test]
    fn w04_delete_all_at_top_does_not_fire() {
        let input = concat!(
            "-D\n",
            // Rules loaded AFTER the -D: this is the standard pattern.
            "-a always,exit -S execve -k exec_user\n",
        );
        let file = Path::new("10-standard-D.rules");
        let rules = parse_rules_str_located(input, file).expect("fixture must parse");
        assert_eq!(rules.len(), 2);

        let diags = w04(&rules);

        assert!(
            diags.is_empty(),
            "-D at the top of the first file (standard pattern) must not fire au-W04, \
             got {diags:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// T9 (#230): AppArmor msgtype opt-in au-W02 subsumption (apparmor-DECIDING).
//
// Predicate-equal-but-key-differs (the established au-W02 shape, see
// w02_predicate_equal_different_key_fires) where the ONLY thing making the two
// msgtype predicates equal is the apparmor fold (1503 == APPARMOR_DENIED).
// Different -k keys keep canonical_key distinct, so it is au-W02 not au-W01.
// ON: the predicates fold equal -> earlier subsumes later -> exactly one au-W02.
// OFF: 1503 and APPARMOR_DENIED are distinct -> no subsumption -> ZERO au-W02.
// This makes the diagnostic count itself depend on --apparmor (the old version
// fired 1/1 either way, proving only signature plumbing, not folding).
// ---------------------------------------------------------------------------
#[test]
fn t9_apparmor_msgtype_w02_requires_on() {
    let input = concat!(
        "-a always,exclude -F msgtype=1503 -k apparmor_a\n",
        "-a always,exclude -F msgtype=APPARMOR_DENIED -k apparmor_b\n",
    );
    let file = Path::new("10-apparmor-w02.rules");
    let rules = parse_rules_str_located(input, file).expect("must parse");
    assert_eq!(rules.len(), 2);

    let diags_on = w02(
        &rules,
        LintOptions {
            include_apparmor: true,
        },
    );
    assert_eq!(
        diags_on.len(),
        1,
        "with --apparmor: msgtype 1503 folds APPARMOR_DENIED -> au-W02 subsumption, \
         got {diags_on:?}"
    );
    assert_eq!(diags_on[0].code, "au-W02");

    let diags_off = w02(&rules, LintOptions::default());
    assert!(
        diags_off.is_empty(),
        "without --apparmor: 1503 and APPARMOR_DENIED are distinct msgtypes, so NO \
         subsumption and NO au-W02, got {diags_off:?}"
    );
}
