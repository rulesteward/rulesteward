//! RED barrier tests for au-W01 (duplicate rule, Warning) and au-E03
//! (load-aborting duplicate, Error) -- issue #193, pipeline P1.
//!
//! Both codes are emitted by `lints::duplicate::w01(&[LocatedRule])`.
//! The entrypoint signature is Phase-0 frozen; it returns `Vec<Diagnostic>`
//! whose `severity` and `code` fields distinguish the two cases.
//!
//! # Severity boundary (owner decision, session 6a PRIOR ANSWERS)
//!
//! * **au-E03 (Error)** -- the later rule is STRUCTURALLY IDENTICAL to the
//!   earlier one: `AuditRule::PartialEq` is true (same field order, same `-S`
//!   syscall order, same `-a`/`-A` prepend flag, same `-k` key).  This is
//!   exactly what `auditctl -R` aborts on with kernel `EEXIST`
//!   (`auditctl.c:1680-1686`, audit 3bfa048): `fclose(f); return -1` -- every
//!   rule after the duplicate silently fails to load.
//!
//! * **au-W01 (Warning)** -- `canonical_key`-equal but NOT `PartialEq`-equal
//!   (field order swapped, syscall order swapped, `-a` vs `-A`, or `-p` letter
//!   order different).  The kernel does NOT EEXIST on these; they load but are
//!   redundant waste.
//!
//! # Grounding citations
//!
//! * `auditctl -R` abort on EEXIST:
//!   `audit-src/src/auditctl.c:1680-1686` (audit 3bfa048).
//! * Syscall-order irrelevance: libaudit syscall bitmask OR:
//!   `audit-src/lib/libaudit.c:1021-1025` (audit 3bfa048).
//! * `-a` vs `-A` position-only flag: `AUDIT_FILTER_PREPEND = 0x10`
//!   (kernel `audit.h:185`), set by `auditctl.c:864` (audit 3bfa048).
//! * `-p` letter-order equivalence: `PermBits` is four independent bools
//!   (r/w/x/a); `canonical_key` renders in fixed `rwxa` order.
//! * D2 boundary: `canonical_key` includes the `-k` key (`normalize.rs:74`).

use std::path::Path;

use rulesteward_auditd::{lints::duplicate::w01, parse_rules_str_located, parse_target_located};
use rulesteward_core::Severity;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fixture_dir(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lints/dup")
        .join(rel)
}

fn fixture_file(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lints/dup")
        .join(rel)
}

fn corpus_dir(scenario: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/auditd")
        .join(scenario)
}

// ---------------------------------------------------------------------------
// Test 1: Cross-file normalized duplicate (field-order swap) -- au-W01
//
// 10-base.rules   line 3: -a always,exit -F arch=b64 -F uid=0 -S execve -k privesc
// 50-dupe.rules   line 4: -a always,exit -F uid=0 -F arch=b64 -S execve -k privesc
//
// Adversarial: a raw-line string-equality impl MISSES this (the lines differ).
// A derived-PartialEq impl also MISSES it (field order differs in the Vec).
// Only canonical_key equality (sorted -F order) fires it correctly.
// Severity must be Warning (au-W01), NOT Error (au-E03): the rules are
// canonical_key-equal but NOT PartialEq-equal (field order differs).
// ---------------------------------------------------------------------------

#[test]
fn cross_file_field_order_swap_fires_one_w01_at_later_file() {
    let dir = fixture_dir("cross-file-swap");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "exactly 2 rules expected");

    let diags = w01(&rules);

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 au-W01 expected for a cross-file pair, got {diags:?}"
    );

    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning, "au-W01 must be Warning");
    assert_eq!(d.code, "au-W01", "code must be au-W01");
    // Finding anchored at the LATER occurrence (50-dupe.rules line 4).
    assert!(
        d.file.to_string_lossy().contains("50-dupe"),
        "diagnostic must anchor at the later file (50-dupe.rules), got file={:?}",
        d.file
    );
    assert_eq!(d.line, 4, "later occurrence is on line 4 of 50-dupe.rules");
    assert_eq!(d.column, 1, "auditd convention: column is always 1");
    // Message must name the first occurrence so the operator knows where to look.
    assert!(
        d.message.contains("10-base"),
        "message must cite the first occurrence's file (10-base.rules), got {:?}",
        d.message
    );
    assert!(
        d.message.contains('3'),
        "message must cite the first occurrence's line (3), got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 2: Syscall-order-swapped duplicate -- au-W01
//
// 10-open.rules  line 5: -a always,exit -S open -S close -k fs-access
// 50-swapped.rules line 4: -a always,exit -S close -S open -k fs-access
//
// Adversarial: a derived-PartialEq impl sees syscalls=[open,close] vs
// [close,open] as distinct Vec values and MISSES this.  Only an impl that
// sorts syscalls before comparing (canonical_key) fires correctly.
// Severity: Warning (au-W01) -- not PartialEq-equal, just canonical-equal.
// ---------------------------------------------------------------------------

#[test]
fn syscall_order_swap_fires_w01() {
    let dir = fixture_dir("syscall-order");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "exactly 2 rules expected");

    let diags = w01(&rules);

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 au-W01 for syscall-order swap, got {diags:?}"
    );

    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning, "au-W01 must be Warning");
    assert_eq!(d.code, "au-W01", "code must be au-W01");
    assert!(
        d.file.to_string_lossy().contains("50-swapped"),
        "anchored at 50-swapped.rules, got {:?}",
        d.file
    );
    assert_eq!(d.line, 4, "50-swapped.rules has its rule on line 4");
    assert!(
        d.message.contains("10-open"),
        "message must cite 10-open.rules, got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 3: -a vs -A (append vs prepend) pair fires -- au-W01
//
// 10-append.rules  line 5: -a always,exit -S execve -F auid>=1000 -k exec
// 50-prepend.rules line 3: -A always,exit -S execve -F auid>=1000 -k exec
//
// Adversarial: an impl that includes `prepend` in its equality check MISSES
// this because prepend=false != prepend=true.  canonical_key excludes
// `prepend: _` (normalize.rs:53).
// Severity: Warning (au-W01) -- the rules differ in prepend flag (PartialEq
// is false), so no EEXIST; they load fine but are redundant.
// ---------------------------------------------------------------------------

#[test]
fn append_vs_prepend_pair_fires_w01() {
    let dir = fixture_dir("append-prepend");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "exactly 2 rules expected");

    let diags = w01(&rules);

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 au-W01 for -a vs -A pair, got {diags:?}"
    );

    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning, "au-W01 must be Warning");
    assert_eq!(d.code, "au-W01", "code must be au-W01");
    assert!(
        d.file.to_string_lossy().contains("50-prepend"),
        "anchored at 50-prepend.rules, got {:?}",
        d.file
    );
    assert_eq!(d.line, 3, "50-prepend.rules has its rule on line 3");
    assert!(
        d.message.contains("10-append"),
        "message must cite 10-append.rules, got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 4: Same-file duplicate fires -- au-W01
//
// 10-same.rules line 4: -a always,exit -S mount -F auid>=1000 -k mounts
// 10-same.rules line 7: -a always,exit -S mount -F auid>=1000 -k mounts (dup)
//
// An intervening rule (-w /etc/fstab ...) separates them to ensure the impl
// does not rely on consecutive-line adjacency.
//
// NOTE: this is a byte-identical same-file pair.  Severity is au-E03 (Error),
// not au-W01 (Warning): the two rules are PartialEq-equal (same field order,
// same syscall list, same prepend flag), so the kernel would EEXIST.
// The fixture and test verify the au-E03 path for same-file identical dups.
// ---------------------------------------------------------------------------

#[test]
fn same_file_duplicate_fires_e03_at_second_occurrence() {
    let path = fixture_file("same-file/10-same.rules");
    let rules = parse_target_located(&path).expect("fixture must parse");
    // 3 rules: mount-syscall, fstab-watch, mount-syscall (dup)
    assert_eq!(rules.len(), 3, "expected 3 rules, got {rules:?}");

    let diags = w01(&rules);

    // Exactly 1 finding: the second mount rule is the duplicate.
    assert_eq!(
        diags.len(),
        1,
        "exactly 1 finding for same-file duplicate, got {diags:?}"
    );

    let d = &diags[0];
    // Same-file byte-identical dup: PartialEq-equal -> au-E03 (Error).
    assert_eq!(
        d.severity,
        Severity::Error,
        "same-file byte-identical dup must be au-E03 Error, got {:?}",
        d.severity
    );
    assert_eq!(d.code, "au-E03", "code must be au-E03");
    assert!(
        d.file.to_string_lossy().contains("10-same"),
        "anchored in 10-same.rules, got {:?}",
        d.file
    );
    assert_eq!(d.line, 7, "second occurrence is on line 7 of 10-same.rules");
    // Message must cite the first occurrence at line 4 and warn about auditctl -R abort.
    assert!(
        d.message.contains('4'),
        "message must cite line 4 (first occurrence), got {:?}",
        d.message
    );
    assert!(
        d.message.to_lowercase().contains("abort") || d.message.to_lowercase().contains("auditctl"),
        "au-E03 message must warn about auditctl -R abort, got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 5 (D2 boundary): Key-differs pair must NOT fire au-W01 or au-E03
//
// 10-key-a.rules line 4: ... -k execpriv
// 50-key-b.rules line 3: ... -k execaudit  (same predicates, different key)
//
// Owner decision D2: the -k key is PART of canonical_key (normalize.rs:74).
// A predicate-equal pair whose keys differ is P2's shadow case (au-W02), never
// au-W01 or au-E03.  Adversarial: an impl that ignores the key produces a
// false positive here.
// ---------------------------------------------------------------------------

#[test]
fn key_differs_pair_does_not_fire_au_w01_or_au_e03() {
    let dir = fixture_dir("key-differs");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "exactly 2 rules expected");

    let diags = w01(&rules);

    assert!(
        diags.is_empty(),
        "au-W01 and au-E03 must NOT fire for a key-differing pair (P2's case, not P1's); got {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Watch duplicate with -p letter order swapped fires -- au-W01
//
// 10-wa.rules  line 5: -w /etc/passwd -p wa -k identity
// 50-aw.rules  line 3: -w /etc/passwd -p aw -k identity
//
// Adversarial: an impl that compares the raw -p string "wa" vs "aw" MISSES
// this (they differ lexicographically).  PermBits is four bools (order-free
// by construction); canonical_key renders them in fixed rwxa order.
// Severity: Warning (au-W01) -- PermBits struct is equal (PartialEq is true
// on PermBits), but the Watch variant's PartialEq uses PermBits directly and
// since PermBits derives PartialEq from its fields (four bools), "-p wa" and
// "-p aw" parse to the SAME PermBits struct.
//
// IMPORTANT: Watch rules with the same path, same perms (same PermBits), and
// same key ARE PartialEq-equal -> this should be au-E03 (Error).
// Adversarial: a naive impl that calls PartialEq on AuditRule correctly sees
// these as equal; only an impl that uses canonical_key without PartialEq would
// miss the E03 severity here.
// ---------------------------------------------------------------------------

#[test]
fn watch_perm_letter_order_swap_fires_e03() {
    let dir = fixture_dir("watch-perm-swap");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "exactly 2 rules expected");

    let diags = w01(&rules);

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 finding for -p wa vs -p aw, got {diags:?}"
    );

    let d = &diags[0];
    // "-p wa" and "-p aw" parse to the same PermBits struct, so AuditRule
    // PartialEq is true -> au-E03 (Error), not au-W01.
    assert_eq!(
        d.severity,
        Severity::Error,
        "watch -p wa vs -p aw: PermBits are equal so PartialEq is true -> au-E03, got {:?}",
        d.severity
    );
    assert_eq!(d.code, "au-E03", "code must be au-E03");
    assert!(
        d.file.to_string_lossy().contains("50-aw"),
        "anchored at 50-aw.rules, got {:?}",
        d.file
    );
    assert_eq!(d.line, 3, "50-aw.rules has its rule on line 3");
    assert!(
        d.message.contains("10-wa"),
        "message must cite 10-wa.rules, got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 7: Triple-occurrence (mixed W01 + E03)
//
// triple-occurrence/ fixture:
//   10-first.rules  line 3: -a always,exit -S adjtimex -S settimeofday -k time-change
//   50-second.rules line 3: -a always,exit -S settimeofday -S adjtimex -k time-change (swapped)
//   90-third.rules  line 3: -a always,exit -S adjtimex -S settimeofday -k time-change (exact)
//
// 50-second: syscall-order-swapped -> canonical-equal but NOT PartialEq-equal -> au-W01.
// 90-third:  byte-identical to 10-first -> PartialEq-equal -> au-E03.
//
// N=3 occurrences must yield N-1=2 findings.
// Both must cite 10-first.rules (not 50-second) as the first occurrence.
// Adversarial: an impl that updates "first seen" on the 50-second duplicate
// would cite 50-second for the 90-third finding.
// Adversarial: an impl that emits Warning for all duplicates misses the E03
// severity on 90-third.
// ---------------------------------------------------------------------------

#[test]
fn triple_occurrence_mixed_yields_w01_and_e03_both_citing_first() {
    let dir = fixture_dir("triple-occurrence");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 3, "exactly 3 rules expected");

    let diags = w01(&rules);

    assert_eq!(
        diags.len(),
        2,
        "3 occurrences must yield exactly 2 findings, got {diags:?}"
    );

    // Both findings must cite the FIRST occurrence (10-first.rules).
    for (i, d) in diags.iter().enumerate() {
        assert!(
            d.message.contains("10-first"),
            "finding {i}: message must cite 10-first.rules (not 50-second), got {:?}",
            d.message
        );
    }

    // The two findings must be anchored at the second and third occurrences.
    let files: Vec<_> = diags
        .iter()
        .map(|d| d.file.to_string_lossy().into_owned())
        .collect();
    assert!(
        files.iter().any(|f| f.contains("50-second")),
        "one finding must be anchored at 50-second.rules, got {files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains("90-third")),
        "one finding must be anchored at 90-third.rules, got {files:?}"
    );

    // 50-second: syscall-order-swapped -> au-W01 (Warning).
    let second = diags
        .iter()
        .find(|d| d.file.to_string_lossy().contains("50-second"))
        .expect("50-second finding must exist");
    assert_eq!(
        second.severity,
        Severity::Warning,
        "50-second (syscall-order-swapped) must be au-W01 Warning, got {:?}",
        second.severity
    );
    assert_eq!(second.code, "au-W01");

    // 90-third: byte-identical -> au-E03 (Error).
    let third = diags
        .iter()
        .find(|d| d.file.to_string_lossy().contains("90-third"))
        .expect("90-third finding must exist");
    assert_eq!(
        third.severity,
        Severity::Error,
        "90-third (byte-identical) must be au-E03 Error, got {:?}",
        third.severity
    );
    assert_eq!(third.code, "au-E03");
}

// ---------------------------------------------------------------------------
// Test 8: Clean-corpus regression -- zero au-W01 AND zero au-E03
//
// The three named corpus scenarios must produce no findings from w01().
// These rulesets were loaded on real Rocky 8/9/10 VMs (see corpus PROVENANCE.md)
// and should contain neither normalized duplicates nor load-aborting ones.
// ---------------------------------------------------------------------------

#[test]
fn clean_corpus_rocky9_stig_hardened_zero_findings() {
    let path = corpus_dir("rocky9-stig-hardened").join("audit.rules");
    let rules = parse_target_located(&path).expect("rocky9-stig-hardened must parse");
    let diags = w01(&rules);
    assert!(
        diags.is_empty(),
        "rocky9-stig-hardened must have zero au-W01/au-E03 findings, got {diags:?}"
    );
}

#[test]
fn clean_corpus_rocky10_cis_benchmark_zero_findings() {
    let path = corpus_dir("rocky10-cis-benchmark").join("audit.rules");
    let rules = parse_target_located(&path).expect("rocky10-cis-benchmark must parse");
    let diags = w01(&rules);
    assert!(
        diags.is_empty(),
        "rocky10-cis-benchmark must have zero au-W01/au-E03 findings, got {diags:?}"
    );
}

#[test]
fn clean_corpus_rocky9_huge_ruleset_zero_findings() {
    let path = corpus_dir("rocky9-huge-ruleset").join("audit.rules");
    let rules = parse_target_located(&path).expect("rocky9-huge-ruleset must parse");
    let diags = w01(&rules);
    assert!(
        diags.is_empty(),
        "rocky9-huge-ruleset must have zero au-W01/au-E03 findings, got {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 9 (supplementary): Span attribute of the diagnostic covers the rule line
//
// Uses two byte-identical rules (au-E03 case) to verify that the span of the
// diagnostic equals the located rule's span (the whole raw line).
//
// Adversarial: an impl that emits Span = 0..0 (no span) or the wrong range
// fails here.
// ---------------------------------------------------------------------------

#[test]
fn duplicate_diagnostic_span_covers_raw_rule_line() {
    // Input layout (0-indexed bytes):
    //   "# comment\n"                            bytes 0..9  (len 9 + newline)
    //   "-a always,exit -S open -k x\n"          bytes 10..37 (len 27 + newline)
    //   "-a always,exit -S open -k x\n"          bytes 38..65 (dup, same text)
    let first_rule_raw = "-a always,exit -S open -k x";
    let input = "# comment\n-a always,exit -S open -k x\n-a always,exit -S open -k x\n";
    let line2_start = "# comment\n".len(); // 10
    let line3_start = line2_start + first_rule_raw.len() + 1; // +1 for '\n'

    let file = Path::new("test.rules");
    let rules = parse_rules_str_located(input, file).expect("must parse");
    assert_eq!(rules.len(), 2);

    // Verify span tracking from the parser (pinning the underlying mechanism).
    assert_eq!(
        rules[1].span.start, line3_start,
        "rule[1] span.start must be at the start of line 3"
    );
    assert_eq!(
        rules[1].span.end,
        line3_start + first_rule_raw.len(),
        "rule[1] span.end must be at the end of line 3 (no newline)"
    );

    let diags = w01(&rules);
    assert_eq!(diags.len(), 1, "one finding expected");

    let d = &diags[0];
    // Byte-identical rules (PartialEq-equal) -> au-E03 (Error).
    assert_eq!(
        d.severity,
        Severity::Error,
        "byte-identical inline dup must be au-E03, got {:?}",
        d.severity
    );
    assert_eq!(d.code, "au-E03");
    // The diagnostic's span must equal the located rule's span.
    assert_eq!(
        d.span, rules[1].span,
        "diagnostic span must equal the located rule's span"
    );
    // Span slices back to the raw rule line.
    assert_eq!(
        &input[d.span.clone()],
        first_rule_raw,
        "span must slice to the exact raw rule text"
    );
}

// ---------------------------------------------------------------------------
// Test 14: prepend-then-append pair fires au-E03 (Miss #1 from adversarial review)
//
// prepend-then-append/10-prepend.rules  line 5: -A always,exit -S execve -F auid>=1000 -k exec
// prepend-then-append/50-append.rules   line 5: -a always,exit -S execve -F auid>=1000 -k exec
//
// Grounding: kernel/auditfilter.c:1003 clears AUDIT_FILTER_PREPEND from an
// already-inserted entry (entry->rule.flags &= ~AUDIT_FILTER_PREPEND).
// So the stored entry always has flags==0.  audit_compare_rule (line 708)
// compares a->flags != b->flags: first.flags==0 vs later.flags==0 => equal
// => audit_find_rule returns non-NULL => EEXIST => auditctl.c:1680-1686 aborts.
//
// The impl uses AuditRule::PartialEq to classify E03 vs W01.  AuditRule's
// PartialEq INCLUDES the prepend field, so first.rule.prepend=true !=
// later.rule.prepend=false -> PartialEq is FALSE -> impl wrongly produces
// au-W01 (Warning) instead of au-E03 (Error).
//
// The correct classification: EEXIST occurs iff the LATER occurrence is
// -a/append (flags==0 at compare time) and the pair is otherwise field-/
// syscall-order/content identical; the EARLIER occurrence's prepend-ness is
// irrelevant because the kernel clears it after insertion.
// ---------------------------------------------------------------------------

#[test]
fn prepend_then_append_fires_e03_not_w01() {
    let dir = fixture_dir("prepend-then-append");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "exactly 2 rules expected");

    let diags = w01(&rules);

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 finding for prepend-then-append pair, got {diags:?}"
    );

    let d = &diags[0];
    // The kernel clears the prepend bit from the first inserted rule, so at
    // compare time both rules have flags==0 -> EEXIST -> au-E03 (Error).
    // The current impl uses AuditRule::PartialEq which includes `prepend`,
    // causing it to produce au-W01 (Warning) instead.
    assert_eq!(
        d.severity,
        Severity::Error,
        "prepend-first / append-later pair: kernel clears the bit, flags both==0 at compare time \
        -> EEXIST -> au-E03 Error; got {:?} (the impl incorrectly includes `prepend` in PartialEq)",
        d.severity
    );
    assert_eq!(d.code, "au-E03", "code must be au-E03");
    assert!(
        d.file.to_string_lossy().contains("50-append"),
        "finding must be anchored at the later occurrence (50-append.rules), got {:?}",
        d.file
    );
    assert!(
        d.message.contains("10-prepend"),
        "message must cite the first occurrence (10-prepend.rules), got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 15: double-prepend pair fires au-W01 (Miss #2 from adversarial review)
//
// double-prepend/10-first-prepend.rules  line 4: -A always,exit -S execve -k exec
// double-prepend/50-second-prepend.rules line 6: -A always,exit -S execve -k exec
//
// Grounding: kernel/auditfilter.c:1003 clears AUDIT_FILTER_PREPEND after the
// first rule is inserted.  At audit_compare_rule (line 708) the compare is
// first.flags(0) vs later.flags(0x10): 0 != 0x10 -> NOT equal -> NO EEXIST.
// The second -A rule loads fine; it is mere redundancy (au-W01 Warning).
//
// The impl uses AuditRule::PartialEq.  AuditRule::PartialEq includes the
// prepend field: both rules have prepend=true -> PartialEq is TRUE -> impl
// wrongly produces au-E03 (Error) instead of au-W01 (Warning).
// ---------------------------------------------------------------------------

#[test]
fn double_prepend_fires_w01_not_e03() {
    let dir = fixture_dir("double-prepend");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "exactly 2 rules expected");

    let diags = w01(&rules);

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 finding for double-prepend pair, got {diags:?}"
    );

    let d = &diags[0];
    // The kernel clears the prepend bit from the first rule after insertion.
    // At compare time: first.flags==0 vs second.flags==0x10 => NOT equal =>
    // no EEXIST; the second -A rule loads fine (mere redundancy => au-W01 Warning).
    // The current impl sees both prepend=true -> PartialEq is true -> wrongly
    // produces au-E03 (Error).
    assert_eq!(
        d.severity,
        Severity::Warning,
        "double-prepend pair: first rule has prepend cleared to 0 after insertion, \
        second still has 0x10 -> NOT equal -> NO EEXIST -> au-W01 Warning; \
        got {:?} (the impl incorrectly includes `prepend` in PartialEq)",
        d.severity
    );
    assert_eq!(d.code, "au-W01", "code must be au-W01");
    assert!(
        d.file.to_string_lossy().contains("50-second-prepend"),
        "finding must be anchored at the later occurrence (50-second-prepend.rules), got {:?}",
        d.file
    );
    assert!(
        d.message.contains("10-first-prepend"),
        "message must cite the first occurrence (10-first-prepend.rules), got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 10: Empty input produces zero findings
// ---------------------------------------------------------------------------

#[test]
fn empty_rules_produce_no_findings() {
    let diags = w01(&[]);
    assert!(diags.is_empty(), "empty input must produce no findings");
}

// ---------------------------------------------------------------------------
// Test 11: Single rule with no duplicate produces zero findings
// ---------------------------------------------------------------------------

#[test]
fn single_rule_no_duplicate_produces_no_findings() {
    let file = Path::new("10-solo.rules");
    let rules =
        parse_rules_str_located("-a always,exit -S execve -k exec\n", file).expect("must parse");
    assert_eq!(rules.len(), 1);
    let diags = w01(&rules);
    assert!(
        diags.is_empty(),
        "single unique rule must produce no findings"
    );
}

// ---------------------------------------------------------------------------
// Test 12: Cross-file byte-identical duplicate fires au-E03
//
// identical-cross-file/10-first.rules  line 6: -a always,exit -F arch=b64 -S execve ...
// identical-cross-file/50-second.rules line 5: byte-identical
//
// AuditRule::PartialEq is true -> kernel EEXIST -> auditctl -R aborts
// loading the remainder (auditctl.c:1680-1686, audit 3bfa048).
// Adversarial: an impl that emits Warning for all duplicates fails here.
// An impl that uses only canonical_key (not PartialEq) to classify severity
// fails here.
// ---------------------------------------------------------------------------

#[test]
fn cross_file_byte_identical_fires_e03() {
    let dir = fixture_dir("identical-cross-file");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "exactly 2 rules expected");

    let diags = w01(&rules);

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 au-E03 for byte-identical cross-file pair, got {diags:?}"
    );

    let d = &diags[0];
    assert_eq!(
        d.severity,
        Severity::Error,
        "byte-identical cross-file dup must be au-E03 Error, got {:?}",
        d.severity
    );
    assert_eq!(d.code, "au-E03", "code must be au-E03");
    assert!(
        d.file.to_string_lossy().contains("50-second"),
        "anchored at 50-second.rules, got {:?}",
        d.file
    );
    assert_eq!(d.line, 5, "50-second.rules rule is on line 5");
    assert_eq!(d.column, 1, "auditd convention: column is always 1");
    // Message must cite the first occurrence and warn about auditctl -R abort.
    assert!(
        d.message.contains("10-first"),
        "message must cite 10-first.rules, got {:?}",
        d.message
    );
    assert!(
        d.message.contains('6'),
        "message must cite line 6 (first occurrence in 10-first.rules), got {:?}",
        d.message
    );
    assert!(
        d.message.to_lowercase().contains("abort") || d.message.to_lowercase().contains("auditctl"),
        "au-E03 message must warn about auditctl -R aborting remaining rules, got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Test 13: Triple-identical -> two au-E03, both citing the first occurrence
//
// triple-identical/10-first.rules  line 3: -a always,exit -S chown ...
// triple-identical/50-second.rules line 3: byte-identical
// triple-identical/90-third.rules  line 3: byte-identical
//
// N=3 identical occurrences -> N-1=2 au-E03 findings, each citing 10-first.
// Adversarial: an impl that updates "first seen" to the second occurrence
// would cite 50-second.rules for the third finding (wrong).
// ---------------------------------------------------------------------------

#[test]
fn triple_identical_yields_two_e03_both_citing_first() {
    let dir = fixture_dir("triple-identical");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 3, "exactly 3 rules expected");

    let diags = w01(&rules);

    assert_eq!(
        diags.len(),
        2,
        "3 identical occurrences must yield exactly 2 au-E03 findings, got {diags:?}"
    );

    // Both findings must be au-E03 and cite 10-first.rules.
    for (i, d) in diags.iter().enumerate() {
        assert_eq!(
            d.severity,
            Severity::Error,
            "finding {i}: must be au-E03 Error, got {:?}",
            d.severity
        );
        assert_eq!(d.code, "au-E03", "finding {i}: code must be au-E03");
        assert!(
            d.message.contains("10-first"),
            "finding {i}: message must cite 10-first.rules (not 50-second), got {:?}",
            d.message
        );
    }

    // The two findings are anchored at 50-second and 90-third.
    let files: Vec<_> = diags
        .iter()
        .map(|d| d.file.to_string_lossy().into_owned())
        .collect();
    assert!(
        files.iter().any(|f| f.contains("50-second")),
        "one finding must be anchored at 50-second.rules, got {files:?}"
    );
    assert!(
        files.iter().any(|f| f.contains("90-third")),
        "one finding must be anchored at 90-third.rules, got {files:?}"
    );
}
