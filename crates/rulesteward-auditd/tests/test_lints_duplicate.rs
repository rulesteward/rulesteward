//! Tests for au-W01 (duplicate rule, Warning) and au-E03
//! (load-aborting duplicate, Error) -- issue #193.
//!
//! Both codes are emitted by `lints::duplicate::w01(&[LocatedRule])`,
//! which returns `Vec<Diagnostic>` whose `severity` and `code` fields
//! distinguish the two cases.
//!
//! # Severity boundary (owner decision, issue #193)
//!
//! * **au-E03 (Error)** -- the kernel treats the later rule as THE SAME RULE as
//!   the earlier one: `AuditRule::PartialEq` is true (same field order, same
//!   `-S` syscall order, same `-a`/`-A` prepend flag, same `-k` key), EXCEPT
//!   that a `-F perm=` field's VALUE is compared as an order-free, case-folded
//!   `rwxa` bitmask (`duplicate::perm_field_values_eexist_equal`).  So
//!   `-F perm=wa` and `-F perm=aw` are kernel-identical and fire E03 even
//!   though their value strings differ and `PartialEq` is therefore false --
//!   see `perm_letter_order_flip_duplicate_fires_e03` and
//!   `perm_letter_case_flip_duplicate_fires_e03` below.  This is exactly what
//!   `auditctl -R` aborts on with kernel `EEXIST` (`auditctl.c:1680-1686`,
//!   audit 3bfa048): `fclose(f); return -1` -- every rule after the duplicate
//!   silently fails to load.
//!
//! * **au-W01 (Warning)** -- `canonical_key`-equal but NOT kernel-identical
//!   (field order swapped, syscall order swapped, `-a` vs `-A`, or a WATCH's
//!   `-p` letter order different -- that axis goes through
//!   `normalize::perm_letters`, not the `-F perm=` bitmask fold above).  The
//!   kernel does NOT EEXIST on these; they load but are redundant waste.
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

use rulesteward_auditd::{
    lints::{LintOptions, duplicate::w01},
    parse_rules_str_located, parse_target_located,
};
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

    let diags = w01(&rules, LintOptions::default());

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
// Test 2: Syscall-order-swapped duplicate -- au-E03 (load-aborting)
//
// 10-open.rules  line 5: -a always,exit -S open -S close -k fs-access
// 50-swapped.rules line 4: -a always,exit -S close -S open -k fs-access
//
// The kernel stores -S syscalls as a commutative bitmask (libaudit ORs each
// name into rule->mask, lib/libaudit.c:1021-1025), so "-S open -S close" and
// "-S close -S open" are the SAME kernel rule. The second therefore EEXISTs and
// auditctl -R aborts (auditctl.c:1680-1686): a LOAD-ABORTING duplicate -> au-E03
// (Error), not a mere redundancy. (Owner decision: the E03/W01
// boundary is kernel-load-aborting, not literal AST byte-identity; verified
// against libaudit + auditctl source.)
//
// Adversarial: a derived-PartialEq / order-sensitive-Vec impl sees
// syscalls=[open,close] vs [close,open] as distinct and MISSES the E03
// classification (emitting W01 or nothing). Only a set-comparing impl fires E03.
// ---------------------------------------------------------------------------

#[test]
fn syscall_order_swap_fires_e03() {
    let dir = fixture_dir("syscall-order");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 2, "exactly 2 rules expected");

    let diags = w01(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "exactly 1 finding for syscall-order swap, got {diags:?}"
    );

    let d = &diags[0];
    assert_eq!(
        d.severity,
        Severity::Error,
        "syscall-order-swapped duplicate is load-aborting -> au-E03 Error"
    );
    assert_eq!(d.code, "au-E03", "code must be au-E03");
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
// Test 2b: Repeated -S (same name twice) duplicate -- au-E03 (load-aborting)
//
// "-S open -S open" sets the same single bit as "-S open" (libaudit OR), so the
// second rule EEXISTs at load just like the order-swap case. Pins that the set
// comparison dedups, not just sorts.
// ---------------------------------------------------------------------------

#[test]
fn repeated_syscall_duplicate_fires_e03() {
    let input = concat!(
        "-a always,exit -S open -S open -k fs\n",
        "-a always,exit -S open -k fs\n",
    );
    let rules = parse_rules_str_located(input, Path::new("10-rep.rules")).expect("must parse");
    assert_eq!(rules.len(), 2);

    let diags = w01(&rules, LintOptions::default());

    assert_eq!(diags.len(), 1, "repeated-syscall duplicate must fire once");
    assert_eq!(
        diags[0].severity,
        Severity::Error,
        "repeated -S duplicate is load-aborting -> au-E03"
    );
    assert_eq!(diags[0].code, "au-E03");
    assert_eq!(diags[0].line, 2, "anchored at the later (line 2) rule");
}

// ---------------------------------------------------------------------------
// Test 2c / 2d: `-F perm=` letter ORDER and CASE flip -- au-E03 (load-aborting)
//
// `canonical_key` (`normalize.rs:70`) folds a `Syscall` rule's field VALUES
// through `super::value::canonical_value`. A `FieldValue::Perm(PermMask)`
// variant (`classify.rs`/`canonical.rs`) folds `-F perm=` into an
// order-free bitmask (falling back to a raw string compare only when the
// value does not parse as perm letters), so `-F perm=wa` and `-F perm=aw`
// (order-swapped), or `-F perm=wa` and `-F perm=WA` (case-flipped), fold to
// the SAME canonical key, matching `lib/libaudit.c`'s
// `audit_rule_fieldpair_data`, which case-folds every `-F perm=` character
// (`tolower((unsigned char)v[i])`) and ORs the letters into one bitmask
// (`wa`/`aw`/`WA` all produce `AUDIT_PERM_WRITE|AUDIT_PERM_ATTR`), so the
// kernel's `audit_compare_rule` (`kernel/auditfilter.c`) sees byte-identical
// fields, `audit_add_rule` returns `-EEXIST`, and `auditctl -R` aborts the
// file exactly as this module's own au-E03 message already describes
// ("every later rule silently fails to load"). The two tests below are
// GREEN: each fires exactly one au-E03.
// ---------------------------------------------------------------------------

#[test]
fn perm_letter_order_flip_duplicate_fires_e03() {
    let input = concat!(
        "-a always,exit -F path=/usr/bin/su -F perm=wa -k k\n",
        "-a always,exit -F path=/usr/bin/su -F perm=aw -k k\n",
    );
    let rules =
        parse_rules_str_located(input, Path::new("10-perm-order.rules")).expect("must parse");
    assert_eq!(rules.len(), 2);

    let diags = w01(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "-F perm=wa and -F perm=aw are the SAME kernel bitmask (order-free) \
         and must fire exactly one au-E03, got {diags:?}"
    );
    assert_eq!(
        diags[0].severity,
        Severity::Error,
        "an order-swapped -F perm= duplicate is load-aborting -> au-E03"
    );
    assert_eq!(diags[0].code, "au-E03");
    assert_eq!(diags[0].line, 2, "anchored at the later (line 2) rule");
}

#[test]
fn perm_letter_case_flip_duplicate_fires_e03() {
    let input = concat!(
        "-a always,exit -F path=/usr/bin/su -F perm=wa -k k\n",
        "-a always,exit -F path=/usr/bin/su -F perm=WA -k k\n",
    );
    let rules =
        parse_rules_str_located(input, Path::new("10-perm-case.rules")).expect("must parse");
    assert_eq!(rules.len(), 2);

    let diags = w01(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "-F perm=wa and -F perm=WA are the SAME kernel bitmask (libaudit \
         case-folds every -F perm= letter) and must fire exactly one \
         au-E03, got {diags:?}"
    );
    assert_eq!(
        diags[0].severity,
        Severity::Error,
        "a case-flipped -F perm= duplicate is load-aborting -> au-E03"
    );
    assert_eq!(diags[0].code, "au-E03");
    assert_eq!(diags[0].line, 2, "anchored at the later (line 2) rule");
}

// ---------------------------------------------------------------------------
// Distinctness pin: genuinely different perm values must stay DISTINCT
// (issues #600/#601, mutation-gate strengthening).
//
// The Test 2c/2d pins above pin only ONE direction of the perm fold: that
// EQUIVALENT spellings (case/order variants of the SAME kernel bitmask) get
// grouped together. Nothing above pins the opposite direction: that GENUINELY
// DIFFERENT perm values stay DISTINCT. A `PermMask::to_letters`
// (`value/classify.rs:107`) that folds every bitmask to a constant string
// (e.g. `String::new()`), or whose `&`/`!=` bit tests are flipped to
// `|`/`^`/`==`, would make EVERY `-F perm=` value canonicalize identically --
// still passing every Test 2c/2d pin above, while silently making au-E03/au-W01
// fire on rule pairs that are NOT duplicates at all: a fail-open in the
// OPPOSITE direction from the bug those tests fixed (it would fire au-E03 on
// `-F perm=r` vs `-F perm=w`, and credit a STIG control with a candidate
// whose perms are simply wrong -- see the Syscall-vs-Syscall au-W06 tests in
// `test_lints_stig_required.rs` for that surface).
//
// Bit values (`classify.rs:72-75`, `permtab.h:28-31`): READ=1, WRITE=2,
// EXEC=4, ATTR=8 -- four distinct single bits, so no two of the sixteen
// possible `rwxa` letter combinations collide under a CORRECT fold.
//
// `duplicate.rs`'s `perm_field_bits`/`perm_field_values_eexist_equal` are a
// DELIBERATE local reimplementation (see both functions' doc comments), so
// they need their own distinctness pin independent of `classify.rs`'s
// `PermMask` -- see `perm_predicates_swapped_positions_with_distinct_
// values_fires_w01_not_e03` below for the one case that reaches it (a
// single differing `-F perm=` value gets a DIFFERENT `canonical_key` per the
// (correct) classify.rs fold, so `w01` never even calls `rules_eexist_equal`
// on that pair at all -- see the doc comment on that test for why TWO `-F
// perm=` predicates per rule are needed to observe `duplicate.rs`'s own
// fold).
// ---------------------------------------------------------------------------

#[test]
fn perm_single_letter_case_fold_fires_e03_for_every_letter() {
    // PER-LETTER coverage: the Test 2c/2d order/case-flip tests above only
    // exercise the 'w' and 'a' arms of both `PermMask::parse` (classify.rs)
    // and `duplicate.rs`'s local `perm_field_bits` -- 'r' and 'x' are
    // entirely unpinned there, so deleting either match arm survives
    // mutation testing. Looping over all four rwxa letters closes the gap
    // for BOTH functions at once in the EQUIVALENCE direction: grouping (`r`
    // and `R` must get the SAME canonical_key) depends on classify.rs's
    // `PermMask::parse`/`to_letters`; the E03-vs-W01 severity call depends
    // on `duplicate.rs`'s `perm_field_bits`/`perm_field_values_eexist_equal`.
    for letter in ['r', 'w', 'x', 'a'] {
        let upper = letter.to_ascii_uppercase();
        let input = format!(
            "-a always,exit -F path=/usr/bin/su -F perm={letter} -k k\n\
             -a always,exit -F path=/usr/bin/su -F perm={upper} -k k\n",
        );
        let rules =
            parse_rules_str_located(&input, Path::new("10-perm-letter.rules")).expect("must parse");
        assert_eq!(rules.len(), 2, "letter {letter:?}: expected 2 rules");

        let diags = w01(&rules, LintOptions::default());

        assert_eq!(
            diags.len(),
            1,
            "letter {letter:?}: perm={letter} and perm={upper} are the SAME \
             kernel bitmask (libaudit case-folds every -F perm= letter) and \
             must fire exactly one au-E03, got {diags:?}"
        );
        assert_eq!(
            diags[0].severity,
            Severity::Error,
            "letter {letter:?}: a case-flipped single-letter -F perm= \
             duplicate is load-aborting -> au-E03"
        );
        assert_eq!(diags[0].code, "au-E03", "letter {letter:?}");
    }
}

#[test]
fn perm_distinct_perm_values_produce_no_duplicate_finding() {
    // DISTINCTNESS table: each pair below names a GENUINELY DIFFERENT
    // AUDIT_PERM bitmask, so `w01` must not group the two rules as "the same
    // rule" at all -- zero findings, not a severity question. The first six
    // pairs cover every unordered pair of single letters; the next four
    // toggle exactly ONE bit relative to a base value that lacks it; the last
    // two are the `rw`-vs-`rx` / `wa`-vs-`ra` pairs called out when this round
    // was scoped.
    //
    // What this table does and does not pin, both confirmed by RUNNING the
    // mutants rather than by reasoning about them. It kills a COLLISION-shaped
    // `to_letters` mutant that forces one bit's letter to always appear: an
    // always-true READ arm makes WRITE=2 and rw=3 both spell "rw", and this
    // test fails. It does NOT kill the INVERSION-shaped mutant cargo-mutants
    // actually generates (`!= 0` -> `== 0`), because inverting a bit test is
    // still a bijection over the 16 masks, so no two masks collide and every
    // equality-shaped assertion here still holds. The inversion is pinned
    // instead by `canonical_perm_spells_each_bit_in_rwxa_order` in
    // rulesteward-auditd/src/lints/value/mod.rs, which asserts the exact
    // canonical string for a proper subset of the bits.
    let pairs = [
        ("r", "w"),
        ("r", "x"),
        ("r", "a"),
        ("w", "x"),
        ("w", "a"),
        ("x", "a"),
        ("w", "rw"),
        ("x", "wx"),
        ("a", "xa"),
        ("r", "ra"),
        ("rw", "rx"),
        ("wa", "ra"),
    ];
    for (a, b) in pairs {
        let input = format!(
            "-a always,exit -F path=/usr/bin/su -F perm={a} -k k\n\
             -a always,exit -F path=/usr/bin/su -F perm={b} -k k\n",
        );
        let rules = parse_rules_str_located(&input, Path::new("10-perm-distinct.rules"))
            .expect("must parse");
        assert_eq!(rules.len(), 2, "perm={a:?}/perm={b:?}: expected 2 rules");

        let diags = w01(&rules, LintOptions::default());

        assert!(
            diags.is_empty(),
            "perm={a:?} and perm={b:?} are DIFFERENT AUDIT_PERM bitmasks and \
             must never be treated as the same rule (canonical_key must \
             differ), got {diags:?}"
        );
    }
}

#[test]
fn perm_predicates_swapped_positions_with_distinct_values_fires_w01_not_e03() {
    // The ONLY reachable way to feed `duplicate.rs`'s local
    // `perm_field_bits`/`perm_field_values_eexist_equal` a GENUINELY
    // DISTINCT pair while `canonical_key` still groups the two rules
    // together: a single `-F perm=` value differing (e.g. perm=r vs
    // perm=w) gets a DIFFERENT canonical_key under the (correct)
    // classify.rs fold, so `w01` never even calls `rules_eexist_equal` on
    // that pair -- see the "no finding at all" test above. Two `-F perm=`
    // predicates per rule, with the SAME two values but SWAPPED positions,
    // gives `canonical_key` the SAME multiset (`{r, w}` either way, per
    // `normalize.rs`'s sorted field-list encoding) while `rules_eexist_
    // equal`'s POSITIONAL compare (`duplicate.rs:110-121`, mirroring the
    // kernel's own `audit_compare_rule` index-by-index loop) must still
    // tell "r" and "w" apart AT EACH INDEX.
    //
    // Kernel grounding: multiple `-F perm=` predicates CONJOIN
    // (`kernel/auditsc.c`'s `audit_filter_rules` calls `audit_match_perm`
    // once PER `AUDIT_PERM` field and ANDs the per-field results), so
    // "perm=r AND perm=w" (index 0/1) is genuinely a DIFFERENT field list,
    // positionally, from "perm=w AND perm=r" -- `audit_compare_rule`'s
    // per-index `!=` sees a real difference at both indices, so the pair
    // does NOT EEXIST at the kernel: au-W01 (redundant), not au-E03
    // (load-aborting).
    //
    // A `perm_field_bits` that folds every value to a constant (`Some(0)`/
    // `Some(1)`), or whose `|=` is broken to `&=` (which also collapses
    // every single-character value to `Some(0)`), or a
    // `perm_field_values_eexist_equal` hard-coded to `true`, would make
    // BOTH indices compare "equal" here and wrongly report au-E03.
    let input = concat!(
        "-a always,exit -F path=/usr/bin/su -F perm=r -F perm=w -k k\n",
        "-a always,exit -F path=/usr/bin/su -F perm=w -F perm=r -k k\n",
    );
    let rules =
        parse_rules_str_located(input, Path::new("10-perm-swap.rules")).expect("must parse");
    assert_eq!(rules.len(), 2);

    let diags = w01(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "both rules name the SAME set of perm values ({{r, w}}), just at \
         swapped positions, so canonical_key groups them as one pair, got \
         {diags:?}"
    );
    assert_eq!(
        diags[0].severity,
        Severity::Warning,
        "positionally index 0 is perm=r vs perm=w (and index 1 is perm=w vs \
         perm=r) -- genuinely DIFFERENT AUDIT_PERM bitmasks at each index, \
         so the kernel's audit_compare_rule sees a real difference and the \
         pair does NOT EEXIST -> au-W01, not au-E03"
    );
    assert_eq!(diags[0].code, "au-W01");
    assert_eq!(diags[0].line, 2, "anchored at the later (line 2) rule");
}

#[test]
fn perm_predicates_swapped_positions_with_unparseable_ne_values_fires_w01_not_e03() {
    // The FALLBACK branch of `perm_field_values_eexist_equal`
    // (`duplicate.rs:148`, `_ => a.trim() == b.trim()`) is only reached when
    // EITHER side fails to parse as `rwxa` letters -- the function's own doc
    // comment calls this a "conservative 'never happens in practice' safety
    // net", reachable only via a `-F perm!=...`-shaped predicate: the
    // parser's `rwxa` letter-set validation only runs for the `=` operator,
    // so a `!=` perm value can carry arbitrary characters that both
    // `classify.rs`'s `PermMask::parse` and this file's own
    // `perm_field_bits` fail to parse (confirmed empirically: `-F
    // path=/usr/bin/su -F perm!=zz -F perm!=qq -k k` parses cleanly with
    // `value: "zz"` / `value: "qq"` kept verbatim -- the parser does not
    // reject a `!=` perm value for containing non-rwxa characters).
    //
    // Mirrors `perm_predicates_swapped_positions_with_distinct_values_
    // fires_w01_not_e03` above exactly, but with two NON-rwxa `!=` values
    // ("zz"/"qq", no rwxa letters at all) instead of valid letters, so BOTH
    // sides' `perm_field_bits` return `None` and the comparison falls
    // through to line 148's raw-string `==` rather than line 147's
    // `Some`/`Some` bitmask `==`. `classify.rs`'s `PermMask::parse` also
    // fails on "zz"/"qq", so both values stay `FieldValue::Opaque` there
    // too -- `canonical_key` groups the two rules as the SAME multiset
    // (`{"qq", "zz"}` either way), exactly as the valid-letter swap test
    // above does, so the severity question again lands entirely on
    // `duplicate.rs`'s LOCAL fallback comparison.
    let input = concat!(
        "-a always,exit -F path=/usr/bin/su -F perm!=zz -F perm!=qq -k k\n",
        "-a always,exit -F path=/usr/bin/su -F perm!=qq -F perm!=zz -k k\n",
    );
    let rules =
        parse_rules_str_located(input, Path::new("10-perm-swap-ne.rules")).expect("must parse");
    assert_eq!(rules.len(), 2);

    let diags = w01(&rules, LintOptions::default());

    assert_eq!(
        diags.len(),
        1,
        "both rules name the SAME set of unparseable perm!= spellings \
         ({{\"qq\", \"zz\"}}), just at swapped positions, so canonical_key \
         groups them as one pair, got {diags:?}"
    );
    assert_eq!(
        diags[0].severity,
        Severity::Warning,
        "positionally index 0 is perm!=zz vs perm!=qq (and index 1 is \
         perm!=qq vs perm!=zz) -- genuinely DIFFERENT raw spellings at each \
         index (neither parses as rwxa letters, so the fallback raw-string \
         compare applies), so the pair does NOT EEXIST -> au-W01, not \
         au-E03. A fallback compare hard-coded (or inverted) to treat any \
         two unparseable spellings as equal would wrongly report au-E03 \
         here"
    );
    assert_eq!(diags[0].code, "au-W01");
    assert_eq!(diags[0].line, 2, "anchored at the later (line 2) rule");
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

    let diags = w01(&rules, LintOptions::default());

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

    let diags = w01(&rules, LintOptions::default());

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

    let diags = w01(&rules, LintOptions::default());

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

    let diags = w01(&rules, LintOptions::default());

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
// Both findings are au-E03: 50-second is syscall-order-swapped (load-aborting
// per the kernel commutative bitmask) and 90-third is byte-identical -- both
// EEXIST and abort the load.
// ---------------------------------------------------------------------------

#[test]
fn triple_occurrence_yields_two_e03_both_citing_first() {
    let dir = fixture_dir("triple-occurrence");
    let rules = parse_target_located(&dir).expect("fixtures must parse");
    assert_eq!(rules.len(), 3, "exactly 3 rules expected");

    let diags = w01(&rules, LintOptions::default());

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

    // 50-second: syscall-order-swapped -> au-E03 (load-aborting per the kernel
    // commutative bitmask: the swapped -S set is the SAME rule and EEXISTs).
    let second = diags
        .iter()
        .find(|d| d.file.to_string_lossy().contains("50-second"))
        .expect("50-second finding must exist");
    assert_eq!(
        second.severity,
        Severity::Error,
        "50-second (syscall-order-swapped) is load-aborting -> au-E03 Error, got {:?}",
        second.severity
    );
    assert_eq!(second.code, "au-E03");

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
    let diags = w01(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "rocky9-stig-hardened must have zero au-W01/au-E03 findings, got {diags:?}"
    );
}

#[test]
fn clean_corpus_rocky10_cis_benchmark_zero_findings() {
    let path = corpus_dir("rocky10-cis-benchmark").join("audit.rules");
    let rules = parse_target_located(&path).expect("rocky10-cis-benchmark must parse");
    let diags = w01(&rules, LintOptions::default());
    assert!(
        diags.is_empty(),
        "rocky10-cis-benchmark must have zero au-W01/au-E03 findings, got {diags:?}"
    );
}

#[test]
fn clean_corpus_rocky9_huge_ruleset_zero_findings() {
    let path = corpus_dir("rocky9-huge-ruleset").join("audit.rules");
    let rules = parse_target_located(&path).expect("rocky9-huge-ruleset must parse");
    let diags = w01(&rules, LintOptions::default());
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

    let diags = w01(&rules, LintOptions::default());
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
// Test 14: prepend-then-append pair fires au-E03
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

    let diags = w01(&rules, LintOptions::default());

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
// Test 15: double-prepend pair fires au-W01
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

    let diags = w01(&rules, LintOptions::default());

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
    let diags = w01(&[], LintOptions::default());
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
    let diags = w01(&rules, LintOptions::default());
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

    let diags = w01(&rules, LintOptions::default());

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

    let diags = w01(&rules, LintOptions::default());

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

// ---------------------------------------------------------------------------
// T8 (#230): AppArmor msgtype opt-in duplicate detection
//
// With --apparmor ON: msgtype=APPARMOR_DENIED and msgtype=1503 are the same
// canonical rule (au-W01). With --apparmor OFF: they are NOT folded (different
// keys), so no au-W01.
// ---------------------------------------------------------------------------
#[test]
fn t8_apparmor_msgtype_duplicate_requires_on() {
    let input = concat!(
        "-a always,exclude -F msgtype=APPARMOR_DENIED\n",
        "-a always,exclude -F msgtype=1503\n",
    );
    let file = std::path::Path::new("10-apparmor-dup.rules");
    let rules = rulesteward_auditd::parse_rules_str_located(input, file).expect("must parse");
    assert_eq!(rules.len(), 2);

    // With ON: APPARMOR_DENIED == 1503 -> au-W01 (duplicate).
    let diags_on = w01(
        &rules,
        LintOptions {
            include_apparmor: true,
        },
    );
    assert_eq!(
        diags_on.len(),
        1,
        "with --apparmor: APPARMOR_DENIED and 1503 are the same rule, expected 1 au-W01, got {diags_on:?}"
    );
    assert_eq!(diags_on[0].code, "au-W01");

    // With OFF: not folded -> no au-W01.
    let diags_off = w01(&rules, LintOptions::default());
    assert!(
        diags_off.is_empty(),
        "without --apparmor: APPARMOR_DENIED and 1503 are distinct, expected no au-W01, got {diags_off:?}"
    );
}
