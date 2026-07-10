//! RED barrier tests for au-W06 (missing STIG-required audit rules, Warning) --
//! issue #474, session 7c-v0_6-wave3 pipeline P2.
//!
//! Emitted by `lints::stig_required::w06(&[LocatedRule], LintOptions,
//! Option<TargetVersion>)`, version-aware: `target == None` (the portable
//! default) always stays silent. The scenario tests below exercise the real
//! matcher via `lints::stig_required::w06_with_baseline(rules, opts,
//! baseline)`, injecting a small, REAL, appendix-cited test-local baseline
//! directly rather than depending on the shipped `RHEL*_REQUIRED` tables --
//! those are intentionally left EMPTY for the implementer to populate from
//! `tools/auditd-stig-update derive`'s output (see
//! `crates/rulesteward-auditd/src/lints/stig_required.rs`'s module doc for
//! why `w06_with_baseline` is `pub` specifically to make this possible). Every
//! `BaselineRule` line below is copied verbatim from the session's P2
//! grounding doc appendix (real DISA RHEL 9 STIG V2R7 check-content), cited by
//! its `SV-...` id / `RHEL-09-NNNNNN` control id inline.
//!
//! # RED-state note
//! `w06_with_baseline`'s real matching body is `todo!()` (the implementer's
//! job; see that function's doc comment for the full grounded C.5 matcher
//! spec). Every test below that passes a NON-EMPTY baseline therefore PANICS
//! today (RED). The two tests that pass through `w06`'s `target == None`
//! branch (never reaching a non-empty baseline) are GREEN already.

use std::path::Path;

use rulesteward_auditd::lints::LintOptions;
use rulesteward_auditd::lints::catalog::AU_CODES;
use rulesteward_auditd::lints::stig_required::{
    BaselineRule, TargetVersion, w06, w06_with_baseline,
};
use rulesteward_auditd::parse_rules_str_located;
use rulesteward_core::Severity;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse(input: &str) -> Vec<rulesteward_auditd::LocatedRule> {
    parse_rules_str_located(input, Path::new("10-audit.rules")).expect("fixture must parse")
}

fn bl(v_number: &'static str, stig_id: &'static str, line: &'static str) -> BaselineRule {
    BaselineRule {
        v_number,
        stig_id,
        line,
    }
}

/// Three real RHEL 9 STIG V2R7 requirements (P2 grounding doc appendix.txt),
/// covering a plain single-path watch, an arch=b32/b64 ABI PAIR (2 lines, one
/// requirement), and an `-S all` + `-F key=` privileged-command line.
fn rhel9_sample_baseline() -> Vec<BaselineRule> {
    vec![
        // SV-258217r1045436_rule (RHEL-09-654215): plain watch.
        bl(
            "V-258217",
            "RHEL-09-654215",
            "-w /etc/sudoers -p wa -k identity",
        ),
        // SV-258177r1155597_rule (RHEL-09-654015): arch b32/b64 pair, ONE requirement.
        bl(
            "V-258177",
            "RHEL-09-654015",
            "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 \
             -F key=perm_mod",
        ),
        bl(
            "V-258177",
            "RHEL-09-654015",
            "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 \
             -F key=perm_mod",
        ),
        // SV-258180r1045325_rule (RHEL-09-654030): -S all + -F key= privileged-command.
        bl(
            "V-258180",
            "RHEL-09-654030",
            "-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 \
             -F key=privileged-mount",
        ),
    ]
}

/// The literal rules.d text satisfying every line in [`rhel9_sample_baseline`]
/// verbatim (the "fully compliant" ruleset).
const COMPLIANT_RULES: &str = "\
-w /etc/sudoers -p wa -k identity
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount
";

// ---------------------------------------------------------------------------
// target=None: always silent (GREEN today -- w06's None branch never reaches
// a non-empty baseline, so no todo!() is hit)
// ---------------------------------------------------------------------------

#[test]
fn target_none_is_silent_even_on_a_wildly_non_compliant_ruleset() {
    let rules = parse("-D\n-b 8192\n"); // no watch, no syscall audit rule at all
    let diags = w06(&rules, LintOptions::default(), None);
    assert!(
        diags.is_empty(),
        "target=None must stay silent regardless of ruleset content: {diags:?}"
    );
}

#[test]
fn target_some_with_populated_shipped_table_yields_exactly_one_finding_per_required_line() {
    // The shipped RHEL9_REQUIRED table is now populated (issue #474): a bare
    // ruleset with zero matching watch/syscall rules is missing every one of
    // the 67 required lines, so w06's real dispatch (w06 -> baseline_for ->
    // w06_with_baseline) must report exactly one finding per line - the exact
    // count this test-author independently confirmed via
    // `code_table(Rhel9).len()` (mirrors
    // `tools/auditd-stig-update`'s frozen `rhel9_known_answer_counts`/
    // `rhel9_fixture_reproduces_code_table_exactly` pins). Distinct from the
    // adjacent `w06_real_entrypoint_fires_on_a_bare_ruleset_...` test (which
    // proves the dispatch fires + names RHEL-09-654010 but does not pin the
    // exact count or that EVERY finding is severity=Warning): this adds the
    // count precision that test lacks.
    let rules = parse("-D\n-b 8192\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert_eq!(diags.len(), 67, "{diags:?}");
    assert!(
        diags.iter().all(|d| d.severity == Severity::Warning),
        "every au-W06 finding must be severity=Warning: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Barrier BLOCKER 2: the real w06(rules, opts, Some(target)) entrypoint must
// actually FIRE, not just the injected-baseline w06_with_baseline(...) path
// every other scenario test below calls directly. Every scenario test in this
// file bypasses w06's target -> baseline_for -> w06_with_baseline dispatch
// chain by injecting a small test-local baseline straight into
// w06_with_baseline, so NOTHING here fails if w06() silently ignores
// stig_baseline(target) and stays permanently silent -- only
// target_some_with_populated_shipped_table_yields_exactly_one_finding_per_required_line
// (above) exercises the real dispatch; the test below adds the "fires + names
// a specific control id" proof that count alone does not give.
// ---------------------------------------------------------------------------

#[test]
fn w06_real_entrypoint_fires_on_a_bare_ruleset_against_the_shipped_rhel9_table() {
    // Goes through the REAL dispatch chain (w06 -> baseline_for ->
    // w06_with_baseline) against the SHIPPED RHEL9_REQUIRED table, on a
    // ruleset with no watch and no syscall audit rule at all (only
    // control-plane lines). RED today for two independent, stacked reasons:
    // RHEL9_REQUIRED is still an empty placeholder (dispatch short-circuits to
    // Vec::new() before ever reaching the matcher -- same as the test above),
    // AND once the implementer populates it, w06_with_baseline's real matcher
    // body is todo!(). GREEN only when BOTH the shipped table is populated
    // (from `auditd-stig-update derive`'s RHEL9 output) AND the matcher
    // actually fires on a non-compliant ruleset.
    let rules = parse("-D\n-b 8192\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        !diags.is_empty(),
        "a bare ruleset with zero matching watch/syscall rules must not pass \
         silently through the real w06 dispatch once the RHEL9 table is \
         populated: {diags:?}"
    );
    assert!(
        diags.iter().all(|d| d.code == "au-W06"),
        "every finding from w06 must carry the au-W06 code: {diags:?}"
    );
    // SV-258176r1155595_rule (RHEL-09-654010, "execve") is one of the 51
    // grounded RHEL9 requirements (P2 grounding doc appendix.txt) that
    // tools/auditd-stig-update's rhel9_fixture_reproduces_code_table_exactly
    // test pins the shipped table must reproduce exactly, so it is guaranteed
    // to be present in the final RHEL9_REQUIRED table and must be reported
    // missing here.
    assert!(
        diags.iter().any(|d| d.message.contains("RHEL-09-654010")),
        "expected the execve requirement (RHEL-09-654010) to be reported \
         missing on a bare ruleset: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Compliant ruleset -> ZERO findings
// ---------------------------------------------------------------------------

#[test]
fn compliant_rhel9_ruleset_yields_zero_findings() {
    let rules = parse(COMPLIANT_RULES);
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a fully compliant ruleset must be clean: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Missing-rule scenarios
// ---------------------------------------------------------------------------

#[test]
fn removing_one_watch_yields_exactly_one_finding_naming_its_stig_id() {
    // SV-258217 (RHEL-09-654215) removed from the ruleset; the ABI pair and the
    // privileged-command line stay present.
    let rules = parse(
        "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount\n",
    );
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning, "au-W06 is a Warning");
    assert_eq!(d.code, "au-W06");
    assert!(
        d.message.contains("RHEL-09-654215"),
        "message must name the missing watch's STIG id, got {:?}",
        d.message
    );
    // CONCERN 1: a plain-missing finding (the required rule has no same-shape
    // counterpart anywhere in the ruleset at all, not even with a different
    // key) must NOT reuse the present-but-key-differs wording -- otherwise the
    // two distinct cases (grounding Part C.5's "Missing" vs "Present-but-
    // key-differs" verdicts) collapse into indistinguishable messages.
    assert!(
        !d.message.contains("different key"),
        "a plain-missing finding must not use the present-but-key-differs \
         wording, got {:?}",
        d.message
    );
}

#[test]
fn removing_one_abi_line_of_a_pair_yields_a_finding_for_the_missing_abi_only() {
    // Drop the b64 chmod line; b32 chmod stays, so ONLY the b64 half is missing.
    let rules = parse(
        "-w /etc/sudoers -p wa -k identity\n\
         -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount\n",
    );
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert_eq!(
        diags.len(),
        1,
        "only the missing b64 half must fire: {diags:?}"
    );
    let d = &diags[0];
    assert_eq!(d.code, "au-W06");
    assert!(
        d.message.contains("RHEL-09-654015"),
        "message must name the ABI pair's STIG id, got {:?}",
        d.message
    );
    assert!(
        d.message.contains("b64"),
        "message must identify the b64 ABI as the missing half, got {:?}",
        d.message
    );
}

#[test]
fn wrong_list_action_does_not_satisfy_the_requirement() {
    // A rule on the WRONG list/action (never,exit instead of always,exit) does
    // not satisfy an always,exit requirement -- it is a structurally different
    // rule (grounding C.5's exact list/action equality axis), so the required
    // line is reported missing, not satisfied.
    let rules = parse(
        "-w /etc/sudoers -p wa -k identity\n\
         -a never,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount\n",
    );
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert_eq!(
        diags.len(),
        1,
        "the never,exit rule must NOT satisfy the always,exit b32 requirement: {diags:?}"
    );
    assert!(
        diags[0].message.contains("RHEL-09-654015"),
        "{:?}",
        diags[0].message
    );
}

#[test]
fn narrower_watch_perms_does_not_satisfy_the_requirement() {
    // Grounding doc Part C.5: watch perms compare by EXACT PermBits equality,
    // not subset -- every DISA watch requirement in the corpus uses `wa`
    // uniformly, so a user watch with only `-p w` (missing the `a` bit) does
    // NOT satisfy a `-p wa` requirement, even though `w` alone might seem
    // "close enough". This is explicitly settled in the grounding doc, not a
    // narrowing left to the implementer's judgment.
    let rules = parse(
        "-w /etc/sudoers -p w -k identity\n\
         -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount\n",
    );
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert_eq!(
        diags.len(),
        1,
        "a narrower -p w watch must NOT satisfy a -p wa requirement: {diags:?}"
    );
    assert!(
        diags[0].message.contains("RHEL-09-654215"),
        "{:?}",
        diags[0].message
    );
}

// ---------------------------------------------------------------------------
// Variant confusion: a Watch-shaped requirement must never be satisfied by a
// kernel-equivalent Syscall-shaped rule (same-variant matching only).
// ---------------------------------------------------------------------------

#[test]
fn watch_requirement_not_satisfied_by_a_kernel_equivalent_syscall_spelling() {
    // CONCERN 2 + grounding doc Part C.2's documented "known non-goal": a
    // rules.d file could express a watch-equivalent effect via the raw
    // syscall-rule spelling (`-a ... -F path=... -F perm=... -F key=...`, no
    // `-S` at all) instead of `-w`. Kernel-functionally `auditctl -l` would
    // print that back as `-w` (per audit-userspace's `is_watch()`), but our
    // STATIC parser (reads rules.d text directly, never `-l` output)
    // classifies it as `AuditRule::Syscall`, never `AuditRule::Watch` -- and
    // this is not merely hypothetical: rhel10's real SV-281154 family
    // (P2 grounding appendix.txt line 324) uses exactly this
    // `-a ... -F path= -F perm= -F key=` shape for the SAME semantic that
    // rhel8/rhel9 express with a plain `-w`. The au-W06 matcher must match a
    // Watch-shaped baseline requirement ONLY against Watch-shaped AST nodes:
    // a same-path/same-perm/same-key Syscall-shaped rule must NOT be accepted
    // as satisfying it.
    let rules = parse(
        "-a always,exit -F path=/etc/sudoers -F perm=wa -F key=identity\n\
         -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 \
         -F key=perm_mod\n\
         -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 \
         -F key=perm_mod\n\
         -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 \
         -F key=privileged-mount\n",
    );
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert_eq!(
        diags.len(),
        1,
        "a kernel-equivalent Syscall-spelled rule must NOT satisfy a \
         Watch-shaped requirement: {diags:?}"
    );
    assert!(
        diags[0].message.contains("RHEL-09-654215"),
        "{:?}",
        diags[0].message
    );
}

// ---------------------------------------------------------------------------
// Present-but-key-differs: the locked DISTINCT finding
// ---------------------------------------------------------------------------

#[test]
fn predicate_equal_rule_with_a_different_key_is_a_distinct_finding() {
    // Every axis of the privileged-command requirement matches EXCEPT the key
    // (WRONG_KEY instead of privileged-mount): this is present-but-key-differs,
    // not plain-missing -- a DISTINCT message shape (pinned contract: contains
    // "different key", per the locked decision that this is its own case).
    let rules = parse(
        "-w /etc/sudoers -p wa -k identity\n\
         -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=WRONG_KEY\n",
    );
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Warning);
    assert_eq!(d.code, "au-W06");
    assert!(d.message.contains("RHEL-09-654030"), "{:?}", d.message);
    assert!(
        d.message.contains("different key"),
        "present-but-key-differs must use a DISTINCT message shape (contains \
         \"different key\"), not the plain-missing wording, got {:?}",
        d.message
    );
}

// ---------------------------------------------------------------------------
// Spelling equivalences that MUST still satisfy
// ---------------------------------------------------------------------------

#[test]
fn dash_k_spelling_satisfies_a_dash_f_key_equals_requirement() {
    // The baseline requires "-F key=perm_mod" (b32 chmod); a user rule spelling
    // the SAME key via "-k perm_mod" must still satisfy (-k == -F key=, locked
    // decision, grounded in auditctl-listing.c print_rule's AUDIT_FILTERKEY
    // case, C.1).
    let rules = parse(
        "-w /etc/sudoers -p wa -k identity\n\
         -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod\n\
         -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount\n",
    );
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "-k perm_mod must satisfy a -F key=perm_mod requirement: {diags:?}"
    );
}

#[test]
fn syscall_key_unify_is_symmetric_in_both_spelling_directions() {
    // BLOCKER 3: rhel9_sample_baseline() spells every SYSCALL requirement's
    // key with "-F key=" (only the watch uses "-k"), so
    // dash_k_spelling_satisfies_a_dash_f_key_equals_requirement above only
    // ever exercises baseline "-F key=" vs ruleset "-k". But the REAL derived
    // RHEL9 table has syscall requirements that spell the key "-k" in
    // check-content too -- e.g. SV-258176r1155595_rule (RHEL-09-654010,
    // "execve"): "... -k execpriv" (P2 grounding doc appendix.txt line 114).
    // An asymmetric key-unify (e.g. reading a rule's "effective key" only via
    // `fields.iter().find(Key)`, never falling back to the parsed `key` slot
    // the "-k" token populates directly -- grounding Part C.5's `.or_else`
    // spec) would pass every OTHER test in this file while false-positively
    // reporting a MISSING finding on a fully compliant host whenever DISA's
    // own baseline happens to spell a syscall key with "-k" instead of
    // "-F key=". Pin BOTH directions side by side in one scenario so neither
    // can be silently skipped.
    let baseline = vec![
        // SV-258176r1155595_rule (RHEL-09-654010): baseline spells the key
        // "-k execpriv" (real grounded line).
        bl(
            "V-258176",
            "RHEL-09-654010",
            "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv",
        ),
        // SV-258177r1155597_rule (RHEL-09-654015): baseline spells the key
        // "-F key=perm_mod" (real grounded line; the opposite direction).
        bl(
            "V-258177",
            "RHEL-09-654015",
            "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 \
             -F key=perm_mod",
        ),
    ];
    let rules = parse(
        // Satisfies V-258176's baseline "-k execpriv" via the OPPOSITE
        // ruleset spelling, "-F key=execpriv".
        "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv\n\
         -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 \
         -k perm_mod\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "both key-spelling directions (baseline -k / ruleset -F key=, AND \
         baseline -F key= / ruleset -k) must satisfy: {diags:?}"
    );
}

#[test]
fn field_order_permutation_still_satisfies() {
    // Same predicates as the privileged-command requirement, scrambled order.
    // Field-order-insensitive per the locked decision (grounded in
    // auditctl-listing.c print_rule's kernel-field-order printing, C.1: a
    // rules.d file's AUTHORED order is never canonical).
    let rules = parse(
        "-w /etc/sudoers -p wa -k identity\n\
         -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -F auid!=-1 -F key=privileged-mount -F auid>=1000 -F perm=x -S all -F path=/usr/bin/umount\n",
    );
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a field-order permutation of an otherwise-identical rule must satisfy: {diags:?}"
    );
}

#[test]
fn auid_sentinel_spellings_all_satisfy() {
    // auid!=-1 (baseline spelling) vs auid!=4294967295 vs auid!=unset: all three
    // denote the IDENTICAL kernel value (grounding Part C.4); the existing,
    // already-mutation-gated `canonical_value` fold (value/canonical.rs) is
    // reused by the matcher, so au-W06 needs zero new normalization code for
    // this axis.
    for sentinel in ["-1", "4294967295", "unset"] {
        let rules_text = format!(
            "-w /etc/sudoers -p wa -k identity\n\
             -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
             -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
             -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!={sentinel} \
             -F key=privileged-mount\n"
        );
        let rules = parse(&rules_text);
        let baseline = rhel9_sample_baseline();
        let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
        assert!(
            diags.is_empty(),
            "auid!={sentinel} must satisfy an auid!=-1 requirement: {diags:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Catalog parity: every au-W06 finding above already asserted severity=Warning
// and code=au-W06 individually; this pins the catalog entry itself agrees.
// ---------------------------------------------------------------------------

#[test]
fn catalog_lists_au_w06_as_warning() {
    let entry = AU_CODES
        .iter()
        .find(|c| c.code == "au-W06")
        .expect("au-W06 must be catalogued");
    assert_eq!(entry.severity, Severity::Warning);
}
