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
//! # RED-state note (session 8b, issue #502)
//! `w06_with_baseline`'s matcher is FULLY IMPLEMENTED (au-W06 shipped in v0.6);
//! the au-W06 scenario tests below are all GREEN. The only RED tests in this
//! file are the control-ID backfill assertions added for issue #502
//! (`w06_missing_finding_carries_its_stig_control_ref` and
//! `multiple_missing_findings_carry_distinct_per_finding_controls`): they pin
//! that every au-W06 finding must ALSO carry a typed
//! `rulesteward_core::ControlRef { framework: Stig, id: <stig_id>, alias:
//! <v_number> }`, which the emit sites do not attach yet. They fail on the
//! `controls.len()` assertion (0 != 1) until the implementer wires the control
//! onto each `Diagnostic`.

use std::path::Path;

use rulesteward_auditd::lints::LintOptions;
use rulesteward_auditd::lints::catalog::AU_CODES;
use rulesteward_auditd::lints::duplicate::w01;
use rulesteward_auditd::lints::stig_required::{
    BaselineRule, TargetVersion, stig_baseline, w06, w06_with_baseline,
};
use rulesteward_auditd::parse_rules_str_located;
use rulesteward_core::{Framework, Severity};

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
    //
    // UPDATED (#523, session 9b-v0_8-wave2 lane 2e): the shipped RHEL9_REQUIRED
    // table grew from 67 to 69 rows for the two Control-shaped deepening
    // entries grounded live against the pinned RHEL 9 STIG V2R7 XCCDF
    // (V-258227/RHEL-09-654265 "-f 2" and V-258229/RHEL-09-654275 "-e 2"; see
    // the "Deepening (#523)" block below) -- that bump already landed and is
    // GREEN. The next bump (also #523, additive round 2): 69 -> 70 rows for
    // the "--loginuid-immutable" deepening entry (V-258228/RHEL-09-654270;
    // see the "Deepening cont'd (#523)" block further below) -- also landed
    // and is GREEN.
    //
    // #549 RE-GROUNDED (session 9e-wave2c pipeline P2, 2026-07-17): DISA RHEL
    // 9 STIG V2R9 (confirmed via U_RHEL_9_V2R9_STIG.zip; lane3-tooling.md T1
    // DRIFT-CHECK, "33 change(s)") rewrote 9 identity/login audit rules from
    // single-line watch form into dual-arch (b32/b64) syscall form (net +9:
    // 9 old single lines -> 18 new lines) and added a new required rule,
    // V-279936 (RHEL-09-654097), for `execve` auditing scoped to
    // `subj_type=crond_t` (cron_exec key), replacing the two old cron watch
    // lines with 4 new dual-arch syscall lines (net +2). Net table growth:
    // 70 + 9 + 2 = 81. RED today: the shipped RHEL9_REQUIRED table is still
    // 70 rows (V2R7-grounded identity/cron content).
    let rules = parse("-D\n-b 8192\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert_eq!(diags.len(), 81, "{diags:?}");
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

// ---------------------------------------------------------------------------
// stig_baseline: the pub accessor for the drift tool. `tools/auditd-stig-
// update`'s `check`/`derive` subcommands import it directly, and (unlike
// baseline_for, which is only reached indirectly via `w06`) it had no
// in-crate test proving it forwards to the REAL per-product table rather
// than an empty slice (mutation gate, session 7c pipeline P2: `stig_baseline
// -> Vec::leak(Vec::new())` survived).
// ---------------------------------------------------------------------------

#[test]
fn stig_baseline_returns_the_real_shipped_table_for_each_target() {
    // Length + a known control id per product, mirroring the tool crate's own
    // rhel{8,9,10}_known_answer_counts pins.
    //
    // UPDATED (#523, session 9b-v0_8-wave2 lane 2e): counts bumped from the
    // prior 61/67/75 to 62/69/77 -- one new Control-shaped deepening entry on
    // RHEL8 (V-230402/RHEL-08-030121, "-e 2") and two each on RHEL9
    // (V-258227/RHEL-09-654265 "-f 2", V-258229/RHEL-09-654275 "-e 2") and
    // RHEL10 (V-281103/RHEL-10-500035 "-f 2", V-281365/RHEL-10-900100 "-e 2"),
    // all grounded live against the pinned DISA XCCDF (see the "Deepening
    // (#523)" block below). That bump already landed and is GREEN.
    //
    // SECOND, additive bump (also #523, additive round 2, "Deepening cont'd"
    // block further below): "--loginuid-immutable" adds ONE MORE entry each to
    // RHEL8 (62 -> 63: V-230403/RHEL-08-030122) and RHEL9 (69 -> 70:
    // V-258228/RHEL-09-654270). RHEL10's XCCDF has no loginuid-immutable
    // control at all (verified live 2026-07-15 -- no Group/Rule mentions
    // "loginuid" anywhere in the pinned U_RHEL_10_V1R1_STIG.zip), so RHEL10
    // stays at 77 (see `rhel10_loginuid_immutable_control_absent_from_baseline`
    // below for that discriminating-negative guard). RED today: the RHEL8 and
    // RHEL9 shipped tables are still 62/69 rows (no loginuid row yet).
    let rhel8 = stig_baseline(TargetVersion::Rhel8);
    assert_eq!(rhel8.len(), 63, "{rhel8:?}");
    assert!(
        rhel8.iter().any(|r| r.stig_id == "RHEL-08-030000"),
        "RHEL8 baseline must contain RHEL-08-030000: {rhel8:?}"
    );
    assert!(
        rhel8.iter().any(|r| r.stig_id == "RHEL-08-030121"),
        "RHEL8 baseline must contain the new RHEL-08-030121 (\"-e 2\") deepening entry: {rhel8:?}"
    );
    assert!(
        rhel8.iter().any(|r| r.stig_id == "RHEL-08-030122"
            && r.v_number == "V-230403"
            && r.line == "--loginuid-immutable"),
        "RHEL8 baseline must contain the new RHEL-08-030122 (V-230403, \
         \"--loginuid-immutable\") deepening entry: {rhel8:?}"
    );

    let rhel9 = stig_baseline(TargetVersion::Rhel9);
    // #549 RE-GROUNDED (session 9e-wave2c pipeline P2, 2026-07-17;
    // strengthened per adversarial review of commit bbcca23): was 70.
    // DISA RHEL 9 STIG V2R9 (confirmed via U_RHEL_9_V2R9_STIG.zip;
    // lane3-tooling.md T1 DRIFT-CHECK, "33 change(s)") rewrote 9
    // identity/login audit rules from single-line watch form into dual-arch
    // (b32/b64) syscall form (net +9: 9 old lines -> 18 new lines) and added a
    // new required rule, V-279936 (RHEL-09-654097), for `execve` auditing
    // scoped to `subj_type=crond_t` (`cron_exec` key), replacing the two old
    // cron watch lines with 4 new dual-arch syscall lines (net +2). Net table
    // growth: 70 + 9 + 2 = 81. RED today: the shipped table is still 70 rows
    // (V2R7-grounded identity/cron content).
    assert_eq!(rhel9.len(), 81, "{rhel9:?}");
    assert!(
        rhel9.iter().any(|r| r.stig_id == "RHEL-09-654010"),
        "RHEL9 baseline must contain RHEL-09-654010: {rhel9:?}"
    );
    assert!(
        rhel9.iter().any(|r| r.stig_id == "RHEL-09-654265"),
        "RHEL9 baseline must contain the new RHEL-09-654265 (\"-f 2\") deepening entry: {rhel9:?}"
    );
    assert!(
        rhel9.iter().any(|r| r.stig_id == "RHEL-09-654275"),
        "RHEL9 baseline must contain the new RHEL-09-654275 (\"-e 2\") deepening entry: {rhel9:?}"
    );
    assert!(
        rhel9.iter().any(|r| r.stig_id == "RHEL-09-654270"
            && r.v_number == "V-258228"
            && r.line == "--loginuid-immutable"),
        "RHEL9 baseline must contain the new RHEL-09-654270 (V-258228, \
         \"--loginuid-immutable\") deepening entry: {rhel9:?}"
    );

    let rhel10 = stig_baseline(TargetVersion::Rhel10);
    assert_eq!(rhel10.len(), 77, "{rhel10:?}");
    assert!(
        rhel10.iter().any(|r| r.stig_id == "RHEL-10-500300"),
        "RHEL10 baseline must contain RHEL-10-500300: {rhel10:?}"
    );
    assert!(
        rhel10.iter().any(|r| r.stig_id == "RHEL-10-500035"),
        "RHEL10 baseline must contain the new RHEL-10-500035 (\"-f 2\") deepening entry: {rhel10:?}"
    );
    assert!(
        rhel10.iter().any(|r| r.stig_id == "RHEL-10-900100"),
        "RHEL10 baseline must contain the new RHEL-10-900100 (\"-e 2\") deepening entry: {rhel10:?}"
    );
}

// ---------------------------------------------------------------------------
// #549 content pins (adversarial-review finding 2a, split into its own test
// function to keep `stig_baseline_returns_the_real_shipped_table_for_each_
// target` under clippy's too_many_lines threshold): exact `line ==` pins for
// ALL 10 V2R9-rewritten RHEL9 V-numbers (9 identity/login + V-279936
// cron_exec), not just the aggregate count the sibling test above pins --
// closes the gap where an impl could hit the count of 81 with wrong syscall
// content, or where a typo'd new form for an already-scenario-tested row
// (V-258222/V-258223/V-279936, see the real-entrypoint tests further below)
// would still pass because the OLD form also fails to match a typo'd
// requirement.
//
// Every line below is transcribed VERBATIM from this V-number's Group's
// <check-content> in the real DISA RHEL 9 STIG V2R9 XCCDF (downloaded
// 2026-07-17 from https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/
// U_RHEL_9_V2R9_STIG.zip into /mnt/side-projects/9e-wave2c/scratch/
// stig-v2r9/U_RHEL_9_V2R9_Manual_STIG/U_RHEL_9_STIG_V2R9_Manual-xccdf.xml,
// outside the repo) -- check-content, NOT fixtext: this project's own
// `tools/auditd-stig-update/src/xccdf.rs` module doc documents a DELIBERATE
// deviation from the sshd-stig-update precedent specifically because fixtext
// disagrees with check-content for 41/51 RHEL9 requirements (omits `-S all`,
// wrong sentinel spelling, `-k` instead of `-F key=`). This project's OWN
// choice of check-content as the authoritative source is independently
// corroborated here: V-258221's fixtext literally has a typo (`-F
// path=/etc/opasswd`, dropping `/security/`) that check-content does NOT
// have (`-F path=/etc/security/opasswd`, matching the Group's own
// title/description) -- verified directly against the raw XCCDF XML, not
// assumed.
// ---------------------------------------------------------------------------

#[test]
fn stig_baseline_rhel9_v2r9_content_pins() {
    let rhel9 = stig_baseline(TargetVersion::Rhel9);

    let identity_pins: &[(&str, &str, &str)] = &[
        (
            "V-258217",
            "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -k identity",
            "-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -k identity",
        ),
        (
            "V-258218",
            "-a always,exit -F arch=b32 -F path=/etc/sudoers.d -F perm=wa -k identity",
            "-a always,exit -F arch=b64 -F path=/etc/sudoers.d -F perm=wa -k identity",
        ),
        (
            "V-258219",
            "-a always,exit -F arch=b32 -F path=/etc/group -F perm=wa -k identity",
            "-a always,exit -F arch=b64 -F path=/etc/group -F perm=wa -k identity",
        ),
        (
            "V-258220",
            "-a always,exit -F arch=b32 -F path=/etc/gshadow -F perm=wa -k identity",
            "-a always,exit -F arch=b64 -F path=/etc/gshadow -F perm=wa -k identity",
        ),
        (
            "V-258221",
            "-a always,exit -F arch=b32 -F path=/etc/security/opasswd -F perm=wa -k identity",
            "-a always,exit -F arch=b64 -F path=/etc/security/opasswd -F perm=wa -k identity",
        ),
        (
            "V-258222",
            "-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -k identity",
            "-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity",
        ),
        (
            "V-258223",
            "-a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -k identity",
            "-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k identity",
        ),
        (
            "V-258224",
            "-a always,exit -F arch=b32 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins",
            "-a always,exit -F arch=b64 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins",
        ),
        // V-258225's b64 check-content line carries a genuine DOUBLE space
        // before `-F perm=wa` in the real DISA V2R9 check-content
        // ("/var/log/lastlog  -F perm=wa", verified against the raw XML; b32
        // and every other line in this table is single-space). RE-GROUNDED
        // (round-2 adversarial review of commit c633771): pinned VERBATIM
        // here, not normalized to one space. The runtime matcher
        // (`w06_with_baseline`'s `rules_match`) tokenizes on whitespace, so
        // it would treat single- and double-space identically -- but
        // `tools/auditd-stig-update`'s drift tooling does NOT: `derive.rs`'s
        // `diff_rules` compares `DerivedRule.line` byte-exactly (a
        // `BTreeSet` difference, not a normalized compare), `xccdf.rs`'s
        // `extract_rule_lines` only trims LINE ENDS
        // (`raw_line.trim()`, xccdf.rs:299) and preserves internal
        // whitespace verbatim, the module doc mandates the `derive`
        // paste-ready output be "pasted verbatim, not hand-edited", and
        // `rhel9_fixture_reproduces_code_table_exactly` (xccdf.rs:339)
        // asserts the fixture-derived table and the shipped code table are
        // byte-exact via that same `diff_rules`. So once the implementer
        // bumps the RHEL9 fixture+table to V2R9, the shipped
        // `RHEL9_REQUIRED` table's V-258225 b64 row MUST carry the verbatim
        // double-space line to keep BOTH `rhel9_fixture_reproduces_code_
        // table_exactly` AND the `auditd-stig-check` CI drift gate green --
        // a single-space pin here would make this content-pin test and
        // those byte-exact tests mutually unsatisfiable.
        (
            "V-258225",
            "-a always,exit -F arch=b32 -F path=/var/log/lastlog -F perm=wa -F auid>=1000 -F auid!=unset -k logins",
            "-a always,exit -F arch=b64 -F path=/var/log/lastlog  -F perm=wa -F auid>=1000 -F auid!=unset -k logins",
        ),
    ];
    for (v_number, b32_line, b64_line) in identity_pins {
        assert!(
            rhel9
                .iter()
                .any(|r| r.v_number == *v_number && r.line == *b32_line),
            "RHEL9 baseline must contain {v_number}'s V2R9 b32 dual-arch \
             syscall form exactly: {b32_line:?}; got {rhel9:?}"
        );
        assert!(
            rhel9
                .iter()
                .any(|r| r.v_number == *v_number && r.line == *b64_line),
            "RHEL9 baseline must contain {v_number}'s V2R9 b64 dual-arch \
             syscall form exactly: {b64_line:?}; got {rhel9:?}"
        );
    }

    // V-279936 (RHEL-09-654097): the new cron_exec rule, 4 lines (b32/b64 x
    // auid-scoped/euid=0 variants), transcribed verbatim from its
    // check-content in the same downloaded V2R9 XCCDF.
    let v279936_lines: &[&str] = &[
        "-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec",
        "-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec",
        "-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec",
        "-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec",
    ];
    for line in v279936_lines {
        assert!(
            rhel9
                .iter()
                .any(|r| r.v_number == "V-279936" && r.line == *line),
            "RHEL9 baseline must contain V-279936's V2R9 line exactly: \
             {line:?}; got {rhel9:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// normalize_watch_path: the trailing-slash-normalized watch-path compare
// (grounding Part B.7.2). Mutation gate, session 7c pipeline P2: the two
// constant-return mutants (-> "" / -> "xyzzy") both survived because every
// other scenario test above uses paths that are ALREADY normalize-equal
// (identical spelling), so a constant normalizer never diverged from the
// real one. RHEL-08-030172 (V-230410) is the real DISA requirement that
// grounded B.7.2's trailing-slash disagreement: "-w /etc/sudoers.d/ -p wa -k
// identity".
// ---------------------------------------------------------------------------

#[test]
fn watch_path_trailing_slash_is_normalized_before_comparison() {
    // A user rule spelled with the OPPOSITE trailing-slash convention (no
    // trailing `/`) must still satisfy the requirement.
    let baseline = vec![bl(
        "V-230410",
        "RHEL-08-030172",
        "-w /etc/sudoers.d/ -p wa -k identity",
    )];
    let rules = parse("-w /etc/sudoers.d -p wa -k identity\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a watch path differing only by a trailing slash must satisfy the \
         requirement: {diags:?}"
    );
}

#[test]
fn distinct_watch_paths_are_not_normalized_to_the_same_value() {
    // Companion to the test above: proves normalize_watch_path is not a
    // constant function. A constant normalizer (the two MISSED mutants)
    // would make EVERY watch path compare equal, silently widening the
    // matcher to accept any watch as satisfying any path-differing
    // requirement. A watch requirement on /etc/sudoers.d/ (RHEL-08-030172)
    // is genuinely NOT satisfied by a user rule watching a DIFFERENT path,
    // /etc/cron.d.
    let baseline = vec![bl(
        "V-230410",
        "RHEL-08-030172",
        "-w /etc/sudoers.d/ -p wa -k identity",
    )];
    let rules = parse("-w /etc/cron.d -p wa -k identity\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert_eq!(
        diags.len(),
        1,
        "a watch on a DIFFERENT path must not satisfy the requirement: {diags:?}"
    );
    assert!(
        diags[0].message.contains("RHEL-08-030172"),
        "{:?}",
        diags[0].message
    );
}

// ---------------------------------------------------------------------------
// Control-ID backfill (issue #502, session 8b): au-W06 findings must carry a
// typed rulesteward_core::ControlRef alongside the existing free-text message,
// mirroring the sysctld-W02 precedent
// (crates/rulesteward-sysctld/src/lints/baseline.rs's
// `w02_baseline_findings_carry_their_stig_control`). Unlike sysctld's
// `BaselineKey` (stig_id only), auditd's `BaselineRule` also carries a DISA
// Group/Vuln `v_number`, so the control's `alias` slot is populated too.
// ---------------------------------------------------------------------------

#[test]
fn w06_missing_finding_carries_its_stig_control_ref() {
    // SV-258217r1045436_rule (RHEL-09-654215, V-258217): plain watch on
    // /etc/sudoers -- the same requirement `rhel9_sample_baseline()` above
    // encodes, and the same shipped-table row at
    // crates/rulesteward-auditd/src/lints/stig_required.rs:673-677
    // (`BaselineRule { v_number: "V-258217", stig_id: "RHEL-09-654215", line:
    // "-w /etc/sudoers -p wa -k identity" }`). Removing it from an otherwise-
    // compliant ruleset (same fixture shape as
    // `removing_one_watch_yields_exactly_one_finding_naming_its_stig_id`
    // above) yields exactly one au-W06 MISSING finding; this test pins the
    // typed `ControlRef` the implementer must additionally attach.
    let rules = parse(
        "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod\n\
         -a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount\n",
    );
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    let d = &diags[0];

    // MESSAGE assertion unchanged (the free-text shape the implementer must
    // not alter): still names the STIG id as plain text.
    assert!(
        d.message.contains("RHEL-09-654215"),
        "message must still name the missing watch's STIG id, got {:?}",
        d.message
    );

    // NEW: the typed control assertion (issue #502). Length-first so a RED
    // failure is a clean `0 != 1`, not an index panic on `controls[0]`.
    assert_eq!(
        d.controls.len(),
        1,
        "au-W06 finding must carry exactly one typed ControlRef: {d:?}"
    );
    assert_eq!(d.controls[0].framework, Framework::Stig);
    assert_eq!(d.controls[0].id, "RHEL-09-654215");
    assert_eq!(d.controls[0].alias.as_deref(), Some("V-258217"));
}

#[test]
fn multiple_missing_findings_carry_distinct_per_finding_controls() {
    // BLOCKER (barrier adversarial review): the single-finding test above is
    // passed by a WRONG hardcoded-constant impl (attach ONE fixed ControlRef to
    // every au-W06 finding). This test forecloses that: only the watch is
    // present, so `rhel9_sample_baseline()`'s OTHER three required lines are all
    // missing -- the chmod ABI pair (both b32 + b64 rows,
    // RHEL-09-654015 / V-258177, shipped-table lines 413-417 and 418-422) and
    // the umount privileged-command line (RHEL-09-654030 / V-258180, shipped-
    // table line 453-457). That yields THREE findings carrying TWO distinct
    // (id, alias) controls. A constant impl would pair, say, the chmod control
    // with the umount finding whose message names RHEL-09-654030 -- caught here
    // by requiring each finding's control id to appear in ITS OWN message.
    let rules = parse("-w /etc/sudoers -p wa -k identity\n");
    let baseline = rhel9_sample_baseline();
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert_eq!(
        diags.len(),
        3,
        "the chmod ABI pair (2) + umount (1) are all missing: {diags:?}"
    );

    // Per-finding sourcing: each finding carries exactly one control whose id is
    // the STIG id named in THAT finding's own message. Length-check first so RED
    // is a clean `0 != 1`, never an index panic on `controls[0]`.
    for d in &diags {
        assert_eq!(d.code, "au-W06");
        assert_eq!(
            d.controls.len(),
            1,
            "each au-W06 finding carries exactly one control: {d:?}"
        );
        assert_eq!(d.controls[0].framework, Framework::Stig);
        assert!(
            d.message.contains(d.controls[0].id.as_str()),
            "each finding's control id must be the one named in its OWN message \
             (per-finding sourcing, not a shared constant): control={:?} \
             message={:?}",
            d.controls[0],
            d.message
        );
    }

    // The (id, alias) set across the findings contains BOTH distinct required
    // controls, each grounded in the shipped RHEL9_REQUIRED table.
    let got: std::collections::HashSet<(&str, Option<&str>)> = diags
        .iter()
        .map(|d| (d.controls[0].id.as_str(), d.controls[0].alias.as_deref()))
        .collect();
    assert!(
        got.contains(&("RHEL-09-654015", Some("V-258177"))),
        "must include the chmod ABI-pair control (RHEL-09-654015 / V-258177): {got:?}"
    );
    assert!(
        got.contains(&("RHEL-09-654030", Some("V-258180"))),
        "must include the umount control (RHEL-09-654030 / V-258180): {got:?}"
    );
}

#[test]
fn w06_present_but_key_differs_finding_carries_its_stig_control_ref() {
    // Barrier re-review gap: au-W06 emits TWO finding kinds from
    // `w06_with_baseline` (stig_required.rs:1220-1241) -- "missing" AND
    // "present-but-key-differs". The two control tests above only exercise the
    // MISSING branch, so an impl attaching `.with_controls(...)` on the missing
    // branch ONLY would leave every present-but-key-differs finding
    // controls-empty yet still pass them. This pins the OTHER branch, mirroring
    // sysctld-W02 which attaches + tests the control on BOTH its missing
    // (baseline.rs:445) and present-insecure (baseline.rs:462) branches.
    //
    // Same fixture as `predicate_equal_rule_with_a_different_key_is_a_distinct_
    // finding` above: the umount privileged-command line matches every axis of
    // its requirement EXCEPT the key (WRONG_KEY instead of privileged-mount), so
    // it is present-but-key-differs, not missing. Control grounded in the
    // shipped RHEL9_REQUIRED table (stig_required.rs:453-457): V-258180 /
    // RHEL-09-654030.
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

    // MESSAGE assertion unchanged: still the present-but-key-differs shape (names
    // the stig id + the distinct "different key" wording).
    assert!(
        d.message.contains("RHEL-09-654030") && d.message.contains("different key"),
        "must stay the present-but-key-differs message shape, got {:?}",
        d.message
    );

    // NEW (#502): the key-differs branch must ALSO carry the typed control.
    // Length-first so RED is a clean `0 != 1`, not an index panic.
    assert_eq!(
        d.controls.len(),
        1,
        "the present-but-key-differs finding must also carry one control: {d:?}"
    );
    assert_eq!(d.controls[0].framework, Framework::Stig);
    assert_eq!(d.controls[0].id, "RHEL-09-654030");
    assert_eq!(d.controls[0].alias.as_deref(), Some("V-258180"));
}

// ---------------------------------------------------------------------------
// Deepening (#523, session 9b-v0_8-wave2 lane 2e): Control-shaped STIG
// requirements ("-e 2" immutable-audit-config, "-f 2" panic-on-critical-
// failure). `rules_match`'s `axes_match` match (stig_required.rs) has
// explicit arms ONLY for (Watch, Watch) and (Syscall, Syscall); every other
// pairing (including Control, Control) falls through to `_ => false`, so a
// Control-shaped BaselineRule can NEVER be satisfied today, regardless of the
// ruleset's real content -- each "compliant" sub-case below is what turns
// RED: a ruleset carrying the literal required Control line still reports
// "missing" until the implementer adds a
// `(AuditRule::Control(a), AuditRule::Control(b)) => a == b` arm (no new type
// needed: `ControlRule` already derives `PartialEq`, and the parser already
// recognizes both "-e" and "-f" -- `crates/rulesteward-auditd/src/parser.rs`'s
// "-e"/"-f" arms, `ControlRule::Enable`/`ControlRule::FailureMode`).
//
// All five controls below were fetched LIVE (2026-07-15) against the exact
// pinned DISA zips `tools/auditd-stig-update/stig-refs.toml` names
// (U_RHEL_{8,9,10}_STIG.zip @ V2R4/V2R7/V1R1) via
// `dl.dod.cyber.mil/wp-content/uploads/stigs/zip/...`. `auditd-stig-update
// check --product {rhel8,rhel9,rhel10}` against those same live pinned zips
// confirms 0 drift for the CURRENT 45/51/50-requirement (61/67/75-line)
// baseline, so these five are genuinely beyond it, not a mis-grounded
// rediscovery of something already shipped. A companion selector-widening
// gap lives in `tools/auditd-stig-update/src/xccdf.rs` (its `RULE_LINE_RE`
// does not recognize "-e"/"-f" leading tokens either, so it never even
// DERIVES these lines from the XCCDF today) -- see that file's new
// `control_rule_check_content_{e,f}_flag_is_selected_as_a_required_line`
// tests.
// ---------------------------------------------------------------------------

#[test]
fn rhel8_e2_immutable_control_deepening_v230402() {
    // SV-230402r1017208_rule (RHEL-08-030121): "RHEL 8 audit system must
    // protect auditing rules from unauthorized change." check-content:
    // `sudo grep "^\s*[^#]" /etc/audit/audit.rules | tail -1` must equal
    // "-e 2" (audit-userspace: -e 2 = AUDIT_STATUS lock/immutable mode).
    let baseline = vec![bl("V-230402", "RHEL-08-030121", "-e 2")];

    // Compliant: the ruleset carries the literal required "-e 2" line.
    let compliant = parse("-w /etc/passwd -p wa -k identity\n-e 2\n");
    let diags = w06_with_baseline(&compliant, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a ruleset carrying the literal \"-e 2\" control line must satisfy \
         RHEL-08-030121: {diags:?}"
    );

    // Discriminating negative: "-e 1" (audit ENABLED but not immutable) is a
    // DIFFERENT control value -- must NOT satisfy. Guards against a naive
    // impl treating "any Control::Enable variant" as satisfying, ignoring
    // the locked value.
    let wrong_value = parse("-w /etc/passwd -p wa -k identity\n-e 1\n");
    let diags = w06_with_baseline(&wrong_value, LintOptions::default(), &baseline);
    assert_eq!(
        diags.len(),
        1,
        "-e 1 must NOT satisfy a -e 2 (immutable) requirement: {diags:?}"
    );
    assert!(
        diags[0].message.contains("RHEL-08-030121"),
        "{:?}",
        diags[0].message
    );

    // Absent entirely. Also spot-checks the typed ControlRef attaches to a
    // Control-shaped finding exactly as it does for Watch/Syscall-shaped
    // ones (issue #502's contract is variant-agnostic in the shared
    // diagnostic-construction code, but this is the only place in this
    // deepening block that re-confirms it end to end).
    let absent = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06_with_baseline(&absent, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    let d = &diags[0];
    assert!(d.message.contains("RHEL-08-030121"), "{:?}", d.message);
    assert_eq!(d.controls.len(), 1, "{d:?}");
    assert_eq!(d.controls[0].framework, Framework::Stig);
    assert_eq!(d.controls[0].id, "RHEL-08-030121");
    assert_eq!(d.controls[0].alias.as_deref(), Some("V-230402"));
}

#[test]
fn rhel9_e2_immutable_control_deepening_v258229() {
    // SV-258229r958434_rule (RHEL-09-654275): same "-e 2" immutable-mode
    // requirement, RHEL9's own STIG id/V-number.
    let baseline = vec![bl("V-258229", "RHEL-09-654275", "-e 2")];

    let compliant = parse("-w /etc/passwd -p wa -k identity\n-e 2\n");
    let diags = w06_with_baseline(&compliant, LintOptions::default(), &baseline);
    assert!(diags.is_empty(), "{diags:?}");

    // Discriminating negative: "-e 0" (audit disabled entirely).
    let wrong_value = parse("-w /etc/passwd -p wa -k identity\n-e 0\n");
    let diags = w06_with_baseline(&wrong_value, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("RHEL-09-654275"),
        "{:?}",
        diags[0].message
    );

    let absent = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06_with_baseline(&absent, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("RHEL-09-654275"),
        "{:?}",
        diags[0].message
    );
}

#[test]
fn rhel9_f2_panic_control_deepening_v258227() {
    // SV-258227r1014992_rule (RHEL-09-654265): "RHEL 9 must take appropriate
    // action when a critical audit processing failure occurs." check-content:
    // `sudo grep "\-f" /etc/audit/audit.rules` must show "-f 2" (audit-
    // userspace: -f 2 = panic on critical error).
    let baseline = vec![bl("V-258227", "RHEL-09-654265", "-f 2")];

    let compliant = parse("-w /etc/passwd -p wa -k identity\n-f 2\n");
    let diags = w06_with_baseline(&compliant, LintOptions::default(), &baseline);
    assert!(diags.is_empty(), "{diags:?}");

    // Discriminating negative: "-f 1" (printk, not panic).
    let wrong_value = parse("-w /etc/passwd -p wa -k identity\n-f 1\n");
    let diags = w06_with_baseline(&wrong_value, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("RHEL-09-654265"),
        "{:?}",
        diags[0].message
    );

    let absent = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06_with_baseline(&absent, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("RHEL-09-654265"),
        "{:?}",
        diags[0].message
    );
}

#[test]
fn rhel10_e2_immutable_control_deepening_v281365() {
    // SV-281365r1167245_rule (RHEL-10-900100): "RHEL 10 must prevent
    // unauthorized changes to the audit system" -- the RHEL10 "-e 2" analogue.
    let baseline = vec![bl("V-281365", "RHEL-10-900100", "-e 2")];

    let compliant = parse("-w /etc/passwd -p wa -k identity\n-e 2\n");
    let diags = w06_with_baseline(&compliant, LintOptions::default(), &baseline);
    assert!(diags.is_empty(), "{diags:?}");

    let wrong_value = parse("-w /etc/passwd -p wa -k identity\n-e 1\n");
    let diags = w06_with_baseline(&wrong_value, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("RHEL-10-900100"),
        "{:?}",
        diags[0].message
    );

    let absent = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06_with_baseline(&absent, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("RHEL-10-900100"),
        "{:?}",
        diags[0].message
    );
}

#[test]
fn rhel10_f2_panic_control_deepening_v281103() {
    // SV-281103r1166261_rule (RHEL-10-500035): the RHEL10 "-f 2" analogue.
    let baseline = vec![bl("V-281103", "RHEL-10-500035", "-f 2")];

    let compliant = parse("-w /etc/passwd -p wa -k identity\n-f 2\n");
    let diags = w06_with_baseline(&compliant, LintOptions::default(), &baseline);
    assert!(diags.is_empty(), "{diags:?}");

    let wrong_value = parse("-w /etc/passwd -p wa -k identity\n-f 0\n");
    let diags = w06_with_baseline(&wrong_value, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("RHEL-10-500035"),
        "{:?}",
        diags[0].message
    );

    let absent = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06_with_baseline(&absent, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("RHEL-10-500035"),
        "{:?}",
        diags[0].message
    );
}

// ---------------------------------------------------------------------------
// Deepening cont'd (#523, session 9b-v0_8-wave2 lane 2e, additive round 2):
// `--loginuid-immutable` (auditctl(8): "make loginuids unchangeable once set,
// requires CAP_AUDIT_CONTROL"). Unlike "-e 2"/"-f 2" above, this is a BRAND
// NEW `ControlRule::LoginuidImmutable` variant (crates/rulesteward-auditd/
// src/ast.rs) -- the parser does not recognize the flag at all yet (still
// hits the "unknown flag" error path, see
// crates/rulesteward-auditd/tests/test_ast_parser.rs's
// `control_loginuid_immutable_parses`), so `w06_with_baseline`'s
// `parse_single_rule` call on a "--loginuid-immutable" BaselineRule line
// PANICS today (not merely "reports missing" like the -e2/-f2 cases) --
// still a genuine RED failure (a panic IS a test failure), it just fails at
// an earlier step than the -e2/-f2 deepening above.
//
// USER-APPROVED IDs (2026-07-15, via the orchestrator): RHEL8 V-230403
// (RHEL-08-030122), RHEL9 V-258228 (RHEL-09-654270). RHEL10's XCCDF was
// checked and contains no "loginuid" occurrence anywhere -- RHEL10 must NOT
// carry this requirement; see `rhel10_loginuid_immutable_control_absent_
// from_baseline` below (a discriminating-negative GUARD, not a RED test: it
// already passes today because nothing has been added for RHEL10 yet, and
// it is designed to keep passing after the implementer lands RHEL8/RHEL9 --
// it exists to catch a future copy-paste mistake that also adds a RHEL10
// entry, not to record a currently-broken behavior).
// ---------------------------------------------------------------------------

#[test]
fn rhel8_loginuid_immutable_control_deepening_v230403() {
    // RHEL-08-030122 (V-230403): the loginuid-immutable requirement.
    let baseline = vec![bl("V-230403", "RHEL-08-030122", "--loginuid-immutable")];

    // Compliant: the ruleset carries the literal required control line.
    let compliant = parse("-w /etc/passwd -p wa -k identity\n--loginuid-immutable\n");
    let diags = w06_with_baseline(&compliant, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a ruleset carrying the literal \"--loginuid-immutable\" control line must satisfy \
         RHEL-08-030122: {diags:?}"
    );

    // Discriminating negative: a DIFFERENT control ("-e 2") must NOT satisfy
    // a "--loginuid-immutable" requirement. Unlike the -e2/-f2 deepening
    // above (which varies the INTEGER value of the same Control variant),
    // LoginuidImmutable carries no value at all -- the meaningful wrong-impl
    // this guards against is one that treats "any Control rule present" as
    // satisfying, ignoring which specific variant is required (the derived
    // `PartialEq` on `ControlRule` is what must actually be consulted).
    let wrong_control = parse("-w /etc/passwd -p wa -k identity\n-e 2\n");
    let diags = w06_with_baseline(&wrong_control, LintOptions::default(), &baseline);
    assert_eq!(
        diags.len(),
        1,
        "a \"-e 2\" rule must NOT satisfy a \"--loginuid-immutable\" requirement: {diags:?}"
    );
    assert!(
        diags[0].message.contains("RHEL-08-030122"),
        "{:?}",
        diags[0].message
    );

    // Absent entirely; also spot-checks the typed ControlRef attaches.
    let absent = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06_with_baseline(&absent, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    let d = &diags[0];
    assert!(d.message.contains("RHEL-08-030122"), "{:?}", d.message);
    assert_eq!(d.controls.len(), 1, "{d:?}");
    assert_eq!(d.controls[0].framework, Framework::Stig);
    assert_eq!(d.controls[0].id, "RHEL-08-030122");
    assert_eq!(d.controls[0].alias.as_deref(), Some("V-230403"));
}

#[test]
fn rhel9_loginuid_immutable_control_deepening_v258228() {
    // RHEL-09-654270 (V-258228): RHEL9's own STIG id/V-number for the same
    // loginuid-immutable requirement.
    let baseline = vec![bl("V-258228", "RHEL-09-654270", "--loginuid-immutable")];

    let compliant = parse("-w /etc/passwd -p wa -k identity\n--loginuid-immutable\n");
    let diags = w06_with_baseline(&compliant, LintOptions::default(), &baseline);
    assert!(diags.is_empty(), "{diags:?}");

    // Discriminating negative: a DIFFERENT control ("-f 2") must NOT satisfy.
    let wrong_control = parse("-w /etc/passwd -p wa -k identity\n-f 2\n");
    let diags = w06_with_baseline(&wrong_control, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert!(
        diags[0].message.contains("RHEL-09-654270"),
        "{:?}",
        diags[0].message
    );

    let absent = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06_with_baseline(&absent, LintOptions::default(), &baseline);
    assert_eq!(diags.len(), 1, "{diags:?}");
    let d = &diags[0];
    assert!(d.message.contains("RHEL-09-654270"), "{:?}", d.message);
    assert_eq!(d.controls.len(), 1, "{d:?}");
    assert_eq!(d.controls[0].framework, Framework::Stig);
    assert_eq!(d.controls[0].id, "RHEL-09-654270");
    assert_eq!(d.controls[0].alias.as_deref(), Some("V-258228"));
}

#[test]
fn rhel10_loginuid_immutable_control_absent_from_baseline() {
    // Verified (2026-07-15) against the pinned RHEL10 DISA XCCDF
    // (tools/auditd-stig-update/stig-refs.toml's U_RHEL_10_STIG.zip, V1R1):
    // no Group/Rule's check-content mentions "loginuid" anywhere -- unlike
    // RHEL8 (V-230403/RHEL-08-030122) and RHEL9 (V-258228/RHEL-09-654270),
    // RHEL10 genuinely drops this control. This is a discriminating-negative
    // GUARD (not a RED test -- see the section doc comment above): it
    // catches a future implementer mistakenly copy-pasting the RHEL8/RHEL9
    // loginuid-immutable entry into the shipped `RHEL10_REQUIRED` table too.
    let rhel10 = stig_baseline(TargetVersion::Rhel10);
    assert!(
        !rhel10.iter().any(|r| r.line == "--loginuid-immutable"),
        "RHEL10's DISA XCCDF has no loginuid-immutable control; the shipped \
         table must never carry one: {rhel10:?}"
    );

    // Same property end to end: a RHEL10-targeted au-W06 pass over a ruleset
    // that lacks "--loginuid-immutable" entirely must never fabricate a
    // finding naming it.
    let absent = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06(&absent, LintOptions::default(), Some(TargetVersion::Rhel10));
    assert!(
        !diags.iter().any(|d| d.message.contains("loginuid")),
        "a RHEL10-targeted au-W06 pass must never mention loginuid-immutable: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Barrier-style real-entrypoint proof, loginuid variant (#523, session
// 9b-v0_8-wave2 lane 2e): mirrors
// `w06_real_entrypoint_fires_on_a_bare_ruleset_against_the_shipped_rhel9_table`
// above -- every loginuid-immutable scenario test so far
// (`rhel{8,9}_loginuid_immutable_control_deepening_v2*`) injects a small
// test-local baseline straight into `w06_with_baseline`, so NONE of them fail
// if the SHIPPED `RHEL8_REQUIRED`/`RHEL9_REQUIRED` tables never actually gain
// a loginuid row at all -- only these two tests go through the REAL dispatch
// chain (`w06` -> `baseline_for` -> `w06_with_baseline`) against the shipped
// tables. RED today: `RHEL8_REQUIRED`/`RHEL9_REQUIRED` have no
// "--loginuid-immutable" row yet, so the real `--target rhel8`/`--target
// rhel9` path never reports RHEL-08-030122/RHEL-09-654270 missing, no matter
// how non-compliant the ruleset is.
// ---------------------------------------------------------------------------

#[test]
fn w06_real_entrypoint_names_rhel8_loginuid_immutable_control() {
    // RHEL-08-030122 (V-230403): the real RHEL8 dispatch, against a ruleset
    // that never sets "--loginuid-immutable" at all, must report it missing
    // once the shipped table carries the row.
    let rules = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags.iter().any(|d| d.message.contains("RHEL-08-030122")),
        "the real RHEL8 dispatch must report the loginuid-immutable control \
         missing once the shipped table carries it: {diags:?}"
    );
}

#[test]
fn w06_real_entrypoint_names_rhel9_loginuid_immutable_control() {
    // RHEL-09-654270 (V-258228): RHEL9's own STIG id, same proof.
    let rules = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        diags.iter().any(|d| d.message.contains("RHEL-09-654270")),
        "the real RHEL9 dispatch must report the loginuid-immutable control \
         missing once the shipped table carries it: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// #549 (session 9e-wave2c pipeline P2, 2026-07-17): RHEL9 V2R7 -> V2R9 content
// drift, real-entrypoint proof (mirrors the loginuid-immutable pattern above:
// against the SHIPPED RHEL9_REQUIRED table, not an injected local baseline).
//
// Grounding: DISA RHEL 9 STIG V2R9, confirmed 2026-07-17 via
// U_RHEL_9_V2R9_STIG.zip (lane3-tooling.md T1 DRIFT-CHECK transcript).
// DISA rewrote 9 identity/login audit rules from a single-line watch form
// (`-w PATH -p wa -k identity`) into dual-arch (b32/b64) syscall form
// (`-a always,exit -F arch=bXX -F path=PATH -F perm=wa -k identity`), and
// added a brand-new required rule, V-279936 (RHEL-09-654097): `execve`
// auditing scoped to `subj_type=crond_t` (`cron_exec` key), replacing the
// two old `-w /etc/cron.d`/`-w /var/spool/cron` watch lines.
//
// Each test below feeds a ruleset containing ONLY the OLD (V2R7-grounded)
// form of one rewritten requirement -- a line that the CURRENT shipped
// table's matching row satisfies EXACTLY (`rules_match` full-axis Watch-vs-
// Watch equality) -- through the REAL `w06` dispatch against the shipped
// RHEL9_REQUIRED table. RED today: the old-form line still satisfies the
// V2R7-grounded shipped row, so au-W06 stays silent for that STIG id. Once
// the table is updated to require the NEW dual-arch syscall form, the same
// old-form-only ruleset no longer satisfies it (a Watch-shaped candidate
// never matches a Syscall-shaped requirement -- `rules_match`'s `_ => false`
// arm), so a "missing" finding must fire naming the STIG id.
// ---------------------------------------------------------------------------

#[test]
fn w06_real_entrypoint_names_rhel9_cron_exec_v279936_new_syscall_form() {
    // V-279936 (RHEL-09-654097): the OLD form (still shipped today) is
    // `-w /etc/cron.d -p wa -k cronjobs` + `-w /var/spool/cron -p wa -k
    // cronjobs`. The V2R9 XCCDF requires 4 dual-arch execve syscall rules
    // scoped to subj_type=crond_t instead (lane3-tooling.md T1 DRIFT-CHECK:
    // "+ V-279936 (RHEL-09-654097): -a always,exit -F arch=b32 -S execve
    // -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec" and its
    // b64/euid=0 siblings; the two old watch lines appear as "-" removals in
    // the same diff). A ruleset with ONLY the old watch-form lines currently
    // satisfies V-279936 in full (exact Watch-vs-Watch match); it must not
    // once the table requires the new syscall form.
    let rules = parse("-w /etc/cron.d -p wa -k cronjobs\n-w /var/spool/cron -p wa -k cronjobs\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-09-654097") && d.message.contains("is missing")),
        "the old watch-form cron lines must no longer satisfy V-279936 \
         (RHEL-09-654097) once the shipped table requires the new dual-arch \
         execve/subj_type=crond_t syscall form: {diags:?}"
    );
}

#[test]
fn w06_real_entrypoint_names_rhel9_identity_syscall_form_v258222_passwd() {
    // V-258222 (RHEL-09-654240): DISA RHEL 9 STIG V2R9 rewrote the
    // /etc/passwd identity-watch rule from `-w /etc/passwd -p wa -k identity`
    // (the form still shipped today) into a dual-arch syscall rule:
    // "-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -k
    // identity" (+ the b64 twin) (lane3-tooling.md T1 DRIFT-CHECK "+
    // V-258222" lines; the old watch line appears as a "-" removal in the
    // same diff). A ruleset with ONLY the old watch-form line currently
    // satisfies V-258222 in full; it must not once the table requires the
    // new syscall form.
    let rules = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-09-654240") && d.message.contains("is missing")),
        "the old watch-form /etc/passwd line must no longer satisfy V-258222 \
         (RHEL-09-654240) once the shipped table requires the new dual-arch \
         syscall form: {diags:?}"
    );
}

#[test]
fn w06_real_entrypoint_v258222_new_syscall_form_satisfies_once_shipped() {
    // Positive complement to
    // `w06_real_entrypoint_names_rhel9_identity_syscall_form_v258222_passwd`
    // above (adversarial-review finding 2b): feed the ruleset the EXACT V2R9
    // dual-arch syscall form for V-258222 (transcribed verbatim from its
    // check-content, same source as the content pins above) and confirm it
    // does NOT get reported missing.
    //
    // RED today, and it lands RED for a DIFFERENT reason than the negative
    // test above: the shipped RHEL9_REQUIRED table's V-258222 row is still
    // the OLD single-line watch form (`Watch`-shaped in `rules_match`'s
    // variant dispatch). A `Syscall`-shaped candidate NEVER matches a
    // `Watch`-shaped requirement (the `_ => false` arm), so au-W06 currently
    // reports V-258222 missing even though this ruleset already carries the
    // (soon-to-be-)correct V2R9 form -- confirmed by actually running this
    // assertion against the shipped table before adding it (see the
    // RED-EVIDENCE report).
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-09-654240")),
        "the V2R9 dual-arch syscall form for V-258222 (RHEL-09-654240) must \
         satisfy the requirement once the shipped table requires it: {diags:?}"
    );
}

#[test]
fn w06_real_entrypoint_names_rhel9_identity_syscall_form_v258223_shadow() {
    // V-258223 (RHEL-09-654245): same drift as V-258222, for /etc/shadow.
    // Old form (still shipped today): `-w /etc/shadow -p wa -k identity`.
    // New V2R9 form: "-a always,exit -F arch=b32 -F path=/etc/shadow
    // -F perm=wa -k identity" (+ the b64 twin) (lane3-tooling.md T1
    // DRIFT-CHECK "+ V-258223" lines).
    let rules = parse("-w /etc/shadow -p wa -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-09-654245") && d.message.contains("is missing")),
        "the old watch-form /etc/shadow line must no longer satisfy V-258223 \
         (RHEL-09-654245) once the shipped table requires the new dual-arch \
         syscall form: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Presence-only decision pin (#523, session 9b-v0_8-wave2 lane 2e; USER
// DECISION 2026-07-16, via the orchestrator): au-W06 Control matching stays
// PRESENCE-based this wave -- it asks "does ANY parsed rule match the
// required Control variant+value", never "what is the LAST
// (auditctl-effective) value for this control flag". Real `auditctl`/the
// audit daemon applies `-e`/`-f` (and other control) directives in FILE ORDER
// with LAST-WINS semantics at load time (a `-f 1` line after a `-f 2` line
// overrides the running daemon's effective failure mode to 1), but this
// lint's static, parse-only matcher does NOT model that: two directives with
// CONFLICTING values both remain "present" candidates in the ruleset, and a
// required value satisfied by EITHER one alone passes, regardless of file
// order. This is a DELIBERATE, tracked scope decision for this wave -- not an
// oversight discovered later -- so it is pinned here as a passing test (not a
// RED one) precisely so a future implementer cannot "fix" this into
// last-wins modeling by accident without first breaking a named, documented
// contract. Last-wins effective-state modeling is tracked as a follow-up
// issue. The complementary "does a rule change after an `-e 2` lock line look
// suspicious" concern is separately covered by the ordering lint (au-E01,
// `lints::ordering`'s post-lock unreachable-rule pass -- `auditctl(8)`: "-e 2"
// makes the config immutable until reboot, so anything loaded after it never
// takes effect), not by au-W06.
// ---------------------------------------------------------------------------

#[test]
fn control_matching_is_presence_only_last_wins_modeling_is_out_of_scope() {
    let baseline = vec![bl("V-258227", "RHEL-09-654265", "-f 2")];
    // "-f 1" AFTER "-f 2" would auditctl-effectively DISABLE panic-on-failure
    // (last-wins), but au-W06's static matcher only asks whether a "-f 2"
    // rule is present ANYWHERE in the parsed ruleset -- it is, so this must
    // NOT report a missing finding for RHEL-09-654265, even though a
    // last-wins-aware checker would flag it.
    let rules = parse("-f 2\n-f 1\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "presence-only matching: a required \"-f 2\" line present anywhere in \
         the ruleset satisfies the requirement, regardless of a later \
         conflicting \"-f 1\" directive (last-wins effective-state modeling \
         is out of scope this wave, tracked as a follow-up issue): {diags:?}"
    );
}

#[test]
fn non_w06_finding_has_empty_controls() {
    // Empty-controls guard (issue #502): this milestone wires a typed
    // ControlRef onto au-W06 only. Every other au- code's findings must keep
    // an EMPTY `controls` Vec (so the field stays omitted from serialization
    // for those codes) -- picked au-E03 (lints::duplicate::w01, unrelated
    // machinery to stig_required entirely) specifically so this guard cannot
    // be satisfied by accident if the implementer wires the au-W06 control
    // onto the wrong emission site or some shared helper.
    let rules = parse(
        "-w /etc/passwd -p wa -k identity\n\
         -w /etc/passwd -p wa -k identity\n",
    );
    let diags = w01(&rules, LintOptions::default());
    assert_eq!(diags.len(), 1, "{diags:?}");
    assert_eq!(diags[0].code, "au-E03");
    assert!(
        diags[0].controls.is_empty(),
        "a non-au-W06 finding must carry no controls: {:?}",
        diags[0].controls
    );
}
