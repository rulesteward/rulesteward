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
//!
//! # dir-shape equivalence fold (issue #571, session 9j lane 8) -- why
//! # V-258218 is DELIBERATELY not credited by a `-F dir=` ruleset
//!
//! Issue #571 was originally reported against V-258218 (RHEL-09-654220,
//! `/etc/sudoers.d`): a ruleset spelling the directory audit rule as
//! `-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k identity` was said to
//! "falsely" report V-258218 missing. That premise is WRONG and must not be
//! re-litigated from the issue text alone: the real DISA RHEL 9 STIG V2R9
//! check-content for V-258218 (`tools/auditd-stig-update/tests/fixtures/
//! rhel9_auditd_controls.xml`, `<Group id="V-258218">`, verified directly
//! against the fixture, not recalled) requires **`-F path=/etc/sudoers.d`**,
//! not `-F dir=`, for BOTH the b32 and b64 rows -- confirmed byte-for-byte
//! against the shipped `RHEL9_REQUIRED` table
//! (`stig_required.rs:747,752`) and independently pinned by the frozen
//! content test `stig_baseline_rhel9_v2r9_content_pins` above. RHEL10 has
//! its OWN, DISTINCT STIG id for the analogous `/etc/sudoers.d` requirement
//! -- V-281155 / RHEL-10-500690, NOT V-258218 -- and that row
//! (`stig_required.rs:1138,1143`) is ALSO spelled `-F path=/etc/sudoers.d/`,
//! never `-F dir=`. So `-F dir=` appears in neither RHEL9's V-258218 nor
//! RHEL10's V-281155 -- two separate STIG ids, one per major release, both
//! independently choosing `path=` for the same directory. Only RHEL8's
//! V-230410 (`stig_required.rs:171`) is genuinely Watch-shaped
//! (`-w /etc/sudoers.d/ -p wa -k identity`), which is why this file's
//! dir-shape tests below anchor on V-230410/V-230406, not V-258218.
//!
//! USER RULING (2026-07-24, confirmed after independent orchestrator
//! verification of the fixture/table citations above): the dir-shape fold
//! credits ONLY genuinely dir-shaped requirements -- `-w DIR` <-> `-F dir=`
//! and `-F dir=` <-> `-F dir=`. It does NOT fold `-F dir=` into `-F path=`
//! (or vice versa) to paper over DISA's own `path=`-for-a-directory
//! spelling. Consequently: **a ruleset that only has a `-F dir=` rule for
//! `/etc/sudoers.d` correctly, truly, and permanently fails V-258218 on
//! RHEL9/RHEL10 -- this is a TRUE missing, not a false positive.** DISA's
//! own fixtext (the literal remediation text an admin is told to paste)
//! ALSO says `-F path=`, so a `dir=`-only ruleset genuinely does not
//! implement what RHEL9/RHEL10's V2R9/V1R2 STIG asks for, whatever a human
//! eyeballing `auditctl -l | grep sudoers.d` might informally accept. See
//! the "dir-shape equivalence fold" test section near the end of this file
//! for the full grounding and the anti-collapse guards that PIN this
//! boundary (`dir_syscall_form_does_not_satisfy_an_explicit_path_shaped_
//! requirement` / `dir_shaped_requirement_not_satisfied_by_an_explicit_
//! path_syscall`).
//!
//! # `is_dir` stays fully ignored (ROUND 3, 2026-07-24) -- the accepted
//! # file/directory over-credit, and why it is harmless
//!
//! Round 2 tried to pin an anti-collapse guard on a `-w /etc/passwd`
//! (real FILE, `is_dir == false`) requirement rejecting a `-F dir=` watch
//! candidate. That guard was internally UNSATISFIABLE: it and the
//! required-satisfied positive test for V-230410 (`-w /etc/sudoers.d/`,
//! `is_dir == true`) are the SAME cross-variant shape with a
//! structurally identical `-F dir=` candidate -- the ONLY discriminator
//! available between "accept" and "reject" was the required Watch's
//! trailing slash, which would make `is_dir` load-bearing. That is
//! forbidden: `is_dir` (see `ast.rs`'s `Watch::is_dir` doc comment) is a
//! `RuleSteward` SPELLING heuristic, not ground truth -- real auditctl
//! derives file-vs-directory by `stat()`-ing the actual filesystem
//! object, never from the trailing slash. Worse, the SHIPPED RHEL8 table
//! spells directories INCONSISTENTLY (V-230410's `-w /etc/sudoers.d/`
//! carries a slash; V-274877's `-w /etc/cron.d` / `-w /var/spool/cron` --
//! both real directories -- do not), so gating on the slash in EITHER
//! direction reproduces issue #571's false-"missing" class on a real,
//! shipped row (pinned directly by
//! `dir_syscall_form_satisfies_v274877_cron_d_watch_spelled_without_a_
//! trailing_slash` below).
//!
//! USER RULING (2026-07-24, ROUND 3): `is_dir` stays fully ignored for
//! the dir-shape fold too (extending the pre-existing, LOCKED path-fold
//! precedent, grounding Part B.7.2, to the new arm). Consequence,
//! explicitly ACCEPTED as harmless rather than treated as a gap: a
//! `-F dir=X` candidate credits a `-w X` requirement regardless of
//! whether X is a real file or a real directory (pinned by
//! `dir_syscall_form_over_credits_a_file_shaped_watch_requirement_and_
//! that_is_accepted` below). This is harmless in practice -- a recursive
//! subtree watch naming a regular file is a nonsense rule the kernel
//! never needs to distinguish, since there is no subtree under a file for
//! the extra reach to matter -- so the over-credit can never mask a
//! genuine compliance gap. The rejected alternative (a curated per-row
//! "names a directory" flag on `BaselineRule`) would fix this properly,
//! but `BaselineRule` is code-generated by
//! `tools/auditd-stig-update/src/main.rs`, owned by a different lane;
//! that is filed as a follow-up issue instead of a mid-barrier shared-
//! surface change.
//!
//! ALSO RULED (2026-07-24): the fold must never resolve file-vs-directory
//! by `stat()`-ing the ANALYZING host's filesystem -- a linter analyzes
//! configs FOR a target host, not the machine it happens to run on, so
//! host-filesystem-dependent behavior would be both a correctness bug and
//! a reproducibility hazard (the same run against the same ruleset must
//! give the same answer on every machine). The over-credit test above
//! deliberately uses `/etc/passwd` -- verifiably a real, ordinary file on
//! every reachable Linux host -- rather than a synthetic, non-existent
//! path, specifically so that guarantee is not an accident of the test
//! machine lacking a file at that path.

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
// Path+Perm+Key syscall spelling satisfies its kernel-equivalent Watch-shaped
// requirement (RE-DECIDED -- see the comment below).
// ---------------------------------------------------------------------------

#[test]
fn watch_requirement_satisfied_by_a_kernel_equivalent_syscall_spelling() {
    // RE-DECIDED (was `watch_requirement_not_satisfied_by_a_kernel_equivalent_
    // syscall_spelling`, added in commit 43cfc5b, v0.6 Wave 3, #493 -- eight
    // days BEFORE the path-watch equivalence fold (`is_pure_path_watch_shaped`
    // / `watch_equivalent_axes_match`) existed at all). USER RULING
    // (2026-07-24, session 9j lane 8, ATL round, issue #571 MISS-2b): this
    // test predated the whole cross-variant fold, introduced 2026-07-17/18 in
    // commit ea9f37c (#573, "USER RULING... watch<->syscall EQUIVALENCE"), and
    // was accidentally missed by that commit's RE-DECIDED sweep -- which
    // explicitly re-grounded three siblings
    // (`w06_real_entrypoint_watch_equivalent_satisfies_v258222_passwd` and its
    // two neighbors below) but not this one. It kept passing only because of
    // a SEPARATE bug (issue #571 MISS-2b): `is_pure_path_watch_shaped` forgot
    // to allow `AuditField::Key` in its field-set membership check, so a
    // candidate spelled `-F key=` (rather than `-k`) fell OUTSIDE the pure
    // path-watch shape and never reached the fold at all. Once MISS-2b's fix
    // landed, `-k KEY` and `-F key=KEY` are the SAME rule everywhere in this
    // module (`auditctl`'s `setopt()` literally implements `-k` as
    // `asprintf(&cmd, "key=%s", key)` before calling
    // `audit_rule_fieldpair_data`, lib/libaudit.c) -- exactly as
    // `effective_key`/`fields_match_excluding_key` already treat the two
    // spellings elsewhere in this file. So the ORIGINAL claim ("a same-path/
    // same-perm/same-key Syscall-shaped rule must NOT satisfy a Watch-shaped
    // requirement") is WRONG for this shape specifically: the first candidate
    // line below (no `-S`, fields limited to path/perm/key) IS a pure
    // path-watch shape and DOES satisfy RHEL-09-654215, the same way the
    // RE-DECIDED siblings' dual-arch forms satisfy V-258222/V-258223. Do NOT
    // "restore" the old assertion -- this comment is why it changed.
    //
    // The genuinely-still-valid HALF of the original scenario -- that
    // Syscall-shaped rules carrying real `-S` syscall lists are NOT pure
    // path-watch shaped and never reach the cross-variant fold at all -- is
    // preserved here, not deleted: the other three lines below keep their
    // `-S`/`-S all` lists and still satisfy their OWN Syscall-shaped required
    // rows (RHEL-09-654015, RHEL-09-654030) purely via the ordinary,
    // unmodified same-variant match, exactly as before. With MISS-2b's fix,
    // ALL FOUR lines are now satisfied, so the whole scenario is asserted
    // fully compliant (zero findings) rather than "exactly one, naming
    // RHEL-09-654215". Genuine negative coverage for a truly NON-equivalent
    // shape (an `-S`-bearing rule that cannot fold into ANY Watch-shaped
    // requirement) lives separately, unaffected by this change, in
    // `crond_watch_does_not_satisfy_v279936_execve_requirement` below.
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
    assert!(
        diags.is_empty(),
        "a Path+Perm+Key syscall-form candidate (no -S, -F key= spelling) is \
         a pure path-watch shape and must satisfy RHEL-09-654215's \
         Watch-shaped requirement -- -k and -F key= are the same \
         kernel-level key axis (issue #571 MISS-2b); the other three lines \
         satisfy their own Syscall-shaped required rows unchanged: {diags:?}"
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
// RE-DECIDED (USER RULING via AskUserQuestion, 2026-07-17, "watch<->syscall
// EQUIVALENCE"): au-W06's matcher must treat a path-watch requirement as
// satisfied by EITHER kernel-equivalent form (a classic single-line
// `-w PATH -p PERMS -k KEY` watch, or the dual-arch
// `-a always,exit -F arch=bXX -F path=PATH -F perm=PERMS -k KEY` syscall
// pair), both directions, all targets. Grounding for the ruling: DISA V2R9's
// own pass/fail check-content (`auditctl -l | egrep <path>`) PASSES on the
// watch form (verified against the downloaded V2R9 XCCDF, e.g. V-258222's
// check-content literally runs `auditctl -l | egrep '(/etc/passwd)'` and
// expects the dual-arch lines OR their auditctl-folded display -- the daemon
// never distinguishes); `auditctl(8)` documents `-w path -p perms` as
// equivalent to `-a always,exit -F path= -F perm=`; ComplianceAsCode's RHEL9
// OVAL (`audit_watches_style` default `'legacy'`, `ssg/constants.py:468`)
// accepts ONLY the watch pattern on RHEL9 while RHEL10 sets `'modern'`; the
// kernel folds path-watch syscall rules back to `-w` in `auditctl -l`. So a
// classic watch and its dual-arch syscall pair are the SAME kernel-level
// audit configuration for a plain path+perm(+key) requirement -- ONE watch
// (arch-independent) satisfies BOTH the b32 and b64 required rows for the
// SAME V-number.
//
// This does NOT apply to every Syscall-shaped requirement -- ONLY to rows
// that are themselves "pure path-watch shaped" (an empty `-S` syscall list,
// just `-F path=`/`-F perm=`[/`-F arch=`]/`-k`, the literal shape `-w`
// compiles down to at the kernel level). V-279936's execve/subj_type rows
// have a non-empty `-S execve` list and a `-F subj_type=` field that no
// `-w` line can ever express, so they have NO watch-equivalent form and stay
// syscall-only (see the negative control below).
//
// Each test below feeds a ruleset containing ONLY the OLD (V2R7-grounded)
// watch form of one rewritten requirement, through the REAL `w06` dispatch
// against the shipped RHEL9_REQUIRED table (now V2R9-grounded, dual-arch
// syscall rows -- commit 0bcbcf0).
// ---------------------------------------------------------------------------

#[test]
fn w06_real_entrypoint_names_rhel9_cron_exec_v279936_new_syscall_form() {
    // V-279936 (RHEL-09-654097): the OLD form (`-w /etc/cron.d -p wa -k
    // cronjobs` + `-w /var/spool/cron -p wa -k cronjobs`) was replaced by 4
    // dual-arch execve syscall rules scoped to subj_type=crond_t
    // (lane3-tooling.md T1 DRIFT-CHECK: "+ V-279936 (RHEL-09-654097):
    // -a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F auid>=1000
    // -F auid!=unset -k cron_exec" and its b64/euid=0 siblings). UNLIKE
    // V-258222/V-258223 below, this STAYS firing under the watch<->syscall
    // equivalence ruling: `-S execve -F subj_type=crond_t` is not a plain
    // path-watch shape at all (no `-F path=`, a non-empty `-S` list, and
    // `subj_type` is a SELinux-context predicate a `-w` line cannot express),
    // so it has no watch-equivalent form regardless of what the user writes.
    let rules = parse("-w /etc/cron.d -p wa -k cronjobs\n-w /var/spool/cron -p wa -k cronjobs\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-09-654097") && d.message.contains("is missing")),
        "the old watch-form cron lines are not (and under the equivalence \
         ruling still are not) a kernel-equivalent form of V-279936's \
         execve/subj_type=crond_t syscall requirement: {diags:?}"
    );
}

#[test]
fn crond_watch_does_not_satisfy_v279936_execve_requirement() {
    // Negative control (equivalence-ruling boundary, item 1): a plausible but
    // WRONG admin mental model -- "watch the crond binary" -- must still be
    // reported missing. V-279936 requires an `-S execve -F subj_type=
    // crond_t` syscall rule, not a path watch on the crond executable; no
    // `-w` line can express a subj_type predicate, so there is no watch
    // form that could ever satisfy this requirement. Passes BOTH before and
    // after the equivalence fold lands (today via the unconditional
    // `_ => false` variant mismatch; after the fix because the fold must
    // recognize V-279936's rows are not path-watch-shaped at all) -- a
    // regression guard against an over-broad equivalence implementation that
    // folds ANY Watch-vs-Syscall pair instead of only pure path-watch shapes.
    let rules = parse("-w /usr/sbin/crond -p x -k cron_exec\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-09-654097") && d.message.contains("is missing")),
        "a path-watch on the crond binary is not a kernel-equivalent form of \
         an execve/subj_type=crond_t syscall rule; V-279936 must still be \
         reported missing: {diags:?}"
    );
}

#[test]
fn w06_real_entrypoint_watch_equivalent_satisfies_v258222_passwd() {
    // RE-DECIDED (was `w06_real_entrypoint_names_rhel9_identity_syscall_form_
    // v258222_passwd`, which asserted the classic watch form no longer
    // satisfies V-258222 post-V2R9-rewrite). USER RULING (AskUserQuestion,
    // 2026-07-17, "watch<->syscall EQUIVALENCE", see the section doc comment
    // above for the full grounding): V-258222's two dual-arch syscall rows
    // ("-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -k
    // identity" + the b64 twin) are a pure path-watch shape (empty `-S`
    // list, only path/perm/arch/key fields) -- the classic
    // `-w /etc/passwd -p wa -k identity` line IS their kernel-equivalent
    // form. ONE watch (arch-independent) must satisfy BOTH the b32 AND b64
    // required rows -- asserting on the full diagnostics list (not just
    // `.any()`) so a partial fold (satisfying only one arch row) still fails
    // this test.
    let rules = parse("-w /etc/passwd -p wa -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-09-654240")),
        "the classic watch line is a kernel-equivalent form of BOTH \
         V-258222's (RHEL-09-654240) b32 and b64 dual-arch syscall rows; \
         neither may be reported missing: {diags:?}"
    );
}

#[test]
fn w06_real_entrypoint_v258222_new_syscall_form_satisfies_once_shipped() {
    // Positive complement to
    // `w06_real_entrypoint_watch_equivalent_satisfies_v258222_passwd` above
    // (adversarial-review finding 2b): feed the ruleset the EXACT V2R9
    // dual-arch syscall form for V-258222 (transcribed verbatim from its
    // check-content, same source as the content pins above) and confirm it
    // does NOT get reported missing. Same-variant (Syscall-vs-Syscall) match:
    // GREEN as of commit 0bcbcf0, which populated the shipped table with the
    // V2R9 syscall form (the equivalence ruling that follows in this file
    // does not change this test's outcome -- it only adds the CROSS-variant
    // watch-form case as an ADDITIONAL way to satisfy V-258222).
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
fn w06_real_entrypoint_watch_equivalent_satisfies_v258223_shadow() {
    // RE-DECIDED (was `w06_real_entrypoint_names_rhel9_identity_syscall_form_
    // v258223_shadow`, which asserted the classic watch form no longer
    // satisfies V-258223 post-V2R9-rewrite). Sibling of
    // `w06_real_entrypoint_watch_equivalent_satisfies_v258222_passwd` above
    // (same USER RULING, 2026-07-17, same grounding -- see the section doc
    // comment). V-258223's two dual-arch syscall rows ("-a always,exit
    // -F arch=b32 -F path=/etc/shadow -F perm=wa -k identity" + the b64
    // twin) are the same pure path-watch shape as V-258222's; the classic
    // `-w /etc/shadow -p wa -k identity` line is their kernel-equivalent
    // form and must satisfy BOTH rows.
    let rules = parse("-w /etc/shadow -p wa -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-09-654245")),
        "the classic watch line is a kernel-equivalent form of BOTH \
         V-258223's (RHEL-09-654245) b32 and b64 dual-arch syscall rows; \
         neither may be reported missing: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Equivalence-ruling boundary pins (item 3): ground each against
// auditctl(8)'s documented -w/-a equivalence and the EXISTING matcher's
// perm/key semantics (`rules_match`, `fields_match_excluding_key`,
// `effective_key`) -- not invented. The perms/path pins below are
// discriminating-negative CONTROLS: they pass BOTH before and after the
// equivalence fold (today via the unconditional Watch-vs-Syscall `_ =>
// false`; after the fix because a correct fold still compares path/perm),
// guarding against an over-broad implementation that folds ANY watch into
// ANY syscall row regardless of content. The key-semantics pin is RED today
// (the current matcher never reaches the key axis for a cross-variant pair
// at all).
// ---------------------------------------------------------------------------

#[test]
fn watch_equivalent_wrong_path_does_not_satisfy_v258222_passwd() {
    // A watch on a DIFFERENT path (/etc/shadow -- which correctly satisfies
    // V-258223 once equivalence lands, per the sibling test above) must NOT
    // satisfy V-258222's /etc/passwd requirement. Mirrors the Watch-vs-Watch
    // path axis (`normalize_watch_path(rp) == normalize_watch_path(cp)` in
    // `rules_match`) applying equally to the cross-variant fold.
    let rules = parse("-w /etc/shadow -p wa -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-09-654240") && d.message.contains("is missing")),
        "a watch on a DIFFERENT path (/etc/shadow) must not satisfy \
         V-258222's /etc/passwd requirement: {diags:?}"
    );
}

#[test]
fn watch_equivalent_wrong_perms_does_not_satisfy_v258222_passwd() {
    // V-258222 requires perm=wa (write+attribute-change). A watch with a
    // NARROWER perm set (-p w only) must NOT satisfy it, even though the
    // path and key match -- mirrors the existing Watch-vs-Watch perms axis
    // (`rpe == cpe` in `rules_match`) and the established same-variant
    // precedent `narrower_watch_perms_does_not_satisfy_the_requirement`
    // (this file) applying equally to the cross-variant fold.
    let rules = parse("-w /etc/passwd -p w -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-09-654240") && d.message.contains("is missing")),
        "a watch with narrower perms (-p w, missing 'a') must not satisfy \
         V-258222's perm=wa requirement: {diags:?}"
    );
}

#[test]
fn watch_equivalent_with_different_key_reports_key_differs_not_missing() {
    // Key-semantics boundary: `rules_match`'s EXISTING two-pass design
    // (`w06_with_baseline` calls it once with `include_key=true` for
    // "Satisfied", then falls back to `include_key=false` for "Present-but-
    // key-differs" vs "Missing" -- see the module doc's `w06_with_baseline`
    // grounded matcher spec, step 3) already distinguishes a same-shape-but-
    // wrong-key match from a genuinely absent rule for EVERY existing axis
    // (pinned for Syscall-vs-Syscall by
    // `w06_present_but_key_differs_finding_carries_its_stig_control_ref`
    // elsewhere in this file). Per the USER RULING (do not invent new key
    // semantics for the new axis), the SAME two-pass distinction must apply
    // once path+perm match ACROSS variants too: a watch with V-258222's
    // correct path (/etc/passwd) and perms (wa) but a DIFFERENT key must
    // produce the SAME "present but with a different key" message, not
    // "is missing".
    //
    // RED today: the current matcher's Watch-vs-Syscall `_ => false` arm
    // short-circuits `axes_match` before path/perm/key are ever compared, so
    // BOTH the `include_key=true` and `include_key=false` passes return
    // `false` today, and `w06_with_baseline` falls all the way to "is
    // missing" rather than "present but with a different key".
    let rules = parse("-w /etc/passwd -p wa -k wrongkey\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel9));
    let v258222: Vec<_> = diags
        .iter()
        .filter(|d| d.message.contains("RHEL-09-654240"))
        .collect();
    assert!(
        !v258222.is_empty(),
        "V-258222 must still produce a finding when the key differs: {diags:?}"
    );
    assert!(
        v258222.iter().all(|d| d.message.contains("different key")),
        "a path+perm-equivalent watch with the WRONG key must produce the \
         'present but with a different key' message, not 'is missing': \
         {v258222:?}"
    );
}

// ---------------------------------------------------------------------------
// Equivalence-ruling reverse direction (item 2): RHEL8's V2R8 required table
// still carries plain single-line watch-form rows (DISA never rewrote
// RHEL8's identity/login set the way V2R9 rewrote RHEL9's -- the RHEL8 pin
// bump V2R4->V2R8, commit 0bcbcf0, confirmed ZERO content drift). A user
// config expressing the SAME kernel-level watch as a dual-arch syscall pair
// must satisfy a watch-shaped required row too -- the equivalence is
// bidirectional (USER RULING: "both directions, all targets").
// ---------------------------------------------------------------------------

#[test]
fn rhel8_watch_required_row_satisfied_by_dual_arch_syscall_equivalent() {
    // V-230406 (RHEL-08-030150): "-w /etc/passwd -p wa -k identity"
    // (stig_required.rs, RHEL8_REQUIRED, unchanged by the V2R8 pin bump). A
    // dual-arch syscall pair expressing the SAME kernel-level watch
    // (auditctl(8): "-w path -p perms" compiles to one path-watch syscall
    // rule PER SUPPORTED ARCHITECTURE; `auditctl -l` folds them back into a
    // single -w line) must satisfy this watch-shaped requirement.
    //
    // RED today: `rules_match`'s Watch-vs-Syscall `_ => false` arm rejects
    // this regardless of content.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030150")),
        "a dual-arch syscall pair expressing the same kernel-level watch as \
         V-230406's required -w line must satisfy it: {diags:?}"
    );
}

#[test]
fn path_syscall_form_wrong_perms_does_not_satisfy_v230406_passwd_watch() {
    // Perm-axis boundary pin for THIS direction (Watch required, Syscall
    // candidate -- the same arm `rhel8_watch_required_row_satisfied_by_
    // dual_arch_syscall_equivalent` above exercises positively). Mirrors
    // `watch_equivalent_wrong_perms_does_not_satisfy_v258222_passwd`'s
    // perm-axis rigor, which only pins the OTHER direction (Syscall
    // required, Watch candidate): V-230406 (RHEL-08-030150) requires
    // perm=wa. A dual-arch -F path= syscall pair with a NARROWER perm set
    // (perm=w only, missing the attribute-change bit) must still be
    // reported missing -- `watch_equivalent_axes_match`'s perm compare is
    // exact `PermBits` equality, not a subset/superset check, in this
    // direction too.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=w -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/passwd -F perm=w -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030150") && d.message.contains("is missing")),
        "a -F path= syscall pair with NARROWER perms (perm=w, missing 'a') \
         than required (perm=wa) must not satisfy V-230406's /etc/passwd \
         watch requirement: {diags:?}"
    );
}

#[test]
fn path_syscall_form_wrong_path_does_not_satisfy_v230406_passwd_watch() {
    // Path-axis boundary pin for THIS direction, sibling of the perm-axis
    // pin above. Mirrors `watch_equivalent_wrong_path_does_not_satisfy_
    // v258222_passwd`'s path-axis rigor (also only pinned for the OTHER
    // direction): a dual-arch -F path= syscall pair naming a DIFFERENT path
    // (/etc/shadow -- itself a real RHEL8_REQUIRED watch target, V-230404/
    // RHEL-08-030130, so this is a genuine sibling requirement's path, not
    // an arbitrary string) must NOT satisfy V-230406's /etc/passwd
    // requirement, even with matching perms and key.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030150") && d.message.contains("is missing")),
        "a -F path= syscall pair naming a DIFFERENT path (/etc/shadow) must \
         not satisfy V-230406's /etc/passwd watch requirement: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Equivalence-ruling perm-bit completeness (mutation-gate report, session
// 9e-wave2c pipeline P2 round 3): `perm_bits_from_field_value` parses a `-F
// perm=` field value into `PermBits` for the equivalence fold, mirroring
// `permtab.h:28-31` / `auditctl(8) -p`'s FOUR letters (r/w/x/a). Every
// existing equivalence test above uses `wa` only (the STIG identity/login
// rows' actual perm), so `cargo mutants` found the `r`- and `x`-arm deletions
// (:1661, :1663) survive -- no test ever feeds a perm string containing `r`
// or `x` through the fold. No shipped RHEL8/9/10 row happens to use `r` or
// `x` via this fold (every real path-watch row is `wa`), so these use a
// SYNTHETIC baseline injected via `w06_with_baseline` (the established
// pattern for matcher-grammar tests in this file, e.g. `rhel9_sample_
// baseline`/`control_matching_is_presence_only_last_wins_modeling_is_out_of_
// scope`) -- pinning the PARSING GRAMMAR's completeness, not a specific STIG
// requirement.
//
// Grounding for exact-vs-superset semantics: the EXISTING same-variant
// Watch-vs-Watch axis in `rules_match` is `rpe == cpe` -- exact `PermBits`
// equality, not a subset/superset check. `watch_equivalent_axes_match`
// mirrors that exact rigor (`perm_bits_from_field_value(sperm).as_ref() ==
// Some(watch_perms)`, also `==`). So the fold requires an EXACT perm match;
// a watch with MORE bits than required (or fewer) does not satisfy it.
// ---------------------------------------------------------------------------

#[test]
fn watch_equivalent_recognizes_read_perm_bit() {
    // Kills the `:1661 - delete 'r' arm` mutant: required perm "ra"
    // (read+attr) with a candidate watch of the SAME "ra" perms (parsed by
    // the real, unmutated rules.d parser). Under the correct impl,
    // `perm_bits_from_field_value("ra")` recognizes both letters and the two
    // PermBits values compare equal -> satisfied (empty diags). Under the
    // mutant, the 'r' character falls through to the wildcard `_ => return
    // None` arm, so the required side never parses at all -> `None !=
    // Some(watch_perms)` -> wrongly reported missing.
    let baseline = vec![bl(
        "SYNTHETIC-PERM-R",
        "TEST-PERM-R",
        "-a always,exit -F path=/etc/synthetic-r -F perm=ra -k synth",
    )];
    let rules = parse("-w /etc/synthetic-r -p ra -k synth\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a watch with perm 'ra' must satisfy a required perm='ra' path-watch \
         row (the read bit must be recognized by perm_bits_from_field_value): \
         {diags:?}"
    );
}

#[test]
fn watch_equivalent_recognizes_exec_perm_bit() {
    // Kills the `:1663 - delete 'x' arm` mutant: sibling of the read-bit
    // test above, for 'x' (exec; PermBits's own doc comment: "exec ->
    // execve, execveat", grounded in auditctl(8) -p / permtab.h:28-31).
    let baseline = vec![bl(
        "SYNTHETIC-PERM-X",
        "TEST-PERM-X",
        "-a always,exit -F path=/etc/synthetic-x -F perm=xa -k synth",
    )];
    let rules = parse("-w /etc/synthetic-x -p xa -k synth\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a watch with perm 'xa' must satisfy a required perm='xa' path-watch \
         row (the exec bit must be recognized by perm_bits_from_field_value): \
         {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Syscall-vs-Syscall `-F perm=` identity WAS a RAW STRING COMPARE prior to
// round 3's fix (session 9m lane 1, round 2-3 ATL) -- unlike the
// Watch-vs-Syscall fold pinned by the two tests just above (which
// case/order-folds via `perm_axis_bits`/`perm_bits_from_field_value` because
// the CANDIDATE is a `Watch`), a required row that is ITSELF `Syscall`-shaped
// (not pure-path-watch-shaped, e.g. because it also restricts `-F auid=`) is
// compared via `fields_match_excluding_key`, whose per-field value equality
// is `super::value::canonical_value(ft, ..)` (called from that function's
// `field_eq` closure). PRIOR to round 3, `classify.rs` bucketed
// `FieldType::Perm` into `FieldValue::Opaque`, and `canonical_value`'s
// `Opaque` arm is `Cow::Borrowed(raw.trim())` -- a raw string compare, so
// `-F perm=X` vs `-F perm=x` (case) and `-F perm=xa` vs `-F perm=ax` (order)
// wrongly compared as DIFFERENT. Round 3 added a `FieldValue::Perm(PermMask)`
// variant (`classify.rs`/`canonical.rs`) that folds `-F perm=` into an
// order-free bitmask instead, so `fields_match_excluding_key` now folds both
// spellings together and the four tests below are all GREEN.
//
// Grounding: `lib/libaudit.c`'s `audit_rule_fieldpair_data` case-folds every
// `-F perm=` character before OR-ing it into a bitmask (`case AUDIT_PERM:
// switch (tolower((unsigned char)v[i])) { case 'r': val |= AUDIT_PERM_READ;
// ... }`, so BOTH case and letter order are semantically irrelevant at the
// kernel: `x`/`X` -> 4, `xa`/`ax`/`XA` -> 12), and the kernel's own
// `audit_compare_rule` (`kernel/auditfilter.c`) has NO `AUDIT_PERM` special
// case, falling to the generic `default: if (a->fields[i].val !=
// b->fields[i].val) return 1;` -- it compares the BITMASK, never the
// spelling.
//
// V-230412/RHEL-08-030190 is a REAL shipped RHEL8 baseline row
// (`stig_required.rs:186-189`), deliberately `Syscall`-only (the `-F auid=`
// restriction takes it outside `is_pure_path_watch_shaped`, per this file's
// existing `dir_syscall_form_with_extra_auid_restriction_is_not_pure_dir_
// watch_shaped` doc comment) -- so it exercises the (pre-round-3, now fixed)
// Syscall-vs-Syscall arm, not the already-fixed Watch-vs-Syscall fold two
// tests above.
// ---------------------------------------------------------------------------

#[test]
fn syscall_vs_syscall_perm_case_flip_wrongly_reports_v230412_missing() {
    let baseline = vec![bl(
        "V-230412",
        "RHEL-08-030190",
        "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change",
    )];
    let rules = parse(
        "-a always,exit -F path=/usr/bin/su -F perm=X -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a candidate spelling -F perm=X (uppercase) must satisfy a required \
         perm=x row -- libaudit case-folds every -F perm= letter before \
         building the bitmask, so the two are the SAME kernel rule: {diags:?}"
    );
}

#[test]
fn watch_equivalent_recognizes_swapped_perm_letter_order_ax() {
    // Positive-control anchor for the contract the next test pins: the
    // Watch-vs-Syscall fold (candidate is a `Watch`) already order-folds via
    // `perm_axis_bits`/`perm_bits_from_field_value` (`PermBits` is four
    // independent bools, order-free by construction), so a candidate spelled
    // `-p ax` (letters swapped) satisfies a required `perm=xa` row exactly
    // like `-p xa` does (`watch_equivalent_recognizes_exec_perm_bit` above).
    let baseline = vec![bl(
        "SYNTHETIC-PERM-X",
        "TEST-PERM-X",
        "-a always,exit -F path=/etc/synthetic-x -F perm=xa -k synth",
    )];
    let rules = parse("-w /etc/synthetic-x -p ax -k synth\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a watch with perm 'ax' (order-swapped) must satisfy a required \
         perm='xa' path-watch row, same as 'xa' -- PermBits is order-free: \
         {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_perm_letter_order_flip_wrongly_reports_v230412_missing() {
    // Pinned as ONE contract with `watch_equivalent_recognizes_swapped_perm_
    // letter_order_ax` immediately above: that test already folds order/case
    // via `perm_axis_bits`/`perm_bits_from_field_value` because the
    // CANDIDATE is a `Watch`. Here BOTH sides are `Syscall`-shaped (required
    // carries the same `-F auid=` restriction as V-230412 above), which
    // routes through the UNFOLDED `fields_match_excluding_key` arm instead --
    // the internal inconsistency IS the point: a fix that folds perm
    // identity in one arm and not the other leaves this pair disagreeing
    // with the Watch-vs-Syscall pair above despite both asserting the exact
    // same kernel-level claim (perm='xa' with the letters swapped).
    let baseline = vec![bl(
        "V-230412",
        "RHEL-08-030190",
        "-a always,exit -F path=/usr/bin/su -F perm=xa -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change",
    )];
    let rules = parse(
        "-a always,exit -F path=/usr/bin/su -F perm=ax -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a candidate spelling -F perm=ax (letters swapped) must satisfy a \
         required perm=xa row, exactly like a `-w path -p ax` watch already \
         satisfies a perm=xa row in the sibling test above: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// ATL round 3 (issues #600/#601 follow-up): PermMask fold DISTINCTNESS on the
// Syscall-vs-Syscall arm. The two tests immediately above pin only that
// EQUIVALENT perm spellings (case/order variants of the SAME kernel bitmask)
// satisfy a required row. Nothing above pins the opposite direction: that a
// candidate whose perm value is a GENUINELY DIFFERENT AUDIT_PERM bitmask
// must still report the control MISSING. A `PermMask::to_letters`
// (`value/classify.rs:107`) that folds every bitmask to a constant string
// (or whose `&`/`!=` bit tests are flipped to `|`/`^`/`==`) would make
// `classify.rs`'s `canonical_value` -- and so `fields_match_excluding_key`
// (whose `field_eq` closure calls it) -- treat every perm value as equal, wrongly
// crediting V-230412/RHEL-08-030190 for a candidate whose perms are simply
// wrong. The two pairs below each toggle exactly one AUDIT_PERM bit
// (READ=1, WRITE=2, EXEC=4, ATTR=8, `classify.rs:72-75`) relative to the
// required row, so a broken single-bit test collapses exactly this pair.
// ---------------------------------------------------------------------------

#[test]
fn syscall_vs_syscall_different_write_vs_read_perm_reports_v230412_missing() {
    let baseline = vec![bl(
        "V-230412",
        "RHEL-08-030190",
        "-a always,exit -F path=/usr/bin/su -F perm=wa -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change",
    )];
    let rules = parse(
        "-a always,exit -F path=/usr/bin/su -F perm=ra -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030190") && d.message.contains("is missing")),
        "a candidate spelling -F perm=ra (READ+ATTR, bits 1|8 = 9) must NOT \
         satisfy a required perm=wa (WRITE+ATTR, bits 2|8 = 10) row -- these \
         are DIFFERENT AUDIT_PERM bitmasks (READ != WRITE), not a case/order \
         respelling of the same value: {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_different_exec_vs_write_perm_reports_v230412_missing() {
    let baseline = vec![bl(
        "V-230412",
        "RHEL-08-030190",
        "-a always,exit -F path=/usr/bin/su -F perm=rw -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change",
    )];
    let rules = parse(
        "-a always,exit -F path=/usr/bin/su -F perm=rx -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030190") && d.message.contains("is missing")),
        "a candidate spelling -F perm=rx (READ+EXEC, bits 1|4 = 5) must NOT \
         satisfy a required perm=rw (READ+WRITE, bits 1|2 = 3) row -- \
         different AUDIT_PERM bitmasks (WRITE != EXEC): {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// ATL round 7 (round-6 adversarial MISS-1, USER RULING): the Syscall-vs-
// Syscall arm (`fields_match_excluding_key` -> `multiset_eq`, `stig_required.
// rs:2035-2073`) never folds `-F perm=` PREDICATE MULTIPLICITY at all --
// rounds 4-5 taught `perm_axis_bits` to fold a chain of `-F perm=` predicates
// to their minimum (subset partial order, `audit_match_perm`'s monotonicity),
// but wired it into the Watch-vs-Syscall/Dir-vs-Syscall arms ONLY. So a
// candidate that is kernel-identical to a required row except for a
// REDUNDANT `-F perm=` predicate (e.g. `-F perm=x -F perm=x`, or `-F perm=x
// -F perm=rx` where `x` subset-of `rx`) fails on `multiset_eq`'s `a.len() !=
// b.len()` guard and is wrongly reported MISSING, even though
// `kernel/auditsc.c`'s `audit_filter_rules` calls `audit_match_perm` once PER
// `AUDIT_PERM` field and ANDs the results (`if (!result) return 0;`) -- the
// SAME idempotent-conjunction argument `perm_axis_bits`'s doc comment already
// makes for the other two arms.
//
// USER RULING (this round, in direct response to the finding above): extend
// the fold to the Syscall-vs-Syscall arm. The locked matcher spec
// (`rules_match`'s doc comment, `:1337-1345`) says to compare `-F` fields "as
// a SET - same size", but its grounding cite (Part C.1/C.5) is about ORDER,
// not multiplicity -- duplicate-predicate semantics were never actually
// decided by that line. The arm already folds perm VALUE identity (rounds
// 2-3, the `syscall_vs_syscall_perm_*` tests above).
//
// The reviewer separately warned that a GENERIC "dedupe `-F` predicates
// before `multiset_eq`" repair would be WRONG: duplicate `-F path=` (and
// other fields) have their OWN kernel semantics -- `kernel/audit_watch.c`'s
// `audit_to_watch` returns `-EINVAL` when `krule->watch` is already set, so a
// second `-F path=` predicate never LOADS at all, and crediting it as if it
// were redundant would be a fail-open, not a fold. The fold must therefore be
// scoped to `AuditField::Perm` specifically, never a generic multiset
// dedupe -- pinned by the path-duplicate fence test below.
// ---------------------------------------------------------------------------

#[test]
fn syscall_vs_syscall_exact_duplicate_perm_predicate_satisfies_v230412() {
    // Item 1: exact duplicate `-F perm=x -F perm=x` -- idempotent
    // conjunction, `match(x) AND match(x) == match(x)`. RED today
    // (`multiset_eq` sees 5 candidate fields vs the required row's 4 and
    // fails on length alone); must go GREEN once the Syscall-vs-Syscall arm
    // folds `-F perm=` predicate multiplicity the same way the Watch-vs-
    // Syscall/Dir-vs-Syscall arms already do via `perm_axis_bits`.
    let baseline = vec![bl(
        "V-230412",
        "RHEL-08-030190",
        "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change",
    )];
    let rules = parse(
        "-a always,exit -F path=/usr/bin/su -F perm=x -F perm=x -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a candidate repeating the SAME -F perm=x predicate twice must \
         satisfy a required perm=x row -- audit_match_perm is called once \
         per AUDIT_PERM field and ANDed, so an exact duplicate is a no-op \
         conjunction: {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_perm_predicate_chain_folds_to_its_minimum_v230412() {
    // Item 2: `-F perm=x -F perm=rx` -- `x` is a SUBSET of `rx`, so the
    // chain's minimum is exactly `x`, the required mask (same monotonicity
    // licence round 5 used for the Watch-vs-Syscall arm). RED today for the
    // same length-mismatch reason as the exact-duplicate case above.
    let baseline = vec![bl(
        "V-230412",
        "RHEL-08-030190",
        "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change",
    )];
    let rules = parse(
        "-a always,exit -F path=/usr/bin/su -F perm=x -F perm=rx -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a candidate spelling -F perm=x -F perm=rx (x subset-of rx) must \
         satisfy a required perm=x row -- the chain's minimum is exactly x: \
         {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_incomparable_perm_predicates_have_no_minimum_and_stay_missing_v230412() {
    // Item 3 (fence): `-F perm=x -F perm=wa` -- {x} and {w,a} are
    // INCOMPARABLE (neither is a subset of the other), so the predicate set
    // has no minimum and nothing licenses a fold (`perm_axis_bits` declines
    // with `None` for exactly this shape). GREEN today (unfolded multiset_eq
    // already rejects on length) and must STAY green: a correct fold must
    // decline here, not fold to an intersection or "first wins".
    let baseline = vec![bl(
        "V-230412",
        "RHEL-08-030190",
        "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change",
    )];
    let rules = parse(
        "-a always,exit -F path=/usr/bin/su -F perm=x -F perm=wa -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030190") && d.message.contains("is missing")),
        "a candidate spelling -F perm=x -F perm=wa has an INCOMPARABLE perm \
         predicate pair (no minimum) and must NOT satisfy a required perm=x \
         row: {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_duplicate_perm_predicate_of_a_different_mask_stays_missing_v230412() {
    // Item 4 (fence): `-F perm=rx -F perm=rx` -- a duplicate of a DIFFERENT
    // mask. The fold gives {r,x} (the set's own minimum, since both
    // predicates are equal), which is NOT the required {x}. Blocks a lazy
    // "drop any extra perm predicate regardless of value" repair: the fold
    // must actually compute the minimum and compare it against the required
    // value, not just collapse duplicates and skip the comparison. GREEN
    // today (unfolded length mismatch) and must STAY green.
    let baseline = vec![bl(
        "V-230412",
        "RHEL-08-030190",
        "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change",
    )];
    let rules = parse(
        "-a always,exit -F path=/usr/bin/su -F perm=rx -F perm=rx -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030190") && d.message.contains("is missing")),
        "a candidate repeating -F perm=rx twice folds to {{r,x}}, which is \
         NOT the required {{x}} mask, and must stay MISSING: {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_duplicate_path_predicate_is_not_folded_stays_missing_v230412() {
    // Item 5 (fence, the sharpest one): a duplicate `-F path=` predicate,
    // with perm left at the single required value. Pins that the fold is
    // scoped to `AuditField::Perm` and must NOT become a generic multiset
    // dedupe applied to every field type -- a second `-F path=` predicate
    // never even LOADS at the kernel level (`kernel/audit_watch.c`'s
    // `audit_to_watch` returns `-EINVAL` once `krule->watch` is already set),
    // so crediting it would be a fail-open, not a fold. GREEN today (length
    // mismatch) and must STAY green.
    let baseline = vec![bl(
        "V-230412",
        "RHEL-08-030190",
        "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset \
         -k privileged-priv_change",
    )];
    let rules = parse(
        "-a always,exit -F path=/usr/bin/su -F path=/usr/bin/su -F perm=x -F auid>=1000 \
         -F auid!=unset -k privileged-priv_change\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030190") && d.message.contains("is missing")),
        "a candidate repeating -F path=/usr/bin/su twice must NOT be folded \
         like a duplicate perm predicate would be -- a second -F path= never \
         loads at the kernel level at all, so crediting it would be a \
         fail-open: {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_incomparable_perm_predicate_pair_still_matches_itself_v601_regression_fence()
{
    // Item 6 (regression fence, round 7 follow-up): pins the half of
    // `fields_match_excluding_key`'s doc comment (`stig_required.rs:
    // 2049-2058`) that Item 3 above
    // (`syscall_vs_syscall_incomparable_perm_predicates_have_no_minimum_and_
    // stay_missing_v230412`) does NOT cover. Item 3 keeps the REQUIRED side
    // single-valued (`perm=x`) while only the CANDIDATE carries an
    // incomparable pair, so `perm_axis_bits(required)` is `Some` and the `if
    // let (Some(r_perm), Some(c_perm))` guard is never even entered -- that
    // case is caught by an ordinary field-count mismatch in the unfolded
    // `multiset_eq`, independent of the fold.
    //
    // Here BOTH sides carry the SAME incomparable pair, `-F perm=rwa -F
    // perm=wxa`: `rwa` = {r,w,a} and `wxa` = {w,x,a}. `r` appears only in the
    // first and `x` only in the second, so neither is a subset of the other
    // -- the set has NO MINIMUM (`perm_axis_bits`'s own doc comment's
    // example verbatim, `stig_required.rs:1935-1938`). So BOTH
    // `perm_axis_bits(required)` and `perm_axis_bits(candidate)` return
    // `None`, the `if let (Some(r_perm), Some(c_perm))` guard is not entered
    // on EITHER side, and the compare falls through to the ORIGINAL,
    // unfolded `multiset_eq` over the full field set -- which trivially
    // matches two byte-identical field lists.
    //
    // The hazard this pins: if a future change ever treated a `None` fold
    // result as "the perm axis does not match" (instead of "no axis-level
    // opinion, defer to the raw field compare"), two byte-identical rules
    // each spelling `-F perm=rwa -F perm=wxa` would flip from satisfied to
    // MISSING -- a fail-closed regression on literally identical input.
    // GREEN today; must STAY green.
    //
    // Level chosen: `w06_with_baseline` with a SYNTHETIC baseline row
    // (labeled accordingly, same pattern as `watch_equivalent_requires_
    // exact_perm_match_not_superset` and its neighbors below), not the
    // shipped `RHEL8_REQUIRED`/`RHEL9_REQUIRED`/`RHEL10_REQUIRED` tables:
    // scanning every literal rule string in all three shipped tables for a
    // second `-F perm=` occurrence finds ZERO rows with more than one `-F
    // perm=` predicate at all, so no shipped required row can carry an
    // incomparable pair -- the required side of this property cannot be
    // constructed from real shipped content. This is the exact seam this
    // file's own module doc (top of file) says `w06_with_baseline` is `pub`
    // specifically to enable: injecting a small, real matcher exercise
    // without depending on the shipped tables. It still runs the REAL
    // public matcher end to end (not a direct call into the private
    // `fields_match_excluding_key`/`perm_axis_bits`), which is the sharper
    // pin whenever it is reachable at all -- and it is reachable here.
    let baseline = vec![bl(
        "SYNTHETIC-PERM-INCOMPARABLE",
        "TEST-PERM-INCOMPARABLE",
        "-a always,exit -F path=/etc/synthetic-incomparable-perm -F perm=rwa -F perm=wxa \
         -k synth",
    )];
    let rules = parse(
        "-a always,exit -F path=/etc/synthetic-incomparable-perm -F perm=rwa -F perm=wxa \
         -k synth\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "two BYTE-IDENTICAL rules each carrying the incomparable perm pair \
         -F perm=rwa -F perm=wxa must still match each other -- perm_axis_bits \
         declines (None) on both sides for a set with no minimum, which must \
         fall through to the unfolded multiset_eq compare rather than being \
         treated as a non-match: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// ATL round 8 (issue #601, a regression introduced by round 7's own fix): a
// FAIL-OPEN on the OPERATOR axis, distinct from the VALUE axis the round-7
// fold section above pins. `perm_axis_bits` (`stig_required.rs`, before its
// operator-gate paragraph was added) selected `-F perm=` predicates with
// `.filter(|f| f.field == AuditField::Perm)` and never inspected `f.op` at
// all -- the round-7 fix wired that op-blind selection straight into the
// Syscall-vs-Syscall arm of `fields_match_excluding_key`. So an ILLEGAL
// OPERATOR on a `-F perm=` predicate (one the kernel/libaudit would refuse
// to load at all) becomes
// INVISIBLE to the matcher: the fold strips it by field NAME only, the same
// way it strips a legal `-F perm=` predicate, and the candidate is wrongly
// credited as satisfying the requirement. Direction: FAIL-OPEN --
// RuleSteward reports a STIG control MET on a host where the audit rule
// never loaded.
//
// Grounding, re-derived THIS round via a fresh userspace-only probe (no
// netlink -- `audit_rule_fieldpair_data()` per its own doc comment in
// `libaudit.h` only builds an in-memory `struct audit_rule_data`; the
// netlink-sending function is the separate, never-called-here
// `audit_add_rule_data()`), calling `audit_rule_fieldpair_data()` directly
// against this host's freshly-installed `audit-libs-devel-4.1.4-1.fc44.
// x86_64` (Fedora Linux 44, Cloud Edition):
//
//   perm=x, perm=wa                       -> rc  0   (loads)
//   perm!=x, perm!=wa, perm>=wa, perm<wa,
//   perm&wa, perm&=wa                     -> rc -29  (refused: any op but
//                                                      `=` is illegal on
//                                                      AUDIT_PERM)
//   perm=zz     (bad letter set)          -> rc -14
//   perm=rwxar  (too long)                -> rc -11
//   perm!=zz                              -> rc -29  (operator is checked
//                                                      BEFORE the letters)
//   perm=x then perm!=x on ONE rule       -> rc1 0, rc2 -29, field_count
//                                             stays 1 (the second pair
//                                             never gets added)
//
// -14/-11 are DIFFERENT codes from -29, which is what makes -29 specifically
// the operator gate rather than a generic "bad perm value" rejection. This
// extends -- same host, same installed library, same refusal code -- the
// identical claim already grounding the two MERGED sibling tests
// `dir_wrong_operator_perm_not_equal_does_not_satisfy_v230410_sudoers_d`
// (this file, above) and `path_wrong_operator_perm_not_equal_does_not_
// satisfy_v230409_sudoers` (this file, below), which cite the same rc=-29
// fact for `!=` alone; this round adds `>=`/`&`/`&=` and the same-rule chain
// case.
//
// No committed EL differential-corpus row covers this axis: none of
// `tests/corpus/auditd-oracle/el8.tsv`, `el9.tsv`, `el10.tsv`,
// `XFAIL-ISSUES.md`, or `PROVENANCE.md` has a `perm!=`/`perm>=`/`perm&`/
// `perm&=` row (checked directly). The corpus's one perm-axis XFAIL entry
// (`f-perm-invalid-letter`, `XFAIL-ISSUES.md`'s "#601 auditd
// permission-letter handling" section) is about LETTER-SET validity, a
// different code path from operator legality. So this section's grounding
// is the libaudit measurement above, not a corpus citation.
//
// V-281128/RHEL-10-500420 (`stig_required.rs:997-1000`, real shipped row:
// "-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 \
// -F auid!=-1 -F key=privileged-chage") is used for items 1-4 via the real
// `w06`/`TargetVersion::Rhel10` entry point, not a synthetic baseline: its
// `-S all` list takes it outside `is_pure_path_watch_shaped` (which
// requires an EMPTY `-S` list), so it always routes through the buggy
// Syscall-vs-Syscall arm, never the already operator-gated Watch-vs-Syscall
// fold (`is_pure_path_watch_shaped`'s own `AuditField::Path | AuditField::
// Perm => f.op == CompareOp::Eq` guard, added for #600).
// ---------------------------------------------------------------------------

#[test]
fn syscall_vs_syscall_perm_not_equal_operator_wrongly_satisfies_v281128_fail_open() {
    // Item 1: `-F perm!=x` in place of the required `-F perm=x`. A `!=`
    // predicate never loads (rc -29 above) and must not satisfy V-281128.
    let rules = parse(
        "-a always,exit -S all -F path=/usr/bin/chage -F perm!=x -F auid>=1000 \
         -F auid!=-1 -F key=privileged-chage\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel10));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-10-500420") && d.message.contains("is missing")),
        "a -F perm!=x rule can never load at the kernel level (audit_rule_ \
         fieldpair_data refuses any op but `=` on AUDIT_PERM, rc -29) and \
         must not satisfy V-281128: {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_perm_relational_operator_wrongly_satisfies_v281128_fail_open() {
    // Item 2: `-F perm>=x`, a relational operator, same refusal code (-29)
    // as `!=` -- the kernel rejects EVERY non-`=` operator on AUDIT_PERM,
    // not just `!=`.
    let rules = parse(
        "-a always,exit -S all -F path=/usr/bin/chage -F perm>=x -F auid>=1000 \
         -F auid!=-1 -F key=privileged-chage\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel10));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-10-500420") && d.message.contains("is missing")),
        "a -F perm>=x rule can never load at the kernel level either (rc \
         -29) and must not satisfy V-281128: {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_perm_bitmask_operator_wrongly_satisfies_v281128_fail_open() {
    // Item 3: `-F perm&x`, the bitmask operator (`&`/`&=` both measured at
    // rc -29 above).
    let rules = parse(
        "-a always,exit -S all -F path=/usr/bin/chage -F perm&x -F auid>=1000 \
         -F auid!=-1 -F key=privileged-chage\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel10));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-10-500420") && d.message.contains("is missing")),
        "a -F perm&x rule can never load at the kernel level either (rc \
         -29) and must not satisfy V-281128: {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_perm_equal_then_not_equal_chain_wrongly_satisfies_v281128_fail_open() {
    // Item 4: the mixed shape `-F perm=x -F perm!=x` on the SAME rule. The
    // libaudit chain measurement above shows the SECOND fieldpair call
    // (perm!=x) returns rc -29 and never gets added (field_count stays at
    // 1, frozen on the first, legal `perm=x`) -- so this candidate rule
    // never loads AT ALL, not merely "loads without the perm!=x half". It
    // must not satisfy V-281128 either.
    let rules = parse(
        "-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F perm!=x \
         -F auid>=1000 -F auid!=-1 -F key=privileged-chage\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel10));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-10-500420") && d.message.contains("is missing")),
        "a candidate spelling -F perm=x -F perm!=x on one rule never loads \
         at all -- the illegal second pair aborts the whole rule at the \
         kernel level (rc -29, field_count frozen at 1) -- and must not \
         satisfy V-281128: {diags:?}"
    );
}

#[test]
fn syscall_vs_syscall_perm_not_equal_reported_missing_on_both_rhel8_and_rhel10_v230409_v281154() {
    // Item 5, the sharpest assertion: whether a rule LOADS is a kernel/
    // libaudit fact that cannot depend on how DISA spelled the required
    // row. The SAME candidate text must be reported MISSING for BOTH
    // targets:
    //
    // - RHEL8's V-230409/RHEL-08-030171 (`stig_required.rs:175-179`,
    //   "-w /etc/sudoers -p wa -k identity") is Watch-shaped, so this
    //   Syscall candidate routes through the (Watch, Syscall) arm via
    //   `is_pure_path_watch_shaped`, which ALREADY guards the perm operator
    //   (`AuditField::Perm => f.op == CompareOp::Eq`, the #600 fix) --
    //   this half is a GREEN fence, confirming the round-8 fix must not
    //   regress the already-correct arm.
    // - RHEL10's V-281154/RHEL-10-500680 (`stig_required.rs:1138-1146`,
    //   "-a always,exit -F arch=bXX -F path=/etc/sudoers -F perm=wa -F
    //   key=logins") is ITSELF Syscall-shaped, so this candidate routes
    //   through the buggy Syscall-vs-Syscall arm -- this half is RED today.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm!=wa -F key=logins\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm!=wa -F key=logins\n",
    );

    let diags_rhel8 = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags_rhel8
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "a -F perm!=wa rule can never load at the kernel level and must not \
         satisfy V-230409 on RHEL8, where the required row is Watch-shaped \
         and already routes through the operator-gated is_pure_path_watch_ \
         shaped check: {diags_rhel8:?}"
    );

    let diags_rhel10 = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel10));
    assert!(
        diags_rhel10
            .iter()
            .any(|d| d.message.contains("RHEL-10-500680") && d.message.contains("is missing")),
        "the SAME -F perm!=wa rule must ALSO not satisfy V-281154 on RHEL10, \
         where the required row is itself Syscall-shaped and routes through \
         the (previously) unguarded Syscall-vs-Syscall arm -- whether a rule \
         loads cannot depend on which RHEL major DISA wrote the requirement \
         for: {diags_rhel10:?}"
    );
}

#[test]
fn syscall_vs_syscall_perm_equal_operator_still_satisfies_v281128() {
    // Positive control: the legal `=` operator must keep satisfying
    // V-281128 once the operator gate lands -- an exact copy of the
    // required row's own perm predicate. GREEN today and must STAY green.
    let rules = parse(
        "-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 \
         -F auid!=-1 -F key=privileged-chage\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel10));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-10-500420")),
        "a -F perm=x candidate (the legal operator) must still satisfy \
         V-281128 -- the operator gate must reject illegal operators \
         without breaking the legal one: {diags:?}"
    );
}

#[test]
fn watch_equivalent_requires_exact_perm_match_not_superset() {
    // Grounding control (not a mutation killer by itself, both mutant and
    // original agree here since "wa" never triggers the r/x arms): pins the
    // EXACT-match semantics explicitly. A watch with MORE bits than required
    // ("-p rwxa", a strict superset of "wa") must NOT satisfy a required
    // perm="wa" row -- the fold mirrors the same-variant Watch-vs-Watch axis
    // (`rpe == cpe`, exact `PermBits` equality), not a "required bits are a
    // subset of the watch's bits" superset check.
    let baseline = vec![bl(
        "SYNTHETIC-PERM-SUPERSET",
        "TEST-PERM-SUPERSET",
        "-a always,exit -F path=/etc/synthetic-super -F perm=wa -k synth",
    )];
    let rules = parse("-w /etc/synthetic-super -p rwxa -k synth\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        !diags.is_empty(),
        "a watch with a SUPERSET of the required perms ('rwxa' vs required \
         'wa') must NOT satisfy the requirement -- the fold requires exact \
         PermBits equality: {diags:?}"
    );
}

#[test]
fn watch_equivalent_missing_required_read_perm_does_not_satisfy() {
    // Load-bearing "both ways" negative complement to
    // `watch_equivalent_recognizes_read_perm_bit`: a required perm 'r' bit
    // that the user's watch OMITS must not be satisfied. Also not a
    // mutation killer by itself (both mutant and original independently
    // arrive at "not equal" here -- the required side genuinely fails to
    // parse under the mutant, and genuinely mismatches under the original --
    // but it documents the negative half of the exact-match contract the
    // positive killer test above pins).
    let baseline = vec![bl(
        "SYNTHETIC-PERM-R-REQUIRED",
        "TEST-PERM-R-REQUIRED",
        "-a always,exit -F path=/etc/synthetic-r2 -F perm=rwa -k synth",
    )];
    let rules = parse("-w /etc/synthetic-r2 -p wa -k synth\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        !diags.is_empty(),
        "a watch missing the required 'r' bit ('wa' vs required 'rwa') must \
         NOT satisfy the requirement: {diags:?}"
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

// ---------------------------------------------------------------------------
// dir-shape equivalence fold (issue #571, USER RULING 2026-07-24): extends
// the existing path-watch equivalence fold (grounded above, "watch<->syscall
// EQUIVALENCE") with a SEPARATE, PARALLEL arm for `-F dir=` <-> `-w DIR`.
//
// Grounding, `auditctl(8)` (`-w path`): "If the path is a file, it's almost
// the same as using the -F path option on a syscall rule. If the watch is on
// a directory, it's almost the same as using the -F dir option on a syscall
// rule." The EXAMPLES section shows both forms side by side: a FILE ("To
// watch a file for changes": `auditctl -w /etc/shadow -p wa` <->
// `auditctl -a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa`) and a
// DIRECTORY ("To recursively watch a directory for changes": `auditctl -w
// /etc/ -p wa` <-> `auditctl -a always,exit -F arch=b64 -F dir=/etc/
// -F perm=wa`). `-F dir=` places a RECURSIVE SUBTREE watch; `-F path=` places
// a SINGLE-INODE watch -- genuinely distinct kernel constructs, confirmed
// directly against `man auditctl` on this machine (`/usr/bin/auditctl`).
//
// CRITICAL: this is implemented as a NEW, SEPARATE structural shape check
// (`is_pure_path_watch_shaped`'s Dir-flavored twin), not an extension of the
// EXISTING path-shape check's allowed-field set. `-F dir=` and `-F path=`
// must never satisfy each other, even though both cross a Watch<->Syscall
// variant boundary the same way -- see the two anti-collapse guards below,
// which are the load-bearing tests in this section.
// ---------------------------------------------------------------------------

#[test]
fn rhel8_sudoers_d_dir_watch_still_satisfied_by_plain_directory_watch() {
    // Regression guard (#571): the classic `-w DIR/` form for V-230410
    // (RHEL-08-030172: "-w /etc/sudoers.d/ -p wa -k identity",
    // RHEL8_REQUIRED) is a SAME-VARIANT Watch-vs-Watch match -- this
    // predates and is entirely independent of the dir-shape fold added for
    // #571 (the bug report's own words: "The common -w /etc/sudoers.d/ form
    // IS already credited"). Pins that adding the new fold arm must not
    // regress this already-working path. GREEN today by design (a
    // regression guard for pre-existing behavior, not the new fold).
    let rules = parse("-w /etc/sudoers.d/ -p wa -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030172")),
        "the classic directory watch line must continue to satisfy V-230410 \
         (RHEL-08-030172) after the dir-shape fold lands: {diags:?}"
    );
}

#[test]
fn dir_syscall_form_satisfies_v230410_sudoers_d_directory_watch() {
    // Positive, direction A (Watch required, Syscall candidate): the
    // asymmetry the bug report names -- an admin who spells the dual-arch
    // SYSCALL form using the kernel-correct -F dir= field (NOT -F path=,
    // which would be the wrong single-inode construct for a directory)
    // against V-230410 (RHEL-08-030172, RHEL8_REQUIRED: "-w
    // /etc/sudoers.d/ -p wa -k identity") currently gets a false "missing".
    //
    // RED today: `is_pure_path_watch_shaped` only recognises path/perm/arch
    // fields, so a Dir field falls outside its shape set and the
    // Watch-vs-Syscall fold never even attempts to compare this candidate.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030172")),
        "a dual-arch syscall pair spelled with -F dir= (the kernel-correct \
         form for a directory watch, per auditctl(8)) must satisfy \
         V-230410's directory-watch requirement (RHEL-08-030172): {diags:?}"
    );
}

#[test]
fn dir_syscall_requirement_satisfied_by_plain_directory_watch() {
    // Positive, direction B (Syscall required, Watch candidate -- the
    // REVERSE of the test above): a REQUIRED line spelled with the syscall
    // -F dir= form (the shape a `-w DIR/` compiles to, per auditctl(8))
    // must be satisfiable by the classic `-w DIR/ -p perms -k key`
    // candidate too. No shipped RHEL8/9/10 table row happens to REQUIRE
    // -F dir= (every real directory-audit STIG row this project has
    // transcribed spells it -F path= instead -- a separate, tracked
    // DISA-authoring quirk confirmed against the real V2R9 XCCDF fixture,
    // see `stig_baseline_rhel9_v2r9_content_pins` above and the module doc
    // for why that is NOT re-litigated here), so this uses a synthetic
    // test-local requirement (the established pattern for matcher-grammar
    // scenarios with no real shipped analog, e.g. the perm-bit completeness
    // tests above).
    //
    // RED today: same root cause as the test above, from the OTHER
    // cross-variant arm (`is_pure_path_watch_shaped` called on the
    // REQUIRED side this time).
    let baseline = vec![bl(
        "SYNTHETIC-DIR-REVERSE",
        "TEST-DIR-REVERSE",
        "-a always,exit -F dir=/etc/synthetic-dir -F perm=wa -k synth",
    )];
    let rules = parse("-w /etc/synthetic-dir/ -p wa -k synth\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a classic directory watch must satisfy a required -F dir= \
         syscall-form requirement (the reverse direction of the dir-shape \
         equivalence fold): {diags:?}"
    );
}

#[test]
fn dir_syscall_form_does_not_satisfy_an_explicit_path_shaped_requirement() {
    // ANTI-COLLAPSE GUARD #1 -- REWRITTEN per USER RULING 2026-07-24,
    // ROUND 3 (adversarial review found the ORIGINAL version internally
    // unsatisfiable against the accepted "over-credit is harmless"
    // decision below -- the same contradiction guard #2 hit in round 2,
    // now closed the SAME way). The ORIGINAL test paired REQUIRED
    // `-w /etc/passwd -p wa -k identity` (a real file, `is_dir == false`)
    // with a CANDIDATE `-F dir=/etc/passwd` and demanded reject. That
    // pairing's only available discriminator between "must accept" (the
    // structurally identical `-w /etc/sudoers.d/` <-> `-F dir=` positive
    // test above) and "must reject" was the required Watch's trailing
    // slash -- which would make `is_dir` load-bearing, contradicting the
    // ruling that `is_dir` stays fully ignored (see
    // `dir_syscall_form_over_credits_a_file_shaped_watch_requirement_and_
    // that_is_accepted` below, and the module doc, for why that is
    // deliberate and harmless).
    //
    // The genuine non-collapse guarantee only exists where BOTH sides
    // spell the kernel construct out EXPLICITLY, as Syscall rules -- the
    // mirror of guard #2 (which pins required=dir=/candidate=path=; this
    // one pins required=path=/candidate=dir=, the OTHER assignment of
    // roles). An admin who writes `-F path=X` has UNAMBIGUOUSLY declared a
    // single-inode watch, and that requirement must NOT be satisfied by a
    // candidate UNAMBIGUOUSLY declaring a recursive subtree watch
    // (`-F dir=X`), regardless of what X actually is on any real host.
    // Like guard #2, this is Syscall-vs-Syscall (SAME variant): it
    // exercises `fields_match_excluding_key`'s EXISTING, unmodified
    // per-field-type discrimination (`AuditField::Path` and
    // `AuditField::Dir` are different enum variants, so the field-set
    // compare never unifies them), NOT the cross-variant
    // `is_pure_path_watch_shaped`/`watch_equivalent_axes_match` machinery.
    // Pinning both role-assignments explicitly guards against an
    // implementation that tries to fold dir<->path by normalizing both
    // into a shared "location" field *before* the generic field
    // comparison.
    let baseline = vec![bl(
        "SYNTHETIC-PATH-VS-DIR",
        "TEST-PATH-VS-DIR",
        "-a always,exit -F path=/etc/passwd -F perm=wa -k identity",
    )];
    let rules = parse("-a always,exit -F dir=/etc/passwd -F perm=wa -k identity\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        !diags.is_empty(),
        "an EXPLICIT -F dir= syscall rule must NOT satisfy a -F path= \
         (single-inode) requirement, even with an identical path string, \
         perms, and key -- both sides unambiguously declare a different \
         kernel construct: {diags:?}"
    );
}

#[test]
fn dir_syscall_form_over_credits_a_file_shaped_watch_requirement_and_that_is_accepted() {
    // ACCEPTED, DELIBERATE over-credit (USER RULING 2026-07-24, ROUND 3):
    // V-230406 (RHEL-08-030150, RHEL8_REQUIRED) is a real FILE watch --
    // "-w /etc/passwd -p wa -k identity". Per the ruling above, `is_dir`
    // stays fully ignored for the dir-shape fold (mirroring the pre-
    // existing, LOCKED path-fold precedent, grounding Part B.7.2), so a
    // candidate spelled with -F dir=/etc/passwd (a recursive subtree watch
    // construct, nominally the "wrong" shape for a file) DOES credit this
    // requirement -- the fold cannot tell file from directory any better
    // than the Watch AST can (`is_dir` is a spelling convention, not
    // ground truth; see `ast.rs`'s `Watch::is_dir` doc comment).
    //
    // This is DELIBERATELY accepted as harmless, not a bug: a recursive
    // subtree watch naming a regular file is a nonsense rule the kernel
    // never actually needs to distinguish in practice (there is no
    // subtree under a file for the extra "recursive" reach to matter), so
    // the over-credit is unreachable in any way that would hide a genuine
    // compliance gap. Pinned here as a PASSING test (not just documented
    // in prose) precisely so a future implementer cannot "fix" this by
    // reintroducing an `is_dir` gate without first breaking a named,
    // documented contract -- exactly the failure mode this whole ruling
    // exists to prevent (a real, shipped row, V-274877's
    // "-w /etc/cron.d -p wa -k cronjobs", spells a GENUINE directory with
    // NO trailing slash; gating on `is_dir` would silently reintroduce
    // issue #571's false-"missing" class on that real row -- see
    // `dir_syscall_form_satisfies_v274877_cron_d_watch_spelled_without_a_
    // trailing_slash` below, which pins that directly).
    //
    // /etc/passwd is used here (rather than a synthetic, non-existent
    // path) SPECIFICALLY because it is verifiably a real, ordinary file on
    // every reachable Linux host, including whichever host happens to run
    // this test -- so this assertion also stands as the "must not resolve
    // dir-ness by `stat()`-ing the analyzing host's filesystem" guarantee
    // (ALSO RULED, 2026-07-24): a linter analyzes configs FOR a target
    // host, not the machine it runs on, so a `stat()`-based implementation
    // that consulted the LOCAL filesystem to reject this pairing (because
    // /etc/passwd is locally a file) would fail this test wherever it
    // runs, not just by the accident of a synthetic path not existing.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/passwd -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/passwd -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030150")),
        "a -F dir= syscall rule on /etc/passwd must be credited against \
         V-230406's file-shaped watch requirement (the accepted, harmless \
         over-credit -- is_dir/file-vs-directory reality plays no part in \
         this fold, by design): {diags:?}"
    );
}

#[test]
fn dir_syscall_form_satisfies_v274877_cron_d_watch_spelled_without_a_trailing_slash() {
    // Regression guard for the EXACT class of bug issue #571 exists to
    // eliminate, reproduced on a REAL shipped row (adversarial review,
    // session 9j lane 8, round 3): V-274877 (RHEL-08-030655,
    // RHEL8_REQUIRED) requires "-w /etc/cron.d -p wa -k cronjobs" --
    // spelled WITHOUT a trailing slash, even though /etc/cron.d is a real
    // directory (confirmed on this host: `test -d /etc/cron.d`
    // succeeds). If a wrong implementation gated the dir-shape fold on
    // `is_dir` (or on the trailing slash directly), a user writing the
    // kernel-correct dual-arch syscall form for this SAME real row would
    // get a false "RHEL-08-030655 is missing" -- the shipped RHEL8 table's
    // own directory rows are spelled INCONSISTENTLY (`stig_required.rs`:
    // V-230410's `-w /etc/sudoers.d/` carries a slash, V-274877's
    // `-w /etc/cron.d` / `-w /var/spool/cron` do not), so the trailing
    // slash is not a usable discriminator in either direction. This test
    // pins that the fold credits this real, unslashed directory row
    // exactly the same way it credits the slashed one.
    //
    // V-274877/RHEL-08-030655 spans TWO required rows (both `/etc/cron.d`
    // and `/var/spool/cron`, both unslashed) -- both are satisfied below
    // so the assertion isolates the /etc/cron.d claim cleanly rather than
    // tripping over the sibling row's independent "missing" finding.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/cron.d -F perm=wa -k cronjobs\n\
         -a always,exit -F arch=b64 -F dir=/etc/cron.d -F perm=wa -k cronjobs\n\
         -a always,exit -F arch=b32 -F dir=/var/spool/cron -F perm=wa -k cronjobs\n\
         -a always,exit -F arch=b64 -F dir=/var/spool/cron -F perm=wa -k cronjobs\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030655")),
        "dual-arch -F dir= syscall pairs for /etc/cron.d and /var/spool/cron \
         must satisfy V-274877's watch requirements even though the shipped \
         rows are spelled WITHOUT a trailing slash (no slash) -- the fold \
         must not gate on is_dir/trailing-slash spelling: {diags:?}"
    );
}

#[test]
fn dir_shaped_requirement_not_satisfied_by_an_explicit_path_syscall() {
    // ANTI-COLLAPSE GUARD #2 -- REWRITTEN per USER RULING 2026-07-24 after
    // adversarial review found the ORIGINAL version of this test
    // internally unsatisfiable against the also-ruled-on `is_dir` decision
    // below. The ORIGINAL test used a plain `-w X` (no trailing slash) as
    // the candidate and asserted it must NOT satisfy a -F dir= requirement.
    // That assertion was WRONG: real auditctl derives file-vs-directory by
    // trimming any trailing slash and `stat()`-ing the actual filesystem
    // object (`audit_setup_watch_name()`), NOT from the trailing-slash
    // spelling -- `man auditctl`'s `-w path` section describes the
    // behavior in terms of what the path IS ("if the path is a file... if
    // the watch is on a directory"), never how it is spelled. A static
    // linter cannot stat the target host, so a `-w X` (slash or not)
    // legitimately DOES credit a `-F dir=X` requirement on any real host
    // where X is a directory -- see
    // `dir_syscall_requirement_satisfied_by_plain_directory_watch` above,
    // which pins exactly that and is UNCHANGED by this rewrite. `is_dir`
    // (`ast.rs`'s `Watch::is_dir`) stays a RuleSteward bookkeeping
    // convention, never a discriminator this fold gates on (locked, same
    // spirit as grounding Part B.7.2).
    //
    // The genuine non-collapse guarantee only exists where BOTH sides
    // spell the kernel construct out EXPLICITLY, as Syscall rules: an
    // admin who writes `-F path=X` has UNAMBIGUOUSLY declared a
    // single-inode watch -- no `stat()`-based inference needed at all,
    // regardless of what X actually is on any real host -- and that must
    // NOT satisfy a requirement UNAMBIGUOUSLY declaring a recursive
    // subtree watch (`-F dir=X`). This is Syscall-vs-Syscall (SAME
    // variant): it exercises `fields_match_excluding_key`'s EXISTING,
    // unmodified per-field-type discrimination (`AuditField::Dir` and
    // `AuditField::Path` are different enum variants, so the field-set
    // compare never unifies them) -- NOT the cross-variant
    // `is_pure_path_watch_shaped`/`watch_equivalent_axes_match` machinery
    // Guard #1 exercises. Pinning it here as an explicit integration test
    // (rather than relying on it being "obviously safe") guards against a
    // DIFFERENT class of mistake: an implementation that tries to fold
    // dir<->path by normalizing both into a shared "location" field
    // *before* the generic field comparison, rather than keeping the
    // equivalence scoped to new, separate cross-variant arms only.
    let baseline = vec![bl(
        "SYNTHETIC-DIR-VS-EXPLICIT-PATH",
        "TEST-DIR-VS-EXPLICIT-PATH",
        "-a always,exit -F dir=/etc/synthetic-mirror -F perm=wa -k synth",
    )];
    let rules = parse("-a always,exit -F path=/etc/synthetic-mirror -F perm=wa -k synth\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        !diags.is_empty(),
        "an EXPLICIT -F path= syscall rule must NOT satisfy a -F dir= \
         (recursive subtree) requirement, even with an identical directory \
         string, perms, and key -- both sides unambiguously declare a \
         different kernel construct: {diags:?}"
    );
}

#[test]
fn dir_equivalent_wrong_perms_does_not_satisfy_v230410_sudoers_d() {
    // Perm-axis rigor for the new dir-shape fold, mirroring the existing
    // path fold's `watch_equivalent_wrong_perms_does_not_satisfy_
    // v258222_passwd`: V-230410 requires perm=wa. A candidate spelled with
    // -F dir= (the RIGHT field this time) but a NARROWER perm set (perm=w
    // only, missing the attribute-change bit) must still be reported
    // missing -- the dir fold must not become a wildcard that credits
    // anything naming the right directory regardless of perms.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=w -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=w -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "a -F dir= rule with NARROWER perms (perm=w, missing 'a') than \
         required (perm=wa) must not satisfy V-230410: {diags:?}"
    );
}

#[test]
fn dir_equivalent_perm_superset_does_not_satisfy_v230410_sudoers_d() {
    // [BLOCKER 4] Perm-superset guard (adversarial review, session 9j lane
    // 8): the NARROWER-perm test above only pins the "candidate has FEWER
    // bits than required" direction -- a wrong implementation comparing
    // "candidate perms are a SUPERSET of required perms" (instead of exact
    // `PermBits` equality) passes that test too, since a superset check
    // and an exact-match check agree whenever the candidate is narrower.
    // This test pins the OTHER half: a candidate with MORE bits than
    // required ("-p rwa", a strict superset of "wa") must ALSO not satisfy
    // the requirement -- mirrors the established path-arm precedent
    // `watch_equivalent_requires_exact_perm_match_not_superset` applied to
    // the new dir arm.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=rwa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=rwa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "a -F dir= rule with a SUPERSET of the required perms ('rwa' vs \
         required 'wa') must NOT satisfy V-230410 -- the fold requires \
         exact PermBits equality, not a subset/superset check: {diags:?}"
    );
}

#[test]
fn dir_equivalent_wrong_dir_value_does_not_satisfy_v230410_sudoers_d() {
    // Directory-value axis (the dir-fold's analog of
    // `distinct_watch_paths_are_not_normalized_to_the_same_value`): a
    // candidate naming a DIFFERENT (SIBLING, not ancestor/descendant)
    // directory entirely must not satisfy V-230410's /etc/sudoers.d
    // requirement, guarding against a fold that credits ANY -F dir= rule
    // regardless of which directory it names. See the ancestor/descendant
    // guards below for the subtree-over-credit boundary specifically.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/cron.d -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/cron.d -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "a -F dir= rule naming a DIFFERENT directory (/etc/cron.d) must not \
         satisfy V-230410's /etc/sudoers.d requirement: {diags:?}"
    );
}

#[test]
fn dir_equivalent_ancestor_directory_does_not_satisfy_v230410_sudoers_d() {
    // [BLOCKER 3] Subtree over-credit guard, ANCESTOR direction
    // (adversarial review, session 9j lane 8): `man auditctl`'s own
    // wording for `-F dir=` ("place a recursive watch on the directory
    // and its whole subtree") could be over-read as "any ANCESTOR
    // directory's watch also covers this one" -- a candidate `-F dir=/etc`
    // rule DOES, in reality, generate events for changes under
    // /etc/sudoers.d too, since it is recursive. But this codebase's
    // established philosophy is EXACT match, never subset/superset/
    // ancestor credit (mirrors `distinct_watch_paths_are_not_normalized_
    // to_the_same_value`'s path axis and
    // `watch_equivalent_requires_exact_perm_match_not_superset`'s perm
    // axis, now also pinned on the perm axis above for this arm): a
    // required directory must be named EXACTLY, not implied by a broader
    // ancestor watch. A wrong implementation that matches "either
    // normalized directory is a prefix of the other" would wrongly credit
    // this pairing.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "a -F dir= rule on the ANCESTOR directory /etc must not satisfy \
         V-230410's /etc/sudoers.d requirement, even though a recursive \
         watch on /etc would, in reality, also cover /etc/sudoers.d -- \
         this fold requires an EXACT directory match, never an ancestor/ \
         descendant relationship: {diags:?}"
    );
}

#[test]
fn dir_equivalent_descendant_directory_does_not_satisfy_v230410_sudoers_d() {
    // [BLOCKER 3] Subtree over-credit guard, DESCENDANT direction (the
    // mirror of the ancestor guard above, decided and pinned here rather
    // than bubbled up: NOT ambiguous once the ancestor direction is
    // settled, since both follow from the SAME exact-match philosophy). A
    // candidate `-F dir=` rule on a SUBDIRECTORY of the required directory
    // (/etc/sudoers.d/subdir, a descendant of /etc/sudoers.d) must NOT
    // satisfy V-230410 either: it only covers a SUBSET of what the
    // required directory needs watched (misses files placed directly in
    // /etc/sudoers.d itself, or in sibling subdirectories), so it is not a
    // kernel-equivalent form of the required watch.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d/subdir -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d/subdir -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "a -F dir= rule on a DESCENDANT subdirectory (/etc/sudoers.d/subdir) \
         must not satisfy V-230410's /etc/sudoers.d requirement -- it only \
         covers a subset of the required directory's contents: {diags:?}"
    );
}

#[test]
fn dir_equivalent_with_different_key_reports_key_differs_not_missing() {
    // Key-axis rigor, mirroring `watch_equivalent_with_different_key_
    // reports_key_differs_not_missing`: the SAME two-pass
    // satisfied/key-differs/missing distinction (`w06_with_baseline`'s
    // grounded matcher spec, step 3) must apply once dir+perm match across
    // the new fold too. A candidate with V-230410's correct directory
    // (/etc/sudoers.d) and perms (wa) but a DIFFERENT key must produce
    // "present but with a different key", not "is missing".
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=wa -k wrongkey\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -k wrongkey\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    let v230410: Vec<_> = diags
        .iter()
        .filter(|d| d.message.contains("RHEL-08-030172"))
        .collect();
    assert!(
        !v230410.is_empty(),
        "V-230410 must still produce a finding when the key differs: {diags:?}"
    );
    assert!(
        v230410.iter().all(|d| d.message.contains("different key")),
        "a dir+perm-equivalent candidate with the WRONG key must produce \
         the 'present but with a different key' message, not 'is missing': \
         {v230410:?}"
    );
}

#[test]
fn dir_syscall_wrong_arch_value_does_not_satisfy_requirement() {
    // Arch-axis grounding control (same-variant Syscall-vs-Syscall,
    // exercised through the NEW Dir field specifically): a candidate with
    // the correct dir/perm/key but the WRONG -F arch= value must not
    // satisfy the requirement. This is the EXISTING, generic
    // fields_match_excluding_key/multiset_eq machinery (arch is just
    // another -F field, handled identically regardless of field type) --
    // pinned here through Dir specifically so a future refactor cannot
    // special-case Dir handling in a way that accidentally bypasses the
    // normal per-field comparison (e.g. matching on dir/perm/key only and
    // silently ignoring arch whenever a Dir field is present).
    //
    // SCOPE NOTE (adversarial review, session 9j lane 8): this test NEVER
    // reaches the NEW cross-variant dir-shape fold code at all (both sides
    // are Syscall) and stays green under every candidate implementation of
    // that fold, correct or not -- it is a Syscall-vs-Syscall grounding
    // control, not an arch-axis guard on the new fold itself. Do not count
    // it toward "the arch axis is covered for the dir fold" in a future
    // report; it covers a different, pre-existing invariant only.
    let baseline = vec![bl(
        "SYNTHETIC-DIR-ARCH-MISMATCH",
        "TEST-DIR-ARCH-MISMATCH",
        "-a always,exit -F arch=b64 -F dir=/etc/synthetic-archmismatch -F perm=wa -k synth",
    )];
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/synthetic-archmismatch -F perm=wa -k synth\n",
    );
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        !diags.is_empty(),
        "a -F dir= candidate with the WRONG -F arch= value must not \
         satisfy the requirement, even with matching dir/perm/key: {diags:?}"
    );
}

#[test]
fn dir_syscall_form_with_extra_auid_restriction_is_not_pure_dir_watch_shaped() {
    // Closing an adjacent hole found while grounding this section: mirrors
    // this file's EXISTING guard for the path arm (`is_pure_path_watch_
    // shaped` requires the field set to be EXACTLY path/perm/arch, not "at
    // least path" -- several real shipped rows, e.g. V-230412's
    // "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F
    // auid!=unset -k privileged-priv_change", deliberately stay
    // Syscall-only for exactly this reason: the auid restriction takes
    // them outside the pure path-watch shape). A naive dir-shape check
    // that only tests "has a Dir field" (instead of "the field set
    // consists ONLY of dir/perm/arch") would wrongly treat this
    // auid-RESTRICTED directory rule as a plain, unconditional
    // directory-watch equivalent, crediting it against V-230410's
    // unconditional requirement even though it generates FEWER audit
    // events than required (it silently misses auid<1000 users) -- the
    // SAME "exact match, not superset/subset" rigor this file already
    // establishes for perms
    // (`watch_equivalent_requires_exact_perm_match_not_superset`) must
    // extend to the field SET itself, not just individual field values.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=wa -F auid>=1000 -F auid!=unset -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -F auid>=1000 -F auid!=unset -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "an auid-RESTRICTED -F dir= rule must NOT satisfy V-230410's \
         unconditional directory-watch requirement -- it generates FEWER \
         events than required (misses auid<1000 users), so it is not a \
         kernel-equivalent form, even though dir/perm/key all match: \
         {diags:?}"
    );
}

#[test]
fn dir_value_trailing_slash_is_normalized_before_comparison() {
    // Trailing-slash normalisation for the dir-fold's directory-value
    // compare, mirroring the EXISTING watch-path precedent
    // (`normalize_watch_path`, grounding Part B.7.2) applied to the NEW
    // -F dir= field's value too. Real-world grounding: RHEL10_REQUIRED's
    // own sudoers.d row (stig_required.rs, RHEL10_REQUIRED table) carries a
    // trailing slash directly on a -F path= field value ("-a always,exit
    // -F arch=b32 -F path=/etc/sudoers.d/ -F perm=wa -F key=identity"),
    // proving DISA's own check-content is just as inconsistent about
    // trailing slashes on -F field values as it is on -w lines (B.7.2) --
    // the same normalize-before-compare treatment must extend to -F dir=
    // values, not just -w paths.
    let baseline = vec![bl(
        "SYNTHETIC-DIR-SLASH",
        "TEST-DIR-SLASH",
        "-a always,exit -F dir=/etc/synthetic-slash/ -F perm=wa -k synth",
    )];
    let rules = parse("-w /etc/synthetic-slash -p wa -k synth\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        diags.is_empty(),
        "a -F dir= requirement value differing only by a trailing slash \
         must still be satisfied by a watch on the same directory: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// Adversarial Testing Loop follow-up (issue #571, session 9j lane 8): an
// impl-aware review of the dir-shape fold above found five miss-cases, each
// grounded in primary source (kernel/audit_tree.c, audit-userspace
// lib/libaudit.c + src/auditctl.c, man auditctl) and several verified
// empirically against the host's installed audit-4.1.4 libaudit. See
// `is_pure_dir_watch_shaped`/`is_pure_path_watch_shaped`/
// `perm_bits_from_field_value`'s doc comments in stig_required.rs for the
// fix-side grounding.
// ---------------------------------------------------------------------------

#[test]
fn dir_wrong_operator_not_equal_does_not_satisfy_v230410_sudoers_d() {
    // MISS-1 (forward direction): `audit_make_tree()` rejects any op other
    // than `Audit_equal` on `AUDIT_DIR` with `-EINVAL` -- the rule never
    // loads at all (kernel/audit_tree.c). A `-F dir!=` candidate therefore
    // implements NOTHING at the kernel level and must not satisfy V-230410,
    // even though the directory/perm/key VALUES look right.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir!=/etc/sudoers.d -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir!=/etc/sudoers.d -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "a -F dir!= rule can never load at the kernel level (audit_make_tree \
         rejects any op but `=` with -EINVAL) and must not satisfy V-230410, \
         regardless of the dir/perm/key values matching: {diags:?}"
    );
}

#[test]
fn dir_wrong_operator_not_equal_required_row_is_not_satisfied_by_a_watch_candidate() {
    // MISS-1 (reverse direction): the SAME unloadable-shape reasoning
    // applies when the `-F dir!=` rule is the REQUIRED row instead of the
    // candidate -- a required rule that can never load at the kernel level
    // has no watch-equivalent form for a plain `-w DIR -p perms -k key`
    // candidate to satisfy.
    let baseline = vec![bl(
        "SYNTHETIC-DIR-NE-REVERSE",
        "TEST-DIR-NE-REVERSE",
        "-a always,exit -F dir!=/etc/synthetic -F perm=wa -k synth",
    )];
    let rules = parse("-w /etc/synthetic/ -p wa -k synth\n");
    let diags = w06_with_baseline(&rules, LintOptions::default(), &baseline);
    assert!(
        !diags.is_empty(),
        "a required `-F dir!=` row can never load at the kernel level and \
         must not be satisfiable by a plain directory watch candidate: {diags:?}"
    );
}

#[test]
fn dir_syscall_form_with_dash_f_key_spelling_satisfies_v230410_sudoers_d() {
    // MISS-2: `-k KEY` and `-F key=KEY` are the SAME rule (`setopt()`
    // literally builds `-F key=%s` from `-k`'s argument before calling
    // `audit_rule_fieldpair_data` -- lib/libaudit.c). `effective_key` and
    // `fields_match_excluding_key` already unify the two spellings
    // elsewhere in this module; the dir-shape test's own allowed-field-set
    // check forgot to exclude Key, so a `-F key=` spelling of an otherwise
    // perfectly-equivalent candidate was wrongly falling OUTSIDE the
    // dir-watch shape and reporting a false "missing".
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=wa -F key=identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -F key=identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030172")),
        "a dual-arch -F dir= pair spelled with -F key= (rather than -k) must \
         still satisfy V-230410 -- -k and -F key= are the same kernel-level \
         key axis: {diags:?}"
    );
}

#[test]
fn watch_form_satisfies_v281155_sudoers_d_on_rhel10_whose_table_spells_the_key_as_dash_f() {
    // MISS-2b: the IDENTICAL omission, in `is_pure_path_watch_shaped` (the
    // pre-existing twin `is_pure_dir_watch_shaped` copied the bug from).
    // RHEL10's shipped table (`RHEL10_REQUIRED`, V-281155/RHEL-10-500690)
    // spells its `/etc/sudoers.d` row with `-F key=identity`
    // (stig_required.rs:1150/1155), while RHEL8's analogous V-230410 row
    // spells the SAME requirement with `-k identity` (stig_required.rs:183).
    // A classic `-w /etc/sudoers.d/ -p wa -k identity` watch -- a real,
    // reasonable admin config -- satisfies V-230410 on RHEL8 today but was
    // wrongly reported "RHEL-10-500690 is missing" on RHEL10, purely
    // because of DISA's own spelling choice for the key field, not any
    // real difference in the ruleset.
    let rules = parse("-w /etc/sudoers.d/ -p wa -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel10));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-10-500690")),
        "a classic -w /etc/sudoers.d/ -p wa -k identity watch must satisfy \
         V-281155/RHEL-10-500690 even though the shipped RHEL10 table spells \
         the required row's key with -F key= rather than -k: {diags:?}"
    );
}

#[test]
fn dir_wrong_operator_perm_not_equal_does_not_satisfy_v230410_sudoers_d() {
    // MISS-3: `lib/libaudit.c`'s AUDIT_PERM case rejects any op but `=`
    // with `-EAU_OPEQ` (verified rc=-29 against the installed audit-4.1.4
    // libaudit) -- a `-F perm!=` rule never loads either, for the same
    // reason a `-F dir!=` rule doesn't (MISS-1).
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm!=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm!=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "a -F perm!= rule can never load at the kernel level (EAU_OPEQ \
         rejects any op but `=`) and must not satisfy V-230410: {diags:?}"
    );
}

#[test]
fn dir_syscall_form_with_two_dir_predicates_does_not_satisfy_v230410_regardless_of_field_order() {
    // MISS-4: `audit_make_tree()` returns `-EINVAL` once a rule's `tree`
    // pointer is already set -- one recursive-subtree watch per rule is a
    // hard kernel limit, so a rule naming `-F dir=` TWICE never loads no
    // matter which value comes first. Pinned in BOTH field orders so a
    // `.find()`-based implementation (which returns whichever Dir predicate
    // happens to come first) cannot pass by accident of iteration order --
    // the correct verdict ("missing") must be identical either way.
    let rules_dir_first = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F dir=/tmp/nope -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F dir=/tmp/nope -F perm=wa -k identity\n",
    );
    let diags_dir_first = w06(
        &rules_dir_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_dir_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "a -F dir= rule naming the CORRECT directory FIRST but a second, \
         wrong -F dir= predicate must not satisfy V-230410 -- the rule never \
         loads at all: {diags_dir_first:?}"
    );

    let rules_dir_second = parse(
        "-a always,exit -F arch=b32 -F dir=/tmp/nope -F dir=/etc/sudoers.d -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/tmp/nope -F dir=/etc/sudoers.d -F perm=wa -k identity\n",
    );
    let diags_dir_second = w06(
        &rules_dir_second,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_dir_second
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "reversing the field order (wrong -F dir= predicate FIRST, correct \
         one second) must produce the SAME 'missing' verdict, not flip to \
         satisfied: {diags_dir_second:?}"
    );
}

#[test]
fn dir_equivalent_uppercase_perm_letters_satisfy_v230410_sudoers_d() {
    // MISS-5: `lib/libaudit.c` case-folds `-F perm=` values with
    // `tolower((unsigned char)v[i])` before building the bitmask (verified
    // on the installed audit-4.1.4 libaudit: `perm=WA` and `perm=wa` both
    // produce `values[0] == 10`). `perm_bits_from_field_value`'s
    // hand-rolled parser must fold case the same way, not reject uppercase
    // letters as unparseable.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=WA -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=WA -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030172")),
        "a -F perm=WA (uppercase) rule must satisfy V-230410's perm=wa \
         requirement -- libaudit case-folds perm letters before comparing: \
         {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// #600: the path twin's fail-open (`is_pure_path_watch_shaped`). NO corpus
// row exists for this issue; these are fresh integration tests, mirroring
// the dir twin's MISS-1/MISS-3/MISS-4 tests above but on V-230409/
// RHEL-08-030171 (`-w /etc/sudoers -p wa -k identity`,
// `src/lints/stig_required.rs:175-179`) -- the PLAIN-FILE twin of the row
// the dir tests use (V-230410/RHEL-08-030172, `/etc/sudoers.d/`).
// ---------------------------------------------------------------------------

#[test]
fn path_wrong_operator_path_not_equal_does_not_satisfy_v230409_sudoers() {
    // #600 MISS-1 analog for the path twin (mirrors
    // `dir_wrong_operator_not_equal_does_not_satisfy_v230410_sudoers_d`
    // above): `kernel/audit_watch.c`'s `audit_to_watch` rejects any op but
    // `=` on an `AUDIT_WATCH` (`path`) predicate at the kernel level -- a
    // `-F path!=` rule never loads either, so it must not satisfy the
    // path-shaped requirement V-230409/RHEL-08-030171.
    //
    // TWO operators are driven through the PUBLIC entry point here, not
    // just `!=`: `au-E02` deliberately treats `-F path>=`/`-F path>`/etc.
    // as CLEAN (`e02_path_relational_and_bitmask_all_clean`,
    // `tests/test_lints_operator_validity.rs:717`, grounded at
    // `libaudit.c:1804-1811` -- userspace has no operator check on
    // AUDIT_WATCH at all), so the Path axis has NO downstream lint net the
    // way Perm partially does. A guard checking only `op != Ne` (instead of
    // `op == Eq`) would pass the `!=` case below while wrongly accepting
    // `>=` and reporting V-230409 SATISFIED for a rule that can never load.
    let rules_bang_eq = parse(
        "-a always,exit -F arch=b32 -F path!=/etc/sudoers -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path!=/etc/sudoers -F perm=wa -k identity\n",
    );
    let diags_bang_eq = w06(
        &rules_bang_eq,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_bang_eq
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "a -F path!= rule can never load at the kernel level (audit_to_watch \
         rejects any op but `=`) and must not satisfy V-230409: {diags_bang_eq:?}"
    );

    let rules_relational = parse(
        "-a always,exit -F arch=b32 -F path>=/etc/sudoers -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path>=/etc/sudoers -F perm=wa -k identity\n",
    );
    let diags_relational = w06(
        &rules_relational,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_relational
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "a -F path>= rule can never load at the kernel level either -- the \
         kernel rejects EVERY non-`=` operator, not just `!=` -- and must \
         not satisfy V-230409: {diags_relational:?}"
    );
}

#[test]
fn path_wrong_operator_perm_not_equal_does_not_satisfy_v230409_sudoers() {
    // #600 MISS-3 analog (mirrors
    // `dir_wrong_operator_perm_not_equal_does_not_satisfy_v230410_sudoers_d`
    // above): `lib/libaudit.c`'s AUDIT_PERM case returns `-EAU_OPEQ` for any
    // op but `=` (verified rc=-29 against the installed audit-4.1.4
    // libaudit) -- a `-F perm!=` rule never loads either, on the path arm
    // just as on the dir arm. Both operator cases are needed: a fix guarding
    // only Path leaves Perm open, and vice versa.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm!=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm!=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "a -F perm!= rule can never load at the kernel level (EAU_OPEQ \
         rejects any op but `=`) and must not satisfy V-230409: {diags:?}"
    );
}

#[test]
fn path_syscall_form_with_two_path_predicates_does_not_satisfy_v230409_regardless_of_field_order() {
    // #600 MISS-4 analog (mirrors
    // `dir_syscall_form_with_two_dir_predicates_does_not_satisfy_v230410_
    // regardless_of_field_order` above): `audit_to_watch` returns -EINVAL
    // once a rule's watch pointer is already set -- one location watch per
    // rule is a hard kernel limit -- so a rule naming `-F path=` TWICE never
    // loads no matter which value comes first. Pinned in BOTH field orders:
    // the correct-path-FIRST order is the one that is RED today (
    // `watch_equivalent_axes_match`'s `.find()` picks the first Path
    // predicate, so today it matches and wrongly credits the requirement);
    // the reversed order already passes. Keeping both in one test is what
    // makes a `.find()`-order-dependent implementation impossible to sneak
    // through.
    let rules_path_first = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F path=/tmp/nope -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F path=/tmp/nope -F perm=wa -k identity\n",
    );
    let diags_path_first = w06(
        &rules_path_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_path_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "a -F path= rule naming the CORRECT path FIRST but a second, wrong \
         -F path= predicate must not satisfy V-230409 -- the rule never \
         loads at all: {diags_path_first:?}"
    );

    let rules_path_second = parse(
        "-a always,exit -F arch=b32 -F path=/tmp/nope -F path=/etc/sudoers -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/tmp/nope -F path=/etc/sudoers -F perm=wa -k identity\n",
    );
    let diags_path_second = w06(
        &rules_path_second,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_path_second
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "reversing the field order (wrong -F path= predicate FIRST, correct \
         one second) must produce the SAME 'missing' verdict, not flip to \
         satisfied: {diags_path_second:?}"
    );
}

#[test]
fn path_well_formed_syscall_pair_still_satisfies_v230409_sudoers() {
    // Positive control (F6): without this, an "always report missing"
    // implementation would pass the three tests above vacuously.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030171")),
        "a well-formed -F path=/etc/sudoers -F perm=wa syscall pair must \
         satisfy V-230409/RHEL-08-030171: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// ATL round (issue #601 follow-up, MISS-3): duplicate `-F perm=` predicates.
// Distinct from the two-Path/two-Dir tests above, which `count() == 1`
// guards on Path/Dir already close -- there is NO analogous multiplicity
// guard on Perm in EITHER `is_pure_path_watch_shaped` or
// `is_pure_dir_watch_shaped`, so a field set with two DIFFERENT-valued
// `-F perm=` predicates still passes the shape test, and
// `watch_equivalent_axes_match`/`dir_watch_equivalent_axes_match`'s
// `.find(|f| f.field == AuditField::Perm)` picks whichever ONE happens to
// come first -- the verdict flips on FIELD ORDER. The kernel loads BOTH perm
// predicates (`kernel/auditfilter.c`'s `audit_data_to_entry` has no dedup
// for AUDIT_PERM, only `if (f->val & ~15) return -EINVAL`) and CONJOINS them
// (`kernel/auditsc.c`'s `audit_filter_rules`: `case AUDIT_PERM: result =
// audit_match_perm(ctx, f->val);` then `if (!result) return 0;` per field),
// so the rule means "perm matches {w,a} AND perm matches {r}", not the
// simple `-p wa` the required row asks for -- it is "missing" in BOTH field
// orders. This also violates the locked field-order-insensitive decision
// (`fields_match_excluding_key`'s grounding, Part C.1).
// ---------------------------------------------------------------------------

#[test]
fn path_syscall_form_with_two_perm_predicates_does_not_satisfy_v230409_regardless_of_field_order() {
    // The correct-value-FIRST order is the one that is RED today:
    // `watch_equivalent_axes_match`'s `.find()` picks the first Perm
    // predicate ("wa", matching the required row), so today it wrongly
    // credits the requirement. The reversed order ("r" first) already
    // reports missing. Keeping both in one test is what makes a
    // `.find()`-order-dependent implementation impossible to sneak through.
    let rules_wa_first = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F perm=r -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F perm=r -k identity\n",
    );
    let diags_wa_first = w06(
        &rules_wa_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_wa_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "a rule naming the CORRECT perm value FIRST but a second, different \
         -F perm= predicate must not satisfy V-230409 -- the two predicates \
         conjoin at the kernel level, they do not mean a simple -p wa watch: \
         {diags_wa_first:?}"
    );

    let rules_r_first = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=r -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=r -F perm=wa -k identity\n",
    );
    let diags_r_first = w06(
        &rules_r_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_r_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "reversing the field order (a different -F perm= predicate FIRST, \
         the correct one second) must produce the SAME 'missing' verdict, \
         not flip to satisfied: {diags_r_first:?}"
    );
}

#[test]
fn dir_syscall_form_with_two_perm_predicates_does_not_satisfy_v230410_regardless_of_field_order() {
    // The Dir-flavored twin of the test above: `is_pure_dir_watch_shaped`
    // has the identical gap (a Dir-count guard, no Perm-count guard), and
    // `dir_watch_equivalent_axes_match`'s `.find()` on Perm is exactly as
    // order-dependent as the path arm's.
    let rules_wa_first = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=wa -F perm=r -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -F perm=r -k identity\n",
    );
    let diags_wa_first = w06(
        &rules_wa_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_wa_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "a rule naming the CORRECT perm value FIRST but a second, different \
         -F perm= predicate must not satisfy V-230410: {diags_wa_first:?}"
    );

    let rules_r_first = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=r -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=r -F perm=wa -k identity\n",
    );
    let diags_r_first = w06(
        &rules_r_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_r_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
        "reversing the field order (a different -F perm= predicate FIRST, \
         the correct one second) must produce the SAME 'missing' verdict, \
         not flip to satisfied: {diags_r_first:?}"
    );
}

#[test]
fn path_syscall_form_with_identical_duplicate_perm_predicates_still_satisfies_v230409_sudoers() {
    // Positive control for the MISS-3 pair above: two Perm predicates with
    // the IDENTICAL value are semantically equivalent to a single `-p wa`
    // watch (`perm=wa AND perm=wa` is just `perm=wa`) and must STAY
    // CREDITED. Without this, an implementer could satisfy the two tests
    // above with a blanket "reject any field set naming Perm more than
    // once", which would ALSO wrongly reject this genuinely-equivalent rule.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030171")),
        "two IDENTICAL -F perm=wa predicates are semantically equivalent to \
         a single -p wa watch and must still satisfy V-230409: {diags:?}"
    );
}

#[test]
fn dir_syscall_form_with_identical_duplicate_perm_predicates_still_satisfies_v230410_sudoers_d() {
    // The Dir-flavored twin of the positive control above, for the same
    // reason: a blanket "reject Perm named more than once" fix applied to
    // the dir arm must not break a genuinely-equivalent identical-duplicate
    // rule either.
    let rules = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=wa -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -F perm=wa -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030172")),
        "two IDENTICAL -F perm=wa predicates are semantically equivalent to \
         a single -p wa watch and must still satisfy V-230410: {diags:?}"
    );
}

// ---------------------------------------------------------------------------
// ATL round 4 (issue #601/#600 follow-up): `perm_axis_bits` demands EQUALITY
// where the kernel is MONOTONE -- a REGRESSION introduced by the round-2 fix
// (commit d21c7aa) above. Round 2 correctly closed the "different predicates
// get first-wins-credited" bug by requiring every `-F perm=` predicate to be
// byte-identical (see `perm_axis_bits`'s doc comment in
// `stig_required.rs`), but "different" is not the same as "incomparable":
// `kernel/auditsc.c`'s `audit_match_perm` is monotone non-decreasing in its
// mask argument (every branch reduces to `mask & <event-determined
// constant>`), so `m1 subset-of m2` implies `match(m1) implies match(m2)`.
// A conjunction of two SUBSET-COMPARABLE perm predicates is therefore
// exactly equivalent to the smaller (stricter) one alone -- `perm=wa AND
// perm=rwxa` collapses to `perm=wa`, not to "no representable value at
// all". Before round 2, first-wins happened to get this SPECIFIC case right
// by accident (it never checked the second predicate); round 2's
// equality-fold regressed it to "missing" in both field orders, which is
// why this is fixed as a regression here rather than filed as a follow-up.
//
// The correct rule: if the perm masks are TOTALLY ORDERED by subset, the
// axis value is the MINIMUM of the chain; otherwise -- genuinely
// incomparable masks, as in the pre-existing
// `path_syscall_form_with_two_perm_predicates_does_not_satisfy_v230409_
// regardless_of_field_order` test above ({w,a} vs {r}, neither subset of
// the other) -- the fold correctly declines (`None`) and the row stays
// "missing".
//
// What each test below actually discriminates (stated precisely, not by
// aspiration): tests 1 and 2 are SATISFIED assertions over SUBSET-COMPARABLE
// pairs. In each, the reversed-field-order half kills first-wins on its own
// (`.find()` would pick the superset predicate on that order and compare it
// to the required value via exact `==`, wrongly reporting missing); BOTH
// orders of each kill the round-2 equality-fold regression under test here
// (it declines whenever the two predicates differ at all, regardless of
// order, which is why both are RED today). Test 2 additionally uses an
// INDEPENDENT chain against a DIFFERENT required row and the dir-form call
// site, so the fix cannot be a special case of test 1's specific superset.
// Neither test 1 nor test 2 can discriminate a correct "subset chain ->
// minimum" fold from a naive "fold via bitwise intersection, then compare
// via ==" fold: for any pair where one mask is a subset of the other,
// intersection(A, B) == min(A, B) by definition, so the two folds provably
// agree on every input either test could construct -- no SATISFIED-subset
// test can ever tell them apart. Test 3 below is the one that can: it uses
// an INCOMPARABLE pair whose intersection happens to be non-empty and to
// equal the required value, which is exactly the shape needed to separate
// the two folds (the pre-existing incomparable-pair test referenced above
// cannot do this either, since its {w,a}-vs-{r} pair intersects to EMPTY,
// which also disagrees with the required value, so "decline" and "naive
// intersection" coincidentally land on the same missing verdict there too).
// ---------------------------------------------------------------------------

#[test]
fn path_syscall_form_with_subset_comparable_perm_predicates_satisfies_v230409_regardless_of_field_order()
 {
    // {w,a} (the required V-230409 value) subset-of {r,w,x,a}: the
    // conjunction `perm=wa AND perm=rwxa` collapses to `perm=wa`, which IS
    // the required row, in BOTH field orders. Discriminates: the reversed
    // order below (rwxa-first) on its own kills first-wins (it would pick
    // rwxa, compare it to the required wa via exact equality, and wrongly
    // report missing); both orders kill the round-2 equality-fold
    // regression (it declines on any two differing predicates, regardless
    // of which comes first). Does NOT discriminate a naive intersection
    // fold from the correct minimum fold -- see the section doc comment
    // above and test 3 below for why no SATISFIED-subset test can.
    let rules_wa_first = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F perm=rwxa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F perm=rwxa -k identity\n",
    );
    let diags_wa_first = w06(
        &rules_wa_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_wa_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171")),
        "perm=wa AND perm=rwxa are SUBSET-COMPARABLE ({{w,a}} subset-of \
         {{r,w,x,a}}) -- audit_match_perm is monotone non-decreasing in its \
         mask, so this conjunction collapses to the smaller mask (perm=wa) \
         and must satisfy V-230409, not report missing: {diags_wa_first:?}"
    );

    let rules_rwxa_first = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=rwxa -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=rwxa -F perm=wa -k identity\n",
    );
    let diags_rwxa_first = w06(
        &rules_rwxa_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_rwxa_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171")),
        "reversing the field order (the superset predicate FIRST, the \
         exact required value second) must produce the SAME satisfied \
         verdict, not flip to missing: {diags_rwxa_first:?}"
    );
}

#[test]
fn dir_syscall_form_with_a_different_subset_comparable_perm_chain_satisfies_v230410_regardless_of_field_order()
 {
    // A SECOND, independent subset chain against a DIFFERENT required row
    // (V-230410/RHEL-08-030172, `/etc/sudoers.d`) exercised through the
    // DIR-flavored call site (`dir_watch_equivalent_axes_match`), so the
    // fix is pinned as "minimum of a subset chain" in general -- not as a
    // special case of the {w,a}-subset-of-{r,w,x,a} pair above: {w,a} (the
    // required value) subset-of {r,w,a} (a superset that adds ONLY 'r',
    // never 'x' -- a genuinely different chain from V-230409's above).
    // Discriminates exactly as test 1 above: the reversed order
    // (superset-first) on its own kills first-wins; both orders kill the
    // round-2 equality-fold regression. Also does NOT discriminate a naive
    // intersection fold from the correct minimum fold, for the same
    // structural reason (subset-comparable inputs make the two folds agree
    // by definition) -- see test 3 below for the test that does.
    let rules_wa_first = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=wa -F perm=rwa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -F perm=rwa -k identity\n",
    );
    let diags_wa_first = w06(
        &rules_wa_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_wa_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172")),
        "perm=wa AND perm=rwa are SUBSET-COMPARABLE ({{w,a}} subset-of \
         {{r,w,a}}) -- this conjunction collapses to perm=wa and must \
         satisfy V-230410, not report missing: {diags_wa_first:?}"
    );

    let rules_superset_first = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=rwa -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=rwa -F perm=wa -k identity\n",
    );
    let diags_superset_first = w06(
        &rules_superset_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_superset_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172")),
        "reversing the field order must produce the SAME satisfied \
         verdict, not flip to missing: {diags_superset_first:?}"
    );
}

#[test]
fn path_syscall_form_with_incomparable_perm_predicates_intersecting_to_the_required_value_still_does_not_satisfy_v230409_regardless_of_field_order()
 {
    // THE test that discriminates "decline on incomparable masks" (correct)
    // from "fold multiple -F perm= predicates via bitwise intersection,
    // then compare via ==" (wrong, ungrounded): {r,w,a} and {w,x,a} are
    // INCOMPARABLE -- neither is a subset of the other ('r' is only in the
    // first, 'x' only in the second) -- so `audit_match_perm`'s
    // monotonicity gives no single mask equivalent to their conjunction,
    // and the fold must decline. Their bitwise INTERSECTION, however, is
    // exactly {w,a} -- V-230409's required value -- so a naive
    // intersection-fold would wrongly report this SATISFIED.
    //
    // Neither test 1 nor test 2 above can catch that bug: intersection
    // provably equals the minimum on any SUBSET-COMPARABLE input, so those
    // two tests can never tell the two folds apart (see the section doc
    // comment above). Nor can the pre-existing
    // `path_syscall_form_with_two_perm_predicates_does_not_satisfy_v230409_
    // regardless_of_field_order` test: its {w,a}-vs-{r} pair intersects to
    // EMPTY, which also disagrees with the required {w,a}, so "decline" and
    // "naive intersection" coincidentally land on the same missing verdict
    // there too. This pair -- incomparable, but with a NON-EMPTY
    // intersection that happens to equal a real required value -- is the
    // only shape that actually separates the two folds.
    //
    // Consequently this test currently PASSES (is GREEN) under BOTH the
    // pre-fix round-2 equality-fold (declines because {r,w,a} != {w,x,a})
    // and the corrected monotone-min-or-decline fold (declines because the
    // masks are incomparable) -- it is not a regression pin like tests 1
    // and 2, but a forward guard: it exists so that whichever fix lands for
    // the round-4 regression above, it cannot silently be (or become) an
    // intersection fold without this test catching it.
    let rules_rwa_first = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=rwa -F perm=wxa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=rwa -F perm=wxa -k identity\n",
    );
    let diags_rwa_first = w06(
        &rules_rwa_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_rwa_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "perm=rwa AND perm=wxa are INCOMPARABLE ({{r,w,a}} vs {{w,x,a}}, \
         neither a subset of the other) even though their intersection \
         ({{w,a}}) equals the required V-230409 value -- a fold that \
         answers via bitwise intersection would wrongly credit this; the \
         correct fold declines (no single equivalent watch exists for an \
         incomparable pair) and V-230409 must stay missing: \
         {diags_rwa_first:?}"
    );

    let rules_wxa_first = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wxa -F perm=rwa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wxa -F perm=rwa -k identity\n",
    );
    let diags_wxa_first = w06(
        &rules_wxa_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        diags_wxa_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "reversing the field order must produce the SAME missing verdict: \
         {diags_wxa_first:?}"
    );
}

// ---------------------------------------------------------------------------
// ATL round 5 (issue #601 follow-up, adversarial MISS-1): `perm_axis_bits`
// demands a TOTAL ORDER (every pair pairwise subset-comparable) where the
// kernel conjunction only requires the predicate set to have a MINIMUM (one
// element that is a subset of every other element). The two conditions
// coincide at |S| == 2 -- exactly why every round-4 test above, all
// two-predicate, missed this -- but diverge at |S| >= 3: a set can have a
// minimum while also containing an incomparable PAIR that never touches the
// minimum. `{w,a}, {r,w,a}, {w,x,a}` has minimum `{w,a}` (a subset of both
// other elements), yet `{r,w,a}` and `{w,x,a}` are themselves incomparable
// ('r' only in the first, 'x' only in the second). The current pairwise loop
// finds that one incomparable pair and declines the WHOLE conjunction --
// a bogus "missing" finding on a genuinely compliant ruleset, reproduced
// end-to-end against the real shipped RHEL8_REQUIRED V-230409/V-230410 rows,
// through both `watch_equivalent_axes_match` and
// `dir_watch_equivalent_axes_match`, and both field orders.
//
// The correct rule: fold to a CANDIDATE minimum first, then verify that
// candidate really is a subset of EVERY element in the set; only then is the
// fold licensed. "Total order" is a strictly stronger, unnecessary condition.
//
// The tests below also fence the fix against a tempting-but-wrong repair:
// deleting the pairwise loop and keeping only the running min-fold (with no
// final re-verification) returns a LOCALLY minimal element, not a true
// minimum, whenever the set has no minimum at all --
// `path_syscall_form_with_wa_and_rw_does_not_satisfy_v230409` below is the
// case that catches it.
//
// Framing note: every `does_not_satisfy` assertion below documents the
// CURRENT posture (decline when no minimum exists), not a claim that
// declining is provably correct -- `audit_match_perm`'s monotonicity is
// silent on an incomparable set; declining is the conservative choice.
// ---------------------------------------------------------------------------

#[test]
fn path_syscall_form_with_a_perm_chain_that_has_a_minimum_but_is_not_a_total_order_satisfies_v230409_regardless_of_field_order()
 {
    // {w,a}, {r,w,a}, {w,x,a}: {w,a} (the required V-230409 value) is a
    // subset of BOTH other elements, so the conjunction has a MINIMUM and
    // collapses to it -- even though {r,w,a} and {w,x,a} are themselves
    // INCOMPARABLE ('r' only in the first, 'x' only in the second), so this
    // three-element set is NOT totally ordered. RED today for BOTH orders
    // (the pairwise loop scans every pair regardless of which element the
    // source text lists first, so it finds the incomparable {r,w,a}/{w,x,a}
    // pair and declines either way); must go GREEN once the fold checks for
    // a minimum rather than a total order.
    let rules_min_first = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F perm=rwa -F perm=wxa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F perm=rwa -F perm=wxa -k identity\n",
    );
    let diags_min_first = w06(
        &rules_min_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_min_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171")),
        "perm=wa AND perm=rwa AND perm=wxa: {{w,a}} is a subset of both \
         {{r,w,a}} and {{w,x,a}}, so the conjunction has a minimum ({{w,a}}) \
         even though {{r,w,a}} and {{w,x,a}} are themselves incomparable -- \
         this must satisfy V-230409 (demanding a TOTAL ORDER is a stronger, \
         wrong condition), not report missing: {diags_min_first:?}"
    );

    let rules_min_last = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=rwa -F perm=wxa -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=rwa -F perm=wxa -F perm=wa -k identity\n",
    );
    let diags_min_last = w06(
        &rules_min_last,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_min_last
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171")),
        "the SAME three predicates with the minimum ({{w,a}}) listed LAST \
         (after the two incomparable elements) must produce the SAME \
         satisfied verdict, not flip to missing: {diags_min_last:?}"
    );
}

#[test]
fn dir_syscall_form_with_a_perm_chain_that_has_a_minimum_but_is_not_a_total_order_satisfies_v230410_regardless_of_field_order()
 {
    // The Dir-flavored twin of the test above, through
    // `dir_watch_equivalent_axes_match` against V-230410/RHEL-08-030172
    // (`/etc/sudoers.d`): the same three-predicate, minimum-exists-but-not-
    // totally-ordered set, exercised through the OTHER call site so the fix
    // cannot be a special case of the path arm alone.
    let rules_min_first = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=wa -F perm=rwa -F perm=wxa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -F perm=rwa -F perm=wxa -k identity\n",
    );
    let diags_min_first = w06(
        &rules_min_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_min_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172")),
        "perm=wa AND perm=rwa AND perm=wxa via the dir-form call site: the \
         same minimum-exists-but-not-totally-ordered set as V-230409 above, \
         must satisfy V-230410, not report missing: {diags_min_first:?}"
    );

    let rules_min_last = parse(
        "-a always,exit -F arch=b32 -F dir=/etc/sudoers.d -F perm=rwa -F perm=wxa -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=rwa -F perm=wxa -F perm=wa -k identity\n",
    );
    let diags_min_last = w06(
        &rules_min_last,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_min_last
            .iter()
            .any(|d| d.message.contains("RHEL-08-030172")),
        "the minimum listed LAST must produce the SAME satisfied verdict \
         through the dir-form call site too: {diags_min_last:?}"
    );
}

#[test]
fn path_syscall_form_with_wa_and_rw_does_not_satisfy_v230409() {
    // {w,a} and {r,w} are INCOMPARABLE (neither a subset of the other: 'a'
    // only in the first, 'r' only in the second) -- this set has NO
    // minimum, so nothing licenses folding the conjunction to a single
    // mask. Per the framing note above (section doc comment), the current
    // documented posture is to decline when no minimum exists; V-230409
    // stays missing under that posture.
    //
    // This is the test that separates the CORRECT fix (compute a candidate
    // minimum, then verify it really is a subset of every element) from a
    // tempting-but-wrong one (delete the pairwise total-order loop and keep
    // only the running min-fold, with no final verification pass): a naive
    // running fold over `[wa, rw]` starts at `wa`, checks whether `rw` is a
    // subset of `wa` (it is not -- 'r' is only in `rw`), so `wa` is NEVER
    // challenged again and the fold returns `Some({w,a})` -- wrongly
    // crediting V-230409 even though `{w,a}` is not a subset of `{r,w}` and
    // the pair has no real minimum. Only a final verification step (checking
    // the candidate against every element) catches this.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F perm=rw -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F perm=rw -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "perm=wa AND perm=rw are INCOMPARABLE ({{w,a}} vs {{r,w}}, neither a \
         subset of the other) so the set has no minimum -- V-230409 must \
         stay missing under the documented decline-when-no-minimum posture: \
         {diags:?}"
    );
}

#[test]
fn path_syscall_form_with_wa_and_ra_does_not_satisfy_v230409() {
    // {w,a} and {r,a} are INCOMPARABLE ('w' only in the first, 'r' only in
    // the second); no minimum exists, so V-230409 stays missing under the
    // documented decline-when-no-minimum posture.
    //
    // This pair isolates the WRITE conjunct of `perm_bits_is_subset`
    // (its `(!a.write || b.write)` term): `{w,a}` has write, `{r,a}` does
    // not, and every other conjunct already agrees (both lack exec; both
    // have attr; read is vacuously satisfied since `{w,a}` lacks read).
    // Deleting the `!` on the write conjunct (a round-5 mutation survivor)
    // turns `is_subset(wa, ra)` from `false` to `true`, which defeats the
    // total-order decline and lets the min-fold wrongly settle on `wa` --
    // flipping this test's verdict from missing to satisfied.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F perm=ra -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F perm=ra -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "perm=wa AND perm=ra are INCOMPARABLE ({{w,a}} vs {{r,a}}, neither a \
         subset of the other) so V-230409 must stay missing: {diags:?}"
    );
}

#[test]
fn path_syscall_form_with_wa_and_wx_does_not_satisfy_v230409() {
    // {w,a} and {w,x} are INCOMPARABLE ('a' only in the first, 'x' only in
    // the second); no minimum exists, so V-230409 stays missing under the
    // documented decline-when-no-minimum posture.
    //
    // This pair isolates the ATTR conjunct of `perm_bits_is_subset`
    // (its `(!a.attr || b.attr)` term): both share write; read and exec
    // are vacuously satisfied (the deciding side lacks the bit in each
    // case); only attr disagrees (`{w,a}` has it, `{w,x}` does not).
    // Deleting the `!` on the attr conjunct (a round-5 mutation survivor)
    // turns `is_subset(wa, wx)` from `false` to `true`, defeating the
    // total-order decline and letting the min-fold wrongly settle on `wa`
    // -- flipping this test's verdict from missing to satisfied.
    let rules = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F perm=wx -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F perm=wx -k identity\n",
    );
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        diags
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
        "perm=wa AND perm=wx are INCOMPARABLE ({{w,a}} vs {{w,x}}, neither a \
         subset of the other) so V-230409 must stay missing: {diags:?}"
    );
}

#[test]
fn path_syscall_form_with_wa_then_wxa_satisfies_v230409_and_pins_the_dropped_exec_conjunct_order_dependently()
 {
    // {w,a} subset-of {w,x,a} (adds only 'x'): the conjunction collapses to
    // {w,a}, which IS V-230409's required value -- already SATISFIED under
    // the current (pre-round-5) code, since a two-element chain is trivially
    // a total order. This test exists to pin FINDING 3: deleting the WHOLE
    // `&& (!a.exec || b.exec)` conjunct from `perm_bits_is_subset` survives
    // the entire frozen suite as of round 4 ("remove a conjunct" is not a
    // `cargo mutants` operator, so no gate run will ever report it).
    //
    // The `wa`-FIRST order is the one that actually catches it: the running
    // min-fold starts at `wa` (min), then considers `wxa` as a candidate --
    // `is_subset(wxa, wa)` must be `false` (wxa's exec bit is not in wa) to
    // keep `min` at `wa`. Deleting the exec conjunct makes
    // `is_subset(wxa, wa)` wrongly evaluate to `true` (read/write/attr all
    // still agree), so `min` becomes `wxa` instead, and the fold returns
    // `Some({w,x,a})` -- which does NOT equal the required `{w,a}` --
    // flipping this test's verdict from satisfied to missing.
    let rules_wa_first = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F perm=wxa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F perm=wxa -k identity\n",
    );
    let diags_wa_first = w06(
        &rules_wa_first,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_wa_first
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171")),
        "perm=wa AND perm=wxa: {{w,a}} subset-of {{w,x,a}} collapses to \
         {{w,a}}, which is V-230409's required value: {diags_wa_first:?}"
    );

    // The REVERSED order (`wxa` first) does NOT, on its own, catch the
    // dropped-exec-conjunct mutant: the fold starts at `wxa` (min), then
    // considers `wa` as a candidate -- `is_subset(wa, wxa)` is `true` both
    // with and without the exec conjunct (`wa`'s exec bit is already false,
    // so that term is vacuously true either way), so `min` becomes `wa`
    // regardless of the mutant. This assertion exists only to confirm
    // order-independence of the CORRECT verdict, not to pin FINDING 3 a
    // second time.
    let rules_reversed = parse(
        "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wxa -F perm=wa -k identity\n\
         -a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wxa -F perm=wa -k identity\n",
    );
    let diags_reversed = w06(
        &rules_reversed,
        LintOptions::default(),
        Some(TargetVersion::Rhel8),
    );
    assert!(
        !diags_reversed
            .iter()
            .any(|d| d.message.contains("RHEL-08-030171")),
        "reversing the field order must produce the SAME satisfied verdict: \
         {diags_reversed:?}"
    );
}

// ---------------------------------------------------------------------------
// Session 9m lane 1 (fixed in passing alongside this lane's #601 work, at
// the user's ruling): the SAME field-name-only fail-open as #600's Path/Perm
// axes, but on the Arch axis of `is_pure_path_watch_shaped`/
// `is_pure_dir_watch_shaped`'s allowed-field-set conjunct
// (`AuditField::Arch | AuditField::Key => true`, "(with any op)"). Measured
// at the CLI (`--target rhel8`) before this fix: `-a always,exit -F
// path=/etc/sudoers -F perm=wa -F arch>=b64 -k identity` gets BOTH an au-E02
// "invalid operator" error (arch's own operator legality is a SEPARATE
// lint's job, unaffected by this fix) AND a wrongly-SATISFIED verdict on
// V-230409/RHEL-08-030171 -- the rule never loads at the kernel level.
//
// Grounding: a userspace-only `audit_rule_fieldpair_data()` probe (no
// netlink -- the function only builds an in-memory `struct
// audit_rule_data`; the netlink-sending function is the separate,
// never-called `audit_add_rule_data()`) against the installed
// `audit-libs-4.1.4-1.fc44.x86_64`:
//
//   arch=b64, arch!=b64                              -> rc  0  (both LOAD)
//   arch<b64, arch>b64, arch<=b64, arch>=b64,
//   arch&b64, arch&=b64                              -> rc -13 (refused)
//
// The committed EL differential corpus (`tests/corpus/auditd-oracle/
// el{8,9,10}.tsv`) has no row exercising a non-`=` arch operator at all
// (every `arch` occurrence in all three TSVs is `arch=b64`) and neither
// `XFAIL-ISSUES.md` nor `PROVENANCE.md` documents this axis, so the above
// libaudit measurement is this section's grounding, not a corpus citation.
// See `src/lints/stig_required.rs`'s `ARCH_REJECT_OPS` doc comment (both
// `pure_path_watch_shape_tests` and `pure_dir_watch_shape_tests` modules)
// for the same grounding restated next to the direct unit-test pin.
//
// `Ne` is the one non-`Eq` operator that MUST stay accepted (rc 0) -- the
// fences below pin that a correct fix gates on `Eq || Ne`, not `Eq` alone.
// Key stays fully operator-blind (no grounded reason to gate it -- libaudit
// accepts `key!=`/`key>=`/`key&`, all rc 0, measured separately): the
// fences below also pin that the arch fix does not accidentally start
// gating Key too.
// ---------------------------------------------------------------------------

#[test]
fn path_syscall_form_arch_rejected_operator_does_not_satisfy_v230409_sudoers() {
    // Every operator libaudit REJECTS on `-F arch=` (measured rc -13 above):
    // a candidate spelling any of these in place of the well-formed
    // `arch=b64` never loads at the kernel level and must not satisfy
    // V-230409/RHEL-08-030171.
    for op in [">=", "<", ">", "<=", "&", "&="] {
        let line =
            format!("-a always,exit -F path=/etc/sudoers -F perm=wa -F arch{op}b64 -k identity\n");
        let rules = parse(&line);
        let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
        assert!(
            diags
                .iter()
                .any(|d| d.message.contains("RHEL-08-030171") && d.message.contains("is missing")),
            "a -F arch{op}b64 rule can never load at the kernel level (rc \
             -13) and must not satisfy V-230409: {diags:?} (line: {line:?})"
        );
    }
}

#[test]
fn dir_syscall_form_arch_rejected_operator_does_not_satisfy_v230410_sudoers_d() {
    // The Dir-flavored twin, against V-230410/RHEL-08-030172.
    for op in [">=", "<", ">", "<=", "&", "&="] {
        let line =
            format!("-a always,exit -F dir=/etc/sudoers.d -F perm=wa -F arch{op}b64 -k identity\n");
        let rules = parse(&line);
        let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
        assert!(
            diags
                .iter()
                .any(|d| d.message.contains("RHEL-08-030172") && d.message.contains("is missing")),
            "a -F arch{op}b64 rule can never load at the kernel level (rc \
             -13) and must not satisfy V-230410: {diags:?} (line: {line:?})"
        );
    }
}

#[test]
fn path_syscall_form_arch_not_equal_still_satisfies_v230409_sudoers() {
    // GREEN fence: `arch!=b64` is the one non-`Eq` operator libaudit still
    // LOADS (rc 0, measured above) -- a fix that gates arch on `Eq` alone
    // (rather than `Eq || Ne`) would wrongly turn this into a "missing"
    // verdict.
    let rules = parse("-a always,exit -F path=/etc/sudoers -F perm=wa -F arch!=b64 -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030171")),
        "a -F arch!=b64 rule DOES load at the kernel level (rc 0) and must \
         still satisfy V-230409: {diags:?}"
    );
}

#[test]
fn dir_syscall_form_arch_not_equal_still_satisfies_v230410_sudoers_d() {
    // The Dir-flavored twin of the fence above.
    let rules = parse("-a always,exit -F dir=/etc/sudoers.d -F perm=wa -F arch!=b64 -k identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030172")),
        "a -F arch!=b64 rule DOES load at the kernel level (rc 0) and must \
         still satisfy V-230410: {diags:?}"
    );
}

#[test]
fn path_syscall_form_key_relational_operator_does_not_disqualify_v230409_sudoers() {
    // GREEN fence: Key stays fully operator-blind (`effective_key` reads
    // only `.value`, never `.op`; libaudit accepts `key>=` fine, rc 0,
    // measured separately -- no grounded reason to gate it). A fix that
    // over-broadly tightens the whole `Arch | Key => true` arm (rather than
    // leaving Key on its own unconditional arm) would wrongly turn this
    // into a "missing" verdict.
    let rules =
        parse("-a always,exit -F path=/etc/sudoers -F perm=wa -F arch=b64 -F key>=identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030171")),
        "a -F key>=identity predicate must not disqualify the path-watch \
         shape -- Key stays operator-blind: {diags:?}"
    );
}

#[test]
fn dir_syscall_form_key_relational_operator_does_not_disqualify_v230410_sudoers_d() {
    // The Dir-flavored twin of the fence above.
    let rules =
        parse("-a always,exit -F dir=/etc/sudoers.d -F perm=wa -F arch=b64 -F key>=identity\n");
    let diags = w06(&rules, LintOptions::default(), Some(TargetVersion::Rhel8));
    assert!(
        !diags.iter().any(|d| d.message.contains("RHEL-08-030172")),
        "a -F key>=identity predicate must not disqualify the dir-watch \
         shape -- Key stays operator-blind: {diags:?}"
    );
}
