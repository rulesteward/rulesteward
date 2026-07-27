//! Data-driven `sudoers(5)` differential-oracle corpus (#538, session 9k-1 Lane C).
//!
//! Checks `RuleSteward`'s own answer (the hand-rolled `parser::parse` + the not-yet-
//! written `oracle` projection/classification helpers) against a REAL `visudo` /
//! `cvtsudoers` (sudo 1.9.x, Rocky 8/9/10) verdict captured per scenario, rather
//! than a hand-authored expectation - see CONTRIBUTING.md "Differential oracle
//! contract". This is the Tier-1 (offline) replay half; `capture_sudoers.sh` +
//! `just diff-sudoers` (`scripts/rs-oracle-diff.sh sudoers`) is the Tier-2 (live)
//! half, re-pointing this SAME test at a freshly captured corpus via
//! `RS_ORACLE_CORPUS_SUDOERS`.
//!
//! # Frozen API this test requires from `rulesteward_sudoers::oracle` (NOT YET
//! WRITTEN - this test is the spec; it will not compile until it lands)
//!
//! - `VisudoVerdict::{Accept, Reject}` + `UnclassifiedVisudo` (the fail-closed
//!   error when rc and evidence text disagree).
//! - `classify_visudo(rc: i32, stdout: &str, stderr: &str) ->
//!   Result<VisudoVerdict, UnclassifiedVisudo>`: `Ok(Accept)` iff `rc == 0` AND
//!   `stdout` contains `"parsed OK"`; `Ok(Reject)` iff `rc != 0` AND `stdout` does
//!   NOT contain `"parsed OK"`; anything else (rc and evidence disagree, e.g. a
//!   captured rc of 2+, or rc==0 with no "parsed OK" text) is
//!   `Err(UnclassifiedVisudo)` - fail-closed, never guessed.
//! - `StructureProjection { tuple_count: usize, users: Vec<String>, hosts:
//!   Vec<String>, commands: Vec<String> }`: a STRUCTURE-ONLY (not full-fidelity;
//!   full AST-vs-AST fidelity is an explicit follow-up, not this session) view of
//!   a sudoers document. `tuple_count` is the number of `(User_List, Host_List,
//!   Cmnd_Specs)` tuples - one per `:`-separated host-group, matching
//!   `cvtsudoers -f json`'s `User_Specs[]` array 1:1 (verified empirically,
//!   2026-07-25: `alice h1 = /bin/ls : h2 = /bin/id` produces TWO `User_Specs[]`
//!   entries, each carrying its OWN copy of the shared `User_List`). `users` /
//!   `hosts` / `commands` are FLAT, file-wide token lists (this test does its own
//!   multiset - i.e. order-independent - comparison via `sorted_eq`, so
//!   `project_ast` / `project_cvtsudoers_json` need not sort internally); for
//!   EVERY host-group tuple, `project_ast` must push the *shared* `UserSpec`
//!   users list once (matching `cvtsudoers`' per-tuple duplication of
//!   `User_List`), that host-group's own hosts, and that host-group's own
//!   commands.
//! - `project_ast(file: &rulesteward_sudoers::ast::SudoersFile) ->
//!   StructureProjection`: `CmndItem::All` projects to the literal string
//!   `"ALL"`; a subject/host token's sigil (`%group`, `+netgroup`, `#uid`, a
//!   leading `!` negation) must be STRIPPED to its bare value (a single optional
//!   leading `!`, then a single optional leading sigil among `%+#`) so it is
//!   comparable to `cvtsudoers`' bare values below.
//! - `project_cvtsudoers_json(json: &serde_json::Value) ->
//!   Result<StructureProjection, CvtsudoersProjectionError>`: fail-closed on any
//!   `User_Specs[]` element whose `User_List`/`Host_List`/`Cmnd_Specs->Commands`
//!   entries do not match a KNOWN key shape. Measured key shapes (`cvtsudoers -f
//!   json`, sudo 1.9.17p2, 2026-07-25 - `cvtsudoers -f json` does NOT expand
//!   aliases, matching this crate's own un-expanded AST):
//!     - `User_List[]`: `{"username": S}` / `{"useralias": S}` (an unexpanded
//!       `User_Alias`/`Cmnd_Alias` reference keeps the alias NAME here) /
//!       `{"usergroup": S}` (bare, no `%`) / `{"netgroup": S}` (bare, no `+`) /
//!       `{"userid": N}` (a JSON NUMBER, no `#` - stringify it).
//!     - `Host_List[]`: `{"hostname": S}` / `{"hostalias": S}`.
//!     - `Cmnd_Specs[].Commands[]`: `{"command": S}` / `{"cmndalias": S}`.
//!
//!   Extract the bare string value regardless of which key is present (ignore
//!   any companion `"negated": true`, which mirrors this test's own sigil-strip
//!   normalization on the AST side - see `project_ast` above).
//!
//! # Three layers
//!
//! 1. **L1 (`sudo-F01`)**: does a `Malformed` line in our AST agree with the
//!    oracle's accept/reject verdict (`visudo -c -f -`)? Grounded per-TARGET,
//!    not once globally: el8's older sudo (1.9.5p2, grammar 48) genuinely
//!    rejects constructs el9/el10 (1.9.17p2, grammar 50) accept (measured:
//!    `INTERCEPT:` and a regex `Cmnd_Alias` `^...$` both syntax-error on el8 but
//!    parse clean on el9/el10) - this corpus deliberately avoids such
//!    version-gated constructs (a THIRD, newly-discovered divergence class
//!    outside #538's two documented gaps; see PROVENANCE.md), so L1 is a clean
//!    regression layer with an EMPTY xfail table.
//! 2. **L2 (the strict gate)**: does `visudo -c -s -f -` agree with `visudo -c
//!    -f -`? Measured (2026-07-25, ~25 varied probes across all three images:
//!    duplicate aliases, unused aliases, unknown `Defaults` names, malformed
//!    hostnames, relative paths, missing `@include` targets, cross-namespace
//!    alias-name collisions): `-s` and `-c` never diverge over STDIN input on
//!    any of the three images. This is plausibly because `-s`'s real-world
//!    value is file mode/ownership checking, which cannot be exercised via `-f
//!    -`. So L2's xfail table is EMPTY too - this is a genuine, surprising
//!    finding surfaced in the PR report, not an assumption.
//! 3. **L3 (structure-only projection)**: for every scenario where the oracle
//!    ACCEPTS and `cvtsudoers -f json`'s stdout parses as JSON, does
//!    `project_ast` agree with `project_cvtsudoers_json`? Two KNOWN, grounded
//!    divergences (#538, do NOT fix here):
//!      - `accept-selinux-role-type`: the tag-parsing loop in
//!        `parser::parse_cmnd_spec` only recognizes `TAG:` syntax; `ROLE=`/
//!        `TYPE=` use `=`, so the whole remainder (`ROLE=... TYPE=... /usr/bin/vim`)
//!        becomes ONE garbage `CmndItem::Cmnd` token instead of the real command.
//!      - `accept-user-list-whitespace-bug`: `classify_user_spec`'s
//!        `split_first_word` on the first host-group segment assumes the
//!        `User_List` has no INTERNAL whitespace; `bob, ALL ALL=(ALL) ALL` splits
//!        at the first whitespace after `bob,`, dropping `ALL` from the user
//!        list and merging it into the host list as one garbage `"ALL ALL"`
//!        token.
//!
//!    `el8`'s `cvtsudoers -f json` emits INVALID JSON for `SELinux_Spec`
//!    (measured 2026-07-25: a JSON array containing bare `"role": "..."` pairs
//!    with no wrapping object - `serde_json` rejects it), so
//!    `accept-selinux-role-type`/`el8` is a SCOPED-OUT parse failure (confirmed,
//!    not silently skipped), not an L3 comparison at all.
//!
//! # Per-version positive control
//!
//! `sudo` on el9 (rpm `sudo-1.9.17p2-3.el9_8`) and el10 (rpm
//! `sudo-1.9.17-4.p2.el10_2`) are the SAME upstream release; `visudo -V` prints
//! the IDENTICAL string (`"visudo version 1.9.17p2"`) on both, and an extensive
//! probe (see above) found NO observable sudoers-parsing divergence between them
//! either - so neither the version string NOR sudoers behavior can prove three
//! DISTINCT captures were really taken. The captured `sudo_rpm` field (from `rpm
//! -q sudo`, read directly, never derived from visudo/cvtsudoers output) DOES
//! differ across all three targets and is what this test pins as the "not
//! secretly the same transcript" control - see `per_version_identity_control`.

use std::path::{Path, PathBuf};

use rulesteward_core::oracle_corpus::{
    CorpusMode, resolve_corpus_root, sentinel_banner, sentinel_count,
};
use rulesteward_sudoers::oracle::{
    VisudoVerdict, classify_visudo, project_ast, project_cvtsudoers_json,
};
use rulesteward_sudoers::parser::parse;
use serde_json::Value;

const SENTINEL: &str = "RS-DIFF-SUDOERS";

/// Named floor, derived from the corpus actually captured 2026-07-25: 22
/// `accept-*` + 8 `reject-*` scenario directories.
const SCENARIO_FLOOR: usize = 30;

/// Named floor for L3's clean (non-xfailed, non-scoped-out) structural
/// comparisons. Measured 2026-07-25: 22 accept scenarios x 3 targets = 66
/// candidate pairs; minus 1 scoped-out (el8 `SELinux` invalid JSON) = 65
/// attempted; minus 5 xfail hits (selinux on el9+el10, whitespace-bug on all
/// 3) = 60 clean structural matches.
const L3_CLEAN_FLOOR: usize = 60;

/// Grounded EMPTY: see the module doc's L1 section. L1 has its OWN xfail
/// table, deliberately separate from [`L2_XFAIL`]: L1 compares our parser's
/// F01 verdict against visudo's DEFAULT gate, while L2 compares visudo's
/// default gate against its STRICT gate - two different comparisons, so an L2
/// divergence is not evidence of an L1 divergence. Reusing `L2_XFAIL` for L1
/// would silently exempt an L1 comparison the moment an L2 entry is added,
/// even though nothing about L1 itself changed.
const L1_XFAIL: &[&str] = &[];

/// Grounded EMPTY: see the module doc's L2 section. Kept as a named const (not
/// a bare `0`) so a future divergence is added here explicitly rather than by
/// loosening an inline literal.
const L2_XFAIL: &[&str] = &[];

/// L3 structural-projection divergences: `(scenario_id, issue_number)`. Both
/// ground #538; do NOT fix #538 in this lane.
const L3_XFAIL: &[(&str, u32)] = &[
    ("accept-selinux-role-type", 538),
    ("accept-user-list-whitespace-bug", 538),
];

/// `(scenario_id, target)` pairs where `cvtsudoers -f json`'s stdout is KNOWN
/// (and CONFIRMED below, not just assumed) to be invalid JSON, so L3 skips the
/// pair entirely rather than comparing against a parse error.
const L3_EL8_INVALID_JSON_SCOPE_OUT: &[(&str, &str)] = &[("accept-selinux-role-type", "el8")];

/// The two-sided oracle positive control (CONTRIBUTING.md rule 2): one input
/// the oracle must ACCEPT, one it must REJECT, on every target.
const POSITIVE_CONTROL_ACCEPT: &str = "accept-basic-all-grant";
const POSITIVE_CONTROL_REJECT: &str = "reject-equals-only";

const TARGETS: [&str; 3] = ["el8", "el9", "el10"];

fn corpus_root() -> (PathBuf, CorpusMode) {
    let default = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/corpus/sudoers-oracle"
    ));
    resolve_corpus_root("RS_ORACLE_CORPUS_SUDOERS", &default)
}

/// Print the two mandatory sentinel lines. Called in every corpus-driven test
/// (not just one), so the banner survives regardless of which test the
/// default parallel runner happens to execute or schedule first -
/// `scripts/rs-oracle-diff.sh` only requires the line to appear somewhere in
/// the combined `--nocapture` output.
///
/// `scenario_count` MUST be the number of comparisons this test actually
/// performed, never the raw corpus directory count: a corpus of entirely
/// unusable or entirely skipped rows would still satisfy the driver's
/// `scenarios=0` anti-vacuity guard if this reported directory count, while
/// comparing nothing. `positive_control_oracle_accepts_and_rejects_distinctly`
/// and `per_version_identity_control` call this FIRST, before anything that
/// could panic, with a fixed count known upfront (they always attempt the
/// same fixed number of checks). The three corpus-loop tests (L1/L2/L3) call
/// this AFTER their comparison loop, with the real accumulated `compared`
/// tally, since how much they compare is data-dependent (L3 legitimately
/// skips reject-verdict and scope-out rows) and cannot be known in advance.
fn announce(root: &Path, mode: CorpusMode, scenario_count: usize) {
    eprintln!("{}", sentinel_banner(SENTINEL, mode, root));
    eprintln!("{}", sentinel_count(SENTINEL, scenario_count));
}

/// Enumerate scenario directories: every subdirectory of the corpus root that
/// does NOT start with `_` and contains an `input.sudoers` file (skips
/// `capture_sudoers.sh` and `PROVENANCE.md`, which are files, not
/// directories, but the filter is defensive regardless). Sorted for
/// deterministic iteration order.
fn scenarios(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(root)
        .unwrap_or_else(|e| panic!("read corpus dir {}: {e}", root.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        if name.starts_with('_') {
            continue;
        }
        if !path.join("input.sudoers").is_file() {
            continue;
        }
        out.push(name);
    }
    out.sort();
    out
}

fn scenario_dir(root: &Path, id: &str) -> PathBuf {
    root.join(id)
}

fn read_input(root: &Path, id: &str) -> String {
    let path = scenario_dir(root, id).join("input.sudoers");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// One target's captured oracle document, read as a bare `serde_json::Value`
/// (no `serde` derive - only `serde_json` is a declared dependency, added in
/// Phase 0 specifically for this lane; adding `serde`'s `derive` feature is
/// out of this test's claim).
struct OracleDoc {
    sudo_rpm: String,
    visudo_rc: i32,
    visudo_stdout: String,
    visudo_stderr: String,
    visudo_strict_rc: i32,
    visudo_strict_stdout: String,
    visudo_strict_stderr: String,
    cvtsudoers_rc: i32,
    cvtsudoers_stdout: String,
}

fn read_target(root: &Path, id: &str, target: &str) -> OracleDoc {
    let path = scenario_dir(root, id).join(format!("{target}.json"));
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v: Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse JSON {}: {e}", path.display()));

    let field_str = |field: &str, key: &str| -> String {
        v[field][key]
            .as_str()
            .unwrap_or_else(|| panic!("{}: missing string {field}.{key}", path.display()))
            .to_string()
    };
    let field_rc = |field: &str| -> i32 {
        let raw = v[field]["rc"]
            .as_i64()
            .unwrap_or_else(|| panic!("{}: missing integer {field}.rc", path.display()));
        i32::try_from(raw)
            .unwrap_or_else(|_| panic!("{}: {field}.rc {raw} does not fit in i32", path.display()))
    };

    OracleDoc {
        sudo_rpm: v["sudo_rpm"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: missing string sudo_rpm", path.display()))
            .to_string(),
        visudo_rc: field_rc("visudo"),
        visudo_stdout: field_str("visudo", "stdout"),
        visudo_stderr: field_str("visudo", "stderr"),
        visudo_strict_rc: field_rc("visudo_strict"),
        visudo_strict_stdout: field_str("visudo_strict", "stdout"),
        visudo_strict_stderr: field_str("visudo_strict", "stderr"),
        cvtsudoers_rc: field_rc("cvtsudoers"),
        cvtsudoers_stdout: field_str("cvtsudoers", "stdout"),
    }
}

/// Order-independent (multiset) equality: this test's own comparison, so
/// `project_ast` / `project_cvtsudoers_json` are free to return their
/// users/hosts/commands in whatever order is natural to them.
fn sorted_eq(a: &[String], b: &[String]) -> bool {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort();
    b.sort();
    a == b
}

// ---------------------------------------------------------------------------
// Direct unit coverage of the fail-closed `classify_visudo` classifier -
// independent of the corpus, pinning the exact contract described in the
// module doc comment.
// ---------------------------------------------------------------------------

#[test]
fn classify_visudo_accepts_on_rc0_with_parsed_ok_evidence() {
    assert_eq!(
        classify_visudo(0, "stdin: parsed OK\n", ""),
        Ok(VisudoVerdict::Accept)
    );
}

#[test]
fn classify_visudo_rejects_on_nonzero_rc_with_error_evidence() {
    assert_eq!(
        classify_visudo(1, "", "stdin:1:1: syntax error\n===\n^\n"),
        Ok(VisudoVerdict::Reject)
    );
}

#[test]
fn classify_visudo_is_fail_closed_when_rc_and_evidence_disagree() {
    // rc says accept, but there is no "parsed OK" evidence: never guess.
    assert!(classify_visudo(0, "", "").is_err());
    // rc says reject, but the evidence claims success: never guess.
    assert!(classify_visudo(1, "stdin: parsed OK\n", "").is_err());
}

#[test]
fn classify_visudo_is_fail_closed_on_an_unknown_rc() {
    assert!(classify_visudo(2, "", "some other error").is_err());
    assert!(classify_visudo(127, "", "").is_err());
}

// ---------------------------------------------------------------------------
// Positive control: the oracle itself must not be broken.
// ---------------------------------------------------------------------------

#[test]
fn positive_control_oracle_accepts_and_rejects_distinctly() {
    let (root, mode) = corpus_root();
    let ids = scenarios(&root);
    // This test always attempts exactly TARGETS.len() checks (one
    // accept-vs-reject distinctness comparison per target), regardless of
    // corpus size, so the true count is known upfront - not `ids.len()`,
    // which is the unrelated corpus-directory count.
    announce(&root, mode, TARGETS.len());
    assert!(
        ids.len() >= SCENARIO_FLOOR,
        "expected >= {SCENARIO_FLOOR} scenarios, found {}",
        ids.len()
    );

    for target in TARGETS {
        let accept_doc = read_target(&root, POSITIVE_CONTROL_ACCEPT, target);
        let reject_doc = read_target(&root, POSITIVE_CONTROL_REJECT, target);
        let accept_verdict = classify_visudo(
            accept_doc.visudo_rc,
            &accept_doc.visudo_stdout,
            &accept_doc.visudo_stderr,
        );
        let reject_verdict = classify_visudo(
            reject_doc.visudo_rc,
            &reject_doc.visudo_stdout,
            &reject_doc.visudo_stderr,
        );
        let broken = match (accept_verdict, reject_verdict) {
            (Ok(a), Ok(r)) => a == r,
            _ => true, // an unclassifiable control input is itself a broken oracle
        };
        if broken {
            eprintln!(
                "{SENTINEL}: ORACLE-BROKEN target={target} accept({POSITIVE_CONTROL_ACCEPT})={accept_verdict:?} \
                 reject({POSITIVE_CONTROL_REJECT})={reject_verdict:?} came back the same (or unclassifiable)"
            );
        }
        assert!(
            !broken,
            "positive control failed on target {target}: the oracle itself is broken"
        );
    }
}

/// The per-version identity control (module doc "Per-version positive
/// control"): `sudo_rpm`, captured directly via `rpm -q sudo` and never
/// derived from visudo/cvtsudoers output, must differ across all three
/// targets. This is what a capture bug that silently reused one container for
/// two target labels would break, even though el9 and el10 are otherwise
/// observably identical for sudoers parsing.
#[test]
fn per_version_identity_control() {
    let (root, mode) = corpus_root();
    // Three fixed pairwise sudo_rpm identity checks (el8-el9, el9-el10,
    // el8-el10), always attempted regardless of corpus size - the true count
    // is known upfront, so this test never needs `scenarios(&root)` at all.
    let identity_pairs = TARGETS.len() * (TARGETS.len() - 1) / 2;
    announce(&root, mode, identity_pairs);

    let el8 = read_target(&root, POSITIVE_CONTROL_ACCEPT, "el8").sudo_rpm;
    let el9 = read_target(&root, POSITIVE_CONTROL_ACCEPT, "el9").sudo_rpm;
    let el10 = read_target(&root, POSITIVE_CONTROL_ACCEPT, "el10").sudo_rpm;

    if el8 == el9 || el9 == el10 || el8 == el10 {
        eprintln!(
            "{SENTINEL}: ORACLE-BROKEN per-version identity control: sudo_rpm not distinct \
             across targets (el8={el8:?} el9={el9:?} el10={el10:?}); the three captures may be \
             the same transcript"
        );
    }
    assert_ne!(el8, el9, "el8 and el9 sudo_rpm must differ");
    assert_ne!(el9, el10, "el9 and el10 sudo_rpm must differ");
    assert_ne!(el8, el10, "el8 and el10 sudo_rpm must differ");
}

// ---------------------------------------------------------------------------
// L1: sudo-F01 (our parser's Malformed classification) vs the oracle's
// visudo -c accept/reject verdict, per target.
// ---------------------------------------------------------------------------

#[test]
fn l1_f01_matches_visudo_verdict_per_target() {
    let (root, mode) = corpus_root();
    let ids = scenarios(&root);
    assert!(
        ids.len() >= SCENARIO_FLOOR,
        "expected >= {SCENARIO_FLOOR} scenarios, found {}",
        ids.len()
    );

    let mut compared = 0usize;
    let mut xfail_hit: Vec<String> = Vec::new();

    for id in &ids {
        let src = read_input(&root, id);
        let file = parse(&src, Path::new("/etc/sudoers"));
        let ours_rejects = file
            .lines
            .iter()
            .any(|l| matches!(l.kind, rulesteward_sudoers::ast::LineKind::Malformed(_)));

        for target in TARGETS {
            let doc = read_target(&root, id, target);
            let oracle_verdict =
                classify_visudo(doc.visudo_rc, &doc.visudo_stdout, &doc.visudo_stderr)
                    .unwrap_or_else(|e| panic!("L1 {id} ({target}): oracle unclassifiable: {e:?}"));
            let oracle_rejects = oracle_verdict == VisudoVerdict::Reject;

            if L1_XFAIL.contains(&id.as_str()) {
                // L1_XFAIL is its OWN table (currently empty), kept separate
                // from L2_XFAIL so that an L2 divergence (visudo default vs
                // strict gate) can never silently exempt an L1 comparison
                // (our parser vs visudo's default gate) it was never measured
                // against. This branch is unreachable today only because the
                // table is empty; it mirrors the selinux-corpus guard shape.
                xfail_hit.push(id.clone());
                continue;
            }
            assert_eq!(
                ours_rejects, oracle_rejects,
                "L1 {id} ({target}): our F01 verdict (rejects={ours_rejects}) disagrees with \
                 the oracle (rejects={oracle_rejects}); visudo stdout={:?} stderr={:?}",
                doc.visudo_stdout, doc.visudo_stderr
            );
            compared += 1;
        }
    }

    // Print AFTER the loop, using the real tally: L1's xfail table may not
    // stay empty forever, and reporting the raw scenario-directory count
    // would overstate what was actually compared the moment it grows.
    announce(&root, mode, compared);
    assert!(
        compared >= SCENARIO_FLOOR * TARGETS.len(),
        "expected >= {} L1 comparisons, got {compared}",
        SCENARIO_FLOOR * TARGETS.len()
    );
    assert_eq!(
        xfail_hit.len(),
        L1_XFAIL.len(),
        "every L1_XFAIL scenario must have been enumerated and hit"
    );
}

// ---------------------------------------------------------------------------
// L2: does `visudo -c -s -f -` agree with `visudo -c -f -`?
// ---------------------------------------------------------------------------

#[test]
fn l2_strict_gate_matches_default_gate() {
    let (root, mode) = corpus_root();
    let ids = scenarios(&root);

    let mut compared = 0usize;
    let mut xfail_hit: Vec<String> = Vec::new();

    for id in &ids {
        for target in TARGETS {
            let doc = read_target(&root, id, target);
            let default_verdict =
                classify_visudo(doc.visudo_rc, &doc.visudo_stdout, &doc.visudo_stderr)
                    .unwrap_or_else(|e| {
                        panic!("L2 {id} ({target}): default gate unclassifiable: {e:?}")
                    });
            let strict_verdict = classify_visudo(
                doc.visudo_strict_rc,
                &doc.visudo_strict_stdout,
                &doc.visudo_strict_stderr,
            )
            .unwrap_or_else(|e| panic!("L2 {id} ({target}): strict gate unclassifiable: {e:?}"));

            if L2_XFAIL.contains(&id.as_str()) {
                assert_ne!(
                    default_verdict, strict_verdict,
                    "L2 {id} ({target}): expected a KNOWN strict-vs-default divergence, but \
                     both gates agreed; update L2_XFAIL"
                );
                xfail_hit.push(id.clone());
                continue;
            }
            assert_eq!(
                default_verdict, strict_verdict,
                "L2 {id} ({target}): -s diverges from -c with no documented xfail entry"
            );
            compared += 1;
        }
    }

    // Print AFTER the loop, using the real tally, for the same reason as L1:
    // the raw scenario-directory count is not the same claim as "this many
    // comparisons actually happened".
    announce(&root, mode, compared);
    assert!(
        compared >= SCENARIO_FLOOR * TARGETS.len(),
        "expected >= {} L2 comparisons, got {compared}",
        SCENARIO_FLOOR * TARGETS.len()
    );
    assert_eq!(
        xfail_hit.len(),
        L2_XFAIL.len(),
        "every L2_XFAIL scenario must have been enumerated and hit"
    );
}

// ---------------------------------------------------------------------------
// L3: structure-only projection, AST vs cvtsudoers, on oracle-accepted
// scenarios only.
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn l3_structure_projection_matches_cvtsudoers() {
    let (root, mode) = corpus_root();
    let ids = scenarios(&root);

    let mut compared = 0usize;
    let mut xfail_hit: Vec<String> = Vec::new();
    let mut scope_out_confirmed = 0usize;

    for id in &ids {
        let src = read_input(&root, id);
        let file = parse(&src, Path::new("/etc/sudoers"));

        for target in TARGETS {
            let doc = read_target(&root, id, target);
            let oracle_verdict =
                classify_visudo(doc.visudo_rc, &doc.visudo_stdout, &doc.visudo_stderr)
                    .unwrap_or_else(|e| panic!("L3 {id} ({target}): oracle unclassifiable: {e:?}"));
            if oracle_verdict != VisudoVerdict::Accept {
                // Reject scenarios have no valid AST to project; L1/L2 already
                // cover them. Not a scope-out, just out of L3's domain.
                continue;
            }

            // Fail-closed: a nonzero cvtsudoers exit means its stdout cannot be
            // trusted for the structural comparison, regardless of whether
            // that stdout happens to parse as syntactically valid JSON.
            // Measured across the whole committed corpus (2026-07-25): every
            // oracle-ACCEPT row, including the el8 SELinux_Spec scope-out
            // below, has cvtsudoers_rc == 0 - that scope-out is a
            // serialization defect (valid run, malformed JSON text), not an
            // invocation failure, so gating on rc here cannot collide with it.
            assert_eq!(
                doc.cvtsudoers_rc, 0,
                "L3 {id} ({target}): cvtsudoers exited {} (nonzero) on an oracle-ACCEPT \
                 scenario; its stdout cannot be trusted for the structural comparison: \
                 stdout={:?}",
                doc.cvtsudoers_rc, doc.cvtsudoers_stdout
            );

            let cvt_parsed: Result<Value, _> = serde_json::from_str(&doc.cvtsudoers_stdout);
            if L3_EL8_INVALID_JSON_SCOPE_OUT.contains(&(id.as_str(), target)) {
                assert!(
                    cvt_parsed.is_err(),
                    "L3 {id} ({target}): expected the KNOWN el8 invalid-JSON SELinux_Spec \
                     quirk, but cvtsudoers stdout parsed as valid JSON; update the scope-out"
                );
                scope_out_confirmed += 1;
                continue;
            }
            let cvt_json = cvt_parsed.unwrap_or_else(|e| {
                panic!(
                    "L3 {id} ({target}): cvtsudoers stdout is not valid JSON and this pair is \
                     not in L3_EL8_INVALID_JSON_SCOPE_OUT: {e}; stdout={:?}",
                    doc.cvtsudoers_stdout
                )
            });

            let ast_proj = project_ast(&file);
            let cvt_proj = project_cvtsudoers_json(&cvt_json).unwrap_or_else(|e| {
                panic!("L3 {id} ({target}): project_cvtsudoers_json failed: {e:?}")
            });

            let matches = ast_proj.tuple_count == cvt_proj.tuple_count
                && sorted_eq(&ast_proj.users, &cvt_proj.users)
                && sorted_eq(&ast_proj.hosts, &cvt_proj.hosts)
                && sorted_eq(&ast_proj.commands, &cvt_proj.commands);

            if let Some((_, issue)) = L3_XFAIL.iter().find(|(sid, _)| *sid == id.as_str()) {
                assert!(
                    !matches,
                    "L3 {id} ({target}): expected the KNOWN #{issue} divergence, but the \
                     projections matched; update L3_XFAIL"
                );
                // Pin the SPECIFIC shape of each known divergence, not merely
                // "some inequality", so a trivial always-different projection
                // could not pass this adversarially.
                match id.as_str() {
                    "accept-selinux-role-type" => {
                        assert!(
                            cvt_proj.commands.iter().any(|c| c == "/usr/bin/vim"),
                            "L3 {id} ({target}): the oracle must show the real command \
                             /usr/bin/vim; got {:?}",
                            cvt_proj.commands
                        );
                        assert!(
                            !ast_proj.commands.iter().any(|c| c == "/usr/bin/vim"),
                            "L3 {id} ({target}): our AST must NOT show the clean command \
                             (the ROLE=/TYPE= tag-loop gap swallows it); got {:?}",
                            ast_proj.commands
                        );
                        assert!(
                            ast_proj
                                .commands
                                .iter()
                                .any(|c| c.contains("ROLE=") && c.contains("TYPE=")),
                            "L3 {id} ({target}): our AST's garbage command token must contain \
                             the swallowed ROLE=/TYPE= text; got {:?}",
                            ast_proj.commands
                        );
                    }
                    "accept-user-list-whitespace-bug" => {
                        assert!(
                            cvt_proj.users.iter().any(|u| u == "ALL")
                                && cvt_proj.users.iter().any(|u| u == "bob"),
                            "L3 {id} ({target}): the oracle must show both bob and ALL as \
                             users; got {:?}",
                            cvt_proj.users
                        );
                        assert!(
                            !ast_proj.users.iter().any(|u| u == "ALL"),
                            "L3 {id} ({target}): our AST must have DROPPED the second user \
                             ALL; got {:?}",
                            ast_proj.users
                        );
                        assert_eq!(
                            cvt_proj.hosts,
                            vec!["ALL".to_string()],
                            "L3 {id} ({target}): the oracle's host list must be exactly [ALL]"
                        );
                        assert!(
                            ast_proj.hosts.iter().any(|h| h.contains(' ')),
                            "L3 {id} ({target}): our AST must have merged two host tokens into \
                             one garbage whitespace-containing token; got {:?}",
                            ast_proj.hosts
                        );
                    }
                    other => panic!("unhandled L3_XFAIL scenario id {other:?}"),
                }
                xfail_hit.push(id.clone());
                continue;
            }

            assert!(
                matches,
                "L3 {id} ({target}): structure-only projection mismatch (no xfail entry)\n  \
                 ast:  tuple_count={} users={:?} hosts={:?} commands={:?}\n  \
                 cvt:  tuple_count={} users={:?} hosts={:?} commands={:?}",
                ast_proj.tuple_count,
                ast_proj.users,
                ast_proj.hosts,
                ast_proj.commands,
                cvt_proj.tuple_count,
                cvt_proj.users,
                cvt_proj.hosts,
                cvt_proj.commands,
            );
            compared += 1;
        }
    }

    // Print AFTER the loop, using the real tally. This is the layer the
    // vacuous-pass risk concretely applies to: reject scenarios, the el8
    // scope-out, and xfail hits are all LEGITIMATE skips that reduce
    // `compared` well below the raw scenario-directory count, so reporting
    // `ids.len()` here would overstate what L3 actually compared.
    announce(&root, mode, compared);

    assert!(
        compared >= L3_CLEAN_FLOOR,
        "expected >= {L3_CLEAN_FLOOR} clean L3 comparisons, got {compared}"
    );
    assert_eq!(
        scope_out_confirmed,
        L3_EL8_INVALID_JSON_SCOPE_OUT.len(),
        "every L3_EL8_INVALID_JSON_SCOPE_OUT pair must have been enumerated and confirmed"
    );
    assert_eq!(
        xfail_hit.len(),
        L3_XFAIL.len() * TARGETS.len() - L3_EL8_INVALID_JSON_SCOPE_OUT.len(),
        "every L3_XFAIL scenario must have been enumerated and xfailed on every non-scoped-out \
         target (2 scenarios x 3 targets, minus the 1 el8 scope-out pair = 5)"
    );
}
