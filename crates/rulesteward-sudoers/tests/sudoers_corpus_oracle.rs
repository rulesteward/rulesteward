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
//!   `stdout` contains `"parsed OK"`; `Ok(Reject)` iff `rc == 1` AND `stdout`
//!   does NOT contain `"parsed OK"`; anything else (rc and evidence disagree,
//!   e.g. a captured rc of 2+, per `visudo(8)`'s own 0-on-success/1-on-error
//!   exit-code contract, or rc==0 with no "parsed OK" text) is
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
//!   `"ALL"`. Every subject/host/COMMAND token's leading `!` negation is
//!   stripped first (widened 2026-07-27: the original contract stripped `!`
//!   from subjects/hosts only, so a negated command like `!/usr/bin/su` kept
//!   its `!` on the AST side while `cvtsudoers` reports `{"command":
//!   "/usr/bin/su", "negated": true}` - an unxfailed divergence that panics
//!   the instant a corpus row exercises it; `accept-negated-command` /
//!   `accept-negated-all` are two such rows). After the `!` strip, a
//!   subject/host token ALSO gets the type tag described in "Type tags"
//!   below; a command token does not (commands are not implicated in the
//!   type-tag finding - see that section).
//! - `project_cvtsudoers_json(json: &serde_json::Value) ->
//!   Result<StructureProjection, CvtsudoersProjectionError>`: fail-closed on any
//!   `User_Specs[]` element whose `User_List`/`Host_List`/`Cmnd_Specs->Commands`
//!   entries do not match a KNOWN key shape. Measured key shapes (`cvtsudoers -f
//!   json`, sudo 1.9.17p2, 2026-07-25 - `cvtsudoers -f json` does NOT expand
//!   aliases, matching this crate's own un-expanded AST):
//!     - `User_List[]`: `{"username": S}` / `{"useralias": S}` (an unexpanded
//!       `User_Alias`/`Cmnd_Alias` reference keeps the alias NAME here) /
//!       `{"usergroup": S}` (bare, no `%`) / `{"usergid": N}` (a JSON NUMBER;
//!       widened 2026-07-27, `%#gid` subjects - `accept-gid-subject`) /
//!       `{"netgroup": S}` (bare, no `+`) / `{"userid": N}` (a JSON NUMBER,
//!       no `#` - canonical decimal, see "uid/gid canonicalization" below).
//!     - `Host_List[]`: `{"hostname": S}` / `{"hostalias": S}` /
//!       `{"netgroup": S}` (widened 2026-07-27, `+netgroup` HOSTS -
//!       `accept-host-netgroup`) / `{"networkaddr": S}` (widened 2026-07-27,
//!       an IP/CIDR host - `accept-host-networkaddr`). `print_member_json_int`
//!       (the real `cvtsudoers` source) keys `typestr` on member TYPE, not on
//!       which list it appears in, so `netgroup` legitimately appears in BOTH
//!       `User_List` and `Host_List`.
//!     - `Cmnd_Specs[].Commands[]`: `{"command": S}` / `{"cmndalias": S}`.
//!
//!   Extract the bare string value regardless of which key is present, then
//!   apply the SAME type tag described below (ignore any companion
//!   `"negated": true`, which mirrors this test's own `!`-strip normalization
//!   on the AST side - see `project_ast` above).
//!
//! ## Type tags (added 2026-07-27)
//!
//! Both projectors previously reduced every subject/host to its bare value
//! ONLY, discarding which of `cvtsudoers`' distinct member-type keys (or, on
//! the AST side, which sigil) produced it. That erasure is SYMMETRIC -
//! present on both sides, thrown away by both projectors - so it cancels
//! exactly: a `project_ast` that dropped a sigil ENTIRELY (e.g. read `%wheel`
//! as if it were the plain user `wheel`) would still MATCH `cvtsudoers`'
//! `{"usergroup": "wheel"}` once both sides reduce to the bare string
//! `"wheel"`. Measured against the real corpus: this made
//! `accept-group-subject` (`%wheel`), `accept-uid-subject` (`#1000`), and
//! `accept-netgroup-subject` (`+admins`) prove nothing about sigil handling -
//! a `project_ast` that dropped any of the three sigils entirely would still
//! have passed L3.
//!
//! Fix: a subject/host value derived from a sigil carries a `"<type>:"`
//! prefix; a bare (no-sigil) value does not:
//!   - `%group` (users only) -> `"usergroup:<group>"`.
//!   - `%#gid` (users only) -> `"usergid:<gid>"` - BOTH sigils stripped, not
//!     just the first (see "uid/gid canonicalization" below; the original
//!     one-sigil `strip_sigil` left a stray `#` in place).
//!   - `+netgroup` (users AND hosts) -> `"netgroup:<name>"`.
//!   - `#uid` (users only) -> `"userid:<uid>"`.
//!   - a bare token (a plain username/hostname, the `ALL` keyword, an
//!     unexpanded `User_Alias`/`Host_Alias` reference, or a `networkaddr`
//!     host) -> UNTAGGED, the bare value itself.
//!
//! Deliberately narrower than a full fix: distinguishing a plain name from an
//! alias reference requires cross-referencing the file's OWN alias
//! definitions (`ast.rs`: "an alias reference is an uppercase token equal to
//! a defined alias name"), which neither projector does today and which this
//! session does not add - `accept-user-alias-basic` (`ADMINS`, a `User_Alias`
//! reference) therefore remains exercised only by the SAME erasure risk this
//! fix does not close for aliases, and is NOT required to gain a tag. On the
//! `cvtsudoers` side this means `username` AND `useralias` collapse to the
//! SAME untagged form (never `"username:"` / `"useralias:"`), matching the
//! AST side's inability to tell them apart. `networkaddr` similarly stays
//! untagged: it has no leading sigil, so distinguishing it from a plain
//! hostname needs shape analysis (does the token look like an IP/CIDR?) that
//! this session does not add either.
//!
//! The minimum-viable proof this closes: a `project_ast` that reads `%wheel`
//! as `"wheel"` (dropping the sigil) now MISMATCHES a correct `project_ast`
//! reading it as `"usergroup:wheel"` - `assert_ne!` on the two, unit-tested
//! below.
//!
//! Tags/runas are a related, NARROWER erasure this session does NOT close:
//! `CmndSpec::runas` / `CmndSpec::tags` are read by NEITHER projector, nor are
//! their oracle counterparts (`runasusers`/`runasgroups`, `Options`), so
//! `alice ALL = NOPASSWD: /bin/ls` projects identically to `alice ALL =
//! /bin/ls`, and `carol ALL = (OPS) /bin/ls` identically to `carol ALL =
//! /bin/ls`. Three corpus scenarios exist to exercise tags/runas
//! (`accept-nopasswd-specific`, `accept-runas-alias`, `accept-runas-noexec`)
//! and none is a real regression test for that axis. Noted, not fixed: unlike
//! the users/hosts type tag above, closing this needs a THIRD
//! `StructureProjection` axis (not a same-shape widening of `users`/`hosts`),
//! which is a bigger surface than this dispatch's scope; left for a follow-up.
//!
//! ## uid/gid canonicalization (added 2026-07-27)
//!
//! `sudo_strtoid` parses a `#uid`/`%#gid` subject in BASE 10, so `#0100` means
//! uid 100, and `cvtsudoers` reports the canonical decimal as a JSON NUMBER
//! (`{"userid": 100}`, no leading zero - `accept-uid-leading-zero`). A textual
//! sigil-strip alone (the original contract) produces `"0100"` - matching
//! neither the canonical value nor, once type tags exist, the right type.
//! Both projectors must CANONICALIZE (parse as an integer, re-render in
//! decimal) rather than only strip the sigil text.
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
//!    -f -`? It does NOT always: `man 8 visudo` documents `-s`'s real value -
//!    "If an alias is referenced but not actually defined or if there is a
//!    cycle in an alias, visudo will consider this a syntax error" - which is
//!    alias-graph checking, not file mode/ownership (that is `-O`/`-P`). The
//!    original ~25-probe sweep (2026-07-25: duplicate aliases, unused aliases,
//!    unknown `Defaults` names, malformed hostnames, relative paths, missing
//!    `@include` targets, cross-namespace alias-name collisions) never tried
//!    either construct `-s` actually checks, so its "no divergence" finding
//!    was an artifact of which inputs were tried, not a property of `-s`.
//!    Confirmed live (2026-07-26, all three images): an undefined alias
//!    reference (`accept-undefined-alias-ref`: `alice ALL = NOSUCHALIAS`) and
//!    an alias cycle (`accept-alias-cycle`: `User_Alias A = B` / `User_Alias
//!    B = A` / `A ALL = ALL`) both parse clean under the default gate (rc 0,
//!    stdout `parsed OK`, a diagnostic naming the alias on stderr - el8
//!    prefixes it `Warning:`, el9/el10 print the bare `stdin:L:C:` message
//!    with no prefix) but are REJECTED under `-s` (rc 1, stdout EMPTY, the
//!    same diagnostic - el8 prefixed `Error:` - naming the same alias). Both
//!    scenarios are in `L2_XFAIL`; see `PROVENANCE.md` section 5 for the
//!    full rc/stdout/stderr shape per target.
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
    UnclassifiedVisudo, VisudoVerdict, classify_visudo, project_ast, project_cvtsudoers_json,
};
use rulesteward_sudoers::parser::parse;
use serde_json::Value;

const SENTINEL: &str = "RS-DIFF-SUDOERS";

/// Named floor, derived from the corpus actually captured: 22 `accept-*` + 8
/// `reject-*` scenario directories captured 2026-07-25; 2 more `accept-*`
/// scenarios (`accept-undefined-alias-ref`, `accept-alias-cycle`) added
/// 2026-07-26 to give L2 a real (non-vacuous) divergence - see the module
/// doc's L2 section; 6 more `accept-*` scenarios
/// (`accept-negated-command`, `accept-negated-all`, `accept-host-netgroup`,
/// `accept-host-networkaddr`, `accept-gid-subject`,
/// `accept-uid-leading-zero`) added 2026-07-27 to ground the "Type tags" /
/// "uid/gid canonicalization" findings in the module doc - see there.
const SCENARIO_FLOOR: usize = 38;

/// Named floor for L3's clean (non-xfailed, non-scoped-out) structural
/// comparisons, once `project_ast` / `project_cvtsudoers_json` correctly
/// implement the frozen contract above (type tags, `!`-stripped commands,
/// uid/gid canonicalization, and the widened `Host_List`/`User_List` key
/// sets) - NOT reachable by the implementation this floor was written
/// against, which is the point: this session's finding is that six
/// additional real scenarios were silently uncovered by L3 (either passing
/// vacuously via the type-tag erasure, or never reaching L3 at all due to an
/// unrecognized key / an unstripped command negation), and the floor states
/// what a correct implementation must reach, not what today's does.
///
/// Measured: 30 accept scenarios x 3 targets = 90 candidate pairs; minus 1
/// scoped-out (el8 `SELinux` invalid JSON) = 89 attempted; minus 11 xfail
/// hits (4 scenarios x 3 targets, minus the 1 el8 scope-out/xfail overlap -
/// see `L3_XFAIL`, unchanged by this session's 6 new scenarios, none of
/// which are xfailed) = 78 clean structural matches. (72 -> 90 candidates is
/// exactly the 6 new scenarios x 3 targets = 18 added, all landing in the
/// "clean" bucket once fixed, hence 60 -> 78 with no other arithmetic
/// changing.)
const L3_CLEAN_FLOOR: usize = 78;

/// Known `tuple_count` anchors: `(scenario_id, expected cvtsudoers
/// User_Specs\[\] length)`, confirmed directly against the committed corpus
/// (2026-07-26, `python3 -c 'import json; ...'` counting `User_Specs` per
/// scenario's `el9.json`). Without an absolute pin, `tuple_count == 0` on
/// BOTH sides for every scenario (an always-empty `project_ast` paired with
/// an always-empty `project_cvtsudoers_json`) would satisfy the `==`
/// comparison everywhere, silently disabling the one axis the module doc's
/// `alice h1 = /bin/ls : h2 = /bin/id` finding is grounded on. Mixes a
/// multi-host-group line, two single-host-group lines sharing an alias, a
/// single plain line, and a Defaults-only file with no `User_Specs` at all,
/// so an implementation cannot pass by hardcoding one particular count.
///
/// `accept-multi-user-list` (`alice,bob ALL = /bin/ls`: 2 users, 1 tuple) is
/// deliberately included because, without it, `tuple_count == users.len()`
/// on every OTHER anchor here (2/2, 2/2, 1/1, 0/0) - a symmetric
/// `tuple_count = users.len()` implementation would satisfy all four
/// without ever counting host-groups at all. This anchor breaks that
/// coincidence for free.
const TUPLE_COUNT_ANCHORS: &[(&str, usize)] = &[
    ("accept-multi-hostgroup", 2),
    ("accept-user-alias-multi-spec", 2),
    ("accept-basic-all-grant", 1),
    ("accept-defaults-global", 0),
    ("accept-multi-user-list", 1),
];

/// Grounded EMPTY: see the module doc's L1 section. L1 has its OWN xfail
/// table, deliberately separate from [`L2_XFAIL`]: L1 compares our parser's
/// F01 verdict against visudo's DEFAULT gate, while L2 compares visudo's
/// default gate against its STRICT gate - two different comparisons, so an L2
/// divergence is not evidence of an L1 divergence. Reusing `L2_XFAIL` for L1
/// would silently exempt an L1 comparison the moment an L2 entry is added,
/// even though nothing about L1 itself changed.
const L1_XFAIL: &[&str] = &[];

/// Known `-s`-vs-default divergences: see the module doc's L2 section and
/// `PROVENANCE.md` section 5. Grounded in `man 8 visudo`'s own description of
/// `-s` (alias-graph checking: undefined references and cycles), not
/// assumed - both scenarios were probed live against all three images before
/// being added here.
const L2_XFAIL: &[&str] = &["accept-undefined-alias-ref", "accept-alias-cycle"];

/// L3 structural-projection divergences: `(scenario_id, issue_number)`. All
/// four ground #538; do NOT fix #538 in this lane.
///
/// `accept-notbefore` and `accept-timeout-option` were found in review
/// (2026-07-26): `parser::parse_cmnd_spec`'s tag loop recognizes only `TAG:`
/// syntax, so an `=`-form option (`NOTBEFORE=`, `TIMEOUT=`, and - the
/// already-documented case - `ROLE=`/`TYPE=`) is not recognized as a tag at
/// all and gets glued onto the following text as ONE garbage command token
/// (`"NOTBEFORE=20260101000000Z /usr/bin/ls"`, `"TIMEOUT=30 /usr/bin/ls"`),
/// while `cvtsudoers` correctly splits the option into its own `Options`
/// entry and reports the bare command (`/usr/bin/ls`). This is the SAME
/// defect class as `accept-selinux-role-type`, not a new one - both were
/// previously in the corpus with their VISUDO VERDICT confirmed identical
/// across targets (PROVENANCE.md section 2), but their STRUCTURAL
/// projection was never checked before L3's `tuple_count` anchors existed.
const L3_XFAIL: &[(&str, u32)] = &[
    ("accept-selinux-role-type", 538),
    ("accept-user-list-whitespace-bug", 538),
    ("accept-notbefore", 538),
    ("accept-timeout-option", 538),
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
    // Both cases below have an IN-CONTRACT rc (0 or 1); it is the STDOUT
    // evidence that disagrees with it. `.is_err()` alone cannot tell this
    // reason apart from "rc outside the visudo(8) 0/1 exit-code contract" -
    // a mutant that flips the `rc == 0 || rc == 1` / `==`-to-`!=` condition
    // deciding between the two `reason` strings still returns `Err` either
    // way, so it survives unless the exact reason is pinned. `reason` is the
    // operator-facing explanation of WHY classification failed: a wrong
    // reason here points the next session at the wrong subsystem (the
    // capture/tool-version vs. the parse itself).
    //
    // rc says accept, but there is no "parsed OK" evidence: never guess.
    assert_eq!(
        classify_visudo(0, "", "").expect_err("rc 0 with no parsed-OK evidence must be Err"),
        UnclassifiedVisudo {
            rc: 0,
            reason: "rc and parsed-OK evidence disagree",
        }
    );
    // rc says reject, but the evidence claims success: never guess.
    assert_eq!(
        classify_visudo(1, "stdin: parsed OK\n", "")
            .expect_err("rc 1 with parsed-OK evidence must be Err"),
        UnclassifiedVisudo {
            rc: 1,
            reason: "rc and parsed-OK evidence disagree",
        }
    );
}

#[test]
fn classify_visudo_is_fail_closed_on_an_unknown_rc() {
    // Both cases below have an rc OUTSIDE {0, 1}, so the reason must be the
    // contract-violation string, not the evidence-disagreement one - see the
    // sibling test's comment for why `.is_err()` alone cannot distinguish them.
    assert_eq!(
        classify_visudo(2, "", "some other error").expect_err("rc 2 must be Err"),
        UnclassifiedVisudo {
            rc: 2,
            reason: "rc outside the visudo(8) 0/1 exit-code contract",
        }
    );
    assert_eq!(
        classify_visudo(127, "", "").expect_err("rc 127 must be Err"),
        UnclassifiedVisudo {
            rc: 127,
            reason: "rc outside the visudo(8) 0/1 exit-code contract",
        }
    );
}

// ---------------------------------------------------------------------------
// Direct unit coverage of `project_ast` / `project_cvtsudoers_json` -
// independent of the corpus (though six new 2026-07-27 corpus scenarios
// reinforce several of these; see module doc). Neither the fail-closed `Err`
// arm of `project_cvtsudoers_json`, the `!`-negation clause on any token
// kind, the users/hosts type tag, nor uid/gid canonicalization was ever
// exercised by unit test before 2026-07-27, so an implementation that never
// constructs `CvtsudoersProjectionError`, that strips only `%+#` and never
// `!`, that never tags a sigil'd subject/host, or that textually strips a
// uid/gid sigil instead of canonicalizing it, would still have passed the
// whole corpus-driven suite as it stood then.
// ---------------------------------------------------------------------------

#[test]
fn project_ast_strips_negation_and_sigil_from_users_and_hosts() {
    use rulesteward_sudoers::ast::{
        CmndItem, CmndSpec, HostGroup, LineKind, LogicalLine, UserSpec,
    };

    let file = rulesteward_sudoers::ast::SudoersFile {
        path: PathBuf::from("/etc/sudoers"),
        source: "!alice,!%wheel !web1 = ALL\n".to_string(),
        lines: vec![LogicalLine {
            line: 1,
            span: 0..26,
            kind: LineKind::UserSpec(UserSpec {
                users: vec!["!alice".to_string(), "!%wheel".to_string()],
                host_groups: vec![HostGroup {
                    hosts: vec!["!web1".to_string()],
                    cmnd_specs: vec![CmndSpec {
                        runas: None,
                        tags: vec![],
                        cmnd: CmndItem::All,
                    }],
                }],
            }),
        }],
    };

    let proj = project_ast(&file);
    // "!alice" has no sigil after the `!` strip, so it stays untagged;
    // "!%wheel" has the `%` sigil, so it now carries the `usergroup:` type
    // tag (updated 2026-07-27 - see the module doc's "Type tags" section;
    // this is a STRENGTHENING of this same test, not a new one, since the
    // old bare "wheel" expectation is no longer the correct contract).
    assert!(
        sorted_eq(
            &proj.users,
            &["alice".to_string(), "usergroup:wheel".to_string()]
        ),
        "a leading `!` negation must be stripped from USERS (in addition to \
         the `%` sigil, which now yields a `usergroup:` type tag rather than \
         a bare value), got {:?}",
        proj.users
    );
    // A projector with two independent strip helpers (one for users, one for
    // hosts) could strip `!` on the user side and forget it on the host
    // side; the users assertion above cannot see that. "!web1" has no
    // recognized host sigil, so it stays untagged.
    assert!(
        sorted_eq(&proj.hosts, &["web1".to_string()]),
        "a leading `!` negation must ALSO be stripped from HOSTS, got {:?}",
        proj.hosts
    );
}

#[test]
fn project_ast_strips_negation_from_commands() {
    // MISS (review, 2026-07-27): `!`-negation was stripped from subjects and
    // hosts but NOT from commands, even though real sudoers allows negating a
    // command (`alice ALL = !/usr/bin/su`) and `cvtsudoers` reports it as
    // `{"command": "/usr/bin/su", "negated": true}` - confirmed live against
    // all three images. `accept-negated-command` / `accept-negated-all` are
    // now committed corpus rows for this; both unit-pinned here too since the
    // corpus alone (a single, possibly-panic-aborted L3 run) cannot cleanly
    // attribute a failure to this ONE cause among several new ones.
    use rulesteward_sudoers::ast::{
        CmndItem, CmndSpec, HostGroup, LineKind, LogicalLine, UserSpec,
    };

    let file_for = |cmnd: CmndItem| rulesteward_sudoers::ast::SudoersFile {
        path: PathBuf::from("/etc/sudoers"),
        source: "alice ALL = X\n".to_string(),
        lines: vec![LogicalLine {
            line: 1,
            span: 0..13,
            kind: LineKind::UserSpec(UserSpec {
                users: vec!["alice".to_string()],
                host_groups: vec![HostGroup {
                    hosts: vec!["ALL".to_string()],
                    cmnd_specs: vec![CmndSpec {
                        runas: None,
                        tags: vec![],
                        cmnd,
                    }],
                }],
            }),
        }],
    };

    let negated_path = project_ast(&file_for(CmndItem::Cmnd("!/usr/bin/su".to_string())));
    assert_eq!(
        negated_path.commands,
        vec!["/usr/bin/su".to_string()],
        "a leading `!` on a COMMAND token must be stripped like it already is \
         for subjects/hosts, got {:?}",
        negated_path.commands
    );

    // `parser.rs:936` compares the raw token literally against `ALL`, so
    // `!ALL` parses as `CmndItem::Cmnd("!ALL")`, never `CmndItem::All` -
    // confirmed directly against `parser::parse`. The `!` strip must still
    // recover the bare `"ALL"` from that raw `Cmnd` token.
    let negated_all = project_ast(&file_for(CmndItem::Cmnd("!ALL".to_string())));
    assert_eq!(
        negated_all.commands,
        vec!["ALL".to_string()],
        "a leading `!` on the literal `Cmnd(\"!ALL\")` token must be \
         stripped to recover the bare ALL, got {:?}",
        negated_all.commands
    );
}

#[test]
fn project_ast_tags_typed_user_subjects_but_not_plain_names() {
    // The minimum-viable proof from the module doc's "Type tags" section: a
    // sigil'd subject must project to something a plain name does NOT, or a
    // `project_ast` that drops the sigil entirely passes L3 vacuously against
    // `cvtsudoers`' own type-carrying JSON key. See `accept-group-subject`
    // (`%wheel`), `accept-netgroup-subject` (`+admins`),
    // `accept-uid-subject` (`#1000`) - all REAL, already-committed corpus
    // rows this finding applies to.
    use rulesteward_sudoers::ast::{
        CmndItem, CmndSpec, HostGroup, LineKind, LogicalLine, UserSpec,
    };

    let file_for = |user: &str| rulesteward_sudoers::ast::SudoersFile {
        path: PathBuf::from("/etc/sudoers"),
        source: format!("{user} ALL = ALL\n"),
        lines: vec![LogicalLine {
            line: 1,
            span: 0..(user.len() + 11),
            kind: LineKind::UserSpec(UserSpec {
                users: vec![user.to_string()],
                host_groups: vec![HostGroup {
                    hosts: vec!["ALL".to_string()],
                    cmnd_specs: vec![CmndSpec {
                        runas: None,
                        tags: vec![],
                        cmnd: CmndItem::All,
                    }],
                }],
            }),
        }],
    };

    let group = project_ast(&file_for("%wheel"));
    assert_eq!(group.users, vec!["usergroup:wheel".to_string()]);

    let netgroup = project_ast(&file_for("+admins"));
    assert_eq!(netgroup.users, vec!["netgroup:admins".to_string()]);

    let userid = project_ast(&file_for("#1000"));
    assert_eq!(userid.users, vec!["userid:1000".to_string()]);

    let plain = project_ast(&file_for("wheel"));
    assert_eq!(
        plain.users,
        vec!["wheel".to_string()],
        "a PLAIN username token must stay untagged"
    );

    // The exact inequality the module doc names as the minimum-viable
    // killing assertion: a project_ast that silently dropped the `%` sigil
    // would make these two calls indistinguishable.
    assert_ne!(
        group.users, plain.users,
        "%wheel (a group subject) must project to something a plain user \
         named \"wheel\" does not - got group={:?} plain={:?}",
        group.users, plain.users
    );
}

#[test]
fn project_ast_canonicalizes_and_tags_uid_and_gid_subjects() {
    // MISS (review, 2026-07-27), sharper than the plain userid case above:
    // `#0100` (leading zero) and `%#1000` (a compound sigil - group-by-gid)
    // both need canonicalization AND (for the gid case) full sigil-stripping
    // in addition to tagging. `accept-uid-leading-zero` / `accept-gid-subject`
    // are the corresponding committed corpus rows.
    use rulesteward_sudoers::ast::{
        CmndItem, CmndSpec, HostGroup, LineKind, LogicalLine, UserSpec,
    };

    let file_for = |user: &str| rulesteward_sudoers::ast::SudoersFile {
        path: PathBuf::from("/etc/sudoers"),
        source: format!("{user} ALL = ALL\n"),
        lines: vec![LogicalLine {
            line: 1,
            span: 0..(user.len() + 11),
            kind: LineKind::UserSpec(UserSpec {
                users: vec![user.to_string()],
                host_groups: vec![HostGroup {
                    hosts: vec!["ALL".to_string()],
                    cmnd_specs: vec![CmndSpec {
                        runas: None,
                        tags: vec![],
                        cmnd: CmndItem::All,
                    }],
                }],
            }),
        }],
    };

    // sudo_strtoid parses base 10: `#0100` means uid 100, matching
    // cvtsudoers' `{"userid": 100}` (a JSON number, no leading zero) - NOT
    // the textual "0100" a naive strip produces.
    let leading_zero = project_ast(&file_for("#0100"));
    assert_eq!(
        leading_zero.users,
        vec!["userid:100".to_string()],
        "a leading-zero uid must be canonicalized to its decimal value, got {:?}",
        leading_zero.users
    );

    // `%#1000`: BOTH sigils (`%` then `#`) must be stripped, not just the
    // first - the original `strip_sigil` stopped after one and would leave a
    // stray `#` in place (`"#1000"`), which is wrong under BOTH the old
    // bare-value contract and the new tagged one.
    let gid = project_ast(&file_for("%#1000"));
    assert_eq!(
        gid.users,
        vec!["usergid:1000".to_string()],
        "a %#gid subject must have BOTH sigils stripped and be tagged \
         usergid, got {:?}",
        gid.users
    );
}

#[test]
fn project_ast_tags_host_netgroup_but_not_networkaddr() {
    // `+netgroup` is a valid HOST token too (not just a subject), and is
    // symmetric with the user-side netgroup finding above: a `project_ast`
    // that dropped the `+` would pass vacuously against `cvtsudoers`'
    // `{"netgroup": S}` Host_List shape - added ALONGSIDE the `Host_List` key
    // widening below (this session's OWN new `accept-host-netgroup` corpus
    // row would otherwise reintroduce the exact erasure this dispatch closes
    // for the user side). `192.168.0.0/24`-style network addresses have no
    // leading sigil, so they are NOT tagged (see module doc) -
    // `accept-host-networkaddr` stays untagged on both sides.
    use rulesteward_sudoers::ast::{
        CmndItem, CmndSpec, HostGroup, LineKind, LogicalLine, UserSpec,
    };

    let file_for = |host: &str| rulesteward_sudoers::ast::SudoersFile {
        path: PathBuf::from("/etc/sudoers"),
        source: format!("alice {host} = ALL\n"),
        lines: vec![LogicalLine {
            line: 1,
            span: 0..(host.len() + 12),
            kind: LineKind::UserSpec(UserSpec {
                users: vec!["alice".to_string()],
                host_groups: vec![HostGroup {
                    hosts: vec![host.to_string()],
                    cmnd_specs: vec![CmndSpec {
                        runas: None,
                        tags: vec![],
                        cmnd: CmndItem::All,
                    }],
                }],
            }),
        }],
    };

    let netgroup = project_ast(&file_for("+webservers"));
    assert_eq!(netgroup.hosts, vec!["netgroup:webservers".to_string()]);

    let networkaddr = project_ast(&file_for("192.168.0.0/24"));
    assert_eq!(
        networkaddr.hosts,
        vec!["192.168.0.0/24".to_string()],
        "a network-address host must stay UNTAGGED (no leading sigil to \
         derive a type from), got {:?}",
        networkaddr.hosts
    );
}

#[test]
fn project_cvtsudoers_json_ignores_negated_companion_flag() {
    let doc = serde_json::json!({
        "User_Specs": [
            {
                "User_List": [{ "username": "alice", "negated": true }],
                "Host_List": [{ "hostname": "ALL" }],
                "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
            }
        ]
    });
    let proj = project_cvtsudoers_json(&doc).expect("known key shapes must not error");
    assert_eq!(
        proj.users,
        vec!["alice".to_string()],
        "a companion \"negated\": true must not change the extracted bare value"
    );
}

#[test]
fn project_cvtsudoers_json_tags_typed_user_list_shapes_but_not_username_or_useralias() {
    // The cvt-side half of the module doc's "Type tags" finding: `usergroup`
    // / `netgroup` / `userid` must carry their type in the extracted value,
    // while `username` and `useralias` COLLAPSE to the same untagged form
    // (the AST side cannot tell a plain name from an alias reference without
    // cross-referencing the file's own alias definitions, which this session
    // does not add - see the module doc for the full reasoning).
    let value_for = |elem: serde_json::Value| {
        let doc = serde_json::json!({
            "User_Specs": [{
                "User_List": [elem],
                "Host_List": [{ "hostname": "ALL" }],
                "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
            }]
        });
        project_cvtsudoers_json(&doc)
            .expect("known key shapes must not error")
            .users
    };

    assert_eq!(
        value_for(serde_json::json!({ "usergroup": "wheel" })),
        vec!["usergroup:wheel".to_string()]
    );
    assert_eq!(
        value_for(serde_json::json!({ "netgroup": "admins" })),
        vec!["netgroup:admins".to_string()]
    );
    assert_eq!(
        value_for(serde_json::json!({ "userid": 100 })),
        vec!["userid:100".to_string()]
    );
    assert_eq!(
        value_for(serde_json::json!({ "username": "alice" })),
        vec!["alice".to_string()],
        "a plain username must stay untagged"
    );
    assert_eq!(
        value_for(serde_json::json!({ "useralias": "ADMINS" })),
        vec!["ADMINS".to_string()],
        "an unexpanded alias reference must collapse to the SAME untagged \
         form as a plain username, not gain its own \"useralias:\" tag - \
         the AST side cannot tell the two apart without alias resolution, \
         which is out of this session's scope (see module doc)"
    );
}

#[test]
fn project_cvtsudoers_json_recognizes_usergid_key() {
    // `%#gid` subjects (a group-by-gid, e.g. `%#1000`) are reported by
    // `cvtsudoers` as `{"usergid": N}` - confirmed live against all three
    // images - which the original User_List key set did not recognize at
    // all. `accept-gid-subject` is the corresponding committed corpus row.
    let doc = serde_json::json!({
        "User_Specs": [{
            "User_List": [{ "usergid": 1000 }],
            "Host_List": [{ "hostname": "ALL" }],
            "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
        }]
    });
    let proj = project_cvtsudoers_json(&doc).expect("usergid must be a recognized User_List key");
    assert_eq!(proj.users, vec!["usergid:1000".to_string()]);
}

#[test]
fn project_cvtsudoers_json_recognizes_host_netgroup_and_networkaddr_shapes() {
    // `+netgroup` and IP/CIDR host tokens are reported by `cvtsudoers` as
    // `{"netgroup": S}` / `{"networkaddr": S}` in Host_List - confirmed live
    // against all three images - which the original Host_List key set (just
    // `hostname` / `hostalias`) did not recognize at all.
    // `print_member_json_int` (the real `cvtsudoers` source) keys `typestr`
    // on member TYPE, not on which list it appears in, so `netgroup`
    // legitimately appears in BOTH `User_List` (already recognized) and
    // `Host_List` (widened here). `accept-host-netgroup` /
    // `accept-host-networkaddr` are the corresponding committed corpus rows.
    let host_value_for = |elem: serde_json::Value| {
        let doc = serde_json::json!({
            "User_Specs": [{
                "User_List": [{ "username": "alice" }],
                "Host_List": [elem],
                "Cmnd_Specs": [{ "Commands": [{ "command": "/bin/ls" }] }]
            }]
        });
        project_cvtsudoers_json(&doc)
            .expect("netgroup/networkaddr must be recognized Host_List keys")
            .hosts
    };

    assert_eq!(
        host_value_for(serde_json::json!({ "netgroup": "webservers" })),
        vec!["netgroup:webservers".to_string()],
        "a HOST netgroup must be tagged the same way a USER netgroup is"
    );
    assert_eq!(
        host_value_for(serde_json::json!({ "networkaddr": "192.168.0.0/24" })),
        vec!["192.168.0.0/24".to_string()],
        "a network-address host must stay UNTAGGED (see module doc)"
    );
}

#[test]
fn project_cvtsudoers_json_is_fail_closed_on_unknown_user_list_key() {
    let doc = serde_json::json!({
        "User_Specs": [
            {
                "User_List": [{ "nosuchkey": "x" }],
                "Host_List": [{ "hostname": "ALL" }],
                "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
            }
        ]
    });
    let err = project_cvtsudoers_json(&doc).expect_err("an unknown User_List key must be rejected");
    assert!(
        err.location.contains("User_List"),
        "expected the error to identify User_List, got location={:?}",
        err.location
    );
}

#[test]
fn project_cvtsudoers_json_is_fail_closed_on_unknown_host_list_key() {
    // The contract names THREE arrays (`User_List` / `Host_List` /
    // `Cmnd_Specs[].Commands`); each has a DIFFERENT known-key set (5 / 2 /
    // 2), so an implementation naturally needs three distinct match arms and
    // this is the one the other two tests here do not exercise. Verified: an
    // implementation that stays fail-closed on User_List and Commands but
    // silently accepts (or skips) an unrecognized Host_List key adds no
    // failure without this test.
    let doc = serde_json::json!({
        "User_Specs": [
            {
                "User_List": [{ "username": "alice" }],
                "Host_List": [{ "nosuchkey": "x" }],
                "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
            }
        ]
    });
    let err = project_cvtsudoers_json(&doc).expect_err("an unknown Host_List key must be rejected");
    assert!(
        err.location.contains("Host_List"),
        "expected the error to identify Host_List, got location={:?}",
        err.location
    );
}

#[test]
fn project_cvtsudoers_json_is_fail_closed_on_unknown_commands_key() {
    let doc = serde_json::json!({
        "User_Specs": [
            {
                "User_List": [{ "username": "alice" }],
                "Host_List": [{ "hostname": "ALL" }],
                "Cmnd_Specs": [{ "Commands": [{ "nosuchkey": "x" }] }]
            }
        ]
    });
    let err = project_cvtsudoers_json(&doc).expect_err("an unknown Commands key must be rejected");
    assert!(
        err.location.contains("Command"),
        "expected the error to identify Cmnd_Specs[].Commands, got location={:?}",
        err.location
    );
}

#[test]
fn project_cvtsudoers_json_location_discriminates_between_the_three_arrays() {
    // Each of the three tests above only checks its OWN error in isolation
    // via `.contains(...)`, so a single constant location string covering
    // all three arrays (e.g. "User_List/Host_List/Cmnd_Specs[].Commands")
    // would satisfy every `.contains(...)` check individually while telling
    // an operator nothing about WHICH array actually had the bad element.
    // Confirm the three `location` values are pairwise distinct instead.
    let user_list_err = project_cvtsudoers_json(&serde_json::json!({
        "User_Specs": [{
            "User_List": [{ "nosuchkey": "x" }],
            "Host_List": [{ "hostname": "ALL" }],
            "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
        }]
    }))
    .expect_err("an unknown User_List key must be rejected");

    let host_list_err = project_cvtsudoers_json(&serde_json::json!({
        "User_Specs": [{
            "User_List": [{ "username": "alice" }],
            "Host_List": [{ "nosuchkey": "x" }],
            "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
        }]
    }))
    .expect_err("an unknown Host_List key must be rejected");

    let commands_err = project_cvtsudoers_json(&serde_json::json!({
        "User_Specs": [{
            "User_List": [{ "username": "alice" }],
            "Host_List": [{ "hostname": "ALL" }],
            "Cmnd_Specs": [{ "Commands": [{ "nosuchkey": "x" }] }]
        }]
    }))
    .expect_err("an unknown Commands key must be rejected");

    assert_ne!(
        user_list_err.location, host_list_err.location,
        "User_List and Host_List errors must report DIFFERENT locations, both got {:?}",
        user_list_err.location
    );
    assert_ne!(
        host_list_err.location, commands_err.location,
        "Host_List and Commands errors must report DIFFERENT locations, both got {:?}",
        host_list_err.location
    );
    assert_ne!(
        user_list_err.location, commands_err.location,
        "User_List and Commands errors must report DIFFERENT locations, both got {:?}",
        user_list_err.location
    );
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
        // `a != r` alone would also pass with the two control inputs SWAPPED
        // (Reject-vs-Accept still satisfies inequality). Pin each side to its
        // named role so that specific misconfiguration is caught too.
        assert_eq!(
            accept_verdict,
            Ok(VisudoVerdict::Accept),
            "target {target}: {POSITIVE_CONTROL_ACCEPT} must classify as Accept, got {accept_verdict:?}"
        );
        assert_eq!(
            reject_verdict,
            Ok(VisudoVerdict::Reject),
            "target {target}: {POSITIVE_CONTROL_REJECT} must classify as Reject, got {reject_verdict:?}"
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
                assert_ne!(
                    ours_rejects, oracle_rejects,
                    "L1 {id} ({target}): expected a KNOWN F01-vs-oracle divergence, but they \
                     agreed; update L1_XFAIL"
                );
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
        L1_XFAIL.len() * TARGETS.len(),
        "every L1_XFAIL scenario must have been enumerated and hit on every target \
         (the push sits inside the per-target loop, so each entry contributes up to \
         TARGETS.len() hits)"
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
    // Every L2_XFAIL entry is a REAL, confirmed divergence (see the module
    // doc's L2 section), so those pairs are deliberately excluded from
    // `compared`; the floor must subtract them rather than assume every pair
    // agrees.
    let l2_clean_floor = SCENARIO_FLOOR * TARGETS.len() - L2_XFAIL.len() * TARGETS.len();
    assert!(
        compared >= l2_clean_floor,
        "expected >= {l2_clean_floor} clean L2 comparisons, got {compared}"
    );
    assert_eq!(
        xfail_hit.len(),
        L2_XFAIL.len() * TARGETS.len(),
        "every L2_XFAIL scenario must have been enumerated and hit on every target \
         (the push sits inside the per-target loop, so each entry contributes up to \
         TARGETS.len() hits)"
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

            // `tuple_count` is otherwise only checked for RELATIVE equality
            // below, which an always-0-on-both-sides projection would satisfy
            // for every scenario. Pin the ABSOLUTE value on both sides for a
            // few scenarios confirmed directly against the corpus, so a
            // never-incremented tuple_count cannot pass everywhere.
            if let Some((_, expected)) = TUPLE_COUNT_ANCHORS
                .iter()
                .find(|(sid, _)| *sid == id.as_str())
            {
                assert_eq!(
                    cvt_proj.tuple_count, *expected,
                    "L3 {id} ({target}): tuple_count anchor - cvtsudoers side expected \
                     {expected}, got {}",
                    cvt_proj.tuple_count
                );
                assert_eq!(
                    ast_proj.tuple_count, *expected,
                    "L3 {id} ({target}): tuple_count anchor - our AST side expected \
                     {expected}, got {}",
                    ast_proj.tuple_count
                );
            }

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
                    "accept-notbefore" => {
                        assert!(
                            cvt_proj.commands.iter().any(|c| c == "/usr/bin/ls"),
                            "L3 {id} ({target}): the oracle must show the real command \
                             /usr/bin/ls; got {:?}",
                            cvt_proj.commands
                        );
                        assert!(
                            !ast_proj.commands.iter().any(|c| c == "/usr/bin/ls"),
                            "L3 {id} ({target}): our AST must NOT show the clean command \
                             (the NOTBEFORE= tag-loop gap swallows it); got {:?}",
                            ast_proj.commands
                        );
                        assert!(
                            ast_proj.commands.iter().any(|c| c.contains("NOTBEFORE=")),
                            "L3 {id} ({target}): our AST's garbage command token must contain \
                             the swallowed NOTBEFORE= text; got {:?}",
                            ast_proj.commands
                        );
                    }
                    "accept-timeout-option" => {
                        assert!(
                            cvt_proj.commands.iter().any(|c| c == "/usr/bin/ls"),
                            "L3 {id} ({target}): the oracle must show the real command \
                             /usr/bin/ls; got {:?}",
                            cvt_proj.commands
                        );
                        assert!(
                            !ast_proj.commands.iter().any(|c| c == "/usr/bin/ls"),
                            "L3 {id} ({target}): our AST must NOT show the clean command \
                             (the TIMEOUT= tag-loop gap swallows it); got {:?}",
                            ast_proj.commands
                        );
                        assert!(
                            ast_proj.commands.iter().any(|c| c.contains("TIMEOUT=")),
                            "L3 {id} ({target}): our AST's garbage command token must contain \
                             the swallowed TIMEOUT= text; got {:?}",
                            ast_proj.commands
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
    // A scope-out `continue`s BEFORE the xfail check ever runs for that
    // (scenario, target) pair, so only a scope-out entry whose scenario id is
    // ALSO in L3_XFAIL steals a hit from `xfail_hit`. Blindly subtracting
    // `L3_EL8_INVALID_JSON_SCOPE_OUT.len()` (as this used to) is only correct
    // by coincidence when every scope-out entry happens to name an L3_XFAIL
    // scenario; compute the actual INTERSECTION instead so a future scope-out
    // entry for a scenario NOT in L3_XFAIL cannot silently make this
    // assertion pass while xfail_hit is short by one.
    let scope_out_xfail_overlap = L3_EL8_INVALID_JSON_SCOPE_OUT
        .iter()
        .filter(|(scope_id, _)| L3_XFAIL.iter().any(|(xfail_id, _)| xfail_id == scope_id))
        .count();
    assert_eq!(
        xfail_hit.len(),
        L3_XFAIL.len() * TARGETS.len() - scope_out_xfail_overlap,
        "every L3_XFAIL scenario must have been enumerated and xfailed on every target not \
         stolen by an overlapping L3_EL8_INVALID_JSON_SCOPE_OUT entry (2 scenarios x 3 targets, \
         minus {scope_out_xfail_overlap} scope-out/xfail overlap = {})",
        L3_XFAIL.len() * TARGETS.len() - scope_out_xfail_overlap
    );
}
