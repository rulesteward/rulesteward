//! Data-driven `sudoers(5)` differential-oracle corpus (#538, session 9k-1 Lane C).
//!
//! Checks `RuleSteward`'s own answer (the hand-rolled `parser::parse` + the
//! `oracle` projection/classification helpers in `src/oracle.rs`) against a REAL
//! `visudo` / `cvtsudoers` (sudo 1.9.x, Rocky 8/9/10) verdict captured per
//! scenario, rather than a hand-authored expectation - see CONTRIBUTING.md
//! "Differential oracle contract". This is the Tier-1 (offline) replay half;
//! `capture_sudoers.sh` + `just diff-sudoers` (`scripts/rs-oracle-diff.sh
//! sudoers`) is the Tier-2 (live) half, re-pointing this SAME test at a freshly
//! captured corpus via `RS_ORACLE_CORPUS_SUDOERS`.
//!
//! # Frozen API this test requires from `rulesteward_sudoers::oracle` (landed in
//! `00d543f`; this section remains the single best description of the frozen
//! contract, so it is retitled rather than deleted now that the oracle exists)
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
//!   `"ALL"`. Every subject/host/COMMAND token's leading `!`-RUN is resolved
//!   by PARITY (see "Negation" below - NOT a single-character strip) and, if
//!   the parity is odd, the projected value is marked (a `"!"` prefix on the
//!   FINAL value, outermost - see "Negation"). After negation is resolved, a
//!   subject/host token ALSO gets the type tag described in "Type tags"
//!   below (a HOST token never gets `usergroup:`/`usergid:`/`userid:` - only
//!   `+netgroup` is valid host-side sigil syntax, so e.g. a literal hostname
//!   `#1000` stays untagged, matching `cvtsudoers`); a command token does not
//!   get a type tag (commands carry no `%+#` sigil in the sudoers grammar).
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
//!       `User_List` and `Host_List`. A `Host_List` `hostname` value can look
//!       exactly like a `#uid`/`%group` token (e.g. `#1000`) without BEING one,
//!       since `man 5 sudoers`'s `Host ::=` production has no such
//!       alternative, so it stays untagged there regardless of what it would
//!       mean in `User_List`.
//!     - `Cmnd_Specs[].Commands[]`: `{"command": S}` / `{"cmndalias": S}`.
//!
//!   Extract the bare string value regardless of which key is present, apply
//!   the SAME type tag described below, THEN mark negation outermost (a
//!   companion `"negated": true` -> a `"!"` prefix on the whole value) - see
//!   "Negation" below. `project_ast` and `project_cvtsudoers_json` must agree
//!   on ORDER (mark negation last, outside any type tag) or a negated,
//!   sigil'd value would compare unequal for a reason that has nothing to do
//!   with negation.
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
//! **Scoping honesty (corrected 2026-07-27):** an earlier version of this
//! module doc and `PROVENANCE.md` described the round-2 fix (this "Type
//! tags" section) as if negation were now covered too. It was NOT - see
//! "Negation" immediately below, which covers it for THIS round. What
//! remains genuinely open after this round: alias resolution and
//! `networkaddr` shape-detection (both just above) and tags/runas (just
//! above); a `#uid` value outside sudo's representable range (see "uid/gid
//! canonicalization"'s closing note) is ALSO left open, deliberately, as a
//! narrower, documented follow-up.
//!
//! ## Negation (added 2026-07-27)
//!
//! Both projectors stripped a leading `!` and then DISCARDED it, rather than
//! marking it - the SAME symmetric-erasure shape "Type tags" above closes for
//! sigils, reintroduced on the one axis that round created: a `project_ast`
//! that dropped negation ENTIRELY still matched `cvtsudoers`' `{"command":
//! "X", "negated": true}`, since both sides reduced to the bare `"X"`.
//! Measured against the committed corpus: `project_ast` on
//! `accept-negated-command` / `accept-negated-all` was BYTE-EQUAL to
//! `project_ast` on the same file with the `!` removed, and to
//! `project_cvtsudoers_json` on the SAME captured JSON. `!` is deny-vs-allow
//! in sudoers - "may run `su`" and "may run anything except `su`" must not
//! project identically.
//!
//! Fix: after resolving negation (see below), a NEGATED value's projection is
//! marked with a `"!"` prefix on the WHOLE value, outermost (applied AFTER
//! any type tag, so a negated group subject is `"!usergroup:wheel"`, not
//! `"usergroup:!wheel"`); an un-negated value is unmarked, exactly as before.
//! `project_ast` and `project_cvtsudoers_json` must apply the mark in the
//! SAME position or a negated, sigil'd value compares unequal for a reason
//! having nothing to do with negation.
//!
//! **Negation is a Kleene star, not a single character** (`man 5 sudoers`:
//! `'!'* command` / `'!'* user` / `'!'* host` - "An odd number of `!`
//! operators negate the value of the item; an even number just cancel each
//! other out"). Confirmed live (all three images): `!!/usr/bin/su` ->
//! `{"command": "/usr/bin/su"}` with NO `negated` key (even count, cancels);
//! `!!!/usr/bin/su` -> `negated: true` (odd count). A SINGLE-character strip
//! (the original, wrong contract) recovers `!/usr/bin/su` from `!!` and
//! `!!/usr/bin/su` from `!!!` - neither the right VALUE nor the right parity.
//! The fix is PARITY COUNTING (count the leading `!`s, mark iff the count is
//! odd, strip them all), not a single strip, on subjects, hosts, AND
//! commands alike.
//!
//! Whitespace after the bang-run: confirmed live, `alice ALL = !
//! /usr/bin/su` (a literal space before the command) still negates and
//! `cvtsudoers` reports the TRIMMED command (`{"command": "/usr/bin/su",
//! "negated": true}`, no leading space) - `parser.rs` keeps the raw token
//! `Cmnd("! /usr/bin/su")` verbatim, space included, so the negation
//! resolution must trim ANY whitespace immediately after the bang-run before
//! taking the remainder as the base value, matching the real tool.
//!
//! **`resolve_bang_run` is EXACT, not an approximation (confirmed 2026-07-27,
//! round 4):** `alice ALL = ! !/usr/bin/su` and `alice ALL = ! !`
//! (whitespace-SEPARATED bangs) are both SYNTAX ERRORS on all three images,
//! while the glued `!!` form parses fine. Real sudo's lexer therefore matches
//! the bang-run as a single CONTIGUOUS token (no embedded whitespace between
//! `!`s) before applying parity - which is exactly what a contiguous
//! `take_while` (stopping at the first non-`!` byte, including a space)
//! followed by `trim_start` on the remainder already does. There is no wider
//! "any whitespace-tolerant bang sequence" case this implementation is
//! missing.
//!
//! This REVERSES `project_cvtsudoers_json_ignores_negated_companion_flag`'s
//! prior assertion (that a `"negated": true` companion must NOT change the
//! extracted value) - that assertion pinned the exact symmetric-erasure bug
//! this section closes, so reversing it is a STRENGTHENING under the
//! frozen-tests rule (correcting a test that encoded WRONG behavior), never
//! a weakening. Both existing negation corpus rows (`accept-negated-command`,
//! `accept-negated-all`) already have `"negated": true` on BOTH sides of the
//! captured JSON, so this needed ZERO corpus churn - no new scenario, no floor
//! change.
//!
//! **First end-to-end coverage (round 4, 2026-07-27):** every negation test
//! above builds its `SudoersFile` BY HAND, so it proves the PROJECTOR handles
//! a negated token but never that the PARSER can actually PRODUCE one - a
//! hand-built AST supplies its own input, so a parser-side gap underneath is
//! invisible to it (this is exactly how `accept-negated-uid-subject`, a real
//! parser bug, survived three rounds of hand-built unit tests; see
//! `L1_XFAIL`). `accept-negated-user` (`!alice ALL = ALL`) and
//! `accept-negated-host` (`alice !ALL = /bin/ls`) close that gap for the
//! user/host mark specifically: both are real, `parser::parse`-produced,
//! live-captured scenarios, confirmed to project cleanly (no xfail needed)
//! through the REAL parser and the REAL oracle - the negation mark's first
//! parser-to-captured-oracle coverage.
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
//! **Left open, deliberately parked (found 2026-07-27):** sudo's uid type is
//! NARROWER than the `u64` this contract implies. Confirmed live (all three
//! images): `#2147483648` (2^31) is accepted as `{"userid": 2147483648}`, but
//! `#4294967295` (`(uid_t)-1`) and above make `cvtsudoers` exit rc 0 with a
//! stderr warning ("user-ID invalid value" / "user-ID value too large") and
//! FALL BACK to treating the whole token as a literal username, `#` kept
//! (`{"username": "#4294967295"}`). A `canonicalize_decimal` with no upper
//! bound produces `"userid:4294967295"` instead. Exotic input (needs a uid
//! at or past `(uid_t)-1`) and a LOUD failure today (a clean value mismatch,
//! not a silent pass or a panic) rather than a compensating error, so this
//! session parks it rather than adding the bound - tracked as a follow-up
//! issue (upper-bound `canonicalize_decimal` at `(uid_t)-1` = 4294967295,
//! exclusive, and fall back to the untagged, un-canonicalized original token
//! above it) rather than fixed here.
//!
//! # Three layers
//!
//! 1. **L1 (`sudo-F01`)**: does a `Malformed` line in our AST agree with the
//!    oracle's accept/reject verdict (`visudo -c -f -`)? Grounded per-TARGET,
//!    not once globally: el8's older sudo (1.9.5p2, grammar 48) genuinely
//!    rejects constructs el9/el10 (1.9.17p2, grammar 50) accept (measured:
//!    `INTERCEPT:` and a regex `Cmnd_Alias` `^...$` both syntax-error on el8 but
//!    parse clean on el9/el10) - this corpus deliberately avoids such
//!    version-gated constructs (a separate, newly-discovered divergence class
//!    outside #538's documented gaps; see PROVENANCE.md). L1 was a clean
//!    regression layer with an EMPTY xfail table through round 3; round 4
//!    (2026-07-27) gave it its FIRST entry, `accept-negated-uid-subject`
//!    (`!#1000 ALL = ALL`) - real `visudo` accepts it, but
//!    `rulesteward_sudoers::parser::parse` classifies the whole line
//!    `Malformed`. This is a `rulesteward-core` parser gap (`comment_index`'s
//!    `prev_allows_uid` byte-set omits `b'!'`), not a sudoers-lane defect -
//!    see `L1_XFAIL`'s doc comment and `PROVENANCE.md` for the full root
//!    cause, why the byte-set cannot simply add `b'!'` (it also serves the
//!    UNRELATED `Defaults!<cmnd>` scope-binding `!`, where the exclusion is
//!    correct), and the drafted (not filed) tracking issue.
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
//!    `project_ast` agree with `project_cvtsudoers_json`?
//!
//!    Through session 9k-1 this layer carried four KNOWN #538 divergences as
//!    `L3_XFAIL` entries. Session 9m closed a SUBSET of #538: gaps A, B and C
//!    below are fixed, so those four entries and their `match` arms are gone,
//!    the four scenarios are now ordinary compared rows, and the three
//!    gaps are pinned directly by `tests/iss538_parser_gaps.rs` (which drives
//!    the public `parse` / `lint` entry points rather than this
//!    differential).
//!
//!    A LATER, NARROWER #538 subclass (a glued `Option_Spec` keyword and/or
//!    a comma INSIDE a quoted option value, each interacting with the
//!    comma/colon splitters) was found later in the session, UNRELATED to
//!    the four scenarios above. A round-6 attempt at both halves (commit
//!    `ec11a15`) greened 9 tests but regressed two confirmed cases against
//!    real `visudo` (a false `sudo-F01` fatal on a comma-free option value,
//!    and a silently swallowed grant/alias), and was narrow-reverted in
//!    commit `50594c4`, which left all 9 marked `#[ignore]`. The
//!    glued-keyword half was then fixed properly by commit `2de19ea`
//!    ("position-anchor the option-value quote opener"), which retires the
//!    position-blind `is_option_value_quote_opener`/`word_immediately_before`
//!    pair `ec11a15` had only patched around; 6 of the 9 tests are ordinary
//!    passing rows since then. The remaining 3 (a comma inside a quoted
//!    option value confusing the `','` arm of `split_top_level_segments`,
//!    unrelated to any glued spelling) are STILL OPEN and remain marked
//!    `#[ignore]` in `tests/iss538_parser_gaps.rs` (search that file for
//!    `"known-open #538 defect"`) rather than deleted, so they remain
//!    executable documentation of the still-open defect. A future session
//!    must NOT read this module and conclude #538 can be closed: it is only
//!    PARTIALLY fixed. For the record, the three FIXED gaps from the
//!    original (pre-round-6) lane were:
//!      - **Gap A** - the tag-parsing loop in `parser::parse_cmnd_spec` only
//!        recognized `TAG:` syntax; an `=`-form `Option_Spec` (`ROLE=`,
//!        `TYPE=`, `NOTBEFORE=`, `TIMEOUT=`, ...) has no colon, so the whole
//!        remainder (`ROLE=... TYPE=... /usr/bin/vim`) became ONE garbage
//!        `CmndItem::Cmnd` token instead of the real command
//!        (`accept-selinux-role-type`, `accept-notbefore`,
//!        `accept-timeout-option`).
//!      - **Gap B** - `classify_user_spec`'s `split_first_word` on the first
//!        host-group segment assumed the `User_List` had no INTERNAL
//!        whitespace; `bob, ALL ALL=(ALL) ALL` split at the first whitespace
//!        after `bob,`, dropping `ALL` from the user list and merging it into
//!        the host list as one garbage `"ALL ALL"` token
//!        (`accept-user-list-whitespace-bug`).
//!      - **Gap C** - an `Option_Spec`'s own `=` desynced
//!        `split_top_level_segments`, so a following tag colon was mistaken
//!        for a top-level host-group separator and the whole line was
//!        discarded as `Malformed`. No corpus scenario exercised it; it was
//!        found during 9m's satisfiability run and is covered by host probes.
//!
//!    `L3_XFAIL` retains ONE entry, `accept-negated-uid-subject`, which is a
//!    `rulesteward-core` bug and NOT #538 - see that const's doc comment.
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
/// "uid/gid canonicalization" findings in the module doc - see there; 3
/// more `accept-*` scenarios (`accept-negated-uid-subject`,
/// `accept-negated-user`, `accept-negated-host`) added 2026-07-27 (round 4),
/// where the first two give the round-3 negation MARK its first end-to-end
/// (parser -> captured-oracle) coverage, and the third is L1's first-ever
/// xfail (see the module doc's "L1" section and `L1_XFAIL`); 4 more `accept-*`
/// scenarios (`accept-glued-closing-quote-principal`,
/// `accept-glued-closing-quote-with-inner-space`,
/// `accept-glued-closing-quote-after-comma-list`,
/// `accept-spaced-closing-quote-control`) added 2026-08-03 with #651, the
/// corpus's first quoted principals - see `PROVENANCE.md` section 17.
/// 22 + 8 + 2 + 6 + 3 + 4 = 45.
///
/// THIS CONSTANT MUST BE BUMPED IN THE SAME COMMIT THAT ADDS A SCENARIO, and
/// #651 initially forgot. The floor is a ONE-SIDED anti-DELETION guard, so it
/// does not fail when it is too low - it silently stops binding. Left at 41
/// against a corpus of 45, four scenario directories could be deleted and all
/// three layers still reported `607 passed`, byte-identical to a clean run
/// (measured 2026-08-03 in a detached worktree: `reject-cmnd-alias-empty-members`,
/// `reject-defaults-bare`, `reject-defaults-scope-no-target` and
/// `reject-no-equals-garbage` removed, rc 0). Half the reject side can vanish
/// unnoticed. That is exactly the #572 shape this project's `no-mnt-guard`
/// exists to prevent: a corpus destroyed and the harness reporting success
/// forever after.
///
/// verified: 2026-08-03 - with the floor at 45, deleting ONE scenario fails
/// again, which is this constant's own positive control.
const SCENARIO_FLOOR: usize = 45;

/// Named floor for L3's clean (non-xfailed, non-scoped-out) structural
/// comparisons.
///
/// DERIVED FROM A RUN, never computed. This is a ONE-SIDED floor: set too
/// high it is unsatisfiable and blocks the implementer forever, set too low
/// it silently weakens the differential, and both are defects. Session 9k-1
/// froze it at a value no contract-honouring implementation could reach (66
/// against an achievable 60); that survived two full adversarial rounds
/// because every reviewer asked "what WRONG implementation passes these
/// tests?" and nobody asked "does any CORRECT one pass them?". So the
/// procedure is: build a reference implementation, set this constant to a
/// deliberately unreachable value, read the TRUE achieved count out of the
/// failure message, put that number here, and re-run to confirm it passes.
/// The arithmetic below is a cross-check ON the measurement, never its
/// source.
///
/// Measured 2026-07-30 (session 9m, lane 3) against a throwaway reference
/// implementation of ALL THREE #538 gaps and the full closed TEN-keyword
/// `Option_Spec` set, with the four `Some(538)` entries removed from
/// `L3_XFAIL` - the state this constant is frozen for, since removing them
/// is #538's acceptance signal. A floor of 999 failed with
/// `expected >= 999 clean L3 comparisons, got 95`, and 95 then passed. That
/// deliberately-failing run is also this assertion's positive control: a
/// floor that cannot be made to fail is not measuring anything.
///
/// Re-derived a SECOND time after the lane's scope grew (the option set went
/// from the man page's seven keywords to the ten the shipping parser really
/// accepts, and Gap C - an option's own `=` desyncing the top-level `:`
/// splitter - was added). The measurement came back 95 again. That is the
/// expected result rather than a coincidence: L3's count is a function of
/// the CORPUS, and neither change adds or removes a corpus scenario - six of
/// the ten keywords and all of Gap C are grounded by host probes in
/// `tests/iss538_parser_gaps.rs`, not by corpus rows. If a later change to
/// the option set or the splitter DOES move this number, that means a corpus
/// scenario changed classification, and it is worth understanding why before
/// re-freezing.
///
/// Cross-check, which AGREES with the measurement: **37** accept scenarios x 3
/// targets = 111 candidate pairs; minus 1 scoped-out (el8 `SELinux` invalid
/// JSON) = 110 attempted; minus **15** xfail hits (the **5** `L3_XFAIL`
/// scenarios x 3 targets, minus 0 scope-out/xfail overlap now that
/// `accept-selinux-role-type` has left `L3_XFAIL` - see that const) = 95.
///
/// Those numbers were 33 / 99 / 98 / 3 until 2026-08-03 and every one of them
/// was stale, while the RESULT stayed 95 and nothing failed. #651 added 4 accept
/// scenarios and 4 `L3_XFAIL` entries, so each new scenario contributed +1
/// attempted and +1 xfail hit per target and the two errors cancelled exactly.
/// A cross-check that survives its own inputs going wrong is not cross-checking
/// anything, which matters because this const's doc tells a later reader to
/// investigate if the number MOVES. Update all four figures in the same commit
/// that adds a scenario or an `L3_XFAIL` entry.
///
/// 84 -> 95 is exactly the four #538 scenarios leaving `L3_XFAIL`:
/// `accept-user-list-whitespace-bug`, `accept-notbefore` and
/// `accept-timeout-option` contribute 3 targets each, while
/// `accept-selinux-role-type` contributes only 2 because its el8 pair is
/// scoped out of L3 entirely (9 + 2 = 11).
const L3_CLEAN_FLOOR: usize = 95;

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

/// L1's OWN xfail table, deliberately separate from [`L2_XFAIL`]: L1
/// compares our parser's F01 verdict against visudo's DEFAULT gate, while L2
/// compares visudo's default gate against its STRICT gate - two different
/// comparisons, so an L2 divergence is not evidence of an L1 divergence.
/// Reusing `L2_XFAIL` for L1 would silently exempt an L1 comparison the
/// moment an L2 entry is added, even though nothing about L1 itself changed.
///
/// First entry added 2026-07-27 (round 4): `accept-negated-uid-subject`
/// (`!#1000 ALL = ALL`). Real `visudo` accepts it (`{"userid": 1000,
/// "negated": true}`), but `rulesteward_sudoers::parser::parse` classifies
/// the WHOLE LINE `Malformed`. Root cause is NOT in this lane -
/// `rulesteward_core::comment::comment_index`'s `prev_allows_uid` byte-set
/// (`crates/rulesteward-core/src/comment.rs:149-155`) omits `b'!'`, so in
/// `!#1000` the `#` reads as a comment start, the rest of the line is
/// stripped, and the lone `!` has no `=` to complete a `UserSpec`. This is
/// NOT the same `!` `lints/tokens/mod.rs:384-388` deliberately excludes -
/// that one is `Defaults!<cmnd>` scope-binding, where `Defaults!#1000` really
/// IS rc 1 and stripping really is correct; one byte-set serves two
/// meanings of `!` with opposite right answers, so the fix is
/// context-sensitive and belongs in `rulesteward-core`, not here. Drafted as
/// a tracked issue (not filed) in `PROVENANCE.md`; do NOT fold this into
/// #538 (unrelated defect, different crate).
const L1_XFAIL: &[&str] = &["accept-negated-uid-subject"];

/// Known `-s`-vs-default divergences: see the module doc's L2 section and
/// `PROVENANCE.md` section 5. Grounded in `man 8 visudo`'s own description of
/// `-s` (alias-graph checking: undefined references and cycles), not
/// assumed - both scenarios were probed live against all three images before
/// being added here.
const L2_XFAIL: &[&str] = &["accept-undefined-alias-ref", "accept-alias-cycle"];

/// L3 structural-projection divergences: `(scenario_id, issue_number)`. The
/// issue number is `None` for a divergence whose issue is DRAFTED but not yet
/// filed (see `PROVENANCE.md`) - `Option<u32>` rather than a placeholder
/// number, so a reader can never mistake a drafted issue for a real, filed
/// one.
///
/// This table held four `Some(538)` entries through session 9k-1:
/// `accept-selinux-role-type`, `accept-user-list-whitespace-bug`,
/// `accept-notbefore` and `accept-timeout-option`. Session 9m fixed exactly
/// the divergences these four entries pinned (#538 gaps A and B - see the
/// module doc's L3 section), so they were deleted rather than widened or
/// skipped - deleting the entry that pins a divergence IS how a fix is
/// demonstrated here, and an xfail surviving its own fix would mean the fix
/// was never demonstrated. The four scenarios are ordinary compared rows
/// now, and they are the reason `L3_CLEAN_FLOOR` went 84 -> 95. A separate,
/// narrower #538 subclass (a comma INSIDE a quoted option value, unrelated
/// to any glued spelling) remains OPEN and unrelated to these four
/// scenarios - see the module doc's L3 section and the `#[ignore]`d tests in
/// `tests/iss538_parser_gaps.rs`; #538 as a whole is NOT closed by this fix.
///
/// Deletion is also forced rather than stylistic: the xfail branch below
/// asserts `!matches` ("expected the KNOWN divergence, but the projections
/// matched"), so a CORRECT parser makes an entry left in place FAIL. There is
/// no path to green that keeps them.
///
/// `accept-negated-uid-subject` (round 4, 2026-07-27) is the L3 half of
/// `L1_XFAIL`'s first entry (see that const's doc comment for the root
/// cause): since `rulesteward_sudoers::parser::parse` classifies the whole
/// line `Malformed`, `project_ast` sees no `UserSpec` at all
/// (`tuple_count=0`, every list empty), while `cvtsudoers` reports one
/// `User_Specs` entry (`tuple_count=1`, a negated, tagged uid user). This is
/// a DIFFERENT crate's bug (`rulesteward-core`), not #538, so it gets its
/// OWN (drafted, unfiled) issue rather than being folded in.
/// The four `Some(667)` entries (added with #651's corpus rows) are a QUOTE-
/// RETENTION divergence, not a structural one: for a quoted principal the two
/// projections agree on `tuple_count`, hosts and commands, and differ only in
/// that the AST keeps the surrounding `"` while `cvtsudoers` reports the
/// dequoted value. (`StructureProjection` has exactly four fields -
/// `tuple_count`, `users`, `hosts`, `commands` - so those ARE the axes; an
/// earlier version of this line also named "arity", which is not one of them.)
///
/// What these rows canNOT witness, stated because a reader may reasonably assume
/// otherwise: `StructureProjection` carries no OPTIONS/TAGS axis and no RUNAS
/// axis, so dropping `NOPASSWD:` from any of these four inputs, or adding a
/// `(root)` runas, leaves every corpus layer green. The grant itself is
/// witnessed only by the `w01_count` / `w05_count` assertions in
/// `boundary_substrate.rs`, never by a corpus row. Full AST-vs-AST fidelity is
/// the module doc's declared follow-up.
///
/// ORDER is deliberately NOT among the things checked - every
/// comparison here goes through [`sorted_eq`], which is documented multiset
/// equality, so an order regression on these rows is out of scope for this gate
/// as it is for every other.
///
/// The verbatim-quote convention is stated at `boundary_substrate.rs:115-117`
/// ("Values are kept VERBATIM from the source bytes, quotes included, per the
/// crate's convention") and frozen by its `["\"a=b\""]` and `["\"a b\""]`
/// assertions. `ast.rs`'s own "kept verbatim" is about `!`-negation, not quoting,
/// so it is deliberately not cited here.
///
/// They are xfailed rather than fixed here because resolving it means either
/// editing this differential gate's own comparison or changing the public AST,
/// and #651's implementer does not alter a barrier test to reach green. #667
/// carries the three candidate resolutions.
///
/// NOTHING about #651 rests on these entries. L1 is the PRIMARY witness: it
/// compares all four scenarios on all three targets and, with the `close + 1`
/// guard reverted, fails with `our F01 verdict (rejects=true) disagrees with the
/// oracle (rejects=false)`. The `#667` arm below is a SECOND witness rather than
/// inert - the same reverted guard trips its own `tuple_count` assertion
/// (`ast=0 cvt=1`), which is exactly what an arm pinned this tightly is built to
/// do.
///
/// verified: 2026-08-03 - guard deleted, `cargo test -p rulesteward-sudoers
/// --no-fail-fast` gives rc 101 with BOTH
/// `l1_f01_matches_visudo_verdict_per_target` and
/// `l3_structure_projection_matches_cvtsudoers` among the failures.
/// `--no-fail-fast` is REQUIRED to observe this: without it the run stops after
/// `boundary_substrate` fails and neither corpus layer executes at all.
///
/// The two NAMED tests are the claim; a failure COUNT deliberately is not. An
/// earlier version of this line said "600 passed / 6 failed" and was falsified
/// within the same branch by a later commit adding one more test that also
/// fails on guard deletion. Any count here is invalidated by any added test,
/// which is how a `verified:` sentinel rots while still looking authoritative.
///
/// Reaching them at all required the corpus's FIRST quoted principals: none of
/// the 41 pre-existing scenarios contained a double quote, on the most
/// defect-dense surface this parser has (#622, #629, #630, #631, #643, #651).
const L3_XFAIL: &[(&str, Option<u32>)] = &[
    ("accept-negated-uid-subject", None),
    ("accept-glued-closing-quote-principal", Some(667)),
    ("accept-glued-closing-quote-with-inner-space", Some(667)),
    ("accept-glued-closing-quote-after-comma-list", Some(667)),
    ("accept-spaced-closing-quote-control", Some(667)),
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
fn project_ast_marks_negation_and_tags_sigil_on_users_and_hosts() {
    // Renamed 2026-07-27 (was `..._strips_negation_and_sigil_...`): review
    // found negation was being STRIPPED AND DISCARDED, the exact
    // symmetric-erasure shape "Type tags" closes for sigils, reintroduced on
    // the axis that fix created. Negation must be MARKED (a `"!"` prefix on
    // the final value, outermost), not merely removed - see the module doc's
    // "Negation" section. This is a STRENGTHENING of this same test.
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
                        options: vec![],
                        tags: vec![],
                        cmnd: CmndItem::All,
                    }],
                }],
            }),
        }],
    };

    let proj = project_ast(&file);
    // "!alice" has no sigil, so it stays untagged but IS marked negated;
    // "!%wheel" has the `%` sigil, so it carries the `usergroup:` type tag
    // AND the negation mark, with the mark OUTERMOST.
    assert!(
        sorted_eq(
            &proj.users,
            &["!alice".to_string(), "!usergroup:wheel".to_string()]
        ),
        "a leading `!` on USERS must be MARKED on the projected value (not \
         silently discarded), and the mark must be OUTSIDE any type tag, \
         got {:?}",
        proj.users
    );
    // A projector with two independent negation helpers (one for users, one
    // for hosts) could mark negation on the user side and forget it on the
    // host side; the users assertion above cannot see that.
    assert!(
        sorted_eq(&proj.hosts, &["!web1".to_string()]),
        "a leading `!` on HOSTS must ALSO be marked, got {:?}",
        proj.hosts
    );
}

#[test]
fn project_ast_marks_negation_on_commands() {
    // MISS (review, 2026-07-27): `!`-negation on commands was being stripped
    // and DISCARDED (real sudoers allows negating a command,
    // `alice ALL = !/usr/bin/su`, and `cvtsudoers` reports it as
    // `{"command": "/usr/bin/su", "negated": true}` - confirmed live against
    // all three images), so a negated and an un-negated command projected
    // IDENTICALLY - measured directly against the committed corpus:
    // `project_ast` on `accept-negated-command` was byte-equal to the
    // un-negated form. `!` is deny-vs-allow; this is the single most
    // security-relevant axis in sudoers. `accept-negated-command` /
    // `accept-negated-all` are committed corpus rows for this (unchanged by
    // this fix - see module doc "Negation", zero corpus churn).
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
                        options: vec![],
                        tags: vec![],
                        cmnd,
                    }],
                }],
            }),
        }],
    };

    let plain = project_ast(&file_for(CmndItem::Cmnd("/usr/bin/su".to_string())));
    let negated_path = project_ast(&file_for(CmndItem::Cmnd("!/usr/bin/su".to_string())));
    assert_eq!(
        negated_path.commands,
        vec!["!/usr/bin/su".to_string()],
        "a leading `!` on a COMMAND must be MARKED on the projected value, \
         got {:?}",
        negated_path.commands
    );
    // The exact killing assertion for the round-1 defect this reintroduced:
    // a projector that discards negation makes these two equal.
    assert_ne!(
        plain.commands, negated_path.commands,
        "\"alice may run su\" and \"alice may run anything except su\" must \
         NOT project identically - plain={:?} negated={:?}",
        plain.commands, negated_path.commands
    );

    // `parser.rs`'s `parse_cmnd_spec` compares the raw token literally
    // against `ALL` (`cmnd_token == "ALL"`), so `!ALL` parses as
    // `CmndItem::Cmnd("!ALL")`, never `CmndItem::All` - confirmed directly
    // against `parser::parse`. The mark must still be recovered from that
    // raw `Cmnd` token.
    let negated_all = project_ast(&file_for(CmndItem::Cmnd("!ALL".to_string())));
    assert_eq!(
        negated_all.commands,
        vec!["!ALL".to_string()],
        "a leading `!` on the literal `Cmnd(\"!ALL\")` token must be \
         recovered and marked, got {:?}",
        negated_all.commands
    );
}

#[test]
fn project_ast_negation_is_kleene_star_not_a_single_strip() {
    // `man 5 sudoers`: `'!'* command` etc - "An odd number of `!` operators
    // negate the value of the item; an even number just cancel each other
    // out." Confirmed live (all three images): `!!/usr/bin/su` ->
    // `{"command": "/usr/bin/su"}` with NO `negated` key; `!!!/usr/bin/su` ->
    // `negated: true`. A single-character strip (the pre-round-3 contract)
    // gets both the VALUE and the PARITY wrong for anything but exactly one
    // `!`. Covers commands, users, and hosts - `resolve_command_negation` /
    // `tag_member` are separate functions and could parity-count one while
    // still single-stripping the other.
    use rulesteward_sudoers::ast::{
        CmndItem, CmndSpec, HostGroup, LineKind, LogicalLine, UserSpec,
    };

    let file_for = |user: &str, host: &str, cmnd: &str| rulesteward_sudoers::ast::SudoersFile {
        path: PathBuf::from("/etc/sudoers"),
        source: format!("{user} {host} = {cmnd}\n"),
        lines: vec![LogicalLine {
            line: 1,
            span: 0..(user.len() + host.len() + cmnd.len() + 5),
            kind: LineKind::UserSpec(UserSpec {
                users: vec![user.to_string()],
                host_groups: vec![HostGroup {
                    hosts: vec![host.to_string()],
                    cmnd_specs: vec![CmndSpec {
                        runas: None,
                        options: vec![],
                        tags: vec![],
                        cmnd: CmndItem::Cmnd(cmnd.to_string()),
                    }],
                }],
            }),
        }],
    };

    // Even count (two `!`s): cancels out, unmarked, on all three token kinds.
    let even = project_ast(&file_for("!!alice", "!!web1", "!!/usr/bin/su"));
    assert_eq!(
        even.users,
        vec!["alice".to_string()],
        "an EVEN count of `!` on a USER must cancel out (unmarked), got {:?}",
        even.users
    );
    assert_eq!(
        even.hosts,
        vec!["web1".to_string()],
        "an EVEN count of `!` on a HOST must cancel out (unmarked), got {:?}",
        even.hosts
    );
    assert_eq!(
        even.commands,
        vec!["/usr/bin/su".to_string()],
        "an EVEN count of `!` on a COMMAND must cancel out (unmarked), got {:?}",
        even.commands
    );

    // Odd count (three `!`s): negates, marked, on all three token kinds.
    let odd = project_ast(&file_for("!!!alice", "!!!web1", "!!!/usr/bin/su"));
    assert_eq!(
        odd.users,
        vec!["!alice".to_string()],
        "an ODD count of `!` on a USER must negate (marked), got {:?}",
        odd.users
    );
    assert_eq!(
        odd.hosts,
        vec!["!web1".to_string()],
        "an ODD count of `!` on a HOST must negate (marked), got {:?}",
        odd.hosts
    );
    assert_eq!(
        odd.commands,
        vec!["!/usr/bin/su".to_string()],
        "an ODD count of `!` on a COMMAND must negate (marked), got {:?}",
        odd.commands
    );
}

#[test]
fn project_ast_trims_whitespace_after_the_bang_run() {
    // Confirmed live (all three images): `alice ALL = ! /usr/bin/su` (a
    // literal space between the bang and the command) still negates AND
    // `cvtsudoers` reports the TRIMMED command
    // (`{"command": "/usr/bin/su", "negated": true}`, no leading space) -
    // `parser::parse` keeps the raw token `Cmnd("! /usr/bin/su")` verbatim,
    // space included (confirmed directly), so negation resolution must trim
    // whitespace immediately after the bang-run, not just strip the `!`s.
    use rulesteward_sudoers::ast::{
        CmndItem, CmndSpec, HostGroup, LineKind, LogicalLine, UserSpec,
    };

    let file = rulesteward_sudoers::ast::SudoersFile {
        path: PathBuf::from("/etc/sudoers"),
        source: "alice ALL = ! /usr/bin/su\n".to_string(),
        lines: vec![LogicalLine {
            line: 1,
            span: 0..26,
            kind: LineKind::UserSpec(UserSpec {
                users: vec!["alice".to_string()],
                host_groups: vec![HostGroup {
                    hosts: vec!["ALL".to_string()],
                    cmnd_specs: vec![CmndSpec {
                        runas: None,
                        options: vec![],
                        tags: vec![],
                        cmnd: CmndItem::Cmnd("! /usr/bin/su".to_string()),
                    }],
                }],
            }),
        }],
    };

    let proj = project_ast(&file);
    assert_eq!(
        proj.commands,
        vec!["!/usr/bin/su".to_string()],
        "whitespace between the bang-run and the command must be TRIMMED, \
         matching cvtsudoers' trimmed report, got {:?}",
        proj.commands
    );
}

#[test]
fn project_ast_distinguishes_which_of_two_commands_is_negated() {
    // `alice ALL = /bin/ls, !/bin/su`: confirmed live, cvtsudoers reports
    // `Commands: [{"command": "/bin/ls"}, {"command": "/bin/su", "negated":
    // true}]` - two independent `Cmnd_Spec`s in ONE host-group, only the
    // second negated. `parser::parse` confirmed to produce two separate
    // `CmndSpec`s (`Cmnd("/bin/ls")`, `Cmnd("!/bin/su")`), so this is a
    // straightforward per-spec application of the negation mark, not a new
    // mechanism - included because a bulk (whole-line) negation mistake
    // would not be caught by the single-command tests above.
    use rulesteward_sudoers::ast::{
        CmndItem, CmndSpec, HostGroup, LineKind, LogicalLine, UserSpec,
    };

    let file = rulesteward_sudoers::ast::SudoersFile {
        path: PathBuf::from("/etc/sudoers"),
        source: "alice ALL = /bin/ls, !/bin/su\n".to_string(),
        lines: vec![LogicalLine {
            line: 1,
            span: 0..30,
            kind: LineKind::UserSpec(UserSpec {
                users: vec!["alice".to_string()],
                host_groups: vec![HostGroup {
                    hosts: vec!["ALL".to_string()],
                    cmnd_specs: vec![
                        CmndSpec {
                            runas: None,
                            options: vec![],
                            tags: vec![],
                            cmnd: CmndItem::Cmnd("/bin/ls".to_string()),
                        },
                        CmndSpec {
                            runas: None,
                            options: vec![],
                            tags: vec![],
                            cmnd: CmndItem::Cmnd("!/bin/su".to_string()),
                        },
                    ],
                }],
            }),
        }],
    };

    let proj = project_ast(&file);
    assert_eq!(
        proj.commands,
        vec!["/bin/ls".to_string(), "!/bin/su".to_string()],
        "exactly one of the two commands must be marked negated, got {:?}",
        proj.commands
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
                        options: vec![],
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
                        options: vec![],
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
fn project_ast_tags_host_netgroup_but_not_networkaddr_or_hash_prefixed_hostname() {
    // `+netgroup` is a valid HOST token too (not just a subject), and is
    // symmetric with the user-side netgroup finding above: a `project_ast`
    // that dropped the `+` would pass vacuously against `cvtsudoers`'
    // `{"netgroup": S}` Host_List shape - added ALONGSIDE the `Host_List` key
    // widening below (this session's OWN new `accept-host-netgroup` corpus
    // row would otherwise reintroduce the exact erasure this dispatch closes
    // for the user side). `192.168.0.0/24`-style network addresses have no
    // leading sigil, so they are NOT tagged (see module doc) -
    // `accept-host-networkaddr` stays untagged on both sides.
    //
    // MISS (review, 2026-07-27): `man 5 sudoers`'s `Host ::=` production has
    // NO `#user-ID` alternative - `#` is not a valid host-side sigil at all,
    // just an unusual first character in an otherwise-plain hostname.
    // `alice #1000 = /bin/ls` is accepted live (all three images) and
    // `cvtsudoers` reports `{"hostname": "#1000"}`, untagged. A shared
    // sigil-tagging helper used for both users and hosts, unaware of which
    // side it is on, would wrongly read the leading `#` as the userid sigil
    // and tag it `"userid:1000"`.
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
                        options: vec![],
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

    let hash_hostname = project_ast(&file_for("#1000"));
    assert_eq!(
        hash_hostname.hosts,
        vec!["#1000".to_string()],
        "a HOST token starting with `#` is a plain (if unusual) hostname, \
         NOT a userid sigil - `Host ::=` has no such alternative - so it \
         must stay untagged, got {:?}",
        hash_hostname.hosts
    );
}

#[test]
fn project_cvtsudoers_json_marks_negated_companion_flag() {
    // REVERSED 2026-07-27 (was `..._ignores_negated_companion_flag`, which
    // asserted the companion flag must NOT change the value): review found
    // that assertion pinned the exact symmetric-erasure bug the round-2
    // type-tag fix closed for sigils, reintroduced here - the oracle DOES
    // distinguish "alice" from "NOT alice" via this flag, and RuleSteward
    // must too. Reversing a test that encoded WRONG behavior is a
    // STRENGTHENING under the frozen-tests rule, never a weakening - see the
    // module doc's "Negation" section for the full reasoning and grounding.
    let doc_for = |negated: bool| {
        let mut user_elem = serde_json::json!({ "username": "alice" });
        if negated {
            user_elem["negated"] = serde_json::json!(true);
        }
        serde_json::json!({
            "User_Specs": [{
                "User_List": [user_elem],
                "Host_List": [{ "hostname": "ALL" }],
                "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
            }]
        })
    };

    let plain = project_cvtsudoers_json(&doc_for(false)).expect("known key shapes must not error");
    let negated = project_cvtsudoers_json(&doc_for(true)).expect("known key shapes must not error");

    assert_eq!(
        negated.users,
        vec!["!alice".to_string()],
        "a companion \"negated\": true MUST mark the extracted value \
         (a `!` prefix, outermost), got {:?}",
        negated.users
    );
    assert_ne!(
        plain.users, negated.users,
        "\"alice\" and \"NOT alice\" must not project identically - \
         plain={:?} negated={:?}",
        plain.users, negated.users
    );
}

#[test]
fn project_cvtsudoers_json_marks_negation_on_hosts_and_commands() {
    // Same finding as the User_List test above, applied to the other two
    // arrays - a projector could mark negation for users and forget it for
    // hosts/commands.
    let host_doc = |negated: bool| {
        let mut host_elem = serde_json::json!({ "hostname": "web1" });
        if negated {
            host_elem["negated"] = serde_json::json!(true);
        }
        serde_json::json!({
            "User_Specs": [{
                "User_List": [{ "username": "alice" }],
                "Host_List": [host_elem],
                "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
            }]
        })
    };
    let plain_host = project_cvtsudoers_json(&host_doc(false)).expect("must not error");
    let negated_host = project_cvtsudoers_json(&host_doc(true)).expect("must not error");
    assert_eq!(negated_host.hosts, vec!["!web1".to_string()]);
    assert_ne!(plain_host.hosts, negated_host.hosts);

    let cmnd_doc = |negated: bool| {
        let mut cmnd_elem = serde_json::json!({ "command": "/usr/bin/su" });
        if negated {
            cmnd_elem["negated"] = serde_json::json!(true);
        }
        serde_json::json!({
            "User_Specs": [{
                "User_List": [{ "username": "alice" }],
                "Host_List": [{ "hostname": "ALL" }],
                "Cmnd_Specs": [{ "Commands": [cmnd_elem] }]
            }]
        })
    };
    let plain_cmnd = project_cvtsudoers_json(&cmnd_doc(false)).expect("must not error");
    let negated_cmnd = project_cvtsudoers_json(&cmnd_doc(true)).expect("must not error");
    assert_eq!(
        negated_cmnd.commands,
        vec!["!/usr/bin/su".to_string()],
        "the reviewer's named killing assertion: {{\"command\":\"X\",\"negated\":true}} \
         must project != {{\"command\":\"X\"}}, got {:?}",
        negated_cmnd.commands
    );
    assert_ne!(plain_cmnd.commands, negated_cmnd.commands);
}

#[test]
fn project_cvtsudoers_json_negation_mark_is_outside_the_type_tag() {
    // Ordering matters: `project_ast` and `project_cvtsudoers_json` must
    // agree on whether the `!` goes before or after a type tag, or a
    // negated, sigil'd value compares unequal for a reason that has nothing
    // to do with negation. Module doc "Negation": the mark goes OUTERMOST.
    let doc = serde_json::json!({
        "User_Specs": [{
            "User_List": [{ "usergroup": "wheel", "negated": true }],
            "Host_List": [{ "hostname": "ALL" }],
            "Cmnd_Specs": [{ "Commands": [{ "command": "ALL" }] }]
        }]
    });
    let proj = project_cvtsudoers_json(&doc).expect("known key shapes must not error");
    assert_eq!(
        proj.users,
        vec!["!usergroup:wheel".to_string()],
        "negation must be marked OUTSIDE the type tag, got {:?}",
        proj.users
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
                // L1_XFAIL is its OWN table, kept separate from L2_XFAIL so
                // that an L2 divergence (visudo default vs strict gate) can
                // never silently exempt an L1 comparison (our parser vs
                // visudo's default gate) it was never measured against. Its
                // first entry (round 4, 2026-07-27) is a rulesteward-core
                // parser gap, not a sudoers-lane defect - see L1_XFAIL's doc
                // comment and PROVENANCE.md.
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

    // Print AFTER the loop, using the real tally: L1's xfail table is no
    // longer empty, and reporting the raw scenario-directory count would
    // overstate what was actually compared now that it is not.
    announce(&root, mode, compared);
    // Every L1_XFAIL entry is a REAL, confirmed divergence (see L1_XFAIL's
    // doc comment), so those pairs are deliberately excluded from
    // `compared`; the floor must subtract them rather than assume every pair
    // agrees. (This formula was latent-wrong before round 4 - it happened to
    // be correct only because L1_XFAIL was always empty.)
    let l1_clean_floor = SCENARIO_FLOOR * TARGETS.len() - L1_XFAIL.len() * TARGETS.len();
    assert!(
        compared >= l1_clean_floor,
        "expected >= {l1_clean_floor} clean L1 comparisons, got {compared}"
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
                let issue_label = issue.map_or_else(
                    || "a drafted, not-yet-filed issue (see PROVENANCE.md)".to_string(),
                    |n| format!("#{n}"),
                );
                assert!(
                    !matches,
                    "L3 {id} ({target}): expected the KNOWN {issue_label} divergence, but the \
                     projections matched; update L3_XFAIL"
                );
                // Pin the SPECIFIC shape of each known divergence, not merely
                // "some inequality", so a trivial always-different projection
                // could not pass this adversarially.
                match id.as_str() {
                    "accept-negated-uid-subject" => {
                        // `!#1000 ALL = ALL`: the WHOLE LINE is `Malformed`
                        // to our parser (a `rulesteward-core` comment-index
                        // bug - see `L1_XFAIL`'s doc comment), so `project_ast`
                        // sees no `UserSpec` at all: zero tuples, every list
                        // empty. `cvtsudoers` sees a real, negated, tagged
                        // uid subject.
                        assert_eq!(
                            ast_proj.tuple_count, 0,
                            "L3 {id} ({target}): our AST must see NO UserSpec at all \
                             (the whole line is Malformed), got tuple_count={}",
                            ast_proj.tuple_count
                        );
                        assert!(
                            ast_proj.users.is_empty()
                                && ast_proj.hosts.is_empty()
                                && ast_proj.commands.is_empty(),
                            "L3 {id} ({target}): our AST's projection must be entirely empty, \
                             got users={:?} hosts={:?} commands={:?}",
                            ast_proj.users,
                            ast_proj.hosts,
                            ast_proj.commands
                        );
                        assert_eq!(
                            cvt_proj.tuple_count, 1,
                            "L3 {id} ({target}): the oracle must show exactly one UserSpec, \
                             got tuple_count={}",
                            cvt_proj.tuple_count
                        );
                        assert_eq!(
                            cvt_proj.users,
                            vec!["!userid:1000".to_string()],
                            "L3 {id} ({target}): the oracle must show a negated, tagged uid \
                             user, got {:?}",
                            cvt_proj.users
                        );
                    }
                    "accept-glued-closing-quote-principal"
                    | "accept-glued-closing-quote-with-inner-space"
                    | "accept-glued-closing-quote-after-comma-list"
                    | "accept-spaced-closing-quote-control" => {
                        // #667: a QUOTE-RETENTION divergence and NOTHING more.
                        // Every structural field must AGREE; the users lists must
                        // agree too once the AST's retained `"` are stripped.
                        //
                        // Pinning it this tightly is the whole point. A loose
                        // "they differ somehow" entry would go on passing if one
                        // of these scenarios later developed a REAL structural
                        // regression - a wrong split, a lost host, a swallowed
                        // command - which is precisely the fail-open #651 is
                        // about. Here a mis-split `"b c"` into `"b` / `c"` is
                        // left UNCHANGED by `unwrap_one_pair` (neither half has
                        // a quote at both ends) and so trips the users assertion
                        // below. `trim_matches` would have stripped both to
                        // `b` / `c` and absorbed the mis-split - which is the
                        // whole reason for the difference.
                        assert_eq!(
                            ast_proj.tuple_count, cvt_proj.tuple_count,
                            "L3 {id} ({target}): #667 is quote-retention only, so tuple_count \
                             must AGREE; got ast={} cvt={}",
                            ast_proj.tuple_count, cvt_proj.tuple_count
                        );
                        assert!(
                            sorted_eq(&ast_proj.hosts, &cvt_proj.hosts),
                            "L3 {id} ({target}): #667 is quote-retention only, so hosts must \
                             AGREE; got ast={:?} cvt={:?}",
                            ast_proj.hosts,
                            cvt_proj.hosts
                        );
                        assert!(
                            sorted_eq(&ast_proj.commands, &cvt_proj.commands),
                            "L3 {id} ({target}): #667 is quote-retention only, so commands must \
                             AGREE; got ast={:?} cvt={:?}",
                            ast_proj.commands,
                            cvt_proj.commands
                        );
                        // Removes ONE leading and ONE trailing quote, and only
                        // when BOTH are present - never `trim_matches('"')`,
                        // which strips any number from either end
                        // independently. (It checks the first and last bytes,
                        // so it is not a true balance check: on `"a"b"` it
                        // removes two quotes that are not a matched pair. That
                        // is deliberate simplicity, not an oversight - the
                        // property it must have is refusing an UNBALANCED
                        // token, which it does.)
                        //
                        // `trim_matches` strips ANY number of quotes from BOTH
                        // ends independently, so it also absorbs an UNBALANCED
                        // token - and an unbalanced principal quote is precisely
                        // what this defect family produces. `simple_quote_pairs`
                        // silently drops a trailing unmatched quote
                        // (`chunks_exact(2)`), and an off-by-one in the very
                        // guard #651 adds yields users `"ops team` with a clean
                        // host `web1`: tuple_count, hosts and commands all agree
                        // and `trim_matches` would have eaten the stray quote.
                        //
                        // Measured with `trim_matches`: a corpus scenario whose
                        // input was changed to `"ab ALL = NOPASSWD: ALL` (one
                        // unbalanced quote) passed EVERY layer, rc 0. #667 is a
                        // BALANCED one-pair divergence, so the assertion states
                        // exactly that and nothing wider.
                        let unwrap_one_pair = |u: &str| -> String {
                            let b = u.as_bytes();
                            if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
                                u[1..u.len() - 1].to_string()
                            } else {
                                u.to_string()
                            }
                        };
                        let dequoted: Vec<String> =
                            ast_proj.users.iter().map(|u| unwrap_one_pair(u)).collect();
                        assert!(
                            sorted_eq(&dequoted, &cvt_proj.users),
                            "L3 {id} ({target}): #667 predicts the users lists agree once ONE \
                             balanced quote pair is removed from each AST token; got ast={:?} \
                             unwrapped={:?} cvt={:?}",
                            ast_proj.users,
                            dequoted,
                            cvt_proj.users
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
         stolen by an overlapping L3_EL8_INVALID_JSON_SCOPE_OUT entry ({} scenarios x {} targets, \
         minus {scope_out_xfail_overlap} scope-out/xfail overlap = {})",
        L3_XFAIL.len(),
        TARGETS.len(),
        L3_XFAIL.len() * TARGETS.len() - scope_out_xfail_overlap
    );
}
