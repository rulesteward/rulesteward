# sudoers oracle corpus provenance (session 9k-1, Lane C, #538)

Captured 2026-07-25 by `capture_sudoers.sh` (the same script IS the capture
implementation for both this committed corpus and `just diff-sudoers`'s live
re-derivation - there is no second, separately-maintained capture path).

## What is captured

45 scenario directories (37 `accept-*`, 8 `reject-*`), 135 JSON documents - 30 captured
2026-07-25, plus 2 more `accept-*` scenarios added 2026-07-26 (review found
L2's original xfail table was empty for the wrong reason; see section 5),
plus 6 more `accept-*` scenarios added 2026-07-27 (review found the users/
hosts type tag, command negation, and uid/gid canonicalization findings;
see section 10), plus 3 more `accept-*` scenarios added 2026-07-27, round 4
(the negation mark's first parser-to-oracle coverage, plus L1's first-ever
xfail; see section 16), plus 4 more `accept-*` scenarios added 2026-08-03 with
#651 (the corpus's first quoted principals; see section 17), each holding:

- `input.sudoers` - the raw sudoers source, fed unchanged over stdin.
- `el8.json` / `el9.json` / `el10.json` - one JSON document per target,
  produced against `rs-oracle8` / `rs-oracle9` / `rs-oracle10`
  (`tools/oracle-images/`), each with:
  - `target`, `sudo_rpm` (the exact `rpm -q sudo` string for that image).
  - `visudo` / `visudo_strict` / `cvtsudoers` / `cvtsudoers_expanded`: the four
    oracle invocations (`visudo -c -f -`, `visudo -c -s -f -`, `cvtsudoers -f
    json`, `cvtsudoers -f json -e`), each `{"rc": N, "stdout": S, "stderr": S}`.

`sudoers_corpus_oracle.rs` reads these directly via `serde_json::Value`
(no `serde` derive - only `serde_json` is declared, added in Phase 0
specifically for this lane).

## Measured facts that ground the test's design

### 1. el9 and el10 sudo are the same upstream release; no parsing divergence found

`visudo -V` prints the IDENTICAL string on el9 and el10
(`visudo version 1.9.17p2`, grammar version 50), matching
`tools/oracle-images/README.md`'s note that they "differ only by patch
level". An extensive probe (2026-07-25, ~25 varied constructs: duplicate
aliases, unused aliases, unknown `Defaults` names, malformed hostnames,
relative paths, missing `@include` targets, `TIMEOUT`/`NOTBEFORE` overflow
and malformed values, cross-namespace alias-name collisions, `-s` vs `-c`)
found **zero** observable sudoers-parsing divergence between el9 and el10 on
either `visudo` or `cvtsudoers`. The only concrete difference is the RPM
package version itself: `sudo-1.9.17p2-3.el9_8.x86_64` vs
`sudo-1.9.17-4.p2.el10_2.x86_64` (Rocky folds the `p2` patch level into the
release field differently per major, but both build the same upstream
`1.9.17p2` source).

**Consequence for the per-version positive control:** since neither the
version string nor sudoers behavior can prove three genuinely distinct
captures were taken, the test's `per_version_identity_control` pins the
captured `sudo_rpm` field (read directly via `rpm -q sudo`, never derived
from visudo/cvtsudoers output) as the thing that must differ across all
three targets. This is the control CONTRIBUTING.md's "add a control pinning
a known version divergence" rule asks for; it happens to be a package-metadata
divergence rather than a behavioral one, because no behavioral one exists
between el9 and el10 for this oracle's surface.

**Directly confirmed against this corpus's own 30 scenarios, not just the
exploratory probe above (2026-07-25):** diffing every scenario's `el9.json`
against its `el10.json`, field-for-field except `target`/`sudo_rpm`, across
all 30/30 scenarios (22 accept + 8 reject) shows zero differences. el9 and
el10 are therefore behaviourally IDENTICAL for sudoers parsing on this
corpus's own captured data, not merely on the separate ~25-construct probe;
`target` and `sudo_rpm` are the only fields that legitimately differ per
version, which is exactly why the per-version control rests on `rpm -q sudo`
rather than on any observable oracle behavior.

### 2. el8 genuinely rejects newer-than-1.9.5p2 syntax; this corpus avoids it

el8 ships `sudo-1.9.5p2` (grammar version 48) vs el9/el10's `sudo-1.9.17p2`
(grammar version 50). Measured real divergences: a regex `Cmnd_Alias`
(`^/usr/bin/vim.*$`, an RHEL9/10-only backported feature per both
distros' RPM changelogs - `rpm -q --changelog sudo` shows "Request to
backport support for regex in sudo") and the `INTERCEPT:` tag (added
upstream after 1.9.5p2) both `visudo -c` REJECT on el8 but ACCEPT on
el9/el10. `TIMEOUT=`, `NOTBEFORE=`/`NOTAFTER=`, `sha256:` command digests,
and all of `EXEC`/`NOEXEC`/`FOLLOW`/`NOFOLLOW`/`LOG_INPUT`/`LOG_OUTPUT`/
`MAIL`/`SETENV`/`NOPASSWD`/`PASSWD` tags, and `ROLE=`/`TYPE=` SELinux specs,
were confirmed IDENTICAL (accept) across all three targets - true of
`visudo`'s VERDICT (which is why all of these are in the corpus at all), but
NOT of the STRUCTURAL projection: `TIMEOUT=` and `NOTBEFORE=` (like the
already-documented `ROLE=`/`TYPE=`) are `=`-form options that
`parser::parse_cmnd_spec`'s tag loop does not recognize (it only recognizes
`TAG:` syntax), so they get glued onto the following text as one garbage
command token instead of being split into their own option and a clean
command. Found in review 2026-07-26; `accept-notbefore` and
`accept-timeout-option` are now in `L3_XFAIL` alongside
`accept-selinux-role-type` - see section 8.

This corpus deliberately contains NO version-gated-newer construct (no
`INTERCEPT`, no regex `Cmnd_Alias`, no `LOG_SUBCMDS`), because RuleSteward's
hand-rolled parser (`parser.rs`) is NOT version-aware at the grammar level -
it would accept `INTERCEPT:` on every target uniformly, which would surface as
an L1 (`sudo-F01`) divergence against el8 specifically. That is a REAL,
plausible finding, but it is a THIRD divergence class distinct from #538's two
documented gaps, and this session's scope is #538 only (grounds it, does not
fix it, does not open new ones). Flagged for a future session/issue rather
than silently folded into an ungrounded L1 xfail.

### 3. Two NEW parser bugs found during grounding, NOT included in this corpus

While selecting scenarios, two additional real divergences between
RuleSteward's parser and real visudo were found and empirically confirmed
(via a throwaway `rulesteward_sudoers::parser::parse` repro), neither of which
is #538:

- **Command-digest colon-splitting**: `alice ALL = sha256:<hex> /usr/bin/ls`
  (visudo accepts) is misparsed by `parser.rs`'s `split_top_level_segments`:
  the colon after `sha256` is not preceded by a recognized `Tag` keyword, so
  it is read as a top-level HOST-GROUP separator (the same colon that
  separates `: Host = Cmnd` segments), splitting the line into two bogus
  segments and producing a spurious `sudo-F01` Malformed finding.
- **Quoted-comma command splitting**: `alice ALL = /bin/echo "hello, world"`
  is REJECTED by real visudo (`expected a fully-qualified path name` - visudo
  treats the comma inside the double-quoted argument as a `Cmnd_Spec_List`
  separator, splitting `world"` off as a second, non-absolute "command"), but
  RuleSteward's `split_cmnd_specs` has NO quote tracking (by documented
  design - see its doc comment) and ALSO splits on that comma, silently
  producing two `CmndSpec`s instead of rejecting the line - an ACCEPT/REJECT
  disagreement in the other direction from #538's two gaps.

Neither is exercised by this corpus (both scenario candidates were dropped
rather than xfailed) since this session's authorized scope is #538's two
gaps only; inventing a corpus entry that requires a THIRD, unauthorized xfail
would either mask a real bug behind undocumented scope creep or require an
issue number this session has no authority to assign. Worth a follow-up
issue.

### 4. el8's `cvtsudoers -f json` emits invalid JSON for `SELinux_Spec`

Confirmed directly: `alice ALL = ROLE=sysadm_r TYPE=sysadm_t /usr/bin/vim`
through `cvtsudoers -f json` on el8 produces:

```json
"SELinux_Spec": [
    "role": "sysadm_r",
    "type": "sysadm_t"
],
```

an array containing bare `"key": "value"` pairs with no wrapping object -
invalid JSON (`serde_json` rejects it). On el9/el10 the SAME construct
instead folds `role`/`type` into the `Options` array as normal
`{"role": ...}` / `{"type": ...}` objects (valid JSON). This is why
`accept-selinux-role-type`/`el8` is in `L3_EL8_INVALID_JSON_SCOPE_OUT` in the
Tier-1 test rather than an L3 comparison.

### 5. `-c` vs `-s` (strict): DOES diverge - the original sweep missed it

**Corrected 2026-07-26** (found in review; this replaces the original
2026-07-25 claim of "no divergence found", which was wrong): `-s` is
documented in `man 8 visudo` by its actual effect -
"If an alias is referenced but not actually defined or if there is a cycle in
an alias, visudo will consider this a syntax error" - which is alias-graph
checking, not file mode/ownership (that is `-O`/`-P`, a claim the original text
made and got backwards). The original ~25-probe sweep (duplicate aliases,
unused aliases, unknown `Defaults` names, malformed hostnames, relative paths,
missing `@include` targets, cross-namespace alias-name collisions) never tried
either construct the man page says `-s` actually checks, so "no divergence"
was an artifact of which inputs were tried, not a property of `-s` itself.

Probed live against all three images (2026-07-26):

- `alice ALL = NOSUCHALIAS` (an undefined `Cmnd_Alias` reference, scenario
  `accept-undefined-alias-ref`): `-c` rc 0, stdout `stdin: parsed OK`, stderr a
  `Cmnd_Alias "NOSUCHALIAS" referenced but not defined` diagnostic (el8
  prefixes it `Warning:`; el9/el10 print the same message with no prefix - a
  label-verbosity difference not seen on any other captured scenario in this
  corpus). `-c -s` rc 1, stdout EMPTY, stderr the SAME diagnostic text (el8
  prefixes it `Error:` instead). rc / stdout-emptiness / message content are
  identical across all three images; only the `Warning:`/`Error:` prefix
  differs by target.
- `User_Alias A = B` / `User_Alias B = A` / `A ALL = ALL` (a 2-alias cycle,
  scenario `accept-alias-cycle`): same rc/stdout/stderr pattern (`cycle in
  User_Alias "A"`), identical on all three images.

Both are now committed scenarios, captured with `capture_sudoers.sh` like
every other row (there is no second, hand-authored capture path), and listed
in `L2_XFAIL`. `cvtsudoers -f json` returns rc 0 with valid JSON for both
(`{"cmndalias": "NOSUCHALIAS"}` / `{"useralias": "A"}`, both within the
already-measured key shapes in section 6), and RuleSteward's own parser does
not flag either `Malformed` (confirmed directly against
`rulesteward_sudoers::parser::parse`), so both also flow through L1 and L3 as
ordinary CLEAN comparisons - no L1 or L3 xfail entry needed, only L2.

### 6. `cvtsudoers -f json` JSON key shapes (non-expanded)

Measured 2026-07-25, sudo 1.9.17p2: `cvtsudoers -f json` (without `-e`) keeps
alias references and sigil-prefixed subjects UN-expanded but ALSO strips the
sigil into a distinct key name rather than keeping it in the value:

| sudoers token | JSON shape |
|---|---|
| plain username | `{"username": "alice"}` |
| `User_Alias`/`Cmnd_Alias` reference (unexpanded) | `{"useralias": "ADMINS"}` / `{"cmndalias": "OPS"}` |
| `Host_Alias` reference (unexpanded) | `{"hostalias": "WEBS"}` |
| `%group` | `{"usergroup": "wheel"}` (no `%`) |
| `+netgroup` | `{"netgroup": "admins"}` (no `+`) |
| `#uid` | `{"userid": 1000}` (a JSON **number**, no `#`) |
| `!negated` | the un-negated key/value plus a companion `"negated": true` |

RuleSteward's own AST keeps every sigil/negation glued to the raw token
(`ast.rs`: "kept verbatim"). The Tier-1 test's structure-only projection
normalizes BOTH sides to the bare value (strip a leading `!`, then a leading
`%`/`+`/`#`) rather than reconstructing sigils on the `cvtsudoers` side, per
the task's "structure-only, full-fidelity is a follow-up" framing. No corpus
row exercises the `!negated` shape (see section 7); it is pinned instead by
dedicated unit tests
(`project_ast_strips_negation_and_sigil_from_users_and_hosts`,
`project_cvtsudoers_json_ignores_negated_companion_flag`) in the Tier-1 test.

### 7. Two follow-up observations (recorded 2026-07-26, NOT acted on this session)

- **Some "clean" L3 comparisons are empty-vs-empty and cannot fail.** The
  three `accept-defaults-*` scenarios (`accept-defaults-global`,
  `accept-defaults-negated`, `accept-defaults-scoped-host`) have no
  `User_Specs` at all, so both `project_ast` and `project_cvtsudoers_json`
  trivially agree at `tuple_count == 0` with empty `users`/`hosts`/`commands`
  - 9 of the 60 `L3_CLEAN_FLOOR` comparisons exercise nothing an incorrect
    implementation could get wrong. `TUPLE_COUNT_ANCHORS` in the Tier-1 test
    pins non-zero values elsewhere in the corpus (including
    `accept-defaults-global` itself, pinned at 0 deliberately, alongside
    non-zero anchors) so an always-0 `tuple_count` cannot pass on every row.
  - No corpus change is needed to fix this; it is a property of which
    scenarios happen to be Defaults-only, not a gap in coverage.
- **`cvtsudoers_expanded` is captured but never read.** Every scenario's JSON
  document stores the `cvtsudoers -f json -e` (alias-EXPANDED) result
  alongside the un-expanded one, but `read_target` / `OracleDoc` in the
  Tier-1 test only reads `cvtsudoers` (unexpanded), matching this session's
  un-expanded `project_ast` / `project_cvtsudoers_json` contract. It is
  stored for a follow-up that compares against the expanded view (e.g. to
  validate alias resolution against `RuleSteward`'s own alias-walk lints),
  not something this session's structure-only projection needs.

### 8. `accept-notbefore` and `accept-timeout-option` share #538's `=`-form-option bug

Found in review (2026-07-26): the frozen `L3_CLEAN_FLOOR` this test carried
(66) was unreachable by ANY implementation honouring the frozen contract -
the true clean count is 60. Cause: `accept-notbefore`
(`carol ALL = NOTBEFORE=20260101000000Z /usr/bin/ls`) and
`accept-timeout-option` (`bob ALL = (root) TIMEOUT=30 /usr/bin/ls`) were
selected for section 2's el8-vs-el9/10 verdict comparison, but neither was
ever checked at the STRUCTURAL (L3) level before `TUPLE_COUNT_ANCHORS` made
that level meaningful. Confirmed directly against
`rulesteward_sudoers::parser::parse`:

```
accept-notbefore:      cmnd: Cmnd("NOTBEFORE=20260101000000Z /usr/bin/ls")
accept-timeout-option: cmnd: Cmnd("TIMEOUT=30 /usr/bin/ls")
```

while `cvtsudoers -f json` (all three targets, both scenarios) splits the
option into its own `Options` entry and reports the bare command:

`accept-notbefore`:

```json
"Options": [{ "notbefore": "20260101000000Z" }],
"Commands": [{ "command": "/usr/bin/ls" }]
```

`accept-timeout-option`:

```json
"runasusers": [{ "username": "root" }],
"Options": [{ "command_timeout": 30 }],
"Commands": [{ "command": "/usr/bin/ls" }]
```

This is `parser::parse_cmnd_spec`'s tag loop recognizing only `TAG:` syntax
and swallowing any `=`-form option into the command token - EXACTLY the
`ROLE=`/`TYPE=` defect already documented for `accept-selinux-role-type`
(section 4 / this file's original #538 grounding), not a new divergence
class. Both are now in `L3_XFAIL` alongside it. `L3_CLEAN_FLOOR` corrected
66 -> 60 (72 candidates - 1 el8 scope-out - 11 xfail hits [4 scenarios x 3
targets, minus the 1 scope-out/xfail overlap]).

### 9. Full corpus re-derived live and diffed byte-for-byte (2026-07-26)

Independent verification (review): re-ran `capture_sudoers.sh` against a
fresh scratch directory and diffed all 128 files (32 scenarios x 4 files)
against the committed corpus. **128 of 128 byte-identical.** This confirms
the corpus is genuinely oracle-derived (not hand-edited after capture) and
that the `rs-oracle{8,9,10}` images have not drifted since capture.

### 10. Four findings from the impl-aware review (2026-07-27), grounded against real sudo 1.9.17p2 and `cvtsudoers_json.c`

All four probed live against all three images before being acted on; see the
Tier-1 test's module doc "Type tags" and "uid/gid canonicalization" sections
for the frozen-contract text these ground.

- **Command negation was never stripped.** `alice ALL = !/usr/bin/su` (rc 0,
  `parsed OK`): `cvtsudoers` reports `{"command": "/usr/bin/su", "negated":
  true}`, but the original contract only stripped `!` from subjects/hosts, so
  `project_ast` kept the literal `"!/usr/bin/su"`. Same for `!ALL`: `parser.rs`
  compares the raw token literally against `ALL`, so `!ALL` parses as
  `CmndItem::Cmnd("!ALL")`, never `CmndItem::All`. New scenarios:
  `accept-negated-command`, `accept-negated-all`.
  **CORRECTED 2026-07-27 (round 3): this bullet, taken alone, reads as if
  negation were now fully covered by these two scenarios. It was NOT.** The
  fix landed here merely STRIPPED `!` (discarding it) rather than marking it
  - the exact symmetric-erasure shape the very next bullet below (type tags)
  closes for sigils, reintroduced on the axis this round created. See section
  14 for the real fix.
- **`Host_List` rejected shapes the tool really emits.** `alice +webservers =
  /bin/ls` and `alice 192.168.0.0/24 = /bin/ls` both parse (rc 0);
  `cvtsudoers` emits `{"netgroup": "webservers"}` / `{"networkaddr":
  "192.168.0.0/24"}` in `Host_List`, neither of which the original two-key set
  (`hostname`/`hostalias`) recognized.
  `print_member_json_int` (the real `cvtsudoers` source) keys `typestr` on
  member TYPE, not on which list it is in, so `netgroup` - already accepted in
  `User_List` - legitimately appears in `Host_List` too. New scenarios:
  `accept-host-netgroup`, `accept-host-networkaddr`.
- **Textual sigil-strip vs sudo's typed parse.** `#0100 ALL = ALL`:
  `cvtsudoers` reports `{"userid": 100}` (`sudo_strtoid` parses base 10, JSON
  number, no leading zero), but a textual strip of the corpus's original
  contract produced `"0100"`. `%#1000 ALL = ALL` (a compound sigil, group-by-
  gid) compounds this: `cvtsudoers` reports `{"usergid": 1000}` (a key the
  original User_List set did not recognize at all), and even with that
  widened, the original `strip_sigil` stopped after ONE sigil, leaving a
  stray `#` (`"#1000"`, not `"1000"`). New scenarios: `accept-uid-leading-
  zero`, `accept-gid-subject`.
- **Symmetric erasure: the compensating-error class.** The member TYPE is
  present on BOTH sides - as the sigil in the AST, as the JSON KEY NAME in
  `cvtsudoers` - and both projectors threw it away, reducing everything to a
  bare value. A `project_ast` that dropped a sigil ENTIRELY (e.g. read
  `%wheel` as the plain user `wheel`) would still match `cvtsudoers`'
  `{"usergroup": "wheel"}`, since both sides reduce to `"wheel"`. This made
  `accept-group-subject`, `accept-uid-subject`, and `accept-netgroup-subject`
  (all THREE pre-existing corpus rows) prove nothing about sigil handling.
  Fixed by requiring a `"<type>:"` prefix on any sigil-derived subject/host
  value (`usergroup:` / `usergid:` / `netgroup:` / `userid:`), while a bare
  (no-sigil) value - including an unexpanded alias reference, which cannot be
  told apart from a plain name without cross-referencing the file's own alias
  definitions - stays untagged. `accept-user-alias-basic` (the alias case) is
  therefore DELIBERATELY left exercised only by the same residual erasure;
  see the module doc for the full reasoning on why alias resolution and
  `networkaddr` shape-detection are out of this session's scope. A related,
  narrower erasure - `CmndSpec::runas` / `CmndSpec::tags` are read by NEITHER
  projector, so `accept-nopasswd-specific` / `accept-runas-alias` /
  `accept-runas-noexec` currently prove nothing about tags/runas either - is
  noted in the module doc but NOT fixed this session (a third
  `StructureProjection` axis, not a same-shape widening of `users`/`hosts`).

`L3_CLEAN_FLOOR` corrected 60 -> 78 (90 candidates - 1 el8 scope-out - 11
xfail hits [unchanged - none of the 6 new scenarios are xfailed; they are
bugs to fix, not accepted divergences] = 78). This floor is NOT reachable by
the implementation this session's corpus was checked against - the six new
scenarios are deliberately either unrecognized (Err, aborting the L3 test
with a panic) or produce a wrong bare/untagged value (a clean assertion
mismatch) until `project_ast` / `project_cvtsudoers_json` are updated to the
widened contract.

### 11. Two leads for the corpus backlog, not fixed (parser-side, not `oracle.rs`)

- **`@include` expansion.** `cvtsudoers` follows includes and lands the
  included user-specs in the SAME top-level `User_Specs` array, while
  RuleSteward's AST records a `LineKind::Include` and projects nothing for it
  - a loud L3 mismatch when it occurs, but no corpus row exercises it today.
- **`%:nonunixgrp ALL = ALL`** (a non-Unix group subject) is classified
  `Malformed` by `rulesteward_sudoers::parser::parse` ("user specification
  segment is missing its `= command` part") while real `visudo` accepts it
  (rc 0, `parsed OK`) and `cvtsudoers` reports `{"nonunixgroup": "nonunixgrp"}`
  - confirmed directly against both. A genuine RuleSteward PARSER gap (not an
  `oracle.rs` one) that L1 would catch immediately if a corpus row existed;
  not added here because fixing or xfailing a parser-level Malformed
  misclassification is outside this lane's `oracle.rs` claim.

### 12. Confirmed clean by the 2026-07-27 review - recorded so it is not re-audited

Not findings; recorded so a future session does not re-derive them. The
`cvtsudoers_rc == 0` gate genuinely runs and gates (positive-controlled by
setting one row's rc to 3 and watching L3 fail at the intended assertion,
corpus then restored). Zero scenario-id-keyed logic exists in `oracle.rs`
itself - the four `L3_XFAIL` entries pass on faithfully-projected buggy
parser output, not a lookup table keyed on the scenario name.
`classify_visudo` cannot be spoofed by a multi-file `@include`. Commands
with arguments remain one string on both sides. `tuple_count` counting is
correct and `TUPLE_COUNT_ANCHORS` does break the `users.len()` coincidence.
`userid` via `to_string()` is right for canonical decimals and negatives.
An absent `User_Specs` key correctly projects to 0 tuples.

### 13. Six new 2026-07-27 scenarios re-derived live and diffed byte-for-byte

Self-verified (not just taken on report, per this project's audit-subagent
discipline): captured a fresh corpus with the committed `capture_sudoers.sh`
and diffed all 32 pre-existing scenarios' 128 files against it - **128 of 128
byte-identical** (unaffected by adding the 6 new ones). The 6 new scenarios'
own captured JSON matches the live probes this section's findings are
grounded on, verified directly (rc, stdout, and the exact `cvtsudoers` JSON
shape) for all three targets before being committed.

### 14. Round-3 review: negation is a Kleene star and was never really covered; a shared tagger mistags hosts

Found in a THIRD adversarial round against the (by-then-landed) implementation
of sections 10-13. All measurements below re-confirmed live against all three
images before being acted on. `L3_CLEAN_FLOOR` / `SCENARIO_FLOOR` are
UNCHANGED by this section - every fix here needed zero new corpus rows (see
each finding).

- **The compensating-error class, reintroduced (REQUIRED fix).** Both
  projectors stripped a leading `!` and DISCARDED it rather than marking it -
  the identical erasure shape section 10's type-tag fix closed for sigils,
  reintroduced on the one axis that same round created. Measured directly
  against the committed corpus: `project_ast` on `accept-negated-command` was
  byte-equal to `project_ast` on the same file with the `!` removed, and to
  `project_cvtsudoers_json` on the SAME captured JSON. `!` is deny-vs-allow -
  "may run `su`" and "may run anything except `su`" projected identically.
  Fixed by marking a negated value with a `"!"` prefix OUTERMOST (applied
  after any type tag: `"!usergroup:wheel"`, never `"usergroup:!wheel"`).
  `project_cvtsudoers_json_ignores_negated_companion_flag`'s prior assertion
  (that the flag must NOT change the value) pinned this exact bug and was
  REVERSED - a STRENGTHENING under the frozen-tests rule, correcting a test
  that encoded wrong behavior, never a weakening. Both existing negation
  scenarios (`accept-negated-command`, `accept-negated-all`) already carry
  `"negated": true` on BOTH sides of the captured JSON, so this needed ZERO
  corpus churn.
- **Negation is a Kleene star, not a single character (REQUIRED fix, same
  pass as above).** `man 5 sudoers`: `'!'* command` / `'!'* user` / `'!'*
  host` - "An odd number of `!` operators negate the value of the item; an
  even number just cancel each other out." Confirmed live: `!!/usr/bin/su` ->
  `{"command": "/usr/bin/su"}` (no `negated` key, cancels); `!!!/usr/bin/su`
  -> `negated: true`. The original single-character strip got BOTH the value
  and the parity wrong for anything but exactly one `!`. Fixed by PARITY
  COUNTING (count the leading `!`s, mark iff odd, strip them all) on
  subjects, hosts, and commands alike. Also confirmed live: `alice ALL = !
  /usr/bin/su` (a literal space after the bang) still negates, and
  `cvtsudoers` reports the TRIMMED command - `parser::parse` keeps the raw
  token `Cmnd("! /usr/bin/su")` verbatim, space included, so negation
  resolution must also trim whitespace immediately after the bang-run.
- **A `#`-prefixed hostname is not a userid (REQUIRED doc correction; impl
  fix TAKEN, not parked).** `man 5 sudoers`'s `Host ::=` production has no
  `#user-ID` alternative. `alice #1000 = /bin/ls` is accepted live (all three
  images) and `cvtsudoers` reports `{"hostname": "#1000"}`, untagged - but
  the shared sigil-tagging helper used for both users and hosts is unaware of
  which side it is on, and would read the leading `#` as the userid sigil,
  tagging it `"userid:1000"`. The implementation's own doc comment (in
  `oracle.rs`) claimed tagging hosts with the user rules "costs nothing even
  though `%`/`%#`/`#` do not occur there in practice" - HALF true: `%`/`%#`
  really are syntax errors on all three images, but `#` is NOT, so that claim
  is empirically false and must be corrected by whoever lands this fix (this
  project treats a false comment as its own defect class, regardless of
  whether the surrounding code is also being touched). Taken as a required
  fix rather than parked (unlike the uid/gid item below) because it is small,
  needs zero corpus churn (a hand-built unit test suffices - no existing
  corpus row uses a `#`-prefixed hostname), and is a real, live-confirmed
  correctness gap, not an exotic edge case.
- **`canonicalize_decimal`'s domain is wider than sudo's uid type - PARKED,
  not fixed (my call as test-author).** Confirmed live: `#2147483648` (2^31)
  is accepted as `{"userid": 2147483648}`, but `#4294967295` (`(uid_t)-1`)
  and above make `cvtsudoers` exit rc 0 with a stderr warning and FALL BACK
  to treating the whole token as a literal username, `#` retained
  (`{"username": "#4294967295"}`). An unbounded `u64` parse instead produces
  `"userid:4294967295"`. Parked rather than fixed: exotic input (needs a uid
  at or past `(uid_t)-1`), and a LOUD failure today (a clean value mismatch)
  rather than a silent compensating error or a panic, so the round-3 boundary
  (this protocol bounds the ATL at roughly 2-3 rounds) is better spent
  elsewhere. Tracked as a follow-up: bound `canonicalize_decimal` at
  `(uid_t)-1` = 4294967295 exclusive, falling back to the untagged, original
  token above it.

Scoping honesty, corrected: as of this section, negation IS covered (Kleene
star, marked on all three token kinds) and the host-`#`-mistagging bug is
closed too. What remains genuinely open: alias resolution and `networkaddr`
shape-detection (section 10), tags/runas (section 10), and the uid/gid
domain bound immediately above - all deliberately narrower, documented,
parked scopes, not silent gaps.

### 15. Two more backlog leads found in round 3, not this lane's work

- **`#-1 ALL = ALL`**: real `visudo` accepts it (rc 0, `parsed OK`) and
  `cvtsudoers` reports `{"username": "#-1"}` (a negative "uid" falls back to
  a literal username, same shape as the out-of-range case above), but
  `rulesteward_sudoers::parser::parse` classifies the ENTIRE LINE as a
  `Comment` - confirmed directly. A parser-side gap (the `#` at the start of
  a `User_List` token is apparently read as a comment marker before the
  UID-subject disambiguation applies), not an `oracle.rs` one.
- **`usergroup\:wheel ALL = ALL`**: `cvtsudoers` unescapes the backslash and
  reports a literal username `{"username": "usergroup:wheel"}` - BYTE-
  IDENTICAL to what a type-tagged `usergroup:` value looks like. Confirmed
  directly this is NOT a silent false-clean today: `rulesteward_sudoers`'s
  own AST keeps the raw token WITH its backslash
  (`users: ["usergroup\\:wheel"]`), which does not match `cvtsudoers`'
  unescaped form either as a plain string or as a tag, so it produces a LOUD
  mismatch rather than a false pass. `:` is therefore NOT a reserved
  namespace this differential can rely on - noted for the corpus backlog,
  not acted on (no corpus row exercises it; would need backslash-unescaping
  in the parser to even reach the comparison meaningfully).
  **Coupling note for whoever fixes this backlog item:** the moment the
  parser starts unescaping `\:`, this collision stops being loud and becomes
  SILENT, because both projectors would then produce the identical
  unescaped literal `"usergroup:wheel"` from different inputs. This is
  promotion trigger 1 of 3 for `StructureProjection`'s "keep the string
  encoding, not a structured `Member` type" decision - see that struct's doc
  comment in `src/oracle.rs`. Re-derive whether the string encoding still
  holds before landing this fix.

### 16. Round 4: the compensating-error class is CLOSED; one parser-level miss remains, tracked outside this lane

The round-4 adversarial review answered the structural question directly:
what information is present on both sides of a `cvtsudoers` member and
discarded by both? At the member level, after rounds 1-3 (value, type key,
negation), the answer is NOTHING - it enumerated every JSON path in the
committed corpus and every member key the real tool emits, and could not
construct an input where both projectors agree while RuleSteward is wrong.
**The compensating-error class that regenerated in rounds 1 and 2 (see
sections 10 and 14) did NOT regenerate in round 4.** `oracle.rs` needed no
further change this round - only three new corpus scenarios and two xfail
entries.

**The one miss found is a `rulesteward-core` parser bug, not an `oracle.rs`
one:** `!#1000 ALL = ALL` is accepted by real `visudo` (`parsed OK`,
`{"userid": 1000, "negated": true}`), but
`rulesteward_sudoers::parser::parse` classifies the WHOLE LINE `Malformed` -
confirmed directly. `oracle.rs`'s `tag_member` is RIGHT
(`tag_member("!#1000", User)` yields `"!userid:1000"`); it is simply never
handed that token, because the line never becomes a `UserSpec` at all
(`project_ast` sees `tuple_count=0`, every list empty).

**Why it survived three rounds of unit tests:** every round-3 negation and
type-tag unit test builds its `SudoersFile` BY HAND
(`file_for("!%wheel")`, `users: vec!["!alice"]`, `Cmnd("!ALL")`). These prove
the PROJECTOR handles a negated/tagged token; they never ask whether the
PARSER can actually PRODUCE that token from real sudoers text. A hand-built
AST supplies its own input, so a parser-level gap underneath is invisible to
it. New scenarios `accept-negated-user` (`!alice ALL = ALL`) and
`accept-negated-host` (`alice !ALL = /bin/ls`) close this gap for the
user/host negation mark specifically - both are real, parser-produced,
live-captured, and confirmed to project cleanly (no xfail) - giving that
mark its first end-to-end (parser -> captured-oracle) coverage, which was
previously zero. `accept-negated-uid-subject` (`!#1000 ALL = ALL`) is the
scenario that actually HITS the parser gap; it is L1's first-ever xfail
entry (see `L1_XFAIL` in the Tier-1 test) plus a new `L3_XFAIL` entry (0
tuples vs 1).

**`! !` (whitespace-separated bangs) is a syntax error; glued `!!` is not -
confirmed live, all three images** (`alice ALL = ! !/usr/bin/su` and
`alice ALL = ! !` both rc 1; `alice ALL = !!/usr/bin/su` rc 0). Real sudo's
lexer therefore matches the bang-run as a single CONTIGUOUS token before
applying parity. This upgrades the Tier-1 test's `resolve_bang_run` (a
contiguous `take_while` + `trim_start`) from an approximation to an EXACT
model of the grammar - there is no wider "whitespace-tolerant bang sequence"
case it is missing. See the Tier-1 test's module doc "Negation" section.

**Root cause of the parser bug, drafted here as a tracked issue (not
filed):**

- `rulesteward_core::comment::comment_index`'s `prev_allows_uid` byte-set
  (`crates/rulesteward-core/src/comment.rs:147-153`) does not include `b'!'`.
  In `!#1000`, the byte immediately before `#` is `!`, which is not in the
  set, so `#` is read as a comment start; the rest of the line is stripped,
  and the lone `!` has nothing after it to complete a `user host = command`
  spec, so the whole line becomes `Malformed`.
- **The byte-set cannot simply add `b'!'`.** `crates/rulesteward-sudoers/src/lints/tokens/mod.rs:382-386`
  records the EXISTING exclusion of `!` as deliberate and verified, but for a
  DIFFERENT `!`: `Defaults!<cmnd>` scope-binding syntax, where
  `Defaults!#1000` really IS rc 1 in real `visudo`, and treating that `#` as
  a comment start (hence stripping it and rejecting the line) really is
  correct. One byte-set, two INDEPENDENT meanings of the character `!`
  (negation-operator prefix vs. `Defaults` scope-bind operator), with
  OPPOSITE right answers for whether the following `#` starts a comment.
  Blindly adding `b'!'` to the set would fix `!#1000` but regress the pinned
  `f02_defaults_cmnd_scope_hash_*` non-regression tests for `Defaults!#1000`.
- **The correct fix is CONTEXT-SENSITIVE**: `comment_index` (or its caller)
  needs to know WHICH grammatical position it is scanning (a `User_List`/
  `Host_List` subject vs. a `Defaults` scope-bind target) before deciding
  whether a preceding `!` permits a following `#` to be a UID rather than a
  comment start. This is a `rulesteward-core` change (the byte-set lives in
  a shared crate used by multiple lint passes), not a `rulesteward-sudoers`
  or `oracle.rs` one - out of this lane's claim, same as sections 11 and 15.
- **`%#1000` already works** (confirmed: the byte before `#` is `%`, which
  IS in `prev_allows_uid`), so even a NEGATED-gid row (`!%#1000 ALL = ALL`)
  would have missed this specific bug - the byte immediately before `#` is
  what matters, and `!%` ends in `%`, not `!`. This is why
  `accept-negated-uid-subject` uses a bare `#uid` form, not a `%#gid` one, to
  isolate the exact byte sequence that trips the exclusion.

Floors recomputed from the corpus (not adjusted to fit): `SCENARIO_FLOOR`
38 -> 41 (33 accept + 8 reject). `L3_CLEAN_FLOOR` 78 -> 84 (99 candidates -
1 el8 scope-out - 14 xfail hits [5 scenarios x 3 targets, minus the 1
scope-out/xfail overlap]). L1's floor formula had a LATENT bug - it never
subtracted `L1_XFAIL` contributions, correct only because the table had
always been empty - fixed in the same commit that gave it its first entry.
Sentinels with the fix landed and all three new scenarios captured: L1=120,
L2=117, L3=84 (all match their floors exactly), 27/27 tests green.

Self-verified (per this project's audit-subagent discipline): re-captured
with the committed `capture_sudoers.sh` and diffed all 38 pre-existing
scenarios' files against the fresh run - 0 differences (unaffected by adding
the 3 new ones). The 3 new scenarios' own captured JSON (`visudo`/
`cvtsudoers` rc and stdout, all three targets) matches the live probes this
section's findings are grounded on, confirmed directly before being
committed.

### 17. The corpus's first quoted principals (2026-08-03, #651)

Four scenarios added alongside the #651 fix, for a glued CLOSING quote in the
principal list. Their inputs, all `visudo -c -f -` rc 0 `parsed OK` on all three
targets:

| scenario | input | oracle User_List / Host_List |
|---|---|---|
| `glued-closing-quote-principal` | `"ab"ALL = NOPASSWD: ALL` | `["ab"]` / `["ALL"]` |
| `glued-closing-quote-with-inner-space` | `"ops team"web1 = NOPASSWD: /bin/ls` | `["ops team"]` / `["web1"]` |
| `glued-closing-quote-after-comma-list` | `alice,"b c"ALL = NOPASSWD: ALL` | `["alice","b c"]` / `["ALL"]` |
| `spaced-closing-quote-control` | `"ab" ALL = NOPASSWD: ALL` | `["ab"]` / `["ALL"]` |

The fourth is the one-byte control: a single added space is the whole difference
from the first, which is what isolates the defect to the glued closing quote
rather than to quoting in a principal generally.

**These are the corpus's FIRST quoted principals.** Checked mechanically when they
were added: `grep -l '"' */input.sudoers` returned exactly these four, so not one
of the 41 pre-existing scenarios contained a double quote. That gap sat on the
most defect-dense surface this parser has - #622, #629, #630, #631, #643 and #651
are all quote-boundary bugs - and it is the reason a shipped fail-open
(`"ab"ALL = ...` reported a false `sudo-F01` and dropped its NOPASSWD grant)
survived every differential run.

All four are L3 xfail against **#667**, a quote-RETENTION divergence they were the
first to reach: the AST keeps the surrounding quotes and `cvtsudoers` reports the
dequoted value, with every structural field agreeing. That is independent of #651
- the SPACED control parses correctly with or without the fix, its L1 passes in
both states, and it still diverges at L3. L1 compares all four on all three
targets and is the layer that witnesses the fix.

Captured with `capture_sudoers.sh` into a staging directory, never hand-authored.
Re-capturing the 41 pre-existing scenarios first reproduced all 123 committed
files byte-for-byte, which is what makes the four new verdicts trustworthy.

The script CANNOT be pointed at its own directory - `cp` then sees source and
destination as the same file and exits 1, which `rs_capture_die` turns into rc 2
on the first scenario. Capture to a staging dir and copy back; the script's own
header says so and gives the command.

(This paragraph used to warn that the script's header claimed the opposite. That
claim was corrected in the header itself later on the same branch, so the warning
outlived what it warned about and pointed a reader at text that no longer exists.
It also attributed the rc 2 to `cp`, which returns 1.)

### 18. The corpus's first backslash ESCAPES (2026-08-19, #649)

Three scenarios added alongside the #649 fix, for a backslash-escaped `#` in
command text. All three are `visudo -c -f -` rc 0 `parsed OK` on all three
targets:

| scenario | input (command part) | oracle Cmnd_Specs |
|---|---|---|
| `escaped-hash-keeps-nopasswd` | `/bin/echo \#x, NOPASSWD: /bin/su` | `/bin/echo #x`, then `authenticate:false` + `/bin/su` |
| `even-backslash-run-before-hash` | `/bin/echo \\#x, NOPASSWD: /bin/su` | `/bin/echo \` only - NO second spec |
| `odd-backslash-run-before-hash` | `/bin/echo \\\#x, NOPASSWD: /bin/su` | `/bin/echo \#x`, then `authenticate:false` + `/bin/su` |

The second is the parity control and it is the interesting one: real sudo
truncates at the `#` when the backslash run before it is EVEN, because the
backslashes escape each other. So the grant genuinely disappears there and
reporting none is CORRECT, while reporting none on the other two is the #649
fail-open. An implementation that only asked "is the previous byte a
backslash?" gets rows 1 and 3 right and row 2 wrong.

**These are the corpus's FIRST backslash ESCAPES**, which is a narrower claim
than "first backslashes" and the distinction is the point. Checked mechanically
when they were added, `grep -l '\\' */input.sudoers` returned these three and
one other: `accept-continuation-line`, whose input is

```
carol ALL = \
    NOPASSWD: ALL
```

That backslash is a line CONTINUATION - a backslash at end of line, consumed by
`split_continuation` - and it never reaches the question this section is about,
which is what a backslash does to the byte AFTER it in the middle of a line. So
of the 45 pre-existing scenarios exactly one contained a backslash at all, and
none contained an escape.

The gap is the same shape as section 17's: the escaped-`#` fail-open discarded
the rest of a logical line with no diagnostic about it, and no differential run
could see it because nothing in the corpus had an escape to sample.

The neighbouring gap is still open. `split_continuation` (`parser.rs:168`) reads
that trailing backslash with a bare `rfind('\\')` and NO parity model, so an
EVEN run at end of line is read as a continuation and silently merges the next
rule. That is **#648**, it is pre-existing and unchanged by #649, and it is the
reason this section's parity control matters beyond its own row: after #649 the
comment stripper and `split_continuation` read backslashes on the SAME string
under two different models.

Rows 1 and 3 are L3 xfail against **#696** - an escape-RETENTION
divergence exactly analogous to #667's quote retention, and reached here for
the first time: the AST keeps the backslash (`/bin/echo \#x`) and `cvtsudoers`
reports the unescaped value (`/bin/echo #x`), with every structural field
agreeing. #696 asks for one ruling covering it and #667 together, since both
are the one cause: this parser does not dequote or unescape token values
anywhere.

Row 2 is deliberately NOT xfailed - measured 2026-08-19, its projections AGREE
with `cvtsudoers`. The harness fails an xfail entry whose projections match, so
listing it would hide a later real regression.

### 19. The negation sigil, all four call sites (2026-08-19, #670 #671 #672)

Four scenarios added alongside the negation-sigil sweep. `sudoers(5)` lets a
leading `!` negate a principal; four places in the crate had an opinion about
that and two of them were wrong.

| scenario | input | oracle |
|---|---|---|
| `accept-glued-bang-principal-boundary` | `alice!h1 = NOPASSWD: ALL` | rc 0; user `alice`, host `h1` NEGATED, `authenticate:false` |
| `accept-negated-quoted-principal` | `ALL,!"svc acct" ALL = (ALL) ALL` | rc 0; users `ALL` + `svc acct` NEGATED, host `ALL`, runas `ALL` |
| `accept-negated-runas-principal` | `alice ALL = (ALL,!root) /bin/ls` | rc 0; runasusers `ALL` + `root` NEGATED |
| `reject-escaped-bang-principal` | `alice\!h1 = NOPASSWD: ALL` | **rc 1** |

The fourth is the important one and it is a REJECT. An escaped `!` is not a
principal boundary, so a boundary scan that ignored escapes would parse an
invalid file as `alice\` / `!h1` and silently drop a correct `sudo-F01`. That
is a lost TRUE POSITIVE rather than a fail-open - the mirror image of the rest
of this class - and it is why `boundary.rs` gained a named separator-rule
predicate (`separator_escaped`) instead of the `!` scan hand-rolling its own.
Witnessed: removing that guard fails L1 on this scenario.

**Grounded facts, all re-derived on this host 2026-08-19 against sudo 1.9.17p2
and confirmed identical on el8/el9/el10:**

- A **RUN** of leading sigils is legal, not just one: `(!!root)`, `alice!!h1`
  and `!!alice ALL = ...` are all rc 0. #671's issue text proposed stripping a
  SINGLE `!`, which would still have reported `(!!root)` as invalid; the fix
  trims the run, matching `command_specs.rs`. A mutant using `strip_prefix`
  SURVIVED the first test set, which is why the multi-sigil rows exist.
- sudo COLLAPSES double negation rather than nesting it: `cvtsudoers` reports
  `(!!root)` as plain `{"username":"root"}` with no `negated` flag.
- A `!` after a comma CONTINUES the user list (`alice,!bob ALL = ...` is rc 0
  with users `alice` + `bob` negated), so it is not a boundary either.
- A `!` in the MIDDLE of a token really is invalid: `(ro!ot)` is rc 1.

**A fifth scenario was captured and then DROPPED**, recorded here because the
reason is a property of this corpus rather than of the change:
`alice ALL = (ro!ot) /bin/ls` is oracle-REJECT, but RuleSteward rejects it at
the LINT layer (`sudo-F02`), not the PARSE layer, and L1's `ours_rejects` keys
on `LineKind::Malformed`. It belongs to the documented "not a command-token
validator" class that is deliberately outside this corpus, so it is pinned by a
unit test (`mid_token_bang_is_still_invalid`) instead. Adding an `L1_XFAIL` to
accommodate it would have weakened L1 to fit a scenario that does not meet the
reject tier's contract.

`accept-negated-quoted-principal` is L3 xfail **#667**: the AST keeps the quotes
around the negated principal (`!"svc acct"`) where `cvtsudoers` reports
`!svc acct`, with every structural field agreeing. Same quote-RETENTION class as
section 17's four rows; this is simply the first input that puts a sigil and a
quoted principal in the same token.

### 20. The runas boundary and the quoted-principal premise (2026-08-19, #650 #652)

Four scenarios added alongside the #650/#652 fix. These two issues are one
commit because #650 MASKED #652's runas face: `is_denylist_char` matched the `"`
first and reported the quote as the invalid character, so fixing #650 alone
would have UNMASKED a still-live false FATAL on `("r t")`.

| scenario | input | oracle |
|---|---|---|
| `accept-quoted-close-paren-in-runas` | `alice ALL = (root,"a)b") NOPASSWD: /bin/ls` | rc 0; runasusers `root` + `a)b` |
| `accept-escaped-close-paren-in-runas` | `alice ALL = (root,a\)b) NOPASSWD: /bin/ls` | rc 0 |
| `accept-quoted-host-space-group-subj` | `%grp "h c" = /bin/ls` | rc 0; host `h c` |
| `accept-quoted-runas-principal-space` | `alice ALL = ("r t") /bin/ls` | rc 0; runasuser `r t` |

**The measured fact that shaped the fix: quoting legitimises the WHOLE denylist,
not just whitespace.** Re-derived on this host 2026-08-19 against sudo 1.9.17p2,
every row rc 0:

```
alice ALL = ("a b") /bin/ls     alice ALL = ("a(b") /bin/ls
alice ALL = ("a>b") /bin/ls     alice ALL = ("a!b") /bin/ls
%grp "h(c" = /bin/ls            %grp "h>c" = /bin/ls
```

So the fix is not "ignore whitespace inside quotes" but the simpler and more
honest "a CLEAN quoted region's interior is literal" - a single early return in
`first_invalid_char`, and one guard on `check_group_subject`'s sub-case (a).
`clean_double_quoted_interior` moved from `parser.rs` into `boundary.rs` to serve
both, rather than either lint growing its own quote model.

**Three rc-1 rows pin the other direction and are deliberately NOT scenarios.**
All three are LINT-level rejects (`sudo-F02`), and L1's `ours_rejects` keys on
`LineKind::Malformed`, so they would fail L1 the way the dropped
`reject-mid-token-bang-runas` did in section 19. They live as unit tests in
`tests/iss650_runas_boundary.rs`:

| input | rc | why it must still fire |
|---|---|---|
| `%bad group ALL = ALL` | 1 | an UNQUOTED space really does split the group name |
| `alice ALL = (a>b) /bin/ls` | 1 | an UNQUOTED denylist char is still invalid |
| `alice ALL = ("a b) /bin/ls` | 1 | an UNTERMINATED quote is not a clean region |

#652 states that without those rows the fix is satisfiable by DELETING the
predicate outright, and #669's abandoned arity check broke the first of them.
Both deletions were run as mutants and both are caught.

`accept-quoted-host-space-group-subj` is L3 xfail **#667**: the AST keeps the
quotes around `"h c"` where `cvtsudoers` reports `h c`. Same quote-RETENTION
class as sections 17 and 19, on the HOSTS axis this time; its arm asserts that
axis specifically so a divergence spreading to users or commands would fail.

### 21. The escape-blind comma, all three faces (2026-08-19, #675)

A backslash-escaped `\,` is a LITERAL comma inside ONE principal and does not
continue a `User_List`. Three conjuncts in `split_user_list` re-decided that
with bare predicates and got it wrong, so lines real sudo ACCEPTS folded to
`Malformed`; per #668 a `Malformed` line is invisible to every W/E pass, making
all three fail-opens that dropped a `NOPASSWD` grant with nothing said.

All rows re-derived on `rs-oracle{8,9,10}` (sudo 1.9.17p2 on el9), stdin only,
`--network=none`. **All three EL majors agree on every row**, so there is no
per-target divergence to model here.

| scenario | input | oracle |
|---|---|---|
| `accept-escaped-comma-user-list` | `alice\, h1 = NOPASSWD: /bin/ls` | rc 0; `User_List ["alice,"]` / `Host_List ["h1"]` |
| `accept-escaped-comma-glued-quote` | `a\,"b" = NOPASSWD: ALL` | rc 0; `["a,"]` / `["b"]` |
| `accept-escaped-comma-negated-host` | `a\,!h1 = NOPASSWD: ALL` | rc 0; `["a,"]` / `["h1"]` NEGATED |
| `reject-unescaped-comma-no-host-list` | `alice, h1 = NOPASSWD: /bin/ls` | **rc 1** |
| `reject-even-backslash-comma-continues` | `a\\, b = NOPASSWD: ALL` | **rc 1** |

The two rejects are what make this a two-sided sweep rather than "stop looking
at commas", and both fail for the RIGHT reason: visudo's caret lands on the `=`
in each case, so the `User_List` continued across the comma and no host list
remained. Neither is rejected for carrying an invalid username token, which is
how a reject-side control on this surface usually goes wrong.

`reject-even-backslash-comma-continues` is the PARITY control and the sharpest
row in the set. The SEPARATOR escape rule counts a backslash RUN mod 2, so an
EVEN run leaves the comma unescaped and the list really does continue. It is
what separates `separator_escaped` from a naive `ends_with('\\')` check, which
would call that comma escaped and convert a correct `sudo-F01` into silence.

**Face C was not in #675's sibling sweep.** The issue lists six sites and marks
the two comma conjuncts as "the last of that class in this function"; that was
true when written and false by the time it was fixed, because `c153bc5` had
since added a third one to the `!` boundary scan. It was found by the post-GREEN
adversarial review of faces A and B and reported back to #675. On `a\,!h1` the
`!` scan is the ONLY candidate producer, so an escape-BLIND conjunct there drops
the grant outright.

That sentence used to end "so unlike the opener guard's twin that site is
redundant against nothing", and #699's review measured it false. What is
load-bearing is the ESCAPE-AWARENESS, not the `,` member: making the conjunct
escape-blind turns named tests RED at both sites, but deleting the `,` member
outright leaves the whole suite green at both, because the continuation filter
re-answers the comma axis downstream. The two sites are symmetric after all.

**The three accepts are L3 xfail #645 Face B, not #667/#696.** The distinction is
deliberate and is the reason they carry a different number from every retention
row above: retention keeps the raw token intact and differs from `cvtsudoers`
only by dequoting or unescaping, whereas `comma_split` (a bare `s.split(',')`)
LOSES a byte - the recovered `alice\,` becomes the member `alice\`, comma gone,
escaping backslash kept. Calling that retention would be a doc-truth defect.
`accept-escaped-comma-glued-quote` is the corpus's only row diverging on TWO
axes at once, users by #645 and hosts by #667, and its arm states both.

None of this is introduced by #675: before the fix these three lines did not
parse at all and never reached L3, which is why the corpus had never sampled an
escaped comma in a principal. The entries are #645's acceptance signal, since
this harness fails an xfail entry whose projections match.

`L3_CLEAN_FLOOR` did NOT move (113 -> 113) while four of its five cross-check
figures did. Three accepts add +9 attempted and all three are xfail, giving back
-9 exactly. Nothing would have failed had the figures been left stale, which is
the cancellation that const's own warning describes; they were updated anyway.

## Scenario list

`accept-*` (oracle ACCEPTs on every target): `basic-all-grant`,
`nopasswd-specific`, `plain-specific-command`, `runas-noexec`,
`selinux-role-type` (L3 xfail #538), `timeout-option` (L3 xfail #538, found
2026-07-26 - see section 8), `notbefore` (L3 xfail #538, found 2026-07-26 -
see section 8), `defaults-global`, `defaults-negated`, `defaults-scoped-host`,
`user-alias-basic`, `user-alias-multi-spec`, `host-alias`, `cmnd-alias`,
`runas-alias`, `multi-hostgroup`, `multi-user-list`,
`user-list-whitespace-bug` (L3 xfail #538), `uid-subject`, `group-subject`,
`continuation-line`, `netgroup-subject`, `undefined-alias-ref` (L2 xfail,
added 2026-07-26 - see section 5), `alias-cycle` (L2 xfail, added
2026-07-26 - see section 5), `negated-command`, `negated-all`,
`host-netgroup`, `host-networkaddr`, `gid-subject`, `uid-leading-zero` (all
six added 2026-07-27, none xfailed - bugs to fix, not accepted divergences -
see section 10), `negated-user`, `negated-host` (added 2026-07-27, round 4,
none xfailed - project cleanly, first end-to-end negation-mark coverage -
see section 16), `negated-uid-subject` (added 2026-07-27, round 4; L1 xfail
- a tracked `rulesteward-core` parser bug, drafted but not filed - AND L3
xfail; see section 16), `glued-closing-quote-principal`,
`glued-closing-quote-with-inner-space`, `glued-closing-quote-after-comma-list`,
`spaced-closing-quote-control` (all four added 2026-08-03 with #651; all four
L3 xfail #667 - see section 17), `escaped-hash-keeps-nopasswd`,
`odd-backslash-run-before-hash` (both added 2026-08-19 with #649; both L3 xfail
#696, an escape-RETENTION divergence),
`even-backslash-run-before-hash` (added 2026-08-19 with #649; the parity
control, NOT xfailed - its projections agree - see section 18),
`glued-bang-principal-boundary`, `negated-runas-principal` (both added
2026-08-19 with the negation-sigil sweep, neither xfailed),
`negated-quoted-principal` (same sweep; L3 xfail #667 - see section 19),
`quoted-close-paren-in-runas`, `escaped-close-paren-in-runas`,
`quoted-runas-principal-space` (all three added 2026-08-19 with #650/#652, none
xfailed), `quoted-host-space-group-subj` (same pair; L3 xfail #667 on the HOSTS
axis - see section 20), `escaped-comma-user-list`,
`escaped-comma-glued-quote`, `escaped-comma-negated-host` (all three added
2026-08-19 with #675; all three L3 xfail **#645 Face B** on the USERS axis, and
the glued-quote one ALSO diverges on hosts by #667 - see section 21),
`escaped-bang-glued-quote`, `escaped-bang-run`, `escaped-bang-runas`,
`even-backslash-bang-boundary` (all four added 2026-08-19 with #699; three carry
an L3 xfail **#696** on the USERS axis and `escaped-bang-runas` is L3-CLEAN,
because L3 projects users/hosts/commands and not the runas group - see
section 22), `nbsp-host-principal` (added 2026-08-19 with #702; L3 xfail **#705**
on the HOSTS axis - see section 24), `even-run-glued-quote` (added 2026-08-20; L1 **and** L3 xfail
**#676** - see section 25).

`reject-*` (oracle REJECTs on every target; each independently confirmed to
also be a structural `sudo-F01` Malformed line in RuleSteward's own parser -
i.e. a clean agreement, not a divergence): `no-equals-garbage`,
`user-alias-bare`, `cmnd-alias-empty-members`, `defaults-bare`,
`user-host-no-eq`, `defaults-scope-no-target`, `user-spec-empty-cmnd`,
`equals-only` (the L1/L2 positive-control REJECT input), `escaped-bang-principal`
(added 2026-08-19 with the negation-sigil sweep; see section 19),
`unescaped-comma-no-host-list`, `even-backslash-comma-continues` (both added
2026-08-19 with #675; the one-byte control and the PARITY control - see
section 21), `lone-sigil-host-list` (added 2026-08-19 with #701 - see
section 23).

## 22. #699 - the escape-blind negation sigil

Four accept scenarios, added 2026-08-19 with the #699 fix. Every row was derived
on `rs-oracle{8,9,10}` by `capture_sudoers.sh` and independently re-derived by
hand against `rs-oracle9` (sudo 1.9.17p2) before the fix was written.

| scenario | input | visudo | cvtsudoers |
|---|---|---|---|
| `accept-escaped-bang-glued-quote` | `alice\!"h1" = NOPASSWD: ALL` | rc 0 | ONE user `alice!`, host `h1`, `authenticate:false` |
| `accept-escaped-bang-run` | `a\!!h1 = NOPASSWD: ALL` | rc 0 | user `a!`, host `h1` NEGATED |
| `accept-escaped-bang-runas` | `alice ALL = (\!root) /bin/ls` | rc 0 | runasuser `!root`, NOT negated |
| `accept-even-backslash-bang-boundary` | `alice\\!"h1" = NOPASSWD: ALL` | rc 0 | user `alice\`, host `h1` NEGATED |

**An escaped sigil is a CHARACTER, not a modifier.** Read those `cvtsudoers`
columns for shape and not just for rc: the escape is consumed and the `!`
survives inside the name (`alice!`, `a!`, `!root`). Three predicates in this
crate read a bare `!` as a sigil without asking whether it was escaped, so the
first two rows lost their boundary entirely - `Malformed`, and per #668 every
W/E lint suppressed on a passwordless-ALL grant - and the third drew a false
`sudo-F02`.

**The fourth row is the PARITY control and it is an ACCEPT, not a reject.** The
separator rule counts a backslash run mod 2, so `alice\\!` is an EVEN run, the
`!` is a real sigil again, and the boundary moves from the quote to the `!`
leaving the host negated. It is what separates `separator_escaped` from a naive
`ends_with('\\')`; that mutant leaves this row RED.

**A fifth was staged and then reclassified, by the harness rather than by
argument.** `alice ALL = (\\!root) /bin/ls` is `visudo` rc **1** - the even run
leaves a literal backslash, so the `!` is MID-token, the same reject as
`(ro!ot)`. Note that this is the OPPOSITE verdict from the row above it on the
same bytes, decided by grammar position. Staged as `reject-even-backslash-bang-runas`
it failed L1 immediately: RuleSteward answers `sudo-F02`, not `sudo-F01`, so it
is a LINT-level reject and belongs with the #650/#652 rc-1 rows as a unit test
(`an_even_backslash_run_leaves_the_runas_sigil_unescaped` in
`tests/iss699_escaped_sigil.rs`), not as a scenario. It was removed.

**The three L3 xfails are #696 ESCAPE retention, not #645.** `alice\!` and
`alice!` are the same token modulo one consumed escape, where #645's rows LOSE
the comma byte outright; the distinction is the same one section 21 draws in the
other direction. Two of the three - `accept-escaped-bang-glued-quote` and
`accept-even-backslash-bang-boundary` - ALSO diverge on hosts by #667 quote
retention, so like `accept-escaped-comma-glued-quote` they are **not
self-removing**: whichever of #667 and #696 lands second must delete them by
hand. `accept-escaped-bang-run` is single-axis and does retire itself.

**Provenance of the defect.** Not shipped. `prev != '!'` does not exist at
`a700c38` and appears at `c153bc5`, the #670/#671/#672 commit on this same
branch: that commit closed three UNESCAPED-sigil fail-opens and opened this
ESCAPED one. The face-C mutation gate ran over exactly this code and returned rc
0 with 0 survivors, because `cargo mutants` has no delete-a-conjunct operator
and a dropped guard inside a compound `&&` chain is invisible to it.

## 23. #701 - a principal-list half of nothing but negation sigils

One reject scenario, `reject-lone-sigil-host-list`, `alice! = NOPASSWD: ALL`.
`visudo -c -f -` **rc 1** on all three targets (`rs-oracle{8,9,10}`; the hand
re-derivation was on `rs-oracle9`, sudo 1.9.17p2, stdin, `--network=none`,
2026-08-19). `rs-oracle8` ships sudo **1.9.5p2**, not 1.9.17p2 - sections 21 and
22 scope the version to el9 and this one dropped the qualifier, which section 2
exists specifically to prevent.

`split_user_list` chose a boundary and never asked whether either half IS a
principal list. This line parsed as user `alice` / host `!`, became a well-formed
`UserSpec`, and RuleSteward reported `sudo-W01` - a passwordless-`ALL` grant -
off a file real sudo REFUSES to load, while dropping the `sudo-F01` that
correctly says the file is broken.

**Two lane regressions, not inherited defects**, confirmed two-sided against
binaries built at four revisions:

| input | `a700c38` (fork) | `c153bc5` | `11f6ea0` | `6abb10a` |
|---|---|---|---|---|
| `alice!` | `sudo-F01` CORRECT | **`sudo-W01`** | `sudo-W01` | `sudo-W01` |
| `a\!!` | `sudo-F01` CORRECT | `sudo-F01` | `sudo-F01` | **`sudo-W01`** |

The `!` boundary scan does not exist at `a700c38`. So `c153bc5` (#670/#671/#672)
introduced the first and `6abb10a` (#699) the second - each while fixing a
different member of the same class.

**Why one scenario and five unit tests.** The corpus row pins the shape at the L1
layer; the discriminating set is wider than one row and lives in
`tests/iss699_escaped_sigil.rs`: `alice!`, `alice!!`, `alice !`, `a\!!` and
`! h1` are all rc 1, against controls `alice!h1`, `alice!!h1`, `a\!!h1`,
`!!alice ALL` and `alice,!bob h1` which are all rc 0. The discriminator is
whether a principal FOLLOWS the sigil - not escape parity, not sigil count.
`! h1` is the one that puts the degenerate half on the USER side; a
postcondition checking only the host half passes every other row and still fails
it, and that is exactly what the `holds_a_principal(before)` mutant demonstrates.

**Why no gate caught it.** `cargo mutants` has no insert-a-conjunct operator, and
both rows are a MISSING conjunct, so the scoped gate returned rc 0 with 25
mutants and 0 missed over exactly this code. Every `!`-bearing test in the crate
put a principal after the sigil, and all four #699 scenarios are `accept-*`. It
was found by the impl-AWARE adversarial reviewer and, independently, by the
suppression lens in the same ATL round.

**Deliberately still divergent:** `alice!"" = ...` is rc 1 and RuleSteward still
reports `sudo-W01` on it. `""` holds a non-sigil character, so `holds_a_principal`
passes it through. That is **#677**, which owns the empty-principal question;
folding it in here risks the #669/#677 masking interaction this lane records as
its sharpest hazard.

## 24. #702 - sudo separates on `[[:blank:]]` only

One accept scenario, `accept-nbsp-host-principal`, input `"a"<NBSP> = NOPASSWD: ALL`
(U+00A0). `visudo -c -f -` **rc 0** on all three targets; `cvtsudoers -f json` on
`rs-oracle9` (sudo 1.9.17p2) reports `User_List [{"username":"a"}]`,
`Host_List [{"hostname":"\u00a0"}]`, `authenticate:false`, command `ALL`. The NBSP is
the HOST NAME.

sudo's `toke.l` discards `[[:blank:]]+` - space and tab - and nothing else. Every
other whitespace character is an ordinary `WORD` byte. This crate asked
`char::is_whitespace` in SIX places on the principal path, so one concept had six
recognizers: the line trim in `classify_logical_line`, the user-spec segment
splitter in `split_top_level_segments`, the LHS trim in `classify_user_spec`, and
in `split_user_list` the entry trim, the closer guard and
`unquoted_whitespace_runs`. All six now route through `is_sudoers_blank`.

**Both failure directions were live, and the second is why this is a class fix
rather than another patch:**

* a line `visudo` ACCEPTS lost its `Host_List`, folded to `Malformed`, and per #668
  every W/E lint on it was suppressed - a passwordless-`ALL` grant evaluated by
  nothing.
* #701's `holds_a_principal` used the NARROW class while the trims stayed WIDE, so
  the trim ate the character that made a half a principal and the postcondition
  then correctly rejected the remainder. Rows like `a!<VT>` and `ALL !<NBSP>` are
  `visudo` rc 0, were CORRECT at `6abb10a`, and regressed at `360ca9c`. VT
  (U+000B) and FF (U+000C) are pure ASCII, so this was never a Unicode corner.

Four consecutive adversarial rounds on this lane each found one defect and all four
were the same shape: two recognizers of one lexical concept disagreeing. Narrowing
one created the next round's regression at the seam with the one beside it.

**Two `boundary_substrate.rs` rows were RE-PINNED rather than deleted.**
`"ab"<NBSP>,alice ALL` and `alice,<NBSP>"b c" ALL` are `visudo` **rc 1**, so no split
of them is the correct one; those tests pinned an arbitrary internal answer that came
from the recognizers disagreeing. Their new answers are recorded with the reasoning,
their rc-1 status is restated, and an rc-0 control was ADDED to the first (it had
none). Nothing oracle-anchored moved: RuleSteward reports `sudo-W01` on both before
and after, which is #669's three-token gap and remains the live defect there.

**Deliberately still divergent, and xfailed as #705:** the host-token layer BELOW
`split_user_list` still discards the character, so this scenario's `Host_List`
projects EMPTY where `cvtsudoers` has one entry. The verdict is correct; the
structure is not. Routing `comma_split` as well moves it to `[""]` rather than to the
NBSP, so at least one more recognizer remains - enumerated in #705 rather than
guessed at here.

## 25. #704 + the postcondition's shape, and #676 gaining a corpus row

**One accept scenario, `accept-even-run-glued-quote`**, input `\\"h1" = NOPASSWD: ALL`.
`visudo -c -f -` **rc 0** on all three targets; `cvtsudoers` reports user `\` and
host `h1`. An EVEN backslash run consumes itself, so the `"` after it really does
open a quoted region.

RuleSteward answers `sudo-F01`. `simple_quote_pairs` asks `quote_is_escaped` - the
INSIDE-a-string rule - at an OPENING position, finds no pair, and the line folds to
`Malformed`. That is **#676** verbatim, and its fix (alternating the two escape
rules) is face D and out of scope here. The scenario carries BOTH an `L1_XFAIL`
entry (the F01-verdict divergence) and an `L3_XFAIL` entry (every projection axis
empty), so it retires itself when #676 lands.

**Why it is entered now rather than when #676 was filed.** #702 changed which
members of the family are visible, and the change deserves to be on the record
rather than discovered later. `\\"<VT>"` and `\\"<NBSP>"` answered CORRECTLY before
#702 - but only by accident: the wide whitespace predicate emitted a run at the
exotic blank, and that run was the line's only candidate. Narrowing the blank class
to sudo's `[[:blank:]]` removed the accident. The pure-ASCII members (`\\"h1"`,
`\\"ax"`) were wrong at the fork point and are wrong now. Nothing about the defect
moved; only which spellings expose it. The scenario pins the ASCII member so the
family is auditable instead of silently re-classified.

**The postcondition is a FILTER again.** #702's round changed it to an abort
(`return (lhs, "")` on a degenerate half) and that was a fail-open on a family of
ACCEPTED lines: `! alice h1 = NOPASSWD: ALL` is rc 0 with user `alice` NEGATED and
host `h1`, and the abort answered `sudo-F01`, suppressing every W/E lint per #668.
sudo's `toke.l` discards `[[:blank:]]`, so `opuser: '!' opuser` binds a sigil across
a blank; the first candidate's `before` is `"!"` and the SECOND is the correct one.
The abort's only advantage - rc-1 rows like `! " a` - was a workaround for #704.

**#704 is fixed, and NOT the way its own sketch proposed.** The sketch said to add
`"` to the excluded character set. Grounding refutes that: `alice " "` and
`alice "!"` are **rc 0** - a quoted span with any interior is a legal name - while
`alice ""` is rc 1. So the predicate is "a character outside `{! , " blank}`, OR a
quote pair with a NON-EMPTY interior". `a!:` is rc 1 and was already correct, so `:`
is deliberately absent: the top-level `:` splits segments upstream of the predicate.

Derived on `rs-oracle9` (sudo 1.9.17p2), stdin, `--network=none`, 2026-08-20.
`rs-oracle8` ships sudo 1.9.5p2; the rc values above were confirmed on all three.

## Re-capturing

```bash
bash crates/rulesteward-sudoers/tests/corpus/sudoers-oracle/capture_sudoers.sh <output-dir>
```

reads every scenario's `input.sudoers` from its OWN directory (siblings of
the script itself), re-derives all four oracle results against
`rs-oracle{8,9,10}`, and writes `<output-dir>/<scenario>/{input.sudoers,
el8.json,el9.json,el10.json}`. `scripts/rs-oracle-diff.sh sudoers` (`just
diff-sudoers`) drives this against a fresh temp directory and re-points
`sudoers_corpus_oracle.rs` at it via `RS_ORACLE_CORPUS_SUDOERS`.
