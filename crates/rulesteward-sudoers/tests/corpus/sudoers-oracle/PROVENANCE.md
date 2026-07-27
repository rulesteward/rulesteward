# sudoers oracle corpus provenance (session 9k-1, Lane C, #538)

Captured 2026-07-25 by `capture_sudoers.sh` (the same script IS the capture
implementation for both this committed corpus and `just diff-sudoers`'s live
re-derivation - there is no second, separately-maintained capture path).

## What is captured

38 scenario directories (30 `accept-*`, 8 `reject-*`) - 30 captured
2026-07-25, plus 2 more `accept-*` scenarios added 2026-07-26 (review found
L2's original xfail table was empty for the wrong reason; see section 5),
plus 6 more `accept-*` scenarios added 2026-07-27 (review found the users/
hosts type tag, command negation, and uid/gid canonicalization findings;
see section 10), each holding:

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
see section 10).

`reject-*` (oracle REJECTs on every target; each independently confirmed to
also be a structural `sudo-F01` Malformed line in RuleSteward's own parser -
i.e. a clean agreement, not a divergence): `no-equals-garbage`,
`user-alias-bare`, `cmnd-alias-empty-members`, `defaults-bare`,
`user-host-no-eq`, `defaults-scope-no-target`, `user-spec-empty-cmnd`,
`equals-only` (the L1/L2 positive-control REJECT input).

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
