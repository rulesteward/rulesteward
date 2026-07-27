# sudoers oracle corpus provenance (session 9k-1, Lane C, #538)

Captured 2026-07-25 by `capture_sudoers.sh` (the same script IS the capture
implementation for both this committed corpus and `just diff-sudoers`'s live
re-derivation - there is no second, separately-maintained capture path).

## What is captured

32 scenario directories (24 `accept-*`, 8 `reject-*`) - 30 captured
2026-07-25, plus 2 more `accept-*` scenarios added 2026-07-26 (review found
L2's original xfail table was empty for the wrong reason; see section 5),
each holding:

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
2026-07-26 - see section 5).

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
