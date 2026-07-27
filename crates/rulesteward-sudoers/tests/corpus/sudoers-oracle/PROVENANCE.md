# sudoers oracle corpus provenance (session 9k-1, Lane C, #538)

Captured 2026-07-25 by `capture_sudoers.sh` (the same script IS the capture
implementation for both this committed corpus and `just diff-sudoers`'s live
re-derivation - there is no second, separately-maintained capture path).

## What is captured

30 scenario directories (22 `accept-*`, 8 `reject-*`), each holding:

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
were confirmed IDENTICAL (accept) across all three targets.

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

### 5. `-c` vs `-s` (strict): no divergence found on any of the three images

See the Tier-1 test's module doc "L2" section. `L2_XFAIL` is empty by
measurement, not assumption.

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
the task's "structure-only, full-fidelity is a follow-up" framing.

## Scenario list

`accept-*` (oracle ACCEPTs on every target): `basic-all-grant`,
`nopasswd-specific`, `plain-specific-command`, `runas-noexec`,
`selinux-role-type` (L3 xfail #538), `timeout-option`, `notbefore`,
`defaults-global`, `defaults-negated`, `defaults-scoped-host`,
`user-alias-basic`, `user-alias-multi-spec`, `host-alias`, `cmnd-alias`,
`runas-alias`, `multi-hostgroup`, `multi-user-list`,
`user-list-whitespace-bug` (L3 xfail #538), `uid-subject`, `group-subject`,
`continuation-line`, `netgroup-subject`.

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
