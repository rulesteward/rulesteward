## Auditd Differential-Oracle Corpus Provenance (Lane A, session 9k-1)

This corpus is DISTINCT from `crates/rulesteward-auditd/tests/corpus/auditd/`
(the pre-existing cost/tier/STIG grammar corpus used by `cost_corpus.rs` and the
`test_lints_*` suites). That corpus's `manifest.json` `"validation"` blocks say
`"method": "grammar-only"` and every `"verdict"` is `"valid"` - meaning it was
never checked against a real `auditctl`. This corpus exists to close that gap:
every row here is a REAL `auditctl -R` verdict, captured live.

### Images and versions (captured 2026-07-25)

| target file | image | `rpm -q audit` |
|---|---|---|
| `el8.tsv` | `rs-oracle8` | `audit-3.1.2-1.el8_10.1.x86_64` |
| `el9.tsv` | `rs-oracle9` | `audit-3.1.5-8.el9.x86_64` |
| `el10.tsv` | `rs-oracle10` | `audit-4.0.3-5.el10.x86_64` |

Built per `tools/oracle-images/README.md`. The exact version string is
re-captured live by `capture_auditd.sh` on every run (committed here, embedded
in each file's `#`-header) rather than hardcoded, so a `just diff-auditd` run
against refreshed base images re-derives its own per-version positive control.

### Safety invariant (non-negotiable; see `tools/oracle-images/README.md` "Lane A")

Audit netlink is NOT namespaced: a container that can reach it mutates the HOST
kernel's ruleset. Every capture in this corpus was taken via
`docker run --rm --network=none --cap-add=AUDIT_CONTROL rs-oracle<N>`, with the
`auditctl -s` canary run FIRST in every single container instantiation. The
canary got `Error sending status request (Operation not permitted)` (rc 255)
every time, confirming netlink was never reachable; had it ever succeeded,
`capture_auditd.sh` aborts (exit 2) instead of capturing anything, and no rule
in this corpus was ever actually loaded into a kernel ruleset.

### Corpus format

Flat TSV, one file per target: `el8.tsv` / `el9.tsv` / `el10.tsv`. Each data row:

```
target\tid\tverdict\tclass\trule\tevidence
```

split with `splitn(6, '\t')`. `rule` and `evidence` are escaped (`\\` -> `\`,
`\t` -> a real TAB, `\x01` -> the 0x01 byte) because several scenarios carry a
literal TAB or 0x01 byte in the rule text itself (see below); a raw byte there
would otherwise corrupt the column split. `target` is the docker image tag
(`rs-oracle8`/`9`/`10`), independent of the `el8`/`el9`/`el10` filename (the
filename groups by RHEL major; the column names the exact image, mirroring
`tools/fapolicyd-probe-update`'s `dataset` column being redundant with its
filename too). A 4-line `#`-header precedes the data rows in every file; line 2
carries `audit_version=<rpm -q audit output>`, which
`auditd_corpus_oracle.rs`'s `assert_version_divergence_control` reads to
confirm the three captures are genuinely distinct (not the same file copied
three times).

### Scenarios: 52 ids x 3 targets = 156 rows

**33 `existing`-class scenarios** re-ground the pre-existing
`tests/corpus/auditd/*/audit.rules` corpus with a REAL per-line verdict: one
representative line per scenario (the first non-comment, non-blank line of its
`audit.rules` - the same line a real `augenrules`-assembled file would present
to `auditctl` first). `rocky8-live-from-log-execve` is excluded (it ships no
`audit.rules`, only a log sample).

**A genuine, unplanned finding surfaced by this regrounding:** 5 of the 33
existing scenarios (`rocky9-arch-paired`, `rocky9-execve-auid`,
`rocky9-filesystem-list`, `rocky9-priv-commands`, `rocky9-task-list`) use a
shell-quoting convention in their `-F` field expressions, e.g.
`-F 'auid>=1000'` (literal single quotes around the field spec). Real
`auditctl -R` REJECTS these (`-F unknown field: 'auid` - the leading quote
character glues onto the field name), because `audit_strsplit` treats quotes as
literal bytes, never stripping them - this is issue #584's exact territory,
found organically rather than synthesized. `rulesteward_auditd::parser`
deliberately treats this differently (it strips a token's balanced
leading+trailing single quote, an admin-UX leniency - see `parser.rs`'s
`quote_strip_balanced_is_stripped` test), so `oracle::classify_rule_line` must
NOT reuse that lenient tokenizer; see the doc comment in
`tests/auditd_corpus_oracle.rs`. `rocky9-never-suppress` hits the same
mechanism via `-F 'uid=0'`.

**A second unplanned finding:** control-only lines (`-D`, `-b 8192`) fed ALONE
via `auditctl -R <file>` are REJECTED SILENTLY (rc 1, empty stdout AND stderr),
even though the SAME flag invoked directly on argv (`auditctl -D`) gets a
distinct, non-silent EPERM message (`Error sending rule list data request`).
This affects 3 existing scenarios whose representative line is a bare `-D`
(`rocky9-huge-ruleset`, `rocky9-stock-control`, `rocky10-rulesd-multifile`) and
one bare `-b 8192` (`rocky9-exclude-msgtype`). Measured directly (not just
through the batch harness) on `rs-oracle8`, confirmed identical on `rs-oracle9`/
`rs-oracle10`. Plausible explanation, NOT verified against source: real
`augenrules`/`service auditd start` pipelines likely issue `-D` as its own
`auditctl -D` invocation BEFORE `auditctl -R`, rather than ever passing a raw
`-D` line through `-R` itself - which would explain why this "just works" in
production despite `-R` alone rejecting it. This is recorded as ground truth,
not a bug to fix; `oracle::classify_rule_line` must replicate it (a standalone
control-only line classifies REJECT).

**19 new scenarios** ground `#584`/`#601`/`#489`/`#491` directly (measured
2026-07-25 on all three images; identical verdict on every image - see "Version
divergence" below):

| id | issue | rule (unescaped) | verdict | evidence |
|---|---|---|---|---|
| `iss584-quoted-path-space` | #584 | `-w "/etc/my dir/file" -p wa -k q1` | reject | (silent) |
| `iss584-backslash-escaped-space` | #584 | `-w /etc/my\ dir/file -p wa -k q2` | **accept** | `Error sending add rule data request` |
| `iss584-embedded-tab-glues-flag` | #584 | `-w /etc/passwd<TAB>-p wa -k q3` | reject | (silent) |
| `iss584-all-tabs-separators` | #584 | `-a<TAB>always,exit<TAB>-S<TAB>execve<TAB>-k<TAB>tabsep` | reject | (silent) |
| `iss584-quoted-field-expr` | #584 | `-a always,exit -F arch=b64 -S execve -F 'auid>=1000' -k q6` | reject | `-F unknown field: 'auid` |
| `iss601-uppercase-perm-all` | #601 | `-w /etc/passwd -p WA -k q4` | accept | `Error sending add rule data request` |
| `iss601-uppercase-perm-mixed` | #601 | `-w /etc/passwd -p Wa -k q5` | accept | `Error sending add rule data request` |
| `iss489-multi-key` | #489 | `-a always,exit -F arch=b64 -S execve -k key1 -k key2` | accept | `Error sending add rule data request` |
| `iss489-key-at-cap-256` | #489 | `-k` value of exactly 256 bytes | accept | `Error sending add rule data request` |
| `iss489-key-over-cap-257` | #489 | `-k` value of exactly 257 bytes | reject | (silent) |
| `iss489-embedded-0x01-in-key` | #489 | `-k key<0x01>withsep` | accept | `Error sending add rule data request` |
| `iss491-neg-a0` | #491 | `-F a0=-1` | accept | `Error sending add rule data request` |
| `iss491-neg-a1` | #491 | `-F a1=-1` | accept | `Error sending add rule data request` |
| `iss491-neg-a2` | #491 | `-F a2=-1` | accept | `Error sending add rule data request` |
| `iss491-neg-a3` | #491 | `-F a3=-1` | accept | `Error sending add rule data request` |
| `iss491-neg-pers` | #491 | `-F pers=-1` | reject | `-F value should be number for pers` |
| `iss491-neg-devminor` | #491 | `-F devminor=-1` | reject | `-F value should be number for devminor` |
| `control-accept` | (control) | `-a always,exit -F arch=b64 -S execve -k exec_control` | accept | `Error sending add rule data request` |
| `control-reject` | (control) | `-a always,exit -F perm=zz -S execve` | reject | `Permission can only contain  'rwxa'` |

The `-k` 256/257-byte boundary was found EMPIRICALLY by bisecting lengths
44/63/64/128/200/255/256/257/300/512 against `rs-oracle8`; 256 is the exact,
measured cutoff (not assumed from the issue text).

The `#489` a0-a3-vs-pers/devminor split, and the `#601` uppercase-permission
acceptance, both confirm the premise in the issue exactly as measured: `a0`-`a3`
accept a negative decimal representation (`strtoll`-shaped), `pers`/`devminor`
reject it (`-F value should be number for <field>`); uppercase permission
letters (`WA`, `Wa`) are accepted identically to lowercase.

### Version divergence (CONTRIBUTING.md's per-version positive control)

Measured fact: NONE of the 52 scenarios' ACCEPT/REJECT verdict differs across
`el8`/`el9`/`el10` (audit-userspace 3.1.2 / 3.1.5 / 4.0.3) - every row is
byte-identical in outcome across all three captures. The per-version divergence
control this project's contract calls for is therefore satisfied by the LIVE
`audit_version=` string captured into each file's header (see "Corpus format"
above and `assert_version_divergence_control` in the test), not by a
rule-level behavioral split - there isn't one to pin, at least not among the
scenarios this corpus covers.

### Honest exclusion: #530 / #531

`#530` and `#531` need kernel-side operator restrictions that only manifest on
a REAL rule load (the kernel enforcing a restriction on which comparison
operators are legal for a given field once the rule is actually active), which
the safe, sandboxed `-R`-only oracle here can never reach (every add is refused
by `EPERM` before the kernel would ever evaluate the rule). This corpus does
NOT xfail these - they are not represented at all, because no offline capture
of this shape could ever produce ground truth for them. A future live-VM
oracle (not a container) would be the right instrument, tracked separately.

### Reproducing this corpus

```bash
bash crates/rulesteward-auditd/tests/corpus/auditd-oracle/capture_auditd.sh /tmp/fresh-auditd-corpus
```

or via the full drift recipe: `just diff-auditd` (needs `rs-oracle8/9/10` built
per `tools/oracle-images/README.md`).
