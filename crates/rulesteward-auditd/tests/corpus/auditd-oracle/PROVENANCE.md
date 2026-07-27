## Auditd Differential-Oracle Corpus Provenance (Lane A, session 9k-1)

This corpus is DISTINCT from `crates/rulesteward-auditd/tests/corpus/auditd/`
(the pre-existing cost/tier/STIG grammar corpus used by `cost_corpus.rs` and the
`test_lints_*` suites). That corpus's `manifest.json` `"validation"` blocks say
`"method": "grammar-only"` and every `"verdict"` is `"valid"` - meaning it was
never checked against a real `auditctl`. This corpus exists to close that gap:
every row here is a REAL `auditctl -R` capture, taken live.

## AMENDMENT (2026-07-26/27): raw facts, not a precomputed verdict

The barrier caught a corpus that would have forced RuleSteward to REJECT `-D`,
the first line of essentially every real `audit.rules` file. The first draft's
`capture_auditd.sh` decided "accept"/"reject" itself, with
`grep -qF "Error sending add rule data request"`. That string only ever fires
on the ADD-RULE netlink path (`-w`/`-a`); every control-only line (`-D`, `-b`,
...) was therefore recorded as a parse REJECT regardless of what really
happened. Owner-approved full remediation: **the capture script now records
raw facts (`rc`, `stdout`, `stderr`) only; `rulesteward_auditd::oracle::
classify_capture` (Rust, unit-tested, clippy'd, mutation-gated) makes the
verdict.** See `crates/rulesteward-auditd/src/oracle.rs` and
`crates/rulesteward-auditd/tests/auditd_corpus_oracle.rs`.

Three things this amendment corrects outright, all previously stated as ground
truth in this file and all WRONG:

1. "A standalone control-only line classifies REJECT" (old line 93-94) - see
   "The silent-rc1 blind spot" below. The correct statement is that such a line
   is **UNOBSERVABLE**, not REJECT.
2. `rocky9-filesystem-list`'s `fstype` divergence was left unclassified with a
   raw evidence string - see "The fstype finding" below: it is a sandbox
   artifact (`Unusable::SandboxLimited`), not a rule-content REJECT.
3. `control-reject`'s rule (`-F perm=zz`) doubled as a product-divergence row -
   see "Positive control changed" below.

### Images and versions (captured 2026-07-25, images unchanged this amendment)

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
`docker run --rm -i --network=none --cap-add=AUDIT_CONTROL rs-oracle<N>`, with
the `auditctl -s` canary run FIRST, before EVERY rule line, inside the same
container instantiation (this amendment batches all ~71 scenario lines into
ONE container per image rather than one container per line - see
`capture_auditd.sh`'s "Batching" section - which means MORE canary checks per
capture, not fewer). The canary got
`Error sending status request (Operation not permitted)` every time, confirming
netlink was never reachable; had it ever succeeded, `capture_auditd.sh` aborts
(exit 2) instead of capturing anything, and no rule in this corpus was ever
actually loaded into a kernel ruleset.

### Corpus format

Flat TSV, one file per target: `el8.tsv` / `el9.tsv` / `el10.tsv`. Each data
row is EXACTLY 10 tab-separated fields:

```
target  id  class  rc  rule_len  out_len  err_len  rule  stdout  stderr
```

split with `str::split('\t')` and the field COUNT asserted (never `splitn`:
every field is escaped, so no raw tab survives inside one). `rule_len`/
`out_len`/`err_len` are byte lengths measured INSIDE the capture container
before the value crosses the host's bash boundary (bash cannot hold a NUL
byte); the replay test asserts `unescape(field).len() == recorded_len`, which
is what catches a truncation or an escaping bug with no external tool needed.
Escapes: `\\` -> `\`, `\t` -> TAB, `\n` -> LF, `\r` -> CR, `\xHH` -> that byte,
and the two-character sentinel `\0` meaning "this field is the empty string"
(paired with `\x20` escaping a leading/trailing space) so no field is ever
empty-looking or starts/ends in whitespace. A 5-line `#`-header precedes the
data rows in every file; line 2 carries `target=... image=...
audit_version=<rpm -q audit output>` and line 3 carries `captured=<UTC
timestamp>` **on its own line** (moved off the `audit_version=` line this
amendment: the timestamp is the only thing that changes on every recapture, so
"every line except `# captured=`" is now the exact byte-identity check for "did
this recapture actually change anything" - the first draft's `f=$(mktemp)`
nondeterminism inside the container is also gone, replaced by the fixed path
`/tmp/rs-oracle-line.rules`, since the filename is an INPUT we choose rather
than an observation).

### Scenarios: 71 ids x 3 targets = 213 rows

**33 `existing`-class scenarios** re-ground the pre-existing
`tests/corpus/auditd/*/audit.rules` corpus with a REAL per-line capture: one
representative line per scenario (the first non-comment, non-blank line of its
`audit.rules` - the same line a real `augenrules`-assembled file would present
to `auditctl` first). `rocky8-live-from-log-execve` is excluded (it ships no
`audit.rules`, only a log sample).

**19 `#584`/`#601`/`#489`/`#491` grounding scenarios plus 2 positive controls**
carried over from the first draft (`control-reject`'s RULE changed - see
below).

**18 new grounding scenarios** (this amendment; see "Fallback scope" below for
why 18 new ids, not a larger nominal count):

- `p-invalid-lower` / `p-invalid-upper` (`-p z` / `-p Z`): closes #601's other
  side - an INVALID (not merely uppercase) permission letter is rejected by
  BOTH sides, on both watch flags (`-p`) and field filters (`-F perm=`, see
  `f-perm-invalid-letter`).
- `op-ne` / `op-lt` / `op-gt` / `op-le` / `op-ge` / `op-and` / `op-andeq`:
  unquoted comparison operators. Before this amendment every `>=`-shaped
  example in the corpus was QUOTED (`-F 'auid>=1000'`, itself #584's own
  territory), so an implementation rejecting every operator except `=` would
  have passed the whole suite undetected. All 7 ACCEPT on both sides.
- `k-cap-valid-longer-line` / `k-cap-invalid-shorter-line`: the anti-monotone-
  length pair for #489's 256-byte `-k` cap - the ACCEPT row's overall LINE is
  longer (padded with extra, semantically inert `-F` clauses) than the REJECT
  row's, so no naive "reject if the line is long" rule can separate them by
  line length alone; only the `-k` VALUE's own length matters.
- `d-extra-silent` / `d-k-only-silent` / `d-k-extra-silent`: see "The
  MSG_SYSLOG-under--R finding" below - NOT the loud confirmation of #541 this
  lane originally planned.
- `f-unknown-field-unquoted`, `lead-A-prepend`, `lead-garbage`,
  `s-unknown-syscall`: named singles (unquoted unknown field name, the `-A`
  prepend leading flag, an unrecognised leading token, an unknown syscall
  name).
- `f-perm-invalid-letter` (`-F perm=zz`): moved OFF `control-reject` this
  amendment - see "Positive control changed" below.

### The silent-rc1 blind spot (supersedes the old "standalone control-only
line classifies REJECT" claim)

Control-only lines (`-D`, `-b 8192`, and this amendment's `-D extra`/`-D -k`/
`-D -k mykey extra`) fed via `auditctl -R <file>` are SILENT (rc 1, both
streams empty). The historical bug treated this silence as a REJECT for every
line, indiscriminately. The corrected model, grounded against `audit-userspace`
`src/auditctl.c` `setopt()` (read live this session at the three shipped tags
v3.1.2/v3.1.5/v4.0.3 - see `oracle.rs`'s `SILENT_SUCCESS_LEADING_FLAGS` doc for
exact citations): a leading flag's SUCCESS path (`-D`'s `delete_all_rules(fd)`,
`-b`/`-e`/`-f`/`-r`'s `audit_set_*(fd, ...)`, `--loginuid-immutable`,
`--backlog_wait_time`) sends its own netlink message and, on failure (EPERM in
this sandbox), returns without printing anything - so a silent rc-1 for one of
these flags is **AMBIGUOUS**: it is produced identically by a successful parse
(silently EPERM'd) and by a genuine parse refusal (if one existed and were also
silent). No pure function of `(rc, stdout, stderr)` can separate those two, so
these rows classify `Unusable::SilentNonAddLine` and sit on the test's
`UNOBSERVABLE` table rather than being called either verdict. This is exactly
the opposite of the old "classifies REJECT" claim, and is the finding the
adversarial review's `-D` counterexample forced.

By contrast, an add-shaped line (`-w`/`-a`) that parses is ALWAYS loud under
this sandbox (`Error sending add rule data request`, from
`audit_add_rule_data`'s caller in `auditctl.c`), so a silent rc-1 for one of
THOSE is conclusive evidence of a genuine parse refusal - see
`silence_is_conclusive`'s doc comment in `oracle.rs` for the full reasoning and
its own pinning unit tests.

### The MSG_SYSLOG-under--R finding (new this amendment)

This lane originally planned `-D extra` / `-D -k` / `-D -k mykey extra` as LOUD
confirmations of issue #541's field-count reject: `auditctl.c`'s `case 'D':`
does call `audit_msg(LOG_ERR, "Wrong number of options for Delete all
request")` unconditionally on a count mismatch, and that check happens BEFORE
any netlink call, so it should be loud regardless of the EPERM sandbox.
Empirically, on all three EL majors, all three rows are SILENT (rc 1, both
streams empty) instead. Root cause, found by reading `auditctl.c`'s `main()`:
the `-R <file>` invocation form (`argc == 3 && strcmp(argv[1], "-R") == 0`)
calls `set_aumessage_mode(MSG_SYSLOG, DBG_NO)`, which redirects EVERY
`audit_msg()`-routed diagnostic to syslog instead of stderr for the remainder
of that invocation - including `case 'D'`'s count check. Field/value validation
messages (`-F unknown field: ...`, `Permission can only contain 'rwxa'`, `-F
value should be number for ...`) remain visible because they are printed by
`audit_number_to_errmsg`, a DIRECT `fprintf(stderr, ...)` call in `libaudit.c`
that bypasses `audit_msg()`/the message-mode system entirely. This explains
both this new finding and the ORIGINAL silent-`-D` finding under one single
mechanism, and is why all three new `-D`-shaped rows joined `UNOBSERVABLE`
(`d-extra-silent`, `d-k-only-silent`, `d-k-extra-silent`) instead of confirming
a loud pin. `-R` remains the correct oracle shape regardless (see
`tools/oracle-images/README.md`); this finding is about which diagnostics `-R`
can surface, not about which invocation form to use.

### The fstype finding (`rocky9-filesystem-list`)

`-a always,filesystem -F fstype=ext4 -F 'auid>=1000' -F 'auid!=unset' -k
fs_ext4` prints `fstype filter is not supported by the kernel` - identical,
byte-for-byte, across el8/el9/el10 (three DIFFERENT compiled audit-userspace
binaries: 3.1.2/3.1.5/4.0.3). Docker containers share the HOST kernel (there is
no per-image guest kernel), so three different binaries reporting the exact
same "kernel" fact is consistent with a RUNTIME kernel-feature query (this
session's sandbox kernel) rather than a per-build compile-time constant - and
the phrasing itself ("not supported by THE KERNEL", not "unknown fstype value"
or "filesystem list not supported") names the kernel specifically. Classified
`Unusable::SandboxLimited`: a property of this capture environment, not of the
rule. (The exact C call site was not pinned to a specific line in this
session's source read - the message text was not found in `auditctl.c` or
`libaudit.c` at the fetched commit, likely a distro-patched or generated
table - so this conclusion rests on the cross-image byte-identity argument
above plus the wording, not a line citation. Flagged honestly rather than
asserted with false precision.)

### Positive control changed (`control-reject`)

The first draft's `control-reject` rule was `-a always,exit -F perm=zz -S
execve` - loud and REJECT on the real oracle, but RuleSteward's OWN parser also
accepts it (`-F perm=` values are stored as an unvalidated string, no `rwxa`
letter-set check), which means this same row is ALSO a product-divergence row.
A positive control must never double as an XFAIL: if it did, a broken harness
and a real divergence would be indistinguishable. The rule moved to
`-a always,exit -F nosuchfield=1 -S execve` (loud REJECT, `-F unknown field:
nosuchfield`, on BOTH sides - RuleSteward's own field-name table also has no
`nosuchfield` entry, so this can never become an XFAIL). The original rule's
divergence is still grounded, now under its own id: `f-perm-invalid-letter`
(an XFAIL, not a control).

### Product/oracle divergences: 18 XFAIL ids (see `auditd_corpus_oracle.rs`'s
`XFAIL` for the full per-id reasons)

- **7 quote-stripping** (deliberate parser leniency, `parser.rs:277-287`):
  `rocky9-arch-paired`, `rocky9-execve-auid`, `rocky9-field-compare`,
  `rocky9-never-suppress`, `rocky9-priv-commands`, `rocky9-task-list`,
  `iss584-quoted-field-expr`.
- **2 TAB tokenization** (#584): `iss584-embedded-tab-glues-flag`,
  `iss584-all-tabs-separators`.
- **2 `-k` cap enforcement missing** (#489): `iss489-key-over-cap-257`,
  `k-cap-invalid-shorter-line`.
- **2 `-F` value typing missing** (#491): `iss491-neg-pers`,
  `iss491-neg-devminor`.
- **1 `-F perm=` letter validation missing** (#601's other half):
  `f-perm-invalid-letter`.
- **1 unknown syscall name accepted** (new finding, not predicted in this
  lane's original 16-id estimate): `s-unknown-syscall` - the parser accepts
  any string as a `-S` syscall name with no table lookup.
- **3 product too STRICT** (the opposite direction - real auditctl accepts,
  the parser rejects; open parser gaps #584/#601, not lint-coverage
  questions): `iss584-backslash-escaped-space` (auditctl's `preprocess()`
  rewrites a backslash-escaped space before tokenizing; the parser has no such
  preprocessing), `iss601-uppercase-perm-all`, `iss601-uppercase-perm-mixed`
  (`parse_perms` only matches lowercase `rwxa`).

None of these 18 are caught by an existing `au-E02`/`E04`/`E05` lint: all three
validate OPERATOR legality (is an operator valid for a field's TYPE, or a field
valid for a filter LIST), never VALUE content, and none of today's divergences
are an operator-legality question.

### Fallback scope: 18 new ids, not a larger nominal count

The session plan's groups 3/5/7/8/9 (additional `-F` field-name coverage,
additional leading-flag coverage beyond `-A`, more #584 tokenization variants,
more `-S` syscall-name coverage, `list,action` order variants) were traded off
against wall-clock and review-cycle cost once the corpus already demonstrated
solid empirical coverage of every category the plan named (groups 1/2/4/6 plus
the four explicitly-named singles). This is a deliberate, DOCUMENTED reduction
per the session plan's own fallback clause, not a silent trim - flagged here
and in the dispatch report.

### Version divergence (CONTRIBUTING.md's per-version positive control)

Re-confirmed on the expanded 71-id corpus: NONE of the 71 scenarios' captured
facts (`rc`/`rule`/`stdout`/`stderr`) differ AT ALL across `el8`/`el9`/`el10`
(audit-userspace 3.1.2 / 3.1.5 / 4.0.3) - every data field is byte-identical
across all three captures (`diff` on the three files' data rows, target column
excluded, is empty). The per-version divergence control this project's
contract calls for is therefore satisfied by the LIVE `audit_version=` string
captured into each file's header (see "Corpus format" above and
`assert_version_divergence_control` in the test), not by a rule-level
behavioral split - there isn't one to pin, at least not among the scenarios
this corpus covers.

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
per `tools/oracle-images/README.md`). Measured wall-clock this session: under
90 seconds for all three images combined (one batched container per image,
canary run before every one of the ~71 lines).
