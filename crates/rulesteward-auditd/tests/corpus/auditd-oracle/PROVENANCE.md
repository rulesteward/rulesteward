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

## ROUND-2 AMENDMENT (2026-07-26): adversarial-review rework

A second, impl-BLIND adversarial review (positive-controlled against its own
instrument: the round-1 bug, a constant `product_verdict`/`classify_capture`
stub, both `silence_is_conclusive` polarity inversions, an accept/complaint
probe reorder, and treating the fstype message as `Reject` were all confirmed
to pass the corpus-driven test ALONE - a reference-correct implementation was
confirmed to be the only one of these that passes) found five blockers and a
promoted concern in the first amendment. Summary of what changed (each
detailed in its own section below):

- **Blocker 1** (all 213 rows had `rc == 1`, so `classify_capture` was never
  forced to inspect `rc` at all): added synthetic (corpus-independent) unit
  tests in `oracle.rs` pinning `rc == 0/4/<other>` and an unrecognised `rc == 1`
  diagnostic.
- **Blocker 2** (the companion string `There was an error in line N of <file>`
  is coextensive with the accept string across every row, so an inverted
  "companion means accept" discriminator also passes): added a synthetic unit
  test with a stderr carrying ONLY the companion string.
- **Blocker 3** (zero corpus rows are comment-only/blank, so the documented
  "exactly one rule" guard was untested): added synthetic
  `product_verdict("# comment only")` / `product_verdict("   ")` pins.
- **Blocker 4** (`UNOBSERVABLE`'s guard checked "id is listed" and "kind is one
  of the two allowed variants" independently, never that THIS id has ITS
  declared kind): `UNOBSERVABLE` is now a `(id, Unusable, reason)` triple with
  the kind checked exactly.
- **Blocker 5** (`--reset-lost` was on the silent-flags denylist on a
  source-argument alone, never measured): resolved EMPIRICALLY - see "Blocker
  5 resolved: `--reset-lost` is LOUD, not silent" below. It is REMOVED from
  the denylist and reclassified `Unusable::SandboxLimited`.
- **Group-9 concern, promoted to required** (every `-a`/`-A` row in the corpus
  was action-first, `always,exit`-shaped; `parser.rs`'s commutative
  `list,action`/`action,list` branch had a nameable surviving mutation): added
  `lead-list-first` (`-a exit,always ...`).
- **Also-fix 1**: the "redirects EVERY `audit_msg()`-routed diagnostic to
  syslog for the remainder of that invocation" claim over-generalized -
  `handle_request` restores `MSG_STDERR` unconditionally, which is why the
  accept probe (also `audit_msg()`-routed) works at all. Corrected to state
  the `-D`-specific timing (case 'D's `audit_msg()` fires inside `setopt()`,
  before `handle_request` ever runs).
- **Also-fix 2**: the fstype message IS in the fetched source
  (`lib/errormsg.h:113`, `EAU_FILTERNOSUPPORT`), contrary to this file's
  earlier "was not found" claim - corrected below with the real citation.
- **Also-fix 3**: `assert_two_sided_positive_control` now also asserts the
  reported `complaint` actually appears in the row's own captured stderr.
- **Also-fix 4**: added `KNOWN_PARSE_COMPLAINTS` (test-side, corpus-grounded,
  runs TODAY independent of `classify_capture`) in `auditd_corpus_oracle.rs`.
- **Also-fix 5**: `assert_hit_exactly_three` now counts per TARGET, not pooled
  across all three files.
- **Also-fix 6**: added a codec positive control - three tests feeding
  `parse_data_row` deliberately corrupted rows, asserting it panics.
- **Also-fix 7**: noted `Row.stdout` is dead (always empty) and `Row.class` is
  panic-string-only, in the `Row` struct's own doc comment.

Corpus grew from 71 to 74 scenario ids (213 -> 222 rows): `lead-list-first`,
`lead-e-enable`, `reset-lost-probe`.

## ROUND-3 (2026-07-26/27): post-implementation impl-AWARE adversarial review

The implementation landed (`bccd015`, `product_verdict` and `classify_capture`
filled in) and passed the impl-BLIND round-2 barrier, `fmt`, `clippy`, and a
12/12-clean mutation gate. The impl-AWARE adversarial review that follows
GREEN (a DIFFERENT step from the impl-blind barrier review - see this
project's Adversarial Testing Loop) found two misses neither the barrier nor
the mutation gate could see, because both require reasoning about the ACTUAL
implementation's specific shortcuts rather than a blind or coverage-driven
probe. Per the loop's discipline, findings route to the TEST-AUTHOR to
strengthen tests (this file's job); the implementer follows to make them
green. `src/oracle.rs`'s BEHAVIOR (the three function bodies and the private
tables `ADD_RULE_NETLINK_REFUSED`/`SANDBOX_LIMITED_SUBSTRINGS`/
`KNOWN_PARSE_COMPLAINTS`/`SILENT_REFUSAL_COMPLAINT`/
`SILENT_SUCCESS_LEADING_FLAGS`) was NOT touched this round - only its test
modules (new synthetic pins, same convention as round 2) and one doc-comment
correction.

### MISS 1: the accept probe misses the DELETE half of `handle_request()`

`classify_capture("-W /etc/passwd -p wa -k x", 1, "", "Error sending delete
rule data request (Operation not permitted)\nThere was an error in line 1 of
/tmp/rs-oracle-line.rules")` produced `Unusable(UnrecognisedDiagnostic)`;
correct is `Accept`. Confirmed against re-fetched upstream source
(`auditctl.c`, all three EL-shipped tags): `handle_request()`'s
`else if (del != AUDIT_FILTER_UNSET)` branch (reached by `case 'W':` and
`case 'd':` in `setopt()`) carries the IDENTICAL
`set_aumessage_mode(MSG_QUIET)` -> `audit_delete_rule_data` ->
`set_aumessage_mode(MSG_STDERR)` sequence as the add branch, then prints
`Error sending delete rule data request (%s)` on failure - the delete-side
twin of `ADD_RULE_NETLINK_REFUSED`, and the SAME evidence that the line
PARSED.

This is worse than a merely-unhit branch: `record_unusable_hit` gives
`UnrecognisedDiagnostic` NO allowlist, so the first delete-form corpus row
kills the whole run as `ORACLE-BROKEN` - inverting the true diagnosis (a
real, previously-unexamined product-too-STRICT parser gap: `parser.rs`'s
`parse_line` has no `-W`/`-d` arm at all, only
`-D -b --backlog_wait_time -f -e -r --loginuid-immutable -w -a -A`) into "the
oracle is broken". Zero of the 222 round-2 corpus rows were delete-form.

Strengthened with: `oracle.rs`'s
`delete_shaped_netlink_refusal_is_recognised_as_accept` synthetic test (both
`-W` and `-d` forms), plus two new corpus scenarios `w-delete-watch` /
`d-delete-syscall` (real captures: both ACCEPT, identical stderr shape to the
one above), landing as new XFAIL entries in the "product too STRICT" group -
see `XFAIL-ISSUES.md`'s new-issue draft.

### MISS 2: an ENUMERATED flag escapes its own denylist by spelling

`classify_capture("-b8192", 1, "", "")` produced
`Reject { complaint: SILENT_REFUSAL_COMPLAINT }`; correct is
`Unusable(SilentNonAddLine)`. Same for `-e1`, `-f1`, `-r100`,
`--backlog_wait_time=60`. Confirmed against source: `setopt()`'s optstring is
`"...e:f:r:b:..."` (each requires an argument) and `long_opts[]` carries
`{"backlog_wait_time", 1, NULL, 2}`, so `getopt_long` dispatches `-b8192` to
`case 'b':` with `optarg == "8192"` exactly as `-b 8192` does, and
`--backlog_wait_time=60` to `case 2:` exactly as the spaced form does -
standard POSIX `getopt_long` attached-optarg semantics. `audit_strsplit`
(`common/strsplit.c`, `strchr(str, ' ')`) splits only on the literal space
byte, so `-b8192` survives tokenization as one token. `silence_is_conclusive`'s
lookup is exact `&str` equality on `split_whitespace().next()`, which does
not recognise this legal alternate spelling of an ENUMERATED denylist entry.

This is the WORSE of the two misses: `parser.rs`'s `parse_line` ALSO rejects
`-b8192` (unknown flag, since it only matches the exact string `"-b"`), so
`product_verdict` is `Reject` too. Oracle `Reject` (wrong) plus product
`Reject` (right, for an unrelated reason) is a MATCH - `compared += 1`, no
panic, no XFAIL entry, nothing to triage. The suite silently records a false
agreement and inflates confidence in the differential, rather than failing
loudly. This is the same failure class as the historical `-D`-as-REJECT bug
this module was built to fix, reached through a spelling the denylist's
exact-match lookup does not recognise as its own entry - explicitly NOT
covered by the "an unenumerated new flag defaults to conclusive and gets
triaged" design note, because the flag IS enumerated; the matcher simply
fails to see it.

Strengthened with: `oracle.rs`'s
`enumerated_flags_with_an_attached_optarg_are_not_conclusive` (all five
glued/`=` forms against `silence_is_conclusive`) and
`glued_optarg_silent_control_flag_is_unusable_not_reject` (`classify_capture`
end to end). No new corpus row needed - these are pure function calls; the
minimal fix (normalising the leading token before lookup: truncate a long
option at `=`, strip an attached optarg from the four `-X:` short flags) is
the implementer's job, not the test-author's. Residual worth noting rather
than testing: `getopt_long` also accepts unambiguous long-option
abbreviations (`--backlog=60`, `--loginuid-imm`), which that normalisation
would not cover.

### Also fixed: a false doc claim on the tokenizer

`oracle.rs`'s `silence_is_conclusive` doc claimed `split_whitespace` "matches
`audit_strsplit`'s own dispatch". It does not: `common/strsplit.c` splits on
the literal space byte only, while `split_whitespace` also splits on TAB.
Corrected in place (no behavioral claim depended on the wrong wording - every
denylisted flag in this corpus happens to agree between the two tokenizers -
but a false comment is its own defect class in this project regardless of
whether it currently causes a wrong answer).

### Confirmed sound - not churned

The impl-aware reviewer also checked, without finding a miss: `product_verdict`
keying on rule text (genuine bare delegation, no `use crate::ast::`); the
`Ok(_)`/`Err(_)` arm merge in `product_verdict` (behaviour-preserving,
`Verdict` has no third variant); the rc-gate-before-silence evaluation order
(pinned in both directions already); `is_sandbox_limited_stderr` misfiring
off-sandbox (all four emitters gate solely on `audit_get_features()`, never on
rule content); wrong-entry complaint matching in `KNOWN_PARSE_COMPLAINTS` (no
entry's text is a substring of another's); and `SILENT_REFUSAL_COMPLAINT`'s
placeholder value (zero consumers outside `oracle.rs` and the test file today,
so a type-design smell with no reachable wrong output - not a miss, but
flagged for later: if a recapture ever made `control-reject` silent,
`assert_two_sided_positive_control`'s `stderr.contains(complaint)` would fail
closed with a confusing message rather than passing).

Corpus grew from 74 to 76 scenario ids (222 -> 228 rows): `w-delete-watch`,
`d-delete-syscall`. `XFAIL` grew from 18 to 20 entries; `UNOBSERVABLE`
unchanged at 10.

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
container instantiation (this amendment batches all ~76 scenario lines into
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

### Scenarios: 76 ids x 3 targets = 228 rows

**33 `existing`-class scenarios** re-ground the pre-existing
`tests/corpus/auditd/*/audit.rules` corpus with a REAL per-line capture: one
representative line per scenario (the first non-comment, non-blank line of its
`audit.rules` - the same line a real `augenrules`-assembled file would present
to `auditctl` first). `rocky8-live-from-log-execve` is excluded (it ships no
`audit.rules`, only a log sample).

**19 `#584`/`#601`/`#489`/`#491` grounding scenarios plus 2 positive controls**
carried over from the first draft (`control-reject`'s RULE changed - see
below).

**19 new grounding scenarios** (this amendment; see "Fallback scope" below for
why 19 new ids, not a larger nominal count):

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

**3 round-2 grounding scenarios** (adversarial-review rework, see "ROUND-2
AMENDMENT" above):

- `lead-list-first` (`-a exit,always -S execve -k listfirst`): closes the
  group-9 surviving mutation - every OTHER `-a`/`-A` row in the corpus is
  action-first (`always,exit`-shaped), so deleting `parser.rs`'s
  `try_list_action` branch (the `list,action` order) left the corpus green.
  ACCEPTs on both sides.
- `lead-e-enable` (`-e 1`): empirical confirmation of a second
  `SILENT_SUCCESS_LEADING_FLAGS` entry beyond `-D`/`-b` (silent, joins
  `UNOBSERVABLE`).
- `reset-lost-probe` (`--reset-lost`): resolves blocker 5 - see "Blocker 5
  resolved" below. LOUD, `Unusable::SandboxLimited`, NOT silent.

**2 round-3 grounding scenarios** (post-implementation adversarial review, see
"ROUND-3" above):

- `w-delete-watch` (`-W /etc/passwd -p wa -k x`): grounds MISS 1 - the
  delete-form watch rule. Real oracle ACCEPTs (`Error sending delete rule
  data request`); the parser has no `-W` dispatch arm, so `product_verdict`
  rejects. XFAIL, product too STRICT.
- `d-delete-syscall` (`-d always,exit -S execve -k x`): same MISS 1 gap, the
  delete-form syscall rule (mirrors `-a`/`-A`). XFAIL, product too STRICT.

### The silent-rc1 blind spot (supersedes the old "standalone control-only
line classifies REJECT" claim)

Control-only lines (`-D`, `-b 8192`, `-e 1`, and this amendment's `-D extra`/
`-D -k`/`-D -k mykey extra`) fed via `auditctl -R <file>` are SILENT (rc 1,
both streams empty). The historical bug treated this silence as a REJECT for
every line, indiscriminately. The corrected model, grounded against
`audit-userspace` `src/auditctl.c` `setopt()` (read live this session at the
three shipped tags v3.1.2/v3.1.5/v4.0.3 - see `oracle.rs`'s
`SILENT_SUCCESS_LEADING_FLAGS` doc for exact citations): a leading flag's
SUCCESS path (`-D`'s `delete_all_rules(fd)`, `-b`/`-e`/`-f`/`-r`'s
`audit_set_*(fd, ...)`, `--loginuid-immutable`, `--backlog_wait_time`) sends
its own netlink message and, on failure (EPERM in this sandbox), returns
without printing anything - so a silent rc-1 for one of these flags is
**AMBIGUOUS**: it is produced identically by a successful parse (silently
EPERM'd) and by a genuine parse refusal (if one existed and were also silent).
No pure function of `(rc, stdout, stderr)` can separate those two, so these
rows classify `Unusable::SilentNonAddLine` and sit on the test's
`UNOBSERVABLE` table rather than being called either verdict. This is exactly
the opposite of the old "classifies REJECT" claim, and is the finding the
adversarial review's `-D` counterexample forced.

`--reset-lost` is DELIBERATELY NOT on this list - see "Blocker 5 resolved"
below: it is always LOUD here, never silent, so it never reaches this
ambiguity at all.

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
calls `set_aumessage_mode(MSG_SYSLOG, DBG_NO)` BEFORE the per-line loop starts.

**CORRECTED (round-2 review, also-fix 1): this does NOT mean every
`audit_msg()`-routed diagnostic is silenced for the rest of the invocation.**
An earlier draft of this note claimed exactly that, and it is self-contradicted
by this corpus's own accept probe: `Error sending add rule data request`
(`auditctl.c:1563`ish) and its companion `There was an error in line %d of %s`
(`:1417`ish) are BOTH `audit_msg()`-routed, and BOTH appear on every one of the
42-then-43 accept rows. The reason is `handle_request()` (called once per
successfully-parsed add-shaped line): it calls
`set_aumessage_mode(MSG_STDERR, DBG_NO)` UNCONDITIONALLY
(`auditctl.c:1552-1554`ish) before doing anything else, flipping the mode back
to stderr. So the real timing is: **`MSG_SYSLOG` holds only from `main()`'s
`-R` setup until the FIRST add-path `handle_request` call flips it back to
`MSG_STDERR`.** For a one-line `-R <file>` invocation, `case 'D'`'s
`audit_msg()` call happens inside `setopt()`, which runs BEFORE
`handle_request` is ever reached for that line - so the mode is still
`MSG_SYSLOG` at that exact point, and the original `-D` silent-reject finding
still holds. But the generalization to "every diagnostic, for the whole
invocation" was wrong.

Field/value validation messages (`-F unknown field: ...`, `Permission can only
contain 'rwxa'`, `-F value should be number for ...`) remain visible
REGARDLESS of this timing question, because they are printed by
`audit_number_to_errmsg`, a DIRECT `fprintf(stderr, ...)` call in `libaudit.c`
that bypasses `audit_msg()`/the message-mode system entirely. This explains
both this new finding and the ORIGINAL silent-`-D` finding, and is why all
three new `-D`-shaped rows joined `UNOBSERVABLE` (`d-extra-silent`,
`d-k-only-silent`, `d-k-extra-silent`) instead of confirming a loud pin.
`-R` remains the correct oracle shape regardless (see
`tools/oracle-images/README.md`); this finding is about which diagnostics `-R`
can surface, not about which invocation form to use.

### The fstype finding (`rocky9-filesystem-list`)

`-a always,filesystem -F fstype=ext4 -F 'auid>=1000' -F 'auid!=unset' -k
fs_ext4` prints `fstype filter is not supported by the kernel` - identical,
byte-for-byte, across el8/el9/el10 (three DIFFERENT compiled audit-userspace
binaries: 3.1.2/3.1.5/4.0.3). Classified `Unusable::SandboxLimited`: a property
of this capture environment, not of the rule.

**CORRECTED (round-2 review, also-fix 2): this file previously claimed the
message "was not found in `auditctl.c` or `libaudit.c`... likely a
distro-patched or generated table", resting the conclusion on cross-image
byte-identity alone. That claim was WRONG - the search only looked in `.c`
files.** The message IS in the fetched source, in a `.h`:
`lib/errormsg.h:113`, `{ -EAU_FILTERNOSUPPORT, 1, "filter is not supported by
the kernel" }` (position 1: printed as `"%s %s\n"` with the field-name operand
FIRST, giving `"fstype filter is not supported by the kernel"`). It is raised
in `libaudit.c` (`audit_rule_fieldpair_data`, ~line 1624-1630): when
`flags == AUDIT_FILTER_FS` (our rule's `always,filesystem` list), it checks
`audit_get_features() & AUDIT_FEATURE_BITMAP_FILTER_FS`, returning
`-EAU_FILTERNOSUPPORT` if that bit is unset. `audit_get_features()`
(`libaudit.c` ~line 670) is a CACHED result of `load_feature_bitmap()`, which
calls `audit_request_status(fd)` over netlink and, on any failure (including
the `EPERM` this sandbox's canary already demonstrates), sets
`features_bitmap = AUDIT_FEATURES_UNSUPPORTED` - so in THIS sandbox the bit is
ALWAYS unset, regardless of what the real target kernel would report. This is
now a PROVEN runtime-query artifact, not merely an inference from cross-image
byte-identity (which remains true and is corroborating evidence, not the
primary proof).

### Blocker 5 resolved: `--reset-lost` is LOUD, not silent

The first amendment's `SILENT_SUCCESS_LEADING_FLAGS` denylist included
`--reset-lost` on the strength of `auditctl.c`'s `case 3:` calling
`audit_number_to_errmsg(rc, ...)` on failure (the same shape as the other
seven entries), flagged AT THE TIME as the weakest-grounded entry because
whether `err_msgtab` even had an `-EPERM` key was unconfirmed. Round-2
resolved this EMPIRICALLY (per the reviewer's own instruction: "resolve it
empirically, do not argue it") by adding a live `reset-lost-probe` (`--reset-
lost`) row.

Measured: LOUD on all three EL majors -
`Field option not supported by kernel: reset-lost`. Root cause, confirmed in
source: `audit_reset_lost()` (`libaudit.c`, ~line 526-533) checks
`audit_get_features() & AUDIT_FEATURE_BITMAP_LOST_RESET` BEFORE attempting any
netlink send at all, returning `-EAU_FIELDNOSUPPORT` immediately if unset -
which, per "The fstype finding" above, this sandbox's blocked feature-bitmap
load always reports. `-EAU_FIELDNOSUPPORT` IS an `err_msgtab` key
(`errormsg.h:108`, `{ -EAU_FIELDNOSUPPORT, 2, "Field option not supported by
kernel:" }`, position 2: cvalue then the option name), printed via
`audit_number_to_errmsg` - the SAME direct-`fprintf` path that bypasses
`MSG_SYSLOG` for the fstype message. (The reviewer's supporting claim that
`-EPERM` itself is an `err_msgtab` key was not confirmed by this session's
read of `errormsg.h` - no entry keys `-EPERM` specifically - but this does not
matter for the conclusion: `audit_reset_lost` never reaches a raw `-EPERM`
from the netlink layer in this sandbox, because the feature-bitmap check
short-circuits before any send is attempted.)

**Resolution:** `--reset-lost` is REMOVED from `SILENT_SUCCESS_LEADING_FLAGS`
in `oracle.rs` (it is never actually silent here, so it never reaches that
denylist's ambiguity) and `reset-lost-probe` is classified
`Unusable::SandboxLimited` on `UNOBSERVABLE`, alongside
`rocky9-filesystem-list` - the SAME feature-bitmap-gated mechanism, just a
different `EAU_*` code and message text. This is corroborating evidence that
the fstype finding is a GENERAL pattern (any feature-bitmap-gated check is
unreliable under this sandbox), not a one-off quirk of the `filesystem` filter
list.

### Positive control changed (`control-reject`)

The first draft's `control-reject` rule was `-a always,exit -F perm=zz -S
execve` - loud and REJECT on the real oracle, but AT THE TIME RuleSteward's
OWN parser also accepted it (`-F perm=` values were stored as an unvalidated
string, no `rwxa` letter-set check), which meant this same row was ALSO a
product-divergence row. A positive control must never double as an XFAIL: if
it did, a broken harness and a real divergence would be indistinguishable.
The rule moved to `-a always,exit -F nosuchfield=1 -S execve` (loud REJECT,
`-F unknown field: nosuchfield`, on BOTH sides - RuleSteward's own field-name
table also has no `nosuchfield` entry, so this can never become an XFAIL).
The original rule's divergence was captured under its own id,
`f-perm-invalid-letter` (an XFAIL, not a control) - since closed: #601's
other half (session 9m lane 1) added the `rwxa` letter-set check to
`parse_field_filter`, so RuleSteward's parser now agrees with the real
oracle on this row and `f-perm-invalid-letter` is no longer in `XFAIL` (see
the divergence tally below).

### Product/oracle divergences: 17 XFAIL ids (see `auditd_corpus_oracle.rs`'s
`XFAIL` for the full per-id reasons)

- **7 quote-stripping** (deliberate parser leniency, `parser.rs:276-286`):
  `rocky9-arch-paired`, `rocky9-execve-auid`, `rocky9-field-compare`,
  `rocky9-never-suppress`, `rocky9-priv-commands`, `rocky9-task-list`,
  `iss584-quoted-field-expr`.
- **2 TAB tokenization** (#584): `iss584-embedded-tab-glues-flag`,
  `iss584-all-tabs-separators`.
- **2 `-k` cap enforcement missing** (#489): `iss489-key-over-cap-257`,
  `k-cap-invalid-shorter-line`.
- **2 `-F` value typing missing** (#491): `iss491-neg-pers`,
  `iss491-neg-devminor`.
- **1 unknown syscall name accepted** (new finding, not predicted in this
  lane's original 16-id estimate): `s-unknown-syscall` - the parser accepts
  any string as a `-S` syscall name with no table lookup.
- **1 product too STRICT** (the opposite direction - real auditctl accepts,
  the parser rejects; an open parser gap, #584, not a lint-coverage
  question): `iss584-backslash-escaped-space` (auditctl's `preprocess()`
  rewrites a backslash-escaped space before tokenizing; the parser has no such
  preprocessing).
- **2 delete-form rules unsupported** (round-3, post-implementation
  adversarial review MISS 1 - see above): `w-delete-watch` (`-W`),
  `d-delete-syscall` (`-d`) - the parser has NO delete-form dispatch arm at
  all, only the add-shaped subset of `auditctl`'s grammar.

Two ids that WERE on this list are now closed, session 9m lane 1 (#601, both
halves): `f-perm-invalid-letter` (see "Positive control changed" above -
`-F perm=` now gets the same letter-set check as `-p`) and
`iss601-uppercase-perm-all`/`iss601-uppercase-perm-mixed` (`parse_perms` now
case-folds before matching `rwxa`, so `-p WA`/`-p Wa` parse instead of
rejecting; these two rows moved OUT of the "product too STRICT" bucket
above, which is why it is 1 id, not 3). Their corpus rows still exist in
`el8.tsv`/`el9.tsv`/`el10.tsv` (the real oracle's verdict on those lines did
not change); only RuleSteward's own parser verdict did, so all three rows now
compare as AGREEMENT rather than divergence.

None of these 17 are caught by an existing `au-E02`/`E04`/`E05` lint: `au-E02`
validates operator legality (is an operator valid for a field's TYPE), `au-E05`
is the KERNEL-side bitmask-operator sibling to that same question, and
`au-E04` validates field-vs-filter-list legality (is this FIELD legal on the
specified LIST) - none of the three validate VALUE content, and none of
today's divergences are an operator- or list-legality question.

### Fallback scope: 19 new ids, not a larger nominal count

The session plan's groups 3/5/7/8/9 (additional `-F` field-name coverage,
additional leading-flag coverage beyond `-A`, more #584 tokenization variants,
more `-S` syscall-name coverage, `list,action` order variants) were traded off
against wall-clock and review-cycle cost once the corpus already demonstrated
solid empirical coverage of every category the plan named (groups 1/2/4/6 plus
the four explicitly-named singles). This is a deliberate, DOCUMENTED reduction
per the session plan's own fallback clause, not a silent trim - flagged here
and in the dispatch report.

### Version divergence (CONTRIBUTING.md's per-version positive control)

Re-confirmed on the expanded 76-id corpus: NONE of the 76 scenarios' captured
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
canary run before every one of the ~76 lines).
