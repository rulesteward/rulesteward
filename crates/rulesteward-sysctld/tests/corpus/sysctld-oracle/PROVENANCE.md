# sysctld differential-oracle corpus provenance (session 9k-1 Lane B, #499, #593)

This directory is the committed Tier-1 corpus for the `sysctld` differential
oracle (see `CONTRIBUTING.md` "Differential oracle contract"). Every scenario
pairs a hand-authored filesystem tree (`tree.plan` + `content/`) with a
transcript captured from a REAL `systemd-sysctl` binary
(`oracle-<image>.txt`), so `tests/sysctld_corpus_oracle.rs` compares
RuleSteward's answer to a primary source rather than a hand-authored
expectation. `capture_sysctld.sh` (Tier-2) re-derives these transcripts live
from the `rs-oracle{8,9,10}` containers; this file documents the corpus
format, the real oracle-fidelity findings and harness bugs the corpus and its
tooling exist to pin, and the measured facts about the oracle binary itself
so no later session re-derives them.

## Corpus format

Each scenario is a directory containing:

- `scenario.meta` - a flat `key: value` line format (see "Why no serde_json"
  below). Required fields: `id`, `category`, `images` (comma-separated
  `rs-oracleN` names), `targets` (comma-separated `rhel8`/`rhel9`/`rhel10`,
  parallel to `images` by position), `key` (the dotted sysctl key this
  scenario tracks, or the literal `NONE` for a scenario that compares the
  REJECT signal instead of a merged value), `xfail_issue` (empty, or an issue
  number - DOCUMENTATION ONLY, no code reads this field; the enforced XFAIL
  truth is the `const XFAIL` table in `sysctld_corpus_oracle.rs`, which is
  itself guarded by an `assert_eq!` that every entry was hit exactly once),
  `comment` (free text grounding the scenario).
- `tree.plan` - TSV `TYPE\tRELPATH\tARG` lines, one entry per line, split by a
  line consisting of exactly `---` into two sections:
  - **Materialize section** (before `---`): what to build. `TYPE` is one of
    `d` (directory, `ARG` ignored), `f` (regular file, content copied from
    `content/RELPATH`, `ARG` ignored), `l` (symlink, `ARG` is the raw target),
    or `p` (FIFO via `mkfifo`, `ARG` ignored - see finding (b) below for why no
    committed scenario actually uses this type live).
  - **Vendored inventory section** (after `---`): the EXPECTED filesystem
    shape, recomputed via globs, never by replaying the plan. This section
    must list every entry EITHER cross-check below covers - including a
    masked file that a same-basename higher-precedence entry hides, since
    masking is a merge-time decision, not a filesystem-absence.
    **Two independent cross-checks, run at different times, each catching a
    DIFFERENT materializer's bug:**
    - Tier-1 (Rust, docker-free, every `cargo test`):
      `rulesteward_sysctld::oracle::compute_inventory` globs the `tempdir()`
      tree the Rust port of the materializer built and compares it to this
      vendored block. Catches a bug in the RUST materializer.
    - Tier-2 (bash, LIVE captures only): `capture_sysctld.sh`'s
      `check_computed_inventory` runs `sh materialize.sh --inventory <root>`
      inside the `rs-oracleN` container right after materializing, and
      compares ITS output to this SAME vendored block on the host before
      accepting the capture. Catches a bug in the BASH materializer - the
      class the Rust-only check cannot see, since Tier-1 never executes
      `materialize.sh` at all. A prior version of this file claimed "both
      materializers recompute a filesystem inventory afterward and compare it
      to a vendored expectation" when only the Rust side actually did; that
      was an aspirational doc-comment, not a description of running code
      (`materialize.sh` had no `--inventory` mode and `capture_sysctld.sh`
      performed no comparison at all). It is now true because both sides were
      built, not merely reworded - proved by both a positive capture-time run
      (all 22 scenarios pass `check_computed_inventory`) and by hand-seeding a
      one-line mismatch between a scenario's tree.plan and its content, which
      makes the capture fail with rc 2 naming the diff.
  - **Symlink target schema rule**: a symlink's `ARG` (ie its target) must be
    a relative path UNLESS it is exactly `/dev/null` - the one permitted
    absolute target in this corpus, used by the man `sysctl.d(5)` disable
    idiom (`degenerate-devnull-disable-idiom`). Both materializers
    (`materialize.sh`'s `l)` case and `rulesteward_sysctld::oracle::materialize`)
    assert this and abort on any other absolute target.
- `content/<relpath>` - the real bytes for every `f`-typed materialize entry.
- `oracle-<image>.txt` - the captured transcript, three `=== ... ===`-delimited
  sections:
  - `CAT-CONFIG` - `systemd-sysctl --cat-config`'s stdout plus its own
    `cat-config RC=<n>` line. A byte-cat only (see "Measured facts" below); not
    authoritative for merge/masking/grammar.
  - `APPLY-DEBUG` - `SYSTEMD_LOG_LEVEL=debug systemd-sysctl`'s stderr/stdout
    plus its own `apply RC=<n>` line. THIS is the authoritative section: every
    `Setting '<path>' to '<value>'`, `Overwriting earlier assignment of
    <path>`, `Skipping overridden file '<path>'`, and parse/file-level
    complaint the differential compares against comes from here.
  - `VERSION` - `systemd-sysctl --version`'s output, used by the corpus-wide
    per-version positive control (the three `baseline-vendor-inventory-el*`
    scenarios' banners must be pairwise distinct).

## Why no serde_json

`rulesteward-sysctld` does not otherwise depend on `serde_json`, and a new
`Cargo.toml`/`Cargo.lock` edit was contended surface shared with the other two
9k-1 lanes (auditd, sudoers) during this session. `tree.plan`'s TSV format
already carries everything both materializers need; `scenario.meta` only
needs a handful of flat scalar fields. A two-line `grep`+trim reader (bash
side: `meta_field()` in `capture_sysctld.sh`; Rust side: `meta_field()` in
`tests/sysctld_corpus_oracle.rs`) is the right tool for that shape, not a
general-purpose parser.

## Oracle-fidelity findings

Findings (a) and (b) are real divergences between `--cat-config` and the real
applier, found while authoring this corpus and pinned by dedicated scenarios
so they are never silently lost. Finding (c) is a capture-HARNESS bug (not an
oracle-fidelity finding in the same sense) that was found and fixed during
review; it is grouped here because, like (a) and (b), it is a real,
already-verified defect this file's job is to make sure no future session
re-derives from scratch.

**(a) `--cat-config` ABORTS where the real applier CONTINUES.**
Confirmed on two distinct degenerate shapes:

- A `.conf`-NAMED DIRECTORY (`degenerate-conf-named-directory`): `--cat-config`
  hard-aborts on it (`cat-config RC=1`, never reaches the next drop-in in
  read order), while the real applier logs `Failed to read file ..., ignoring:
  Is a directory` and CONTINUES to the next file (still exits 1 overall, but
  every subsequent key still applies).
- A DANGLING SYMLINK at an ordinary (non-99-slot) drop-in name
  (`degenerate-dangling-dropin`): `--cat-config` aborts identically, while the
  real applier SILENTLY skips it - no `Parsing` line, no error at all - and
  continues, exiting 0.

RuleSteward's own model (`enumerate()` in `system.rs`: a `.conf`-named
directory or a dangling symlink claims and masks its basename, contributes no
assignments, never aborts) matches the APPLIER's behavior, not
`--cat-config`'s - confirming the CONTRIBUTING guidance to model the applier
rather than the config-dump tool. This is also why the corpus's oracle
transcripts are authoritative from `APPLY-DEBUG`, never from `CAT-CONFIG`.

**(b) A `.conf` FIFO HANGS `systemd-sysctl` indefinitely.**
A `mkfifo`'d `.conf` entry with no writer blocks `systemd-sysctl` forever when
it tries to read it (confirmed empirically: `timeout 5 systemd-sysctl` exits
124, never completing). No committed scenario materializes a live FIFO for
this reason - the `p` tree.plan type exists in both materializers' vocabulary
for a possible FUTURE bounded-timeout scenario, but is otherwise unused. Both
materializers (`materialize.sh` and
`rulesteward_sysctld::oracle::materialize`) explicitly refuse an unsupported
plan type rather than silently skipping it, so an accidental `p` entry fails
loudly at materialization time instead of hanging a live capture.

**(c) Merging the container's stdout and stderr AT THE HOST is nondeterministic
- fixed by merging at the SOURCE instead.**
`systemd-sysctl` writes every line this differential asserts on (`Parsing`,
`Setting`, `Overwriting earlier assignment of`, `Skipping overridden file`,
and every parse/file-level complaint) to STDERR, while `capture_sysctld.sh`'s
own `=== ... ===` section markers and `RC=` lines are STDOUT written by the
capture's own shell. The original capture merged the two AT THE HOST
(`docker start -a "${cid}" >"${out_file}" 2>&1`), which races their arrival
order across docker's two independently-demuxed container streams. Measured
directly: three capture runs against unchanged images and an unchanged
product produced 2/22, 0/22, and 1/22 scenarios with a stderr block landing
on the wrong side of a `=== ` marker. A race-emptied `APPLY-DEBUG` section
reads as "key unset" - which silently HIDES real drift for exactly the
scenarios whose CORRECT verdict is "unset" (`precedence-masked-key-drop`,
`degenerate-devnull-disable-idiom`, `slot-symlink-absent-divergence`), proved
directly: rewriting `precedence-masked-key-drop`'s transcript to contain BOTH
a genuine oracle drift and the observed race shape (the stderr block landing
after `=== VERSION ===`) made the suite report PASS.

Fixed by merging stderr into stdout INSIDE the container, at the source,
before docker's demuxing layer ever sees two streams to race
(`run_one_capture`'s payload script is wrapped in `( ... ) 2>&1`, so the
kernel serializes every write to the one remaining fd in true program order).
Verified, not merely argued: three independent full capture runs after the
fix are pairwise byte-for-byte identical across all 22 scenarios (`cmp`,
never `rtk diff`, which false-reports IDENTICAL on genuinely different
files).

## A structural blind spot this corpus cannot close

`rulesteward_verdict` in `tests/sysctld_corpus_oracle.rs` reads
RuleSteward's own answer out of DIAGNOSTIC MESSAGE TEXT (`sysctld-W02`/`W04`
"insecure"/"unset"), which only exists when the tracked key is NOT compliant
for its target - a compliant value emits no diagnostic at all, and
`rulesteward_verdict` panics fail-closed rather than guess. Every scenario in
this corpus therefore MUST choose a non-compliant value for its tracked key
(this drove four `content/` corrections during review: a scenario had
accidentally picked a compliant value, so no diagnostic fired and the panic
caught it exactly as designed). The systematic consequence: **this corpus
can never hold a scenario whose correct merged answer is a COMPLIANT value**
- there is no way, with `rulesteward_verdict` as written, to differentially
test "RuleSteward correctly recognizes a compliant configuration as
compliant" for any scenario that goes through the generic comparison path.
That gap is real and not closed by this session; a future lane wanting to
cover it needs either a different oracle-reading mechanism (e.g. asserting
the ABSENCE of a W02/W04 diagnostic for a key, rather than reading one) or an
explicit acceptance that this corpus only exercises the non-compliant half of
the state space.

## Measured sysctld oracle facts (2026-07-25/26, so no later session re-derives them)

- **`systemd-sysctl` has NO `--root`** on el8/el9/el10. `--help` lists only
  `--cat-config`, `--prefix=PATH`, `--no-pager` (el10 additionally lists
  `--tldr`). The fixture tree must therefore BE the container's real `/`, via
  one throwaway `docker run --rm --network=none` per scenario/image pair -
  this is why `capture_sysctld.sh` clears and rematerializes the standard
  search directories INSIDE the container rather than passing a prefix flag.
- **`--cat-config` is a byte-cat and cannot observe key grammar at all** (it
  literally concatenates each surviving file's bytes with a `# <path>`
  header) and DISAGREES with the real applier on the two degenerate shapes in
  finding (a) above. `SYSTEMD_LOG_LEVEL=debug` apply mode is authoritative for
  masking / read-order / merge / grammar; `--cat-config` is authoritative only
  for file bytes and the filesystem-determined `cat-config RC`.
- **el8's systemd 239 omits the `/proc/sys/` prefix** on `Setting '<path>' to
  '<value>'` lines that el9/el10 include (`oracle_setting_value` in
  `rulesteward_sysctld::oracle` tolerates both forms).
- **Apply mode really does attempt to write every resolved key to
  `/proc/sys`.** This is only safe because Docker's default runtime
  bind-mounts `/proc/sys` read-only inside an unprivileged container
  (confirmed empirically: `rc=1, Read-only file system` on all three
  `rs-oracle` images) - a write attempt fails closed rather than mutating the
  host kernel. `capture_sysctld.sh` never passes `--privileged` or
  `--network=host`, and its canary POSITIVELY CONFIRMS `/proc/sys` refuses a
  write before touching any real scenario; if the canary write unexpectedly
  succeeds, the script aborts rather than risk a live host mutation.
- **procps `sysctl --system` and `systemd-sysctl` genuinely diverge on
  whether `/etc/sysctl.conf` applies at all** when no `/etc/sysctl.d/99-
  sysctl.conf -> ../sysctl.conf` symlink exists: procps reads
  `/etc/sysctl.conf` dead-last UNCONDITIONALLY; systemd-sysctl applies it
  ONLY via that symlink slot (see `system.rs` module doc point 3, and
  `sysctld-W03-b`). RuleSteward's own `sysctld-W02`/`W04` STIG/CIS baseline
  passes deliberately reason over the PROCPS-merged view (`system.rs`'s
  `merged`), not the systemd one, so for a scenario built specifically to
  exercise this divergence (`slot-symlink-absent-divergence`), RuleSteward's
  own W02/W04 diagnostic and this test's systemd-based oracle transcript
  legitimately disagree - a real, already-understood applier difference, not
  a bug in either side. `sysctld_corpus_oracle.rs` compares that scenario's
  oracle signal directly (asserting the transcript shows the key UNSET)
  rather than through the generic W02/W04-derived comparison, mirroring the
  file's existing `key-grammar-*` special cases.

## Scenario categories (22 total, `SCENARIO_FLOOR` in `sysctld_corpus_oracle.rs`)

| category | count | what it grounds |
|---|---|---|
| `precedence` | 6 | same-basename directory masking + global lexicographic merge across the four standard search directories |
| `slot-symlink` | 5 | the `/etc/sysctl.d/99-sysctl.conf -> ../sysctl.conf` slot: standard, dangling, absent, misdirected (#593), and a regular-file (non-symlink) impostor |
| `key-grammar` | 4 | dotted-vs-slash key canonicalization, dash-prefix (ignore-error) identity, inline `#` in a value, and a malformed-line reject |
| `baseline-vendor-inventory` | 3 | one per RHEL major (8/9/10); the corpus-wide per-version positive control (pairwise-distinct `--version` banners) |
| `degenerate` | 4 | a `.conf`-named directory, a dangling drop-in symlink, the `-> /dev/null` disable idiom, and a `.conf`-named non-regular masked entry |

## Corpus stability and reproducibility (what was actually measured)

A prior version of this section claimed one clean capture run as a general
reproducibility property. That claim was wrong: independent re-runs against
the PRE-FIX script (see finding (c) above) produced 2/22, 0/22, and 1/22
scenarios with byte-level stream-ordering drift - one clean run is not the
same thing as "reproducible", and reporting it as such was the mistake.

What is actually true, stated narrowly:

- **After finding (c)'s fix** (merging stdout/stderr inside the container,
  not at the host), three independent full `capture_sysctld.sh` runs are
  pairwise byte-for-byte identical across all 22 scenarios (`cmp`). The
  transcripts committed in this directory are one of those three runs.
- **Before that fix**, per the review that found finding (c) (an independent
  live re-capture and corruption sweep, not re-derived by this note): the
  CONTENT this differential actually asserts on (values, overwrite/skip/reject
  signals) never disagreed across the pre-fix runs it examined - only
  stream-ordering (which section a stderr line landed in relative to a
  marker) drifted, in 2 of 22 scenarios in the worst observed run. The corpus
  DATA corrections made during review (four `content/` value fixes so a
  tracked key is genuinely non-compliant, and two `tree.plan`
  vendored-inventory additions for a masked file) are independent of the race
  and remain valid: that same review separately confirmed the corpus DATA
  itself against a live run.
- `degenerate-conf-named-directory` and `degenerate-dangling-dropin`
  specifically: their transcripts, `scenario.meta`, and materialized content
  agree with the fresh, race-fixed captures above. Do not re-capture them
  casually, but the reason is "already re-verified this session", not
  "guaranteed stable forever" - re-verify mechanically before relying on that
  again in a future session, the same discipline this whole section exists
  to enforce on itself.
