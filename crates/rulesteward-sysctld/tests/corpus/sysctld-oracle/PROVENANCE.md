# sysctld differential-oracle corpus provenance (session 9k-1 Lane B, #499, #593)

This directory is the committed Tier-1 corpus for the `sysctld` differential
oracle (see `CONTRIBUTING.md` "Differential oracle contract"). Every scenario
pairs a hand-authored filesystem tree (`tree.plan` + `content/`) with a
transcript captured from a REAL `systemd-sysctl` binary
(`oracle-<image>.txt`), so `tests/sysctld_corpus_oracle.rs` compares
RuleSteward's answer to a primary source rather than a hand-authored
expectation. `capture_sysctld.sh` (Tier-2) re-derives these transcripts live
from the `rs-oracle{8,9,10}` containers; this file documents the corpus
format, the two real bugs the corpus exists to pin, and the measured facts
about the oracle binary itself so no later session re-derives them.

## Corpus format

Each scenario is a directory containing:

- `scenario.meta` - a flat `key: value` line format (see "Why no serde_json"
  below). Required fields: `id`, `category`, `images` (comma-separated
  `rs-oracleN` names), `targets` (comma-separated `rhel8`/`rhel9`/`rhel10`,
  parallel to `images` by position), `key` (the dotted sysctl key this
  scenario tracks, or the literal `NONE` for a scenario that compares the
  REJECT signal instead of a merged value), `xfail_issue` (empty, or an issue
  number - see `XFAIL` in `sysctld_corpus_oracle.rs`), `comment` (free text
  grounding the scenario).
- `tree.plan` - TSV `TYPE\tRELPATH\tARG` lines, one entry per line, split by a
  line consisting of exactly `---` into two sections:
  - **Materialize section** (before `---`): what to build. `TYPE` is one of
    `d` (directory, `ARG` ignored), `f` (regular file, content copied from
    `content/RELPATH`, `ARG` ignored), `l` (symlink, `ARG` is the raw target),
    or `p` (FIFO via `mkfifo`, `ARG` ignored - see finding (b) below for why no
    committed scenario actually uses this type live).
  - **Vendored inventory section** (after `---`): the EXPECTED filesystem
    shape, recomputed via globs by both materializers, never by replaying the
    plan (see `rulesteward_sysctld::oracle`'s module doc "The materializer
    equivalence guard"). This section must list every entry the equivalence
    guard covers - including a masked file that a same-basename
    higher-precedence entry hides, since masking is a merge-time decision, not
    a filesystem-absence. A materializer bug that creates an extra or
    wrongly-typed entry is caught here, with no docker required.
  - **Symlink target schema rule**: a symlink's `ARG` (ie its target) must be
    a relative path UNLESS it is exactly `/dev/null` - the one permitted
    absolute target in this corpus, used by the man `sysctl.d(5)` disable
    idiom (`degenerate-devnull-disable-idiom`). Both materializers
    (`materialize.sh` and `rulesteward_sysctld::oracle::materialize`) assert
    this.
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

Two real divergences between `--cat-config` and the real applier, found while
authoring this corpus and pinned by dedicated scenarios so they are never
silently lost:

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

## Corpus stability

`degenerate-conf-named-directory` and `degenerate-dangling-dropin` are
considered STABLE and should not be re-captured casually: their transcripts,
`scenario.meta`, and materialized content already agree with each other and
with a fresh live capture (verified 2026-07-26 via a full `capture_sysctld.sh`
run compared byte-for-byte against the committed corpus - zero drift across
all 22 scenarios). A prior in-session report that these two were stale was
incorrect; do not act on that claim without re-verifying mechanically first.
