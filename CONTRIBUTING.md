# Contributing to RuleSteward

Thanks for your interest. This document covers the local-dev workflow, the
shape of a useful first contribution, and the conventions PRs are expected
to follow.

## Local dev

The CI gates are reproducible locally. The full re-run is:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo llvm-cov --workspace --locked --fail-under-lines 80
```

A `justfile` at the repo root wraps the above as `just ci`. The
`rust-toolchain.toml` pins the channel so a fresh clone bootstraps the
right toolchain on first `cargo` invocation; no `rustup install` step
needed.

## How to add a new lint code

The fapolicyd module is the worked example. Each lint code (fapd-E02,
fapd-E03, fapd-E04, fapd-E05, fapd-W07) lives as its own file under
`crates/rulesteward-fapolicyd/src/lints/` with the diagnostic builder, the
test fixtures, and the `#[cfg(test)]` module side by side. Copy the shape
of an existing code, register the new code in `lints/mod.rs`, and add
fixture-driven tests; the CI gate enforces 80% line coverage.

## Good first issue

Issues labeled `good-first-issue` are a curated entry point. Comment on
the issue to claim it before opening a PR, so the maintainer can flag any
in-flight work that would conflict.

## PR review

Issues and PRs are reviewed on a solo-dev best-effort basis. Filing a PR
with a clear summary, a passing CI run, and a checked-off PR template
checklist is the fastest path to review.

## DAC guard: root-safe chmod deny-mode fixtures

Some tests exercise a permission-denied code path by chmod'ing a file or
directory to a restrictive mode (`from_mode(0o000)` for read-deny,
`from_mode(0o555)` for write-deny) and checking the resulting error. RHEL-
family distro CI runs the suite as root, and root bypasses Linux DAC
(discretionary access control) via `CAP_DAC_OVERRIDE` - the chmod still
"succeeds" on disk, but the denial never actually blocks the process, so
the assertion would silently pass for the wrong reason (or, before #464/#465,
outright fail under root). Every such test must probe the real precondition
and skip cleanly instead of assuming the deny lands:

```rust
if std::fs::File::open(&f).is_ok() {
    let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644));
    eprintln!(
        "SKIP <test_name>: 0o000 is readable here (running as root / \
         CAP_DAC_OVERRIDE); cannot exercise the deny arm"
    );
    return;
}
```

See `crates/rulesteward-sysctld/tests/system.rs`
(`unreadable_search_directory_emits_a_file_level_f01`) for the canonical
worked example, and the 7 guards added across `crates/rulesteward-cli` in
#465 for more instances.

`scripts/check-dac-guard.sh` (#467) is a static gate that enforces this;
CI's lint job runs it directly as `bash scripts/check-dac-guard.sh`, and
`just ci` (via the `dac-guard` recipe) runs the same script locally. Every
`from_mode(0o000)` or `from_mode(0o555)`
call under `crates/**/{src,tests}/**/*.rs` must have a `CAP_DAC_OVERRIDE`
marker (a comment or string literal containing that exact token) somewhere
in the *same function* as the call. If a fixture genuinely does not need the
guard (for example, an illustrative chmod whose assertions do not depend on
the denial actually being enforced), add an explicit escape hatch instead of
a `CAP_DAC_OVERRIDE` marker:

```rust
// dac-override-exempt: illustrative chmod only, no assertion in this
// fixture depends on the denial actually being enforced.
```

Run `just dac-guard` locally to check before pushing (the local equivalent
of the `bash scripts/check-dac-guard.sh` step CI's lint job runs).

The gate's per-function scoping is deliberately fail-closed around nested
`fn` items: a `fn` declared inside another fn's body splits the outer fn
into two search regions at that point, so a `CAP_DAC_OVERRIDE` marker
placed after a nested `fn` is not credited to a `from_mode(...)` call
before it even though both are lexically inside the same outer fn - place
the marker before the nested item (or use the `dac-override-exempt:`
hatch) if you hit this shape.

## Differential oracle contract

A "differential" here means checking RuleSteward's answer against the real
subsystem's answer (the fapolicyd daemon, `checkmodule`, `auditctl`,
`systemd-sysctl`, `visudo`) rather than against a hand-authored expectation.
Hand-authored expectations have repeatedly frozen the wrong answer; a daemon
cannot.

Every differential is built in **two tiers, and only the live tier may skip**:

- **Tier 1, the replay test** (`crates/<crate>/tests/<x>_oracle.rs`). Pure Rust.
  Reads a committed corpus of `(input, recorded-oracle-verdict)` pairs and
  asserts the product agrees. No docker, no root, no network, no tool on PATH,
  **so there is no skip path at all.** Runs in `just test` / `just ci` and in
  every CI container. Model: `crates/rulesteward-selinux/tests/selinux_corpus_oracle.rs`.
- **Tier 2, the capture/drift tool.** Re-derives the oracle from the live
  subsystem and fails on drift. The only part allowed to skip. Model for the
  tool/recipe SHAPE: `tools/sshd-probe-update` + `just diff-sshd`.

This split is why a missing docker daemon degrades the guarantee from "nothing
was checked" to "the oracle was not re-derived."

### The branch differential: a third axis (`just diff-<lane>-branch`)

The two tiers above both hold the BINARY fixed and vary the CORPUS. A third
instrument, `scripts/rs-branch-diff.sh` (#661), does the opposite: it holds the
corpus fixed and varies the binary, replaying this WORKING TREE's corpus against
a build at a base ref and a build from this working tree.

It exists because of `scripts/check-corpus-growth.sh` (#658). That gate forces a
branch touching `crates/X/src/**` to add a file under `crates/X/tests/corpus/**`,
but nothing checks the added file DISCRIMINATES anything: a branch can satisfy it
with a scenario the old code already passed. Three runs separate those cases,
because then the only delta between R1 and R2 is the corpus the branch added:

| run | binary | corpus |
|---|---|---|
| R1 | base worktree | the base worktree's committed corpus (baseline) |
| R2 | base worktree | **this working tree's** corpus |
| R3 | this working tree | this working tree's corpus |

"Working tree", not "committed": R3's binary is built from the repo root and both
R2 and R3 read the corpus from it, so uncommitted work is included. That is what
makes "diff my uncommitted work against the commit I am sitting on" a supported
mode, and it is why the driver's nothing-to-vary guard asks git a ONE-ref
question (`git diff <base> -- <paths>`, commit against working tree) rather than
comparing two commits.

R1 `ok` + R2 `FAILED` + R3 `ok` is proof the growth catches the old code. R1 `ok`
+ R3 `FAILED` is a regression, and takes precedence: `ok / FAILED / FAILED` is a
REGRESSION, not a discrimination. R1 `FAILED` with the test still PRESENT at HEAD
is unattributable and excluded: that failure predates the branch. A test the
branch REMOVED is reported base-only regardless of its base verdict, because the
absent-at-HEAD check runs first.

The four `#[ignore]` cases are deliberately asymmetric, because `cargo test`
skips ignored tests by default and this is the last gate able to see a replay
test that is not being checked:

| at base | at HEAD | verdict |
|---|---|---|
| ran and PASSED | `#[ignore]`d | SILENCED, **rc 1**: a loss of coverage |
| `#[ignore]`d | failing | no baseline and FAILING, **rc 1**: un-parked and left red |
| `#[ignore]`d | ran, or still `#[ignore]`d | ignored at base, rc 0; rc **2** if EVERY shared row is in this state AND nothing else failed (a row FAILING with no baseline, or a SILENCED row, stands that gate down and the run is rc 1) |
| absent | `#[ignore]`d | HEAD-only and PARKED, rc 0 |

The third row is what a branch produces against a base that parks a replay test in
the lane's own `*_corpus_oracle.rs` target. No lane's replay target carries an
`#[ignore]` today, so that row is currently unreachable for all four lanes.
`boundary_substrate.rs`'s parked #669/#677 pins are cited above as the repo's
CONVENTION, not as rows in this table: they live in a different cargo test target,
and this driver builds only `--test <lane>_corpus_oracle`.

The last row is rc 0 because adding a parked pin for a known-open bug is this
repo's convention (`boundary_substrate.rs`: "`#[ignore]`d rather than deleted,
per this repo's convention: removing the `#[ignore]` is how the fix gets
demonstrated"; #669 and #677 are live examples). There is no override switch.

Note that `#[ignore = "reason"]` renders as `test <name> ... ignored, <reason>`,
which is the form every ignore attribute in this repo uses; a lane parser that
anchors on the bare word will not see it.

**Run it every Adversarial Testing Loop round, not once.** A divergence table is
the only instrument in the loop whose evidence accumulates across rounds; the
adversary's is re-rolled every time, which is how session 9o declared a round DRY
over a live fail-open.

Rows are libtest TEST NAMES, not corpus scenario ids, because libtest already
reports per-test pass/fail and continues past a panic. Stated plainly so nobody
over-reads the table: this granularity **cannot** separate a regression from
residual defects inside a single test. Scenario granularity needs the replay
tests to accumulate rather than panic at the first divergence and is tracked
separately.

Adding a lane takes two things. First, the lane's replay test must resolve its
corpus through `rulesteward_core::oracle_corpus::resolve_corpus_root` and announce
`sentinel_count`.

The BANNER needs no work from the lane: `resolve_corpus_root` emits it, on every
resolution, before returning. That placement is deliberate and is not a
convenience. The driver's sentinel check is EXISTENTIAL, so it can only prove
that something read the tree it handed over, never that nothing read a different
one; a binary that resolves the corpus correctly in one place and from a
compiled-in `CARGO_MANIFEST_DIR` in another used to satisfy it completely.
`rulesteward-selinux`'s `policy_corpus::archive_path` was exactly that shape.
Announcing from the single resolver makes a MISDIRECTED resolution visible: a call
that reaches the resolver under a variable the driver did not set announces
`mode=committed`, and the driver refuses the run. It does NOT close the bypass
class: a read that never calls the resolver announces nothing, matches neither
half of the guard, and passes. Nothing mechanically forces a read through it, so
route a new corpus read through the resolver deliberately.

The COUNT is the lane's job and is not always knowable early: sudoers' L1/L2/L3
announce after their comparison loop with the real accumulated tally, because how
much they compare is data-dependent. That is why the driver requires a count only
on a GREEN run, where "nothing fired" and "nothing ran" are the same transcript.

Second, a row in the frozen lane table in
`scripts/rs-branch-diff.sh` plus a recipe. Note `selinux` appears in that lane
table but not in `rs-oracle-diff.sh`'s: it has no live capture script, so it is
offline-only.

### Exit codes

Applies to NEW dev-tooling harnesses (`tools/*-update`, `just diff-*`). This is
a separate numbering from the `rulesteward` binary's own exit codes in
`crates/rulesteward-cli/src/exit_code.rs` (spec 12.4), where `3` is
`EXIT_TOOL_FAILURE`. Different programs, different contracts; do not conflate
them when reading a CI log.

| rc | meaning |
|---|---|
| 0 | verified clean. The success line MUST carry a non-zero count, e.g. `OK (0 drift, 214 scenarios)`. `rs-branch-diff.sh` enforces this as a final gate before printing OK, because its per-run count requirement is green-run-only |
| 1 | drift: the product and the oracle disagree |
| 2 | tool/environment error: unparseable transcript, zero data rows, or the oracle was required but missing |
| 3 | precondition unmet, a legitimate skip (no docker, image absent) |

`3` exists so a developer without docker gets an honest skip while CI turns the
same condition into a hard failure. Collapsing it into `0` is exactly the bug
that made `just diff-fapolicyd` report success while checking nothing (#572).

**`just diff-<lane>-branch` has NO rc 3, and that is not an oversight.** It is
OFFLINE tier throughout - no docker, no root, no live oracle - so it has no
legitimate precondition to skip on. Everything a live recipe would skip for
(a base that predates the corpus, a base whose harness will not build, a run
that announced the wrong corpus) is `2`, "these two builds cannot be compared".
Giving it a skip path would recreate #572 in a new file. `scripts/rs-branch-diff-test.sh`
asserts that no case in its FIRST pass, against the real driver, ever yields `3`.
Exit codes from its positive-control phases, where the driver is deliberately
sabotaged, are not covered and should not be.

**Status, stated plainly: `just diff-auditd`, `just diff-sysctld` and
`just diff-sudoers` (session 9k-1) are the first recipes to implement `3`. For a
new harness, do not copy one of them: add a lane to the frozen table in
`scripts/rs-oracle-diff.sh`, which all three delegate to.** The two older LIVE
recipes (`just diff-sshd`, `just fapolicyd-probe-check`) predated this contract
and `exit 0`d on missing prerequisites. They were grandfathered by owner decision
on 2026-07-25 and **retrofitted on 2026-08-01**: both now `exit 3` on a missing
docker binary and on missing images, promoted to `2` when the oracle is declared
required. That promotion is delegated to `scripts/rs-oracle-required.sh` rather
than re-tested inline, so it honours the per-lane `RS_REQUIRE_<TOKEN>` as well as
the global `RS_ORACLE_REQUIRED` and treats `false`/`no`/`off`/blank as
off-switches. All four skip paths were verified in both modes against a PATH with
no docker and against a docker stub whose `image inspect` fails, with a live
docker-present run as the negative control.

**Scope of that retrofit, stated exactly:** it covered the two `diff-*`-family
LIVE ORACLE recipes and nothing else. Twenty-three `just` recipes still `exit 0`
when a prerequisite is missing - eleven `*-derive` print-only helpers, where an
exit-0 skip is defensible, and **twelve `*-check` network-drift recipes, where it
is not**: `stig-check`, `cis-check`, `cis-check-latest`, `fapd-attr-check`,
`sshd-stig-check`, `sshd-stig-check-pin`, `auditd-stig-check`,
`auditd-stig-check-pin`, `auditd-msgtype-check`, `fapolicyd-stig-check`,
`selinux-stig-check`, `sudoers-stig-check`. Those download a pinned STIG/CIS zip
and drift-check against it; with `curl` or `unzip` absent they report success
having checked nothing, which is #572's shape in a different subsystem. They are
out of scope here only because they are a separate change with a separate
verification surface, not because they are correct.

The 9k-1 recipes also demonstrate the shape that keeps the two tiers from
drifting apart: the drift check is not a second implementation of "does the
product agree with the oracle", it is the SAME Tier-1 test binary re-pointed at
a freshly captured corpus through `RS_ORACLE_CORPUS_<LANE>`. The driver owns the
exit codes; the test owns the comparison. Two consequences worth copying:

- `cargo test` exits `101` for a failed assertion AND for a compile error, and
  exits `0` when zero tests ran. So the recipe consumes every cargo-level error
  first with `--no-run` (any failure there is rc 2 by construction), then
  executes the built test binary DIRECTLY, where `101` can only mean libtest saw
  a failing test. That is what makes drift-vs-tool-error structural rather than
  a guess.
- The test prints a sentinel banner naming the corpus root and mode, and the
  recipe refuses to classify any exit code until it has grepped for it. That is
  the only guard that catches a variable-name typo between the recipe and the
  test, which would otherwise make the "fresh" run silently replay the committed
  corpus and exit 0. Neither the count floor, nor the positive control, nor the
  exit code can detect that.

The corpus-root resolution itself lives once in
`rulesteward_core::oracle_corpus`, not copied per lane: a blank override must be
an ERROR rather than a silent fall-back to the committed corpus, and that
failure mode is invisible in a green run.

Each harness declares its own `RS_REQUIRE_<ORACLE>` environment variable for
this, and **CI must set it** wherever the oracle is actually installed. The one
shipped example is `RS_REQUIRE_CHECKMODULE`, used by
`crates/rulesteward-selinux/tests/te_emit_checkmodule.rs` and set in `ci.yml` on
both the EL matrix and the `selinux-feature` job.

Parse that variable **fail-closed**: treat any non-empty value that is not an
explicit off-switch (`0`, `false`, `no`, `off`) as "required". Comparing against
the literal `"1"` is fail-OPEN, because a later session writing
`RS_REQUIRE_X: true` in YAML gets the string `true` and silently re-disables the
requirement. That mistake was made and caught in this contract's own first
implementation.

### Three rules every harness must satisfy

These apply to BOTH tiers, but the two tiers fail differently and the remedy
differs with them. A Tier-1 replay test is a `cargo test`: it has no exit-code
control (a failed assertion exits 101) and its stdout is swallowed unless it
fails. A Tier-2 tool owns its exit code and its stdout. So each rule below gives
the Tier-1 form and the Tier-2 form; do not apply the Tier-2 remedy to a test.

1. **Assert the count, do not merely print it.**
   - *Both:* `assert!(scenarios.len() >= FLOOR)` before reporting success, so
     "compared nothing" cannot be reported as "compared everything, all clean".
     `FLOOR` is a named constant beside the test or in the tool's config; raise
     it deliberately when the corpus grows, in the same commit.
   - *Tier 2 additionally:* the rc-0 success line MUST carry the count, e.g.
     `OK (0 drift, 214 scenarios)`. The older `tools/*-update` print such a line
     but never assert `N > 0`; new tools must do both.
   - *Tier 1:* print the count too (`eprintln!`, visible under `--nocapture`),
     but the assertion is what carries the guarantee, since cargo hides stdout
     for passing tests. Do not rely on a human noticing the number.
2. **Carry a positive control.** Every corpus holds at least one input the
   oracle must REJECT and one it must ACCEPT. If both come back with the same
   verdict the *oracle* is broken, not the product, and the run must fail rather
   than report either clean or drift.
   - *Tier 1:* a failed assertion naming the control (see
     `checkmodule_availability_declared` in
     `crates/rulesteward-selinux/tests/te_emit_checkmodule.rs`, which is the
     shipped example).
   - *Tier 2:* exit 2, never 0 and never 1.
   - Where an oracle is captured per-version, add a control pinning a known
     version divergence: it is the only thing that detects "all three
     transcripts are secretly the same file".
3. **Parse fail-closed.** Empty body, header-only input, or zero data rows must
   return an error, never `Ok(vec![])`. See
   `tools/fapolicyd-probe-update/src/transcript.rs`. Applies wherever a
   transcript is read, in either tier.

The through-line: **an instrument must prove it saw something.** "Nothing fired"
and "nothing ran" produce identical output otherwise, and every one of this
project's silent-gate failures has been that confusion. The mechanical guard for
the narrower case of out-of-repo inputs is `just no-mnt-guard`.

## Commit authorship

All commits are user-authored. Do not add `Co-Authored-By: Claude` or
any other AI-attribution trailer to a commit message. This applies even
if the commit was drafted with AI assistance.

## License

By contributing, you agree that your contributions are licensed under the
project's Apache-2.0 license (engine) or BSD-3-Clause (rule templates),
matching the existing license boundary.
