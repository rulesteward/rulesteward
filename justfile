# RuleSteward developer task runner.
#
# Each recipe mirrors a CI gate verbatim so `just ci` reproduces the
# blocking gate locally. Run `just --list` to see all recipes.
#
# This file lives alongside .github/workflows/ci.yml; when you change
# a CI invocation, update the corresponding recipe here.

# Default: print recipes when `just` is invoked with no args.
_default:
    @just --list

# Check formatting (cargo fmt --all --check).
fmt:
    cargo fmt --all --check

# Apply formatting in-place (cargo fmt --all).
fmt-fix:
    cargo fmt --all

# Run clippy with --deny warnings.
clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Run the workspace test suite.
test:
    cargo test --workspace --locked

# Run llvm-cov: 80% workspace floor + >=90% parser/lint floor (mirrors ci.yml). (#395)
cov:
    cargo llvm-cov --no-report --workspace --locked
    cargo llvm-cov report --fail-under-lines 80
    cargo llvm-cov report --package rulesteward-core --package rulesteward-fapolicyd --package rulesteward-selinux --package rulesteward-auditd --package rulesteward-sshd --package rulesteward-sudoers --package rulesteward-sysctld --package rulesteward-cli --fail-under-lines 90

# (#467) Guard against unguarded chmod deny-mode fixtures (from_mode(0o000) /
# from_mode(0o555)) under crates/**/{src,tests} that lack a CAP_DAC_OVERRIDE
# marker (or a dac-override-exempt: escape hatch) in the same function - see
# the "DAC guard" section of CONTRIBUTING.md.
dac-guard:
    bash scripts/check-dac-guard.sh

# (#586) Guard against doc-truth decay in the per-backend "N codes" prose: every
# "N `<prefix>-` codes" mention in README.md and in the clap doc-comments must equal
# the corresponding catalog length (FAPD_CODES, AU_CODES, SSHD_CODES, SUDO_CODES,
# SYSCTLD_CODES, SE_CODES). The counts have drifted four times (#556, its two
# predecessors, and the three-line au-/sudo-/sysctld- drift this same lane fixed);
# each fix before this one was manual. Same shape as dac-guard: standalone bash
# (grep-based, no cargo build), so it belongs in the lint tier.
#
# Assert every "N codes" doc mention matches its lint catalog's length. (#586)
codes-guard:
    bash scripts/check-codes-count.sh

# (#572) No-mnt guard: no repo-invoked command may reference a path outside the
# repo. The wave3 fapolicyd corpus lived at an absolute /mnt path, was destroyed
# in the 2026-07-13 NFS rebuild, and `just diff-fapolicyd` then exited 0 with a
# skip message on every run - reporting success while checking nothing. A
# violation is `/mnt/` in EXECUTABLE position; comment lines and data files are
# provenance, not dependencies. Same shape as dac-guard and codes-guard:
# standalone bash (grep-based, no cargo build), so it belongs in the lint tier.
#
# Assert no repo-invoked command depends on a path outside the repo. (#572)
no-mnt-guard:
    bash scripts/check-no-mnt-paths.sh

# (session 9k-1) Capture-write guard: every Tier-2 capture script
# (crates/*/tests/corpus/*/capture_*.sh) must route every write through
# rs_checked / rs_checked_write (scripts/rs-capture-guard.sh) rather than
# performing a bare cp/mv/install/mkdir/rmdir/ln/truncate/tee/dd or an
# unwrapped `cat >` redirect. This is layer 3 of that defense: a bare write
# that skips both runtime layers is exactly how a Tier-2 capture continued
# past `cp: Disk quota exceeded` and exited 0 having written a truncated
# corpus. Same shape as dac-guard/codes-guard/no-mnt-guard: standalone bash
# + awk (no cargo build), so it belongs in the lint tier alongside them.
#
# Assert every Tier-2 capture script routes its writes through the guard. (session 9k-1)
capture-guard:
    bash scripts/check-capture-writes.sh

# (session 9o, #658) Corpus-growth guard: a branch that changes crates/X/src/**
# must ADD a file under crates/X/tests/corpus/**, per crate.
#
# The other lint-tier guards walk a TREE; this one walks a COMMIT RANGE, because
# its escape marker lives in a commit body. That is also why it can fail in a way
# they cannot: a base that does not resolve yields an empty diff, and an empty
# diff has no violations. The script exits 2 rather than 0 in that case, so a CI
# run with an unfetched origin/main fails loudly instead of reporting clean.
#
# Base defaults to `git merge-base origin/main HEAD`; pass one to override.
#
# Assert an in-scope crate's src change is paid for by that crate's corpus. (#658)
corpus-growth-guard base="":
    bash scripts/check-corpus-growth.sh "{{base}}"

# Self-test EVERY instrument in scripts/. An unverified instrument is the exact
# failure this contract exists to prevent: a gate that reports clean having
# scanned nothing is indistinguishable downstream from a real pass.
#
# This SUPERSEDES `oracle-harness-test` in `just ci` and runs a superset of it
# (that recipe stays callable on its own for the four differential suites). Three
# suites - check-dac-guard-test, check-codes-count-test, check-no-mnt-paths-test,
# 99 KB carrying this project's explicitly named anti-vacuity positive controls -
# were reachable from no recipe or workflow at all, so the anti-vacuity behaviour
# of two of the three `just ci` lint guards was unverified on every commit.
#
# Pure bash: no cargo, no docker, no network.
instrument-test:
    #!/usr/bin/env bash
    set -uo pipefail
    # Never chain with && - a short-circuit hides which one failed, and rc is the
    # gate here, not the transcript.
    fail=0
    ran=0
    for t in rs-oracle-required rs-oracle-diff rs-branch-diff rs-capture-guard \
             check-capture-writes check-dac-guard check-codes-count \
             check-no-mnt-paths rs-mutation-gate check-doc-citations \
             check-corpus-growth; do
        # Captured rather than streamed, so the FAIL-token assertion below can see
        # it. Printed verbatim immediately afterwards: a suite's own transcript is
        # what a maintainer debugs from, and swallowing it would trade one
        # readability defect for another.
        out="$(bash "scripts/${t}-test.sh" 2>&1)"
        rc=$?
        ran=$((ran + 1))
        printf '%s\n' "${out}"
        echo "instrument-test: ${t}-test rc=${rc}"
        [ "${rc}" -eq 0 ] || fail=1
        # A GREEN suite must not print the token FAIL (#641). Three suites used to
        # run their positive-control phase through the ordinary per-case reporter,
        # so a fully passing `just ci` emitted 14 lines beginning with FAIL - the
        # SUCCESS condition, announced with the word for failure. That cost real
        # debugging time on 2026-08-01, and it silently arms any log-scraping check
        # keyed on FAIL to fire on every healthy run.
        #
        # Only asserted when rc is 0: a genuinely failing suite is SUPPOSED to say
        # FAIL, and gating that would be the opposite defect.
        #
        # Matched with a bash `case`, not a grep pipeline, for the reason the guard
        # count below is counted with a glob: a filter in the middle of a pipeline
        # is rewritten by this project's command wrapper, so a gate must never read
        # its answer through one.
        if [ "${rc}" -eq 0 ]; then
            case "${out}" in
                *FAIL*)
                    echo "instrument-test: ${t}-test passed (rc=0) but printed the token FAIL - a green run must not, see #641" >&2
                    fail=1
                    ;;
            esac
        fi
    done
    # ANTI-VACUITY on this recipe itself, in two directions.
    #
    # (1) Every guard in scripts/ must appear in the list above, so adding a guard
    # without a self-test fails HERE rather than going unverified for weeks.
    # Counted with a shell glob rather than `ls | grep -v`: a count derived through
    # a filter is not evidence, and this project's own command wrapper rewrites a
    # mid-pipeline grep and changes the number (measured while writing this recipe,
    # which reported 16 guards where there were 8 at the time). The count is
    # asserted below rather than quoted here, so it cannot drift while green.
    #
    # The same walk carries the MODE invariant (#658). Nothing in this tree
    # invokes a script in a way that consults the executable bit - the justfile
    # and every CI step say `bash scripts/x.sh`, and rs-capture-guard.sh is
    # SOURCED - so a `test -x` PREFLIGHT on the recipes would gate a property no
    # caller consumes and could only ever produce a false failure. This is the
    # other shape: a tree invariant, asserted where the tree is already being
    # walked. It catches a script silently losing +x, which really happened (every
    # script in scripts/ was non-executable until #644) and which breaks ad-hoc
    # `./scripts/x.sh` use and reads as broken in any file listing.
    guards=0
    notexec=""
    for f in scripts/*.sh; do
        case "${f}" in *-test.sh) ;; *) guards=$((guards + 1)) ;; esac
        [ -x "${f}" ] || notexec="${notexec} ${f}"
    done
    [ -z "${notexec}" ] || { echo "instrument-test: not executable:${notexec} - every scripts/*.sh is mode 0755 (#658)" >&2; fail=1; }
    [ "${guards}" -eq 11 ] || { echo "instrument-test: scripts/ has ${guards} guards, this recipe self-tests 11 - add the new guard's -test.sh to the loop above and bump this number" >&2; fail=1; }
    # (2) The loop itself must have run. A typo'd list that iterates zero times
    # would otherwise report clean, which is the very defect being gated.
    [ "${ran}" -eq 11 ] || { echo "instrument-test: ran ${ran} suites, expected 11" >&2; fail=1; }
    echo "instrument-test: ${ran} suites run, ${guards} guards present, fail=${fail}"
    [ "${fail}" -eq 0 ]

# Per-manifest gate for the workspace-EXCLUDED tools/* crates. `cargo --workspace`
# cannot see them, but six CI workflows build them with --locked. In 9j a branch
# was pushed with `# acked-verify` on a green `just ci` while three tools/* --locked
# builds that CI gates were broken; it was caught 27 minutes later by an ad-hoc
# per-manifest run, not by a gate. (#603)
tools-gate:
    #!/usr/bin/env bash
    set -uo pipefail
    rc=0
    n=0
    for m in tools/*/Cargo.toml; do
      [ -f "${m}" ] || continue
      n=$((n + 1))
      cargo fmt --manifest-path "${m}" --all -- --check || rc=1
      cargo clippy --manifest-path "${m}" --all-targets --locked -- -D warnings || rc=1
      cargo test --manifest-path "${m}" --locked || rc=1
    done
    # Zero manifests means the layout moved, not that everything passed.
    [ "${n}" -gt 0 ] || { echo "tools-gate VACUOUS: 0 manifests found under tools/" >&2; exit 2; }
    echo "tools-gate: ${n} manifests checked, rc=${rc}"
    exit "${rc}"

# Build the static musl binary (requires musl-gcc + the rustup target).
musl:
    CC_x86_64_unknown_linux_musl=musl-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    cargo build --release --target x86_64-unknown-linux-musl --bin rulesteward --locked

# Run the full local CI gate in CI order (fmt + clippy + dac-guard + codes-guard +
# no-mnt-guard + capture-guard + instrument-test + tools-gate + test + cov).
# `instrument-test` runs a SUPERSET of `oracle-harness-test`, so the latter is not
# listed here; it remains callable on its own.
ci: fmt clippy dac-guard codes-guard no-mnt-guard capture-guard corpus-growth-guard instrument-test tools-gate test cov

# (#291) Isolated trustdb NO_LOCK RW-contention harness (opt-in; NOT part of
# `just ci`). Runs ONLY the #[ignore]d `trustdb_contention` integration test:
# a NO_LOCK reader (open_trustdb_readonly + iter_entries/get_entry) hammered
# against a separate live writer PROCESS that churns the same DB. Gated by both
# `#[ignore]` and `required-features = ["test-fixtures"]` so the default
# `just test` / coverage run never executes it. A dedicated CI job runs only
# this recipe, isolated from the main test matrix.
trustdb-contention:
    cargo test -p rulesteward-fapolicyd --features test-fixtures \
        --test trustdb_contention --locked -- --ignored --test-threads=1

# (#335, #512) Drift-check / refresh the sysctld-W02 STIG baselines against the
# OFFICIAL DISA XCCDF. Same nested-tool pattern as sshd-stig-*/auditd-stig-* below
# (tools/stig-update, OUT of `just ci`). #512 (session 9h-v0_8-wave4 Lane B) ported
# this tool off ComplianceAsCode/content onto DISA XCCDF; DISA versions each RHEL
# STIG by FILENAME (no releases API), so there is NO `--latest` mode (the prior
# `stig-check-latest` recipe is retired - see stig-drift.yml for the replacement
# weekly live-pinned-zip posture). `check` derives at the pinned zips in the tool's
# stig-refs.toml. The LIVE recipe skips gracefully (exit 0) when curl/unzip are
# absent.
#
# stig-check         : LIVE - fetch the pinned DISA zips; exit 1 on any drift vs
#                      baseline.rs (the weekly stig-drift workflow uses this).
# stig-check-offline : OFFLINE - drift-check baseline.rs against the committed real
#                      DISA fixtures; no network (the PR-gate uses this).
# stig-derive <p>    : print the derived table + diff + paste-ready k(...)/k_exact(...)
#                      lines for review (p = rhel8|rhel9|rhel10, or `all`). Usage:
#                      just stig-derive rhel9
stig-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "stig-check: prerequisites missing - need curl + unzip + network to dl.dod.cyber.mil" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/stig-update/Cargo.toml -- check

stig-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: derive from the committed real-DISA fixtures and confirm
    # baseline.rs still matches. No network. Any product's drift (exit 1) or error
    # (2) fails the recipe.
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/stig-update/Cargo.toml -- \
            check --product "$p" --file "tools/stig-update/tests/fixtures/${p}_sysctld_controls.xml"
    done

stig-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "stig-derive: prerequisites missing - need curl + unzip + network access" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/stig-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/stig-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (#524) Derive / drift-check the per-backend CIS control tables against
# ComplianceAsCode/content CIS profiles. Same nested-tool pattern
# (tools/cis-update, OUT of `just ci`); all three recipes skip gracefully
# (exit 0) when curl is absent.
#
# cis-check          : derive at the PINNED refs (cis-refs.toml); verify the sudoers
#                      anchors; exit 1 on drift vs any shipped CIS table (families
#                      without a shipped table yet report SKIPPED, never vacuous OK).
# cis-check-latest   : derive at the LATEST CaC release; report pending upstream changes.
# cis-derive <p>     : print the derived per-family tables for review
#                      (p = rhel8|rhel9|rhel10, or `all`). Direct `cargo run` flags
#                      --family <f> / --values narrow to one backend / add sysctl values.
cis-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "cis-check: prerequisites missing - need curl + network access to ComplianceAsCode" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/cis-update/Cargo.toml -- check

cis-check-latest:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "cis-check-latest: prerequisites missing - need curl + network access" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/cis-update/Cargo.toml -- check --latest

cis-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "cis-derive: prerequisites missing - need curl + network access" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/cis-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/cis-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (#479) Drift-check / refresh the fapd-E01 attribute registry against upstream
# fapolicyd's src/library/{subject,object}-attr.c. Same nested-tool pattern
# (tools/fapolicyd-attr-update, OUT of `just ci`). The LIVE recipe skips gracefully
# (exit 0) when curl is absent; the OFFLINE recipe never touches the network.
#
# fapd-attr-check          : LIVE - fetch the pinned attr-refs.toml sources from
#                            GitHub; exit 1 on any drift vs the shipped
#                            rulesteward-fapolicyd attrs.rs consts.
# fapd-attr-check-offline  : OFFLINE - drift-check against the committed
#                            tests/fixtures/ (the PR-gate uses this); no network.
# fapd-attr-derive <v>     : print the derived registry + paste-ready rows for
#                            review (v = a pinned fapolicyd version, or `all`).
fapd-attr-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "fapd-attr-check: prerequisites missing - need curl + network access to GitHub" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/fapolicyd-attr-update/Cargo.toml -- check

fapd-attr-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: derive from the committed tests/fixtures/ and confirm the
    # shipped attrs.rs registry still matches. No network. Drift (exit 1) or error
    # (exit 2) fails the recipe.
    cargo run --quiet --manifest-path tools/fapolicyd-attr-update/Cargo.toml -- \
        check --fixtures tools/fapolicyd-attr-update/tests/fixtures

fapd-attr-derive version="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "fapd-attr-derive: prerequisites missing - need curl + network access" >&2
        exit 0
    fi
    if [ "{{version}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/fapolicyd-attr-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/fapolicyd-attr-update/Cargo.toml -- derive --version "{{version}}"
    fi

# (#444) Drift-check / refresh the sshd W01/W02 STIG baselines against the OFFICIAL
# DISA XCCDF. Same nested-tool pattern (tools/sshd-stig-update, OUT of `just ci`).
# DISA versions each RHEL STIG by FILENAME (no releases API), so there is NO
# `--latest` mode; `check` derives at the pinned zips in the tool's stig-refs.toml.
# The LIVE recipes skip gracefully (exit 0) when curl/unzip are absent.
#
# sshd-stig-check         : LIVE - fetch the pinned DISA zips; exit 1 on any drift vs
#                           stig.rs (the weekly sshd-stig-drift workflow uses this).
# sshd-stig-check-offline : OFFLINE - drift-check stig.rs against the committed real
#                           DISA fixtures; no network (the PR-gate uses this).
# sshd-stig-derive <p>    : print the derived table + diff + paste-ready lines for
#                           review (p = rhel8|rhel9|rhel10, or `all`).
sshd-stig-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "sshd-stig-check: prerequisites missing - need curl + unzip + network to dl.dod.cyber.mil" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/sshd-stig-update/Cargo.toml -- check

sshd-stig-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: derive from the committed real-DISA fixtures and confirm
    # stig.rs still matches. No network. Any product's drift (exit 1) or error (2)
    # fails the recipe.
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/sshd-stig-update/Cargo.toml -- \
            check --product "$p" --file "tools/sshd-stig-update/tests/fixtures/${p}_sshd_controls.xml"
    done

sshd-stig-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "sshd-stig-derive: prerequisites missing - need curl + unzip + network access" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/sshd-stig-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/sshd-stig-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (#474) Drift-check / refresh the auditd au-W06 STIG missing-rule baselines against
# the OFFICIAL DISA XCCDF. Same nested-tool pattern as sshd-stig-* above
# (tools/auditd-stig-update, OUT of `just ci`). DISA versions each RHEL STIG by
# FILENAME (no releases API), so there is NO `--latest` mode; `check` derives at the
# pinned zips in the tool's stig-refs.toml. The LIVE recipes skip gracefully (exit 0)
# when curl/unzip are absent.
#
# auditd-stig-check         : LIVE - fetch the pinned DISA zips; exit 1 on any drift vs
#                              stig_required.rs (the weekly auditd-stig-drift workflow
#                              uses this).
# auditd-stig-check-offline : OFFLINE - drift-check stig_required.rs against the
#                              committed real DISA fixtures; no network (the PR-gate
#                              uses this).
# auditd-stig-derive <p>    : print the derived table + diff + paste-ready lines for
#                              review (p = rhel8|rhel9|rhel10, or `all`).
auditd-stig-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "auditd-stig-check: prerequisites missing - need curl + unzip + network to dl.dod.cyber.mil" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/auditd-stig-update/Cargo.toml -- check

auditd-stig-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: derive from the committed real-DISA fixtures and confirm
    # stig_required.rs still matches. No network. Any product's drift (exit 1) or
    # error (2) fails the recipe.
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/auditd-stig-update/Cargo.toml -- \
            check --product "$p" --file "tools/auditd-stig-update/tests/fixtures/${p}_auditd_controls.xml"
    done

auditd-stig-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "auditd-stig-derive: prerequisites missing - need curl + unzip + network access" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/auditd-stig-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/auditd-stig-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (#519) Drift-check / refresh the fapolicyd STIG control table
# (Installed/Enabled/DenyAll) against the OFFICIAL DISA XCCDF. Same nested-tool
# pattern as sshd-stig-*/auditd-stig-* above (tools/fapolicyd-stig-update, OUT of
# `just ci`). DISA versions each RHEL STIG by FILENAME (no releases API), so
# there is NO `--latest` mode; `check` derives at the pinned zips in the tool's
# stig-refs.toml. The LIVE recipes skip gracefully (exit 0) when curl/unzip are
# absent.
#
# fapolicyd-stig-check         : LIVE - fetch the pinned DISA zips; exit 1 on any
#                                 drift vs stig.rs (the weekly
#                                 fapolicyd-stig-drift workflow uses this).
# fapolicyd-stig-check-offline : OFFLINE - drift-check stig.rs against the
#                                 committed real DISA fixtures; no network (the
#                                 PR-gate uses this).
# fapolicyd-stig-derive <p>    : print the derived table + diff + paste-ready
#                                 lines for review (p = rhel8|rhel9|rhel10, or
#                                 `all`).
fapolicyd-stig-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "fapolicyd-stig-check: prerequisites missing - need curl + unzip + network to dl.dod.cyber.mil" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/fapolicyd-stig-update/Cargo.toml -- check

fapolicyd-stig-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: derive from the committed real-DISA fixtures and confirm
    # stig.rs still matches. No network. Any product's drift (exit 1) or error (2)
    # fails the recipe.
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/fapolicyd-stig-update/Cargo.toml -- \
            check --product "$p" --file "tools/fapolicyd-stig-update/tests/fixtures/${p}_fapolicyd_controls.xml"
    done

fapolicyd-stig-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "fapolicyd-stig-derive: prerequisites missing - need curl + unzip + network access" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/fapolicyd-stig-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/fapolicyd-stig-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (#520) Same nested-tool pattern for the selinux se-W01/se-W02 STIG table
# (tools/selinux-stig-update, OUT of `just ci`); mirrors the fapolicyd-stig-*
# triad above.
#
# selinux-stig-check           : LIVE - fetch the pinned DISA zips; exit 1 on any
#                                 drift vs stig.rs (the weekly
#                                 selinux-stig-drift workflow uses this).
# selinux-stig-check-offline   : OFFLINE - drift-check stig.rs against the
#                                 committed real DISA fixtures; no network (the
#                                 PR-gate uses this).
# selinux-stig-derive <p>      : print the derived table + diff + paste-ready
#                                 lines for review (p = rhel8|rhel9|rhel10, or
#                                 `all`).
selinux-stig-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "selinux-stig-check: prerequisites missing - need curl + unzip + network to dl.dod.cyber.mil" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/selinux-stig-update/Cargo.toml -- check

selinux-stig-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: derive from the committed real-DISA fixtures and confirm
    # stig.rs still matches. No network. Any product's drift (exit 1) or error (2)
    # fails the recipe.
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/selinux-stig-update/Cargo.toml -- \
            check --product "$p" --file "tools/selinux-stig-update/tests/fixtures/${p}_selinux_controls.xml"
    done

selinux-stig-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "selinux-stig-derive: prerequisites missing - need curl + unzip + network access" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/selinux-stig-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/selinux-stig-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (#372) Drift-check the sshd E01/E04/W04 lint tables against a LIVE sshd daemon by
# probing the Rocky 8/9/10 + openssh-server images. Same nested-tool pattern
# (tools/sshd-probe-update, OUT of `just ci`). `diff-sshd` skips with rc 3 when docker
# or the images are absent, promoted to rc 2 when the oracle is declared required
# (RS_ORACLE_REQUIRED / RS_REQUIRE_SSHD); `sshd-probe-derive` is a print-only helper and
# still exits 0. The weekly sshd-probe-drift workflow builds the images and runs the
# live check in CI.
#
# diff-sshd             : LIVE - probe the sshd-probe{8,9,10} images; exit 1 on drift.
# diff-sshd-offline     : OFFLINE - drift-check against the committed daemon fixtures
#                         (the PR-gate uses this); no docker.
# sshd-probe-derive <p> : print the derived sets + diff + paste-ready lines (p =
#                         rhel8|rhel9|rhel10, or `all`).

# LIVE: probe the sshd-probe{8,9,10} images and drift-check; exit 1 on drift.
diff-sshd:
    #!/usr/bin/env bash
    set -uo pipefail
    # rc 3 = precondition unmet, per CLAUDE.md's differential contract. NOT 0:
    # `just diff-fapolicyd` exited 0 with this exact shape of message for six
    # weeks while checking nothing (#572), so a box that is supposed to have the
    # oracle must not be able to skip silently.
    #
    # The 3->2 promotion is DELEGATED, never rewritten inline. An inline
    # `[ "${RS_ORACLE_REQUIRED:-0}" != "0" ]` was written here first and was
    # wrong in both directions, measured: it cannot see the per-lane
    # RS_REQUIRE_SSHD (so a CI job that requires only this lane got rc 3, a
    # silent skip - #572's own shape), and it treats `false`/`no`/`off`/blank as
    # truthy. scripts/rs-oracle-required.sh is the single fail-closed parse, and
    # its own header says why there must not be a second copy of it.
    skip_or_fail() {
        bash scripts/rs-oracle-required.sh SSHD
        case "$?" in
        0) exit 2 ;;
        1) exit 3 ;;
        *) echo "diff-sshd: rs-oracle-required.sh SSHD gave an unexpected exit; refusing to guess whether the oracle is required" >&2; exit 2 ;;
        esac
    }
    if ! command -v docker >/dev/null 2>&1; then
        echo "diff-sshd: prerequisites missing - need docker + the sshd-probe{8,9,10} images (build from tools/sshd-probe-update/dockerfiles/<n>/)" >&2
        skip_or_fail
    fi
    if ! docker image inspect sshd-probe8 sshd-probe9 sshd-probe10 >/dev/null 2>&1; then
        echo "diff-sshd: prerequisites missing - sshd-probe8/9/10 images not found; build each from tools/sshd-probe-update/dockerfiles/<n>/Dockerfile (docker build -t sshd-probe<n> ...)" >&2
        skip_or_fail
    fi
    cargo run --quiet --manifest-path tools/sshd-probe-update/Cargo.toml -- check

diff-sshd-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: replay the committed daemon-probe fixtures and confirm the
    # shipped E01/E04/W04 tables still match. No docker. Any product's drift (exit 1)
    # or error (2) fails the recipe.
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/sshd-probe-update/Cargo.toml -- \
            check --product "$p" --transcript "tools/sshd-probe-update/tests/fixtures/${p}_probe.jsonl"
    done

sshd-probe-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v docker >/dev/null 2>&1; then
        echo "sshd-probe-derive: prerequisites missing - need docker + the sshd-probe{8,9,10} images" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/sshd-probe-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/sshd-probe-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (#478) Drift-check the shipped fapolicyd version-map / pattern= value-set / fapd-E07
# type-category tables against a REAL fapolicyd daemon by probing the prebuilt
# fapolicyd8/9/10 images directly (see this repo's CLAUDE.md "Differential
# verification" section - these images are NOT built by this tool, unlike
# tools/sshd-probe-update's dockerfiles/, since fapolicyd already ships on them). Same
# nested-tool pattern (tools/fapolicyd-probe-update, OUT of `just ci`). `fapolicyd-probe-check`
# skips with rc 3 when docker or the images are absent, promoted to rc 2 when the oracle
# is declared required (RS_ORACLE_REQUIRED / RS_REQUIRE_FAPOLICYD); `fapolicyd-probe-derive`
# is a print-only helper and still exits 0. The offline recipe replays the committed
# daemon-probe fixtures (no docker) and is what the PR-gate workflow runs.
#
# fapolicyd-probe-check          : LIVE - probe fapolicyd8/9/10; exit 1 on drift.
# fapolicyd-probe-check-offline  : OFFLINE - drift-check against the committed
#                                   tests/fixtures/ transcripts (the PR-gate uses this).
# fapolicyd-probe-derive <t>     : print the derived sets + diff (t = rhel8|rhel9|rhel10,
#                                   or `all`).

# LIVE: probe the prebuilt fapolicyd8/9/10 images and drift-check; exit 1 on drift.
fapolicyd-probe-check:
    #!/usr/bin/env bash
    set -uo pipefail
    # rc 3 = precondition unmet, per CLAUDE.md's differential contract. NOT 0:
    # `just diff-fapolicyd` exited 0 with this exact shape of message for six
    # weeks while checking nothing (#572). The 3->2 promotion is delegated to the
    # single fail-closed parse rather than re-tested inline; see diff-sshd's
    # skip_or_fail for the two measured ways the inline form was wrong.
    skip_or_fail() {
        bash scripts/rs-oracle-required.sh FAPOLICYD
        case "$?" in
        0) exit 2 ;;
        1) exit 3 ;;
        *) echo "fapolicyd-probe-check: rs-oracle-required.sh FAPOLICYD gave an unexpected exit; refusing to guess whether the oracle is required" >&2; exit 2 ;;
        esac
    }
    if ! command -v docker >/dev/null 2>&1; then
        echo "fapolicyd-probe-check: prerequisites missing - need docker + the prebuilt fapolicyd{8,9,10} images (see CLAUDE.md 'Differential verification')" >&2
        skip_or_fail
    fi
    if ! docker image inspect fapolicyd8 fapolicyd9 fapolicyd10 >/dev/null 2>&1; then
        echo "fapolicyd-probe-check: prerequisites missing - fapolicyd8/9/10 docker images not found; pull or build them first (see CLAUDE.md 'Differential verification')" >&2
        skip_or_fail
    fi
    cargo run --quiet --manifest-path tools/fapolicyd-probe-update/Cargo.toml -- check

# OFFLINE: replay the committed tests/fixtures/ transcripts; no docker. Any target's
# drift (exit 1) or error (exit 2) fails the recipe. This is the PR-CI gate.
fapolicyd-probe-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/fapolicyd-probe-update/Cargo.toml -- \
            check --target "$p" --transcript-dir tools/fapolicyd-probe-update/tests/fixtures
    done

fapolicyd-probe-derive target="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v docker >/dev/null 2>&1; then
        echo "fapolicyd-probe-derive: prerequisites missing - need docker + the prebuilt fapolicyd{8,9,10} images" >&2
        exit 0
    fi
    if [ "{{target}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/fapolicyd-probe-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/fapolicyd-probe-update/Cargo.toml -- derive --target "{{target}}"
    fi

# (#476) Drift-check / refresh the auditd msgtype name<->number tables
# (crates/rulesteward-auditd/src/lints/value/msgtype.rs) against upstream
# audit-userspace's lib/msg_typetab.h + lib/audit-records.h and the Linux
# kernel's include/uapi/linux/audit.h. Same nested-tool pattern
# (tools/auditd-msgtype-update, OUT of `just ci`). The LIVE recipe skips
# gracefully (exit 0) when curl is absent; the OFFLINE recipe never touches
# the network.
#
# auditd-msgtype-check          : LIVE - fetch the pinned msgtype-refs.toml
#                                  sources from GitHub; exit 1 on any drift vs
#                                  the shipped rulesteward-auditd msgtype.rs
#                                  consts.
# auditd-msgtype-check-offline  : OFFLINE - drift-check against the committed
#                                  tests/fixtures/ (the PR-gate uses this); no
#                                  network.
# auditd-msgtype-derive         : print the derived tables for review.
auditd-msgtype-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "auditd-msgtype-check: prerequisites missing - need curl + network access to GitHub" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/auditd-msgtype-update/Cargo.toml -- check

auditd-msgtype-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: derive from the committed tests/fixtures/ and confirm the
    # shipped msgtype.rs tables still match. No network. Drift (exit 1) or error
    # (exit 2) fails the recipe.
    cargo run --quiet --manifest-path tools/auditd-msgtype-update/Cargo.toml -- \
        check --fixtures tools/auditd-msgtype-update/tests/fixtures

auditd-msgtype-derive:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "auditd-msgtype-derive: prerequisites missing - need curl + network access" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/auditd-msgtype-update/Cargo.toml -- derive

# ---------------------------------------------------------------------------
# 9j Phase 0: recipes declared ahead of the tooling they invoke.
#
# These are landed on the session branch BEFORE the fan-out so that no parallel
# lane has to edit this file (justfile was the only surface three lanes would
# otherwise have contended for). Each recipe below fails until its lane lands the
# tool it calls; none is part of `just ci`, matching every other *-stig-* recipe,
# so the gate is unaffected in the interim.
# ---------------------------------------------------------------------------

# (#550, 9j lane 5) Upstream-pin staleness detection for the two DISA-derived STIG
# tools that lack it. Unlike ComplianceAsCode, DISA publishes no releases API: each
# RHEL STIG is versioned by FILENAME (V<major>R<minor>), so staleness is detected by
# probing the next candidate revision (increment minor, then major, until 404)
# rather than by querying for "latest". That is why this is NOT the `cis-update
# --latest` mechanism, which hits api.github.com/repos/.../releases/latest.
#
# Non-blocking by design: a newer upstream revision is news, not a build failure.
# Both recipes skip gracefully (exit 0) when curl is absent. A monthly scheduled
# workflow (also lane 5) mirrors mutants.yml's shape and opens an issue on a hit.
#
# LIVE: report whether a newer DISA sshd STIG revision than the pin exists. (#550)
sshd-stig-check-pin:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "sshd-stig-check-pin: prerequisites missing - need curl + network to dl.dod.cyber.mil" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/sshd-stig-update/Cargo.toml -- check-pin

# LIVE: report whether a newer DISA auditd STIG revision than the pin exists. (#550)
auditd-stig-check-pin:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1; then
        echo "auditd-stig-check-pin: prerequisites missing - need curl + network to dl.dod.cyber.mil" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/auditd-stig-update/Cargo.toml -- check-pin

# (#551, 9j lane 6) Drift-check / refresh the sudo-W04 DISA control families against
# the OFFICIAL DISA XCCDF. Mirrors the sshd-stig-* triad above.
#
# SCOPE: DISA ONLY. The CIS half of sudo-W04 is already drift-checked by
# tools/cis-update (registry.rs registers Family::Sudoers against
# rulesteward_sudoers::lints::cis::cis_baseline, gated by cis-check.yml /
# cis-drift.yml), so this tool must not duplicate it.
#
# The sudo-W06 grounding stays OUT of this tool: it keeps the inline hermetic
# pinning locked 2026-07-15 (see sudoers/lints/tags.rs w06_stig_drift_tests), which
# cross-checks sshd/auditd stig-refs.toml via include_str!. Do not "unify" the two;
# doing so silently drops W06's cross-tool revision check.
#
# LIVE: drift-check the sudo-W04 DISA control families vs the pinned zips. (#551)
sudoers-stig-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "sudoers-stig-check: prerequisites missing - need curl + unzip + network to dl.dod.cyber.mil" >&2
        exit 0
    fi
    cargo run --quiet --manifest-path tools/sudoers-stig-update/Cargo.toml -- check

sudoers-stig-check-offline:
    #!/usr/bin/env bash
    set -euo pipefail
    # Offline drift gate: derive from the committed real-DISA fixtures and confirm
    # stig.rs still matches. No network. Any product's drift (exit 1) or error (2)
    # fails the recipe.
    for p in rhel8 rhel9 rhel10; do
        cargo run --quiet --manifest-path tools/sudoers-stig-update/Cargo.toml -- \
            check --product "$p" --file "tools/sudoers-stig-update/tests/fixtures/${p}_sudoers_controls.xml"
    done

sudoers-stig-derive product="all":
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
        echo "sudoers-stig-derive: prerequisites missing - need curl + unzip + network access" >&2
        exit 0
    fi
    if [ "{{product}}" = "all" ]; then
        cargo run --quiet --manifest-path tools/sudoers-stig-update/Cargo.toml -- derive
    else
        cargo run --quiet --manifest-path tools/sudoers-stig-update/Cargo.toml -- derive --product "{{product}}"
    fi

# (session 9k-1) LIVE differential drift checks for the auditd / sysctld / sudoers
# backends: capture a fresh oracle corpus from the rs-oracle{8,9,10} containers and
# replay the SAME Tier-1 test binary against it.
#
# These three are deliberately NOT in `just ci`. Their OFFLINE tier is an ordinary
# `cargo test` over the committed corpus, which needs no docker and therefore has no
# skip path at all, so it is already covered by `just test`. That split is the point:
# a missing docker daemon degrades the guarantee from "nothing was checked" to "the
# oracle was not re-derived". See CONTRIBUTING.md "Differential oracle contract".
#
# All three delegate to ONE driver, scripts/rs-oracle-diff.sh. The exit-code mapping
# is the part of this harness whose every wrong branch fails toward "clean"; written
# out three times it would be wrong in three different ways, which is how
# `just diff-fapolicyd` came to report success while checking nothing for 12 days,
# from the 2026-07-13 NFS rebuild until the recipe was retired 2026-07-25 (#572).
# (This line read "six weeks" until 2026-08-03; the recipe's entire life was 30 days.) The driver is positive-controlled by scripts/rs-oracle-diff-test.sh, which
# re-seeds that bug into a copy of it and requires named cases to catch it.
#
# Exit codes: 0 clean (the success line carries a non-zero count), 1 drift,
# 2 tool/environment error, 3 legitimate skip. RS_ORACLE_REQUIRED=1 - or the per-lane
# RS_REQUIRE_AUDITCTL / RS_REQUIRE_SYSTEMD_SYSCTL / RS_REQUIRE_VISUDO - promotes every
# rc-3 skip to a hard rc-2 failure, which is what the weekly drift workflows set.

# LIVE: drift-check auditd rule-line verdicts against auditctl -R. (#584, #601)
diff-auditd:
    bash scripts/rs-oracle-diff.sh auditd

# LIVE: drift-check the sysctl.d merge model against systemd-sysctl. (#593)
diff-sysctld:
    bash scripts/rs-oracle-diff.sh sysctld

# LIVE: drift-check sudoers parse + AST against visudo / cvtsudoers. (#538)
diff-sudoers:
    bash scripts/rs-oracle-diff.sh sudoers

# ---------------------------------------------------------------------------
# OFFLINE: branch-vs-fork-point differential replay. (#661, epic #654)
#
# The recipes above hold the BINARY fixed and vary the CORPUS ("has the real
# subsystem drifted?"). These hold the CORPUS fixed and vary the BINARY, which
# answers the question #658's corpus-growth gate leaves open: "would the corpus
# this branch added have caught the bug this branch fixed?". A branch can satisfy
# the growth gate with a scenario the old code already passed - evidence that
# accumulates without discriminating - and nothing else in the chain notices.
#
# Run these EVERY Adversarial Testing Loop round, not once. A divergence table is
# the only instrument in the loop whose evidence accumulates across rounds; the
# adversary's is re-rolled each time, which is how session 9o declared a round DRY
# over a live fail-open.
#
# No docker, no root, no live oracle, so unlike diff-* above there is NO rc 3:
# 0 clean (the success line carries a non-zero announcement count), 1 a REGRESSION,
# OR a test with no baseline left FAILING at HEAD (added, or un-parked), OR a test
# the branch silenced with #[ignore] - the driver is explicit that the middle one
# is NOT a regression, so the separators matter, 2 tool error (including "these two
# builds cannot be compared"). Positive-controlled by
# scripts/rs-branch-diff-test.sh, which re-seeds SOME of the driver's guards into
# a copy of it and requires named cases to catch each. Not every guard is
# controlled; that file's header says why, and gives the two commands that count
# both numbers rather than quoting either.
#
# The base build is cached per sha under TMPDIR, so repeated rounds against the
# same fork point pay for it once. Deliberately NOT in `just ci`: it takes a base
# ref and builds two trees.
#
# Usage: just diff-sudoers-branch 96038c9

diff-auditd-branch base:
    bash scripts/rs-branch-diff.sh auditd "{{base}}"

diff-selinux-branch base:
    bash scripts/rs-branch-diff.sh selinux "{{base}}"

diff-sudoers-branch base:
    bash scripts/rs-branch-diff.sh sudoers "{{base}}"

diff-sysctld-branch base:
    bash scripts/rs-branch-diff.sh sysctld "{{base}}"

# Self-test of the differential/capture INSTRUMENTS. In `just ci` because an
# unverified instrument is the exact failure this contract exists to prevent: a
# harness that reports clean having compared (or scanned) nothing is
# indistinguishable downstream from a real pass. Pure bash - cargo and docker
# are stubbed, no containers, no network - so it needs no toolchain and runs in
# every CI container. Covers both the two rs-oracle-diff.sh instruments and the
# two rs-capture-guard.sh instruments (session 9k-1's write-discipline layer),
# since all four share this same "prove you saw something" shape.
#
# Self-test the differential + capture-guard instruments (session 9k-1).
oracle-harness-test:
    #!/usr/bin/env bash
    set -uo pipefail
    # Never chain these with && - a short-circuit would hide which one failed,
    # and rc is the gate here, not the transcript.
    bash scripts/rs-oracle-required-test.sh
    req_rc=$?
    bash scripts/rs-oracle-diff-test.sh
    diff_rc=$?
    bash scripts/rs-capture-guard-test.sh
    guard_rc=$?
    bash scripts/check-capture-writes-test.sh
    capwrites_rc=$?
    echo "oracle-harness-test: rs-oracle-required-test rc=${req_rc}, rs-oracle-diff-test rc=${diff_rc}, rs-capture-guard-test rc=${guard_rc}, check-capture-writes-test rc=${capwrites_rc}"
    [ "${req_rc}" -eq 0 ] && [ "${diff_rc}" -eq 0 ] && [ "${guard_rc}" -eq 0 ] && [ "${capwrites_rc}" -eq 0 ]
