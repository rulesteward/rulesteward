#!/usr/bin/env bash
# Every static gate, in one pass.
#
# **Runs them all and reports them all.** `just`'s recipe dependencies are
# fail-fast, which is right for a pipeline and wrong for a developer: someone who
# has just touched Rust, a shell script and a workflow wants three verdicts, not
# the first one. So this accumulates rather than &&-chaining, and the summary at
# the end is the thing to read. The exit status is still nonzero if any gate
# failed, so the Stop hook and CI both see a failure.

# shellcheck source=xtask/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

failed=()
gate() {
    local name="$1"; shift
    if "$@"; then
        printf '  ok    %s\n' "$name"
    else
        printf '  FAIL  %s\n' "$name"
        failed+=("$name")
    fi
}

# A first-party action at a mutable tag is somebody else's moving code running
# with the job's token. Only a 40-hex commit sha pins what will run.
#
# Anchored at the YAML key, so a comment that names `uses:` is not a hit.
actions_are_pinned() {
    local hits
    hits="$(grep -rnE '^[[:space:]]*-?[[:space:]]*uses:' "$REPO/.github/workflows" |
        grep -vE 'uses: actions/[a-z-]+@[0-9a-f]{40}' || true)"
    [ -z "$hits" ] || { printf '%s\n' "$hits" >&2; return 1; }
}

# A skip must be able to become a failure. `#[ignore]` with no reason string is a
# test that quietly does not run and says nothing about why; `#[ignore = "..."]`
# is a decision someone can read and reverse.
ignore_carries_a_reason() {
    local hits
    hits="$(grep -rnE '#\[ignore\]' "$REPO/src" "$REPO/tests" || true)"
    [ -z "$hits" ] || { printf '%s\n' "$hits" >&2; return 1; }
}

# -x follows `source lib.sh`, so a variable used only by a caller is not reported
# unused and a genuinely unused one still is.
#
# .claude/hooks/ is in scope because its scripts are shell this repo ships and CI
# would otherwise never read them. That glob is empty until the agent-config PR
# lands, hence nullglob: an unmatched glob passed through as a literal would fail
# this gate on a missing file, which reads as a broken hook rather than an absent
# one.
shell_scripts_are_clean() {
    local -a files
    shopt -s nullglob
    files=("$REPO"/xtask/*.sh "$REPO"/.claude/hooks/*.sh)
    shopt -u nullglob
    [ ${#files[@]} -gt 0 ] || die "no shell scripts matched -- the globs are wrong"
    shellcheck -x -s bash "${files[@]}"
}

main() {
    cd "$REPO"
    need cargo
    need shellcheck

    log "lint"
    gate "cargo fmt"                cargo fmt --check
    gate "clippy"                   cargo clippy --all-targets -- -D warnings
    # tests/corpus.rs is behind `full-corpus` and compiles to nothing without it,
    # so the default clippy run never reads it. A gate that quietly passes
    # because it did not run is worse than no gate.
    gate "clippy (full-corpus)"     cargo clippy --all-targets --features full-corpus -- -D warnings
    # Licences, advisories, bans and sources. It never compiles, and it clones
    # the RustSec database once per run rather than per check. cargo-audit is
    # rejected: it reads the same database this already reads.
    gate "cargo deny"               cargo deny check
    gate "actions are pinned"       actions_are_pinned
    gate "ignore carries a reason"  ignore_carries_a_reason
    gate "shellcheck"               shell_scripts_are_clean
    # The only gate over the strings users read; fixtures and goldens are
    # excluded because they are verbatim daemon bytes with deliberate corruption.
    gate "typos"                    typos

    if [ ${#failed[@]} -gt 0 ]; then
        die "${#failed[@]} gate(s) failed: ${failed[*]}"
    fi
    log "all gates pass"
}

main "$@"
