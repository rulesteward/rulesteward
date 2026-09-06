#!/usr/bin/env bash
# Mutation testing, with a verdict.
#
#   ./xtask/mutants.sh                  full run, then judge it against the baseline
#   MUTANTS_SHARD=k/8 ./xtask/mutants.sh   run shard k, judge nothing, report its numbers
#   ./xtask/mutants.sh --in-diff        absolute gate on the code this change touched
#   ./xtask/mutants.sh --verdict        sum the eight shards' numbers and judge the sum
#   ./xtask/mutants.sh --write-baseline record what is there now as accepted
#
# **`cargo mutants` exits 2 whenever any mutant survives.** That is an absolute
# verdict and useless as a gate on its own: it is red from the first run and stays
# red, because no pipeline can fix a survivor -- only someone writing a test can.
# An always-red gate is muted within a month and green by neglect thereafter. So
# docs/mutation-baseline.json holds what has been looked at and accepted, and the
# full run fails only on what is *new*. A ratchet, not a floor.
#
# `--in-diff` is the exception and is absolute: a change may not leave a surviving
# mutant in a function it touched. It matches against code under test and not test
# code, so a change that only deletes tests generates zero mutants and passes --
# the sharded full run is what catches that.
#
# **The mutation score is reported and never gated.** Its denominator moves when
# code is added or deleted, so deleting dead code would improve it without a test
# being written.
#
# **Never put `-D warnings` in RUSTFLAGS.** Mutated bodies routinely produce
# unused-variable warnings, and under `-D warnings` cargo-mutants records them as
# *unviable* rather than *caught*, which silently shrinks the denominator. It stays
# a clippy argument in xtask/lint.sh, which is the correct form.
#
# **`--in-place` on every run.** The gitignored `research` symlink does not survive
# cargo-mutants' default tree copy cleanly, and the book recommends `--in-place`
# for CI regardless.
#
# **The shard arrives in an environment variable rather than a flag.** The
# workflows-carry-no-logic gate in xtask/lint.sh fullmatches every CI command
# against `./.tools/bin/just [a-z][a-z-]*`, and `just mutants --shard 0/8` is not
# that. A local run sets nothing and is unsharded.

# shellcheck source=xtask/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

BASELINE="$REPO/docs/mutation-baseline.json"
OUTCOMES="$REPO/mutants.out/outcomes.json"

# The four counters plus the count of mutants generated. `outcomes.json` is
# documented as subject to change, so this is one jq expression that a format
# change breaks loudly rather than silently: a missing key errors here instead of
# arriving downstream as an empty field and a smaller, better-looking number.
read_outcomes() {
    [ -f "$OUTCOMES" ] ||
        die "no $OUTCOMES -- the run did not get far enough to write one"
    jq -er '[.missed, .caught, .unviable, .timeout, .total_mutants]
            | map(if type == "number" then . else error("field missing or not a number") end)
            | @tsv' "$OUTCOMES" ||
        die "could not read $OUTCOMES -- cargo-mutants' outcome format moved"
}

# The summary block and the score, printed by every path that holds a full set of
# numbers: the single run and the verdict over a sharded one.
report() {
    local missed="$1" caught="$2" unviable="$3" timeout="$4" total="$5" tested score
    tested=$(( caught + missed ))
    # Truncating integer division, which is the right direction for a figure
    # nobody asserts on: it never flatters.
    if [ "$tested" -gt 0 ]; then score="$(( caught * 100 / tested ))%"; else score="n/a"; fi
    log ""
    log "  mutants   $total"
    log "  caught    $caught"
    log "  missed    $missed"
    log "  unviable  $unviable"
    log "  timeout   $timeout"
    log "  score     $score  (caught of caught + missed; reported, never gated)"
    log ""
}

# The comparison against docs/mutation-baseline.json. One copy, called by the
# single-run path and by --verdict, so a sharded pipeline cannot drift into
# judging by a different rule than a developer's `just mutants` does.
judge() {
    local missed="$1" caught="$2" unviable="$3" timeout="$4" total="$5" base_missed

    [ -f "$BASELINE" ] ||
        die "no docs/mutation-baseline.json yet -- run './xtask/mutants.sh --write-baseline' once the numbers are settled"
    base_missed="$(jq -er '.missed | if type == "number" then . else error("not a number") end' "$BASELINE")" ||
        die "docs/mutation-baseline.json has no numeric .missed"

    report "$missed" "$caught" "$unviable" "$timeout" "$total"
    log "  baseline missed  $base_missed"
    log ""

    [ "$missed" -le "$base_missed" ] ||
        die "missed rose from $base_missed to $missed -- $(( missed - base_missed )) mutant(s) that no test notices"

    # The other direction. Not a failure -- somebody wrote a test -- but the
    # ceiling is now loose by exactly that much, and a ceiling nobody tightens
    # stops being a ceiling.
    [ "$missed" -eq "$base_missed" ] ||
        log "  baseline is loose: $base_missed -> $missed, hand-edit docs/mutation-baseline.json with the reason in the commit body"

    log "no mutation regression against the baseline"
}

# A mutated build that fails a property makes proptest write its seed into
# proptest-regressions/, a directory this repo commits. Those seeds are
# regressions of a mutant, not of the code, so every mutant run discards them:
# tracked files restored, untracked ones removed, nothing outside that directory
# touched. A real failure under `cargo test` still persists as before.
discard_mutant_seeds() {
    git -C "$REPO" checkout -q -- proptest-regressions 2>/dev/null || true
    git -C "$REPO" clean -fdq -- proptest-regressions 2>/dev/null || true
}

# One shard: run its slice, report its numbers, judge nothing. The verdict is a
# question about all N shards at once and no shard holds the answer.
#
# `--baseline=skip` because the `check` job already proved the suite passes on an
# unmutated tree, and skipping it means an explicit `--timeout`: the baseline run
# is what derives the per-mutant timeout otherwise. 60 s covers the test phase
# only, and the suite takes about 5 s on 16 cores and under 15 s on a hosted
# runner. A handful of mutants on this tree stop a byte-walking loop advancing
# and cost their shard the whole timeout each, under the memory cap that
# xtask/limit-memory.sh applies, which is why the default is not larger.
run_shard() {
    local spec="$1" k n compact
    [[ "$spec" =~ ^([0-9]+)/([0-9]+)$ ]] ||
        die "MUTANTS_SHARD is '$spec' -- expected 'k/N', as in 0/8"
    k="${BASH_REMATCH[1]}"
    n="${BASH_REMATCH[2]}"
    # cargo-mutants shards are 0-based and it rejects k >= n itself; saying so
    # here names the variable rather than leaving a cargo usage error.
    { [ "$n" -ge 1 ] && [ "$k" -lt "$n" ]; } ||
        die "MUTANTS_SHARD is '$spec' -- need 0 <= k < N"

    log "running shard $k of $n"
    # Exit status ignored: 2 means survivors, which is the verdict job's question
    # and not this one's. A run that produced no outcomes.json dies in
    # read_outcomes below.
    cargo mutants --in-place \
        --shard "$k/$n" --sharding round-robin \
        --baseline=skip --timeout "${MUTANTS_TIMEOUT:-60}" || true
    discard_mutant_seeds

    [ -f "$OUTCOMES" ] || die "no $OUTCOMES -- shard $spec produced no outcomes at all"
    compact="$(jq -ec '{missed, caught, unviable, timeout}' "$OUTCOMES")" ||
        die "could not read $OUTCOMES -- cargo-mutants' outcome format moved"

    # A job output rather than an artifact: the account's artifact storage quota is
    # shared across repositories and recalculated only every 6 to 12 hours, and a
    # hundred bytes of counters fit the 1 MB per-job output budget with room over.
    # One `jq -c` and one line: a step output is a `name=value` pair a newline ends.
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        printf 'stats-%s=%s\n' "$k" "$compact" >> "$GITHUB_OUTPUT"
    fi
    log "shard $k: $compact"
}

# The absolute gate on changed code. The diff must come straight from `git diff`;
# cargo-mutants matches its `b/` paths against the tree.
#
# On a pull request MUTANTS_BASE is `github.base_ref` and the comparison is against
# the merge base. On a master push it is empty and `HEAD^...HEAD` is the squashed
# pull request that just landed.
in_diff() {
    local base="${MUTANTS_BASE:-}" diff="$REPO/.cache/git.diff"
    mkdir -p "$REPO/.cache"
    if [ -n "$base" ]; then
        git fetch -q origin "$base"
        git diff "origin/$base...HEAD" > "$diff"
    else
        git diff 'HEAD^...HEAD' > "$diff"
    fi
    if [ ! -s "$diff" ]; then
        log "empty diff -- nothing to mutate"
        return 0
    fi
    # Its exit status *is* the verdict here: on changed code the answer is zero
    # survivors, not a ratchet. Measured on 27.1.0: a diff that touches no
    # production code prints "No mutants to filter" and exits 0, so a test-only or
    # comment-only change needs no special case.
    local status=0
    cargo mutants --in-place --in-diff "$diff" || status=$?
    discard_mutant_seeds
    return "$status"
}

# Sum a sharded run and judge the sum. The shard jobs share nothing but these
# environment variables, so this is where a sharded pipeline gets its verdict.
verdict() {
    local k var val stats="" sums missed caught unviable timeout total sum

    for k in 0 1 2 3 4 5 6 7; do
        var="MUTANTS_STATS_$k"
        val="${!var:-}"
        # Diagnosed rather than skipped: an empty output is a cancelled or crashed
        # shard, and skipping it would leave a smaller, better-looking sum.
        [ -n "$val" ] || die "$var is empty -- shard $k reported nothing, and a missing shard is not a pass"
        jq -e 'type == "object"' >/dev/null <<<"$val" ||
            die "$var is not a JSON object: $val"
        stats+="$val"$'\n'
    done

    sums="$(jq -s -e -r '[ (map(.missed) | add), (map(.caught) | add),
                       (map(.unviable) | add), (map(.timeout) | add) ]
                     | map(if type == "number" then . else error("field missing or not a number") end)
                     | @tsv' <<<"$stats")" ||
        die "could not sum the eight shard stats -- cargo-mutants' outcome format moved"
    read -r missed caught unviable timeout <<<"$sums"

    # The floor, and the check that matters most. Every mutant belongs to exactly
    # one shard, so the four counters add to the number of mutants that exist --
    # unless a shard tested nothing, which otherwise looks like a smaller and
    # therefore better set of numbers. The count comes from a fresh `--list`, not
    # from a shard, so it is independent of the thing it is checking.
    total="$(cargo mutants --list --json | jq length)"
    sum=$(( missed + caught + unviable + timeout ))
    [ "$sum" -eq "$total" ] ||
        die "the eight shards account for $sum of $total mutants -- a shard tested nothing"

    log "summed eight shards"
    judge "$missed" "$caught" "$unviable" "$timeout" "$total"
}

# Denied to the agent in .claude/settings.json: raising the accepted survivor count
# is the obvious helpful action and exactly the wrong one. A baseline change is a
# hand edit to the file with the reason in the commit body, and this flag only
# exists to produce the first one.
write_baseline() {
    local missed caught unviable timeout total out
    # Command substitution, not a process substitution: `shopt -s inherit_errexit`
    # in lib.sh makes a `die` in there stop this script, where `< <(...)` would
    # hand `read` an empty line and carry on with zeroes.
    out="$(read_outcomes)"
    read -r missed caught unviable timeout total <<<"$out"
    report "$missed" "$caught" "$unviable" "$timeout" "$total"
    mkdir -p "$(dirname "$BASELINE")"
    jq -n --argjson missed "$missed" --argjson total "$total" \
        '{missed: $missed, total: $total, note: "hand-edited; reason in the commit body"}' \
        > "$BASELINE"
    log "wrote docs/mutation-baseline.json: missed $missed of $total"
}

# Every cargo test a mutant run spawns goes through xtask/limit-memory.sh,
# which caps its address space. The variable is cargo's per-target `runner`
# setting spelled as an environment variable, so it reaches the `cargo test`
# cargo-mutants runs without a .cargo/config.toml that would also bind
# `just test`. See the runner script for the measurement behind it.
limit_test_memory() {
    local host
    host="$(rustc -vV | sed -n 's/^host: //p' | tr 'a-z-' 'A-Z_')"
    [ -n "$host" ] || die "rustc -vV printed no host triple"
    export "CARGO_TARGET_${host}_RUNNER=$REPO/xtask/limit-memory.sh"
}

main() {
    need jq
    cd "$REPO"
    limit_test_memory

    case "${1:-}" in
        --verdict)   verdict; return ;;
        --in-diff)   in_diff; return ;;
    esac

    local shard="${MUTANTS_SHARD:-}"
    if [ -n "$shard" ]; then
        [ "${1:-}" != "--write-baseline" ] ||
            die "--write-baseline with MUTANTS_SHARD set -- a baseline is a full run, and a shard holds only its own part of the count"
        run_shard "$shard"
        return
    fi

    # Reads the last run's outcomes and starts none of its own.
    if [ "${1:-}" = "--write-baseline" ]; then
        write_baseline
        return
    fi

    # Baseline strategy left at its default `run`, which also derives the
    # per-mutant timeout, so no --timeout here. Exit status ignored for the reason
    # in the header: judge is the verdict.
    cargo mutants --in-place || true
    discard_mutant_seeds

    local missed caught unviable timeout total out
    out="$(read_outcomes)"
    read -r missed caught unviable timeout total <<<"$out"
    judge "$missed" "$caught" "$unviable" "$timeout" "$total"
}

main "$@"
