#!/usr/bin/env bash
#
# Positive-controlled test suite for scripts/rs-branch-diff.sh.
#
# The driver holds the CORPUS fixed and varies the PRODUCT: it replays one
# committed corpus against a binary built at a base sha and a binary built at
# HEAD. Like its sibling rs-oracle-diff.sh, every wrong branch in it fails toward
# "clean" - two binaries that agree because NEITHER ran look exactly like two
# binaries that agree because the code is correct. So the driver is exercised
# here against a stubbed cargo, a stubbed git and two stubbed test binaries, once
# per interesting outcome.
#
# The suite ends with positive controls that seed SOME of the driver's guards
# back into a COPY of the driver and assert that NAMED cases catch it. Without
# those, this file could pass while testing nothing.
#
# SOME, not "each": the driver has substantially more `die 2` sites than there are
# controls, and they are not all controlled. Saying "each" invited the next person
# to skip adding a control for a new guard because the comment claimed one already
# existed. No exact count is quoted for EITHER number, deliberately - the first
# version of this comment said the driver had "28" die sites in the very commit
# that made it 34, it was 38 two commits later, and the control count has since
# been "six" and "NINE" in a file whose own rule forbids quoting counts. Count
# them today with `grep -c 'die 2 '` and `grep -cE '^run_positive_control '`.
#
# A control proves a guard is WITNESSED, which a case NAME does not. Round 3 found
# a guard whose only named case exited earlier and never reached it: neutering the
# guard left every case passing. If you add a guard, add a control, and check the
# control fails when the guard is gone.
#
# Usage: bash scripts/rs-branch-diff-test.sh
# Exit:  0 all cases pass, 1 a case failed, 2 the suite could not run.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
DRIVER="${REPO_ROOT}/scripts/rs-branch-diff.sh"

[ -f "${DRIVER}" ] || {
    echo "SUITE ERROR: ${DRIVER} not found" >&2
    exit 2
}

SANDBOX_BASE="$(mktemp -d "${TMPDIR:-/tmp}/rs-branch-diff-test-XXXXXX")" || exit 2
trap 'rm -rf "${SANDBOX_BASE}"' EXIT

PASS=0
FAIL=0
FAILED_CASES=()
# 1 while a positive-control phase is running; see case_marker().
CONTROL_PHASE=0
# Every exit code pass 1 observed, so the "there is no rc 3" contract is asserted
# against real behaviour rather than merely documented.
OBSERVED_RCS=""

# The per-case marker for a case that did NOT meet its expectation.
#
# During a positive-control phase the cases are SUPPOSED not to meet it - that is
# how the control proves the guard is load-bearing - so printing `FAIL` there
# announces SUCCESS using the word for failure (#641). `just instrument-test`
# asserts that a suite exiting 0 prints no `FAIL` token, and `EXPECTED-FAIL`
# would still trip a log scrape keyed on it.
case_marker() {
    if [ "${CONTROL_PHASE}" -eq 1 ]; then printf 'CAUGHT'; else printf 'FAIL'; fi
}

# Print a case's captured driver output, EXCEPT during a positive-control phase.
#
# This suite differs from its sibling in one way that matters here: the driver's
# divergence table legitimately contains libtest's own `FAILED` verdict in its
# R1/R2/R3 columns. During a control phase every case is SUPPOSED to mismatch, so
# echoing those tables sprays the token `FAIL` across a run that then exits 0 -
# which `just instrument-test` rejects (#641), and rightly: it arms every log
# scrape keyed on that token to fire on a healthy run.
#
# Suppressed rather than rewritten, because mangling the token would put a line
# in the transcript that the driver never printed. The `CAUGHT` line above still
# names the case and both exit codes, and a control that fails to catch reports
# exactly which cases it missed.
dump_output() {
    [ "${CONTROL_PHASE}" -eq 1 ] && return 0
    printf '     output: %s\n' "$1" >&2
}

# ---------------------------------------------------------------------------
# Sandbox construction.
#
# Builds a fake repo root holding the driver under test, a committed HEAD corpus,
# and a PATH directory with stub cargo / git / test binaries.
#
# The two stub test binaries are the heart of this suite. The BASE binary is run
# TWICE, against two different corpora, and it decides its verdicts from the
# corpus path it was handed - which is exactly the discrimination the driver
# exists to measure, and exactly what a broken driver would fail to distinguish.
# ---------------------------------------------------------------------------
make_sandbox() {
    local driver_src="$1"
    local box
    box="$(mktemp -d "${SANDBOX_BASE}/box-XXXXXX")" || return 2

    mkdir -p "${box}/scripts" "${box}/bin" "${box}/sysbin" "${box}/tmp" \
        "${box}/crates/rulesteward-auditd/tests/corpus/auditd-oracle"
    cp "${driver_src}" "${box}/scripts/rs-branch-diff.sh"

    # The driver's repo-root sanity check looks for a known sibling, so the
    # sandbox must carry one (a `cd "/.."` collapse otherwise resolves every
    # relative path against `/` and succeeds).
    : >"${box}/scripts/rs-oracle-diff.sh"

    # A committed HEAD corpus with at least one regular file in it. An empty one
    # is its own case (STUB_HEAD_CORPUS_EMPTY).
    if [ "${STUB_HEAD_CORPUS_EMPTY:-0}" != "1" ]; then
        : >"${box}/crates/rulesteward-auditd/tests/corpus/auditd-oracle/scenario-a.tsv"
    fi

    # A PRE-EXISTING cache directory, which is the driver's common path (the ATL
    # runs it every round against one fork point) and had zero coverage: every
    # sandbox got a fresh TMPDIR, so the reuse branch was never taken. Built here
    # WITHOUT going through the stub `git worktree add`, which is exactly the
    # state that made the creation path's failure unobservable.
    if [ "${STUB_PRECREATE_WT:-0}" = "1" ]; then
        local wt="${box}/tmp/rs-branch-diff/aaaaaaaabbbbbbbbccccccccdddddddd00000000"
        mkdir -p "${wt}/crates/rulesteward-auditd/tests/corpus/auditd-oracle"
        : >"${wt}/crates/rulesteward-auditd/tests/corpus/auditd-oracle/scenario-a.tsv"
    fi

    # A curated system PATH rather than /usr/bin, so the suite cannot pass or fail
    # for reasons outside the sandbox. (Its sibling suite also uses this to make
    # docker genuinely absent; no case here needs a missing tool, so that is a
    # property of the design rather than something exercised.)
    local tool resolved
    # `head` was missing until round 7, so the driver's `| head -N` pipes - two of
    # them then ("the cached worktree is dirty, here are the first 10 lines" and
    # the committed-mode banner dump), three since round 8 added the ignored-path
    # dump - failed with `command not found` inside EVERY
    # case and nothing noticed: the suite asserts an rc and one substring of the
    # `die` message, never that the transcript arrived. Same shape as the
    # multi-operand `tail` defect found in the same round.
    # `tr` was missing too, found by the check above on its first run: the
    # `cargo said: $(tail -3 ... | tr '\n' ' ')` diagnostic that round 3 added
    # specifically to stop stderr being discarded produced an EMPTY tail inside
    # the sandbox, and `json_phase_failure` passed regardless because it asserts
    # only the substring BEFORE that interpolation. The driver is fine in
    # production, where `tr` is on PATH; the CASE was vacuous for the half it
    # exists to pin.
    for tool in mktemp mkdir rm tail head tr grep cut env bash dirname cat cp; do
        resolved="$(command -v "${tool}")" || {
            echo "SUITE ERROR: required tool '${tool}' not found" >&2
            return 2
        }
        ln -s "${resolved}" "${box}/sysbin/${tool}"
    done

    # Stub cargo. Which test binary it reports depends on the working directory:
    # the driver builds the base side inside the cached worktree, whose path
    # contains `/rs-branch-diff/`, and the HEAD side at the repo root. A driver
    # that built the same tree twice would get the same binary here and every
    # comparison would be a self-comparison - which is why the marker is the
    # working directory rather than a knob the driver could satisfy by accident.
    cat >"${box}/bin/cargo" <<'STUB'
#!/usr/bin/env bash
case "${PWD}" in
*/rs-branch-diff/*) which_bin="${STUB_BASE_TEST_BIN}"; rc="${STUB_CARGO_BASE_RC:-0}" ;;
*)                  which_bin="${STUB_HEAD_TEST_BIN}"; rc="${STUB_CARGO_HEAD_RC:-0}" ;;
esac
for a in "$@"; do
    if [ "$a" = "--message-format=json" ]; then
        # A non-test artifact carries "executable":null and must be ignored; a
        # build-script artifact must be filtered by name. Both are emitted so the
        # driver's filtering is genuinely exercised.
        printf '{"reason":"compiler-artifact","executable":null}\n'
        printf '{"reason":"compiler-artifact","executable":"/nonexistent/build-script-build"}\n'
        printf '{"reason":"compiler-artifact","executable":"%s"}\n' "${which_bin}"
        [ -n "${STUB_CARGO_EXTRA_EXE:-}" ] &&
            printf '{"reason":"compiler-artifact","executable":"%s"}\n' "${STUB_CARGO_EXTRA_EXE}"
        exit "${STUB_CARGO_JSON_RC:-0}"
    fi
done
[ -n "${STUB_CARGO_MSG:-}" ] && echo "${STUB_CARGO_MSG}" >&2
exit "${rc}"
STUB

    # Stub git. The five subcommands the driver uses: `rev-parse`, `status`,
    # `ls-files`, `diff` and `worktree`.
    #
    # This read "the two subcommands" from the first commit, where it was true
    # (`rev-parse` and `worktree add`). Round 1 added `status` and round 2 added
    # `diff`, and the sentence stayed. It was false for nine commits and survived a
    # dedicated doc-truth pass plus six review rounds, because a count phrased as
    # prose scans as boilerplate rather than as a claim.
    #
    # Round 9 repaired it to "four". Round 10's `ls-files` guard made that false in
    # the very next commit, which is the useful half of the story: the count is not
    # hard to get right, it is hard to keep right, because the thing that falsifies
    # it is always a feature somewhere else. The sweep for this line now happens
    # BEFORE a subcommand is added rather than a round after.
    #
    # `worktree add` materialises a base tree carrying its own committed corpus,
    # so that R1 (base binary against the BASE corpus) has something real to read.
    # STUB_BASE_CORPUS_MISSING models a base sha that predates the corpus.
    cat >"${box}/bin/git" <<'STUB'
#!/usr/bin/env bash
# Stub git. Distinguishes calls made INSIDE the cached base worktree (`git -C
# <dir> ...`) from calls against the repo, because the driver now validates the
# cache and those two must be able to disagree.
in_worktree=0
if [ "${1-}" = "-C" ]; then
    in_worktree=1
    shift 2
fi

BASE_DEFAULT="aaaaaaaabbbbbbbbccccccccdddddddd00000000"
HEAD_DEFAULT="1111111122222222333333334444444455555555"

if [ "${1-}" = "rev-parse" ]; then
    if [ "${in_worktree}" -eq 1 ]; then
        # What the CACHED worktree reports it is checked out at.
        echo "${STUB_WT_SHA:-${STUB_BASE_SHA:-$BASE_DEFAULT}}"
        exit 0
    fi
    rc="${STUB_GIT_REVPARSE_RC:-0}"
    [ "${rc}" -ne 0 ] && { echo "fatal: stub rev-parse failure" >&2; exit "${rc}"; }
    # Retained for a driver that resolves HEAD; the current one does NOT (round 3
    # dropped the `rev-parse HEAD^{commit}` call when the nothing-to-vary guard
    # became a one-ref `git diff`), and no case sets STUB_HEAD_SHA. Kept because
    # the arm costs nothing and a future caller would otherwise be mis-answered.
    case "${3-}" in
    'HEAD^{commit}') echo "${STUB_HEAD_SHA:-$HEAD_DEFAULT}" ;;
    *) echo "${STUB_BASE_SHA:-$BASE_DEFAULT}" ;;
    esac
    exit 0
fi

if [ "${1-}" = "status" ]; then
    # Does the caller want untracked files suppressed?
    #
    # The driver no longer passes `-uno` ANYWHERE: round 3 replaced the
    # nothing-to-vary `status --porcelain -uno` scan with a one-ref `git diff`,
    # which reads tracked content by construction. Its TWO `status` calls are both
    # on the cached worktree: `status --porcelain -unormal`, and
    # `status --porcelain --ignored -unormal -- <CORPUS_SUBPATH>`. Both deliberately
    # omit `-uno` and pin `-unormal`, because the corpus is enumerated from the
    # filesystem and an untracked or ignored scenario dir IS part of the base's
    # replay input.
    #
    # This said "its only `status` call" until round 9. Round 8 added the second
    # call, and the paragraph that falsified this sentence is the one beginning
    # "`--ignored` is the SECOND question the driver asks of this command", added
    # in that same commit and sitting below it ever since without touching it.
    # A maintainer reading here first believes the `status` branch below serves a
    # single driver call site, which is the exact misreading that made
    # `STUB_GIT_STATUS_IGNORED_RC` necessary.
    #
    # Round 9's repair of that sentence then said "eleven lines below ... a
    # paragraph explaining why the second one needs its own rc knob". It named the
    # right OFFSET and the wrong paragraph: eleven lines below sits the "SECOND
    # question" text, while the rc-knob explanation is fifty-six lines down. So a
    # commit whose whole thesis was that positional references rot introduced a
    # positional reference in the prose explaining why. Verifying a pointer has two
    # halves - does a target exist at that offset, and is it the one you named -
    # and checking the first half feels like checking both. Name the paragraph.
    #
    # So every `status` reaching this stub arrives with `-C`, and the `else` arm
    # below is currently unreachable. Both are kept so a future caller that does
    # pass `-uno`, or that asks about the repo rather than the worktree, is
    # modelled rather than silently mis-answered.
    uno=0
    for a in "$@"; do case "${a}" in -uno|--untracked-files=no) uno=1 ;; esac; done
    # `--ignored` is the SECOND question the driver asks of this command, and the
    # stub could not express its answer at all until round 8.
    #
    # Real `git status --porcelain` OMITS ignored paths (git-status(1): `--ignored`
    # is what "show ignored files as well" takes), while the lanes enumerate the
    # corpus with `read_dir`, which ignores nothing. So a scenario directory whose
    # name `.gitignore` matches is replay input AND invisible - and with only
    # STUB_WT_DIRTY and STUB_WT_UNTRACKED there was no way to state "a file is
    # present that `git status` does not report", which is precisely the bug.
    # A stub that cannot state the bug cannot catch it.
    ign=0
    for a in "$@"; do case "${a}" in --ignored|--ignored=*) ign=1 ;; esac; done
    # `status.showUntrackedFiles=no`, modelled. Until round 9 the stub could only
    # express what the driver ASKED, never what the developer's git CONFIG did to
    # the answer - and that config is unversioned, reaches every cached worktree
    # through the common dir, and silently turns BOTH cleanliness guards off.
    #
    # Measured on git 2.55.0: under that config `--porcelain` loses its `??` rows
    # and `--porcelain --ignored` returns ZERO BYTES, losing `!!` as well, because
    # with `-uno` git does not walk untracked directories at all and so never
    # reaches the ignored entries inside them. Both still exit 0, which is why the
    # rc guards cannot see it. Modelled by folding the config into `uno`, so the
    # single suppression path serves both rows exactly as real git does.
    unorm=0
    for a in "$@"; do case "${a}" in -unormal|--untracked-files=normal) unorm=1 ;; esac; done
    if [ "${STUB_GIT_UNTRACKED_NO:-0}" = "1" ] && [ "${unorm}" -eq 0 ]; then
        uno=1
    fi
    if [ "${in_worktree}" -eq 1 ] && [ "${ign}" -eq 1 ]; then
        # The driver scopes this call with `-- <CORPUS_SUBPATH>`, so a modification
        # OUTSIDE the corpus is correctly not reported here; that is the whole-tree
        # call's job. Modelled rather than merged, or the case would pass for the
        # wrong reason.
        [ -n "${STUB_WT_IGNORED:-}" ] && [ "${uno}" -eq 0 ] &&
            echo "!! crates/rulesteward-auditd/tests/corpus/auditd-oracle/docs/"
    elif [ "${in_worktree}" -eq 1 ]; then
        [ -n "${STUB_WT_DIRTY:-}" ] && echo " M crates/rulesteward-auditd/src/lib.rs"
        # UNTRACKED inside the cached base worktree. The corpus is enumerated from
        # the filesystem, so an untracked scenario dir IS part of the base's
        # replay input - which is why this site must NOT pass -uno.
        [ -n "${STUB_WT_UNTRACKED:-}" ] && [ "${uno}" -eq 0 ] &&
            echo "?? crates/rulesteward-auditd/tests/corpus/auditd-oracle/zz-extra/"
    else
        [ -n "${STUB_TREE_DIRTY:-}" ] && echo " M crates/rulesteward-auditd/src/lib.rs"
        # Untracked-only: visible to a bare `status --porcelain`, invisible to -uno.
        [ -n "${STUB_TREE_UNTRACKED:-}" ] && [ "${uno}" -eq 0 ] && echo "?? .serena/"
    fi
    # A FAILING `git status`, which this arm could not express until round 6. A
    # mutation probe showed the driver's rc guard on this command survived all 68
    # cases when removed, and removing it yields `OK` at rc 0: a failing status
    # writes nothing to stdout, so the driver's `-n "${wt_dirty}"` test reads
    # "could not check" as "checked, and clean". The reachable trigger is a corrupt
    # index in the long-lived cached worktree (`git status` refreshes and writes
    # the index; `rev-parse --verify HEAD` reads refs only, so the earlier guard
    # passes). Measured on git 2.55.0: a corrupt index gives rc 128 with EMPTY
    # stdout and `fatal: .../index: index file smaller than expected`, which is
    # exactly this knob's shape. NOT a stale `index.lock`, which an earlier
    # version of this comment also claimed: status takes that lock non-blocking
    # and simply skips writing, returning rc 0 and empty output.
    # A stub that cannot state the bug cannot catch it.
    #
    # The `--ignored` call gets its OWN rc knob rather than sharing this one. Both
    # calls carry an rc guard and both fail open the same way when it is removed
    # (git fails, stdout is empty, "could not check" reads as "checked, and
    # clean"), so both need a witness - but STUB_GIT_STATUS_RC makes the FIRST
    # call die, and the second is then never reached. One knob could only ever
    # witness one of the two guards.
    if [ "${ign}" -eq 1 ]; then
        exit "${STUB_GIT_STATUS_IGNORED_RC:-0}"
    fi
    exit "${STUB_GIT_STATUS_RC:-0}"
fi

if [ "${1-}" = "ls-files" ]; then
    # THE THIRD MEMBER OF THE SUPPRESSED-ROW SET, and the stub could not state it
    # until round 10. Round 8 taught this stub to hide the `!!` row, round 9 the
    # `??` row; this is the ` M` row - a TRACKED file that is modified and that
    # `git status` does not report, because the index says stop looking at it.
    #
    # It needs its own arm rather than another `status` knob, because the driver
    # asks a different COMMAND: `status` reports what git can see, and no answer
    # from it can describe what git has been told not to look at. Modelling the
    # blindness inside the `status` arm would have made the two indistinguishable,
    # which is the mistake round 3's `diff` arm records ("a stub that cannot state
    # the bug cannot catch it").
    #
    # `-v` prefixes each path with its index flag. `H` is the normal cached entry;
    # any LOWERCASE letter is assume-unchanged (what `core.ignoreStat` burns in at
    # `worktree add` time), and `S` is skip-worktree (what `git sparse-checkout`
    # sets). Both suppress identically, so both get a case - a remedy aimed at one
    # cause would leave the other open, which is why the driver reads the FLAGS
    # rather than guarding any single mechanism.
    if [ -n "${STUB_WT_LSFILES_EMPTY:-}" ]; then
        # No tracked files at all. A count over zero lines is zero, so without the
        # driver's vacuity guard this reads as "nothing is suppressed" when it
        # means "nothing was examined".
        exit "${STUB_GIT_LSFILES_RC:-0}"
    fi
    echo "H crates/rulesteward-auditd/src/lib.rs"
    echo "H crates/rulesteward-auditd/tests/corpus/auditd-oracle/aa-one/input.rules"
    case "${STUB_WT_SUPPRESSED:-}" in
    assume) echo "h crates/rulesteward-auditd/src/parser.rs" ;;
    skip) echo "S crates/rulesteward-auditd/src/parser.rs" ;;
    esac
    exit "${STUB_GIT_LSFILES_RC:-0}"
fi

if [ "${1-}" = "diff" ]; then
    # THE NUMBER OF REFS IS THE WHOLE POINT, so this stub counts them.
    #
    #   `git diff --quiet <base> -- <paths>`        ONE ref: base COMMIT vs WORKING TREE
    #   `git diff --quiet <base> <head> -- <paths>` TWO refs: commit vs commit
    #
    # The driver builds the WORKING TREE, so only the one-ref question is the one
    # it is entitled to act on. The previous version of this stub discarded its ref
    # arguments entirely and answered both forms from a single variable, which made
    # the distinction INEXPRESSIBLE in the suite - and that is why a guard asking
    # the wrong pair survived four repairs and three review rounds with every case
    # green. A stub that cannot state the bug cannot catch it.
    refs=0
    for a in "$@"; do
        case "${a}" in
        diff | --quiet) ;;
        --) break ;;
        *) refs=$((refs + 1)) ;;
        esac
    done
    # A git that could not ANSWER, which is neither 0 nor 1 and which this arm
    # could not express until round 6. The driver's `*)` catch-all was therefore
    # dead code from the suite's point of view, and a mutation probe confirmed it:
    # gutting the catch-all survived all 68 cases and yields `OK` at rc 0.
    #
    # The existing `nothing-to-vary-guard-removed` control does NOT cover it, and
    # that is the part worth remembering: it seeds `false` over the whole `git
    # diff` invocation, and `false` exits 1, so it drives the "they differ,
    # proceed" arm and credits the gate with coverage the catch-all lacks.
    #
    # Reachable via a partial or shallow clone whose promisor fetch fails, where
    # `git rev-parse --verify <ref>^{commit}` still passes cleanly.
    [ -n "${STUB_GIT_DIFF_RC:-}" ] && exit "${STUB_GIT_DIFF_RC}"
    if [ "${refs}" -le 1 ]; then
        [ -n "${STUB_WORKTREE_MATCHES_BASE:-}" ] && exit 0
        exit 1
    fi
    [ -n "${STUB_TREES_IDENTICAL:-}" ] && exit 0
    exit 1
fi

if [ "${1-}" = "worktree" ]; then
    case "${2-}" in
    prune)
        # A LOCKED registration is exactly what prune must NOT remove - that is
        # what locking is for - so a locked-but-missing worktree survives this and
        # the plain `add` below still fails. Modelling prune as "always heals
        # everything" is what hid the interaction between the two.
        exit "${STUB_GIT_PRUNE_RC:-0}"
        ;;
    lock)
        if [ -n "${STUB_GIT_LOCK_ALREADY:-}" ]; then
            echo "fatal: '${3-}' is already locked" >&2
            exit 128
        fi
        exit "${STUB_GIT_LOCK_RC:-0}"
        ;;
    add)
        forced=0
        for a in "$@"; do
            case "${a}" in -f | --force) forced=$((forced + 1)) ;; esac
        done
        # git refuses a plain `add` at a path it still has registered but that no
        # longer exists, and documents the recovery: "To add a missing but locked
        # worktree path, specify --force twice."
        if [ -n "${STUB_WT_LOCKED_MISSING:-}" ] && [ "${forced}" -lt 2 ]; then
            # Real git 2.55.0's wording, checked rather than invented. The driver
            # reads only the rc, but a fixture that quotes the manual and then
            # makes up the string is the drift this file otherwise refuses.
            echo "fatal: '${3-}' is a missing but locked worktree; use 'add -f -f' to override, or 'unlock' and 'prune' or 'remove' to clear" >&2
            exit 128
        fi
        rc="${STUB_GIT_WORKTREE_RC:-0}"
        if [ "${rc}" -eq 0 ]; then
            # `worktree add --detach <dir> <sha>`: the directory is the absolute arg.
            for arg in "$@"; do case "${arg}" in /*) dest="${arg}" ;; esac; done
            mkdir -p "${dest}"
            if [ "${STUB_BASE_CORPUS_MISSING:-0}" != "1" ]; then
                mkdir -p "${dest}/crates/rulesteward-auditd/tests/corpus/auditd-oracle"
                : >"${dest}/crates/rulesteward-auditd/tests/corpus/auditd-oracle/scenario-a.tsv"
            fi
        else
            echo "fatal: stub worktree add failure" >&2
        fi
        exit "${rc}"
        ;;
    esac
    exit 0
fi
exit 0
STUB

    # Stub replay binaries.
    #
    # Verdict lists are `name:ok name:FAILED` strings. The exit code is DERIVED
    # from them the way libtest derives its own (101 if any test failed), so a
    # case cannot accidentally set up an rc that disagrees with its own table -
    # disagreement is its own case, via STUB_FORCE_RC.
    cat >"${box}/bin/stub-replay-base" <<'STUB'
#!/usr/bin/env bash
SENTINEL="RS-DIFF-AUDITD"
root="${RS_ORACLE_CORPUS_AUDITD:-}"

# Which of the three runs is this?
#
# The SIDE comes from the stub's own filename, because that is the only thing the
# driver actually varies between R2 and R3: both are handed HEAD's corpus, and
# only the binary differs. Deriving it from anything the two runs share would
# make R3 indistinguishable from R2, and every case that needs them to differ
# would then pass or fail for the wrong reason.
case "$0" in
*-head) run=3 ;;
*)
    # The BASE binary is invoked twice and tells its two runs apart by the
    # corpus it was handed.
    case "${root}" in
    */rs-branch-diff/*) run=1 ;;
    *) run=2 ;;
    esac
    ;;
esac
eval "tests=\"\${STUB_R${run}_TESTS-replay_alpha:ok replay_beta:ok}\""
eval "scen=\"\${STUB_R${run}_SCENARIOS:-7}\""

# A binary that ignores the override reads its OWN corpus and announces
# `mode=committed`. That is the silent failure the sentinel guard exists for: it
# agrees with itself and exits 0.
if [ -n "${root}" ] && [ "${STUB_IGNORES_ENV:-0}" != "${run}" ]; then
    mode="fresh"
else
    mode="committed"
    root="/its/own/corpus"
fi
# DOES ANY TEST BODY RUN? Announcements come from test BODIES in every real lane
# (the corpus is resolved inside a `#[test]` fn), so a binary whose tests are all
# `#[ignore]`d announces NOTHING - measured on rustc 1.97.0: complete per-test
# table, `0 passed; 0 failed; N ignored`, rc 0, and zero bytes on stderr.
#
# This stub announced unconditionally until round 7, which let cases pin
# transcripts the real system cannot emit: an all-parked run that still produced a
# banner. One of those cases was a `must_catch` for round 5's control, so that
# control was witnessing a fiction.
any_ran=0
for entry in ${tests}; do
    case "${entry##*:}" in
    ignored | ignoredr) ;;
    *) any_ran=1 ;;
    esac
done

# Announcements go to STDERR and the per-test table to STDOUT, exactly as a real
# replay binary does it: libtest writes its own progress to stdout, and the replay
# tests announce with `eprintln!`. The driver relies on that split, so the stub
# must honour it or the suite would be testing a shape that does not occur.
[ "${any_ran}" -eq 1 ] && [ "${STUB_NO_BANNER:-0}" != "${run}" ] &&
    echo "${SENTINEL}: mode=${mode} corpus=${root}" >&2

# A SECOND resolution in the same process that did NOT consult the override, and
# therefore announces committed mode against its own tree. This is the shape
# `rulesteward-selinux`'s `policy_corpus::archive_path` had before this branch:
# scenarios honoured the override while the policy archive came from a compiled-in
# CARGO_MANIFEST_DIR. The existential `grep -qF` for the fresh banner passes on
# this transcript, so only the negative half can see it.
[ "${STUB_SECOND_COMMITTED_READ:-0}" = "${run}" ] &&
    echo "${SENTINEL}: mode=committed corpus=/some/other/tree/tests/corpus" >&2

# An extra vacuous announcement BEFORE the real one models a suite where one of
# several announcing tests compared nothing. (Not parallel threads: the driver
# passes `--test-threads=1`.) The healthy count lands last on purpose, because
# that is the ordering under which a `tail -1` sampler reports success.
[ "${STUB_ZERO_COUNT_FIRST:-0}" = "${run}" ] && echo "${SENTINEL}: scenarios=0" >&2
[ "${any_ran}" -eq 1 ] && [ "${STUB_NO_COUNT:-0}" != "${run}" ] &&
    echo "${SENTINEL}: scenarios=${scen}" >&2
[ "${STUB_ORACLE_BROKEN:-0}" = "${run}" ] &&
    echo "${SENTINEL}: ORACLE-BROKEN accept and reject controls returned the same verdict" >&2

failed=0
total=0
mangled=0
ignored=0
for entry in ${tests}; do
    name="${entry%%:*}"
    verdict="${entry##*:}"
    total=$((total + 1))
    if [ "${STUB_MANGLE_ROW:-0}" = "${run}" ] && [ "${mangled}" -eq 0 ]; then
        # Models what libtest ACTUALLY does under --nocapture when a test writes
        # to the same stream as the progress line: `test <name> ... ` is printed
        # BEFORE the test body runs, so the body's output lands mid-line and the
        # verdict never appears. This is not invented - it is the line the first
        # real sudoers run produced. The row must go missing rather than parse to
        # a bogus verdict, and the summary cross-check must then refuse the run.
        printf 'test %s ... %s: mode=fresh corpus=%s\n' "${name}" "${SENTINEL}" "${root}"
        mangled=1
    else
        case "${verdict}" in
        # `ignoredr` is not a libtest verdict, it is this stub's knob for the
        # REASONED form. `#[ignore = "reason"]` renders as `ignored, <reason>`,
        # measured on rustc 1.97.0, and that is the form the repo actually uses:
        # every `#[ignore]` attribute under `crates/` carries a reason, and
        # `boundary_substrate.rs` documents the convention. The driver's
        # `$`-anchored regex rejected it for two rounds while every case in this
        # file used the bare form, so round 3's whole SILENCED feature was
        # witnessed only on a rendering the repo does not produce.
        # STUB_IGNORE_REASON exists because the REASON TEXT is load-bearing, which
        # is not obvious and cost a round to learn. The driver derived "did a test
        # body run" from `grep -qE '^test .+ \.\.\. (ok|FAILED)$'`, whose `.+` is
        # greedy and unanchored in the middle, so a reason containing " ... ok"
        # satisfied it and an all-parked lane was refused at rc 2 instead of the
        # rc 1 SILENCED three specifications promise. Hardcoding one benign reason
        # made that inexpressible.
        ignoredr) echo "test ${name} ... ignored, ${STUB_IGNORE_REASON:-flaky under NFS}" ;;
        *) echo "test ${name} ... ${verdict}" ;;
        esac
    fi
    [ "${verdict}" = "FAILED" ] && failed=$((failed + 1))
    # libtest's third per-test verdict. Counted here so the summary line below
    # stays ARITHMETICALLY HONEST: the driver reconciles passed+failed+ignored
    # against the number of rows it parsed, so a stub that emitted an `ignored`
    # row while still claiming `0 ignored` would trip the cross-check instead of
    # exercising the case, and would look like a driver defect.
    case "${verdict}" in ignored | ignoredr) ignored=$((ignored + 1)) ;; esac
done

# libtest's own tally, the independent second count the driver reconciles against.
if [ "${STUB_NO_SUMMARY:-0}" != "${run}" ]; then
    if [ "${STUB_SUMMARY_BAD:-0}" = "${run}" ]; then
        echo "test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s"
    else
        if [ "${failed}" -eq 0 ]; then word="ok"; else word="FAILED"; fi
        echo "test result: ${word}. $((total - failed - ignored)) passed; ${failed} failed; ${ignored} ignored; 0 measured; 0 filtered out; finished in 0.00s"
    fi
fi

if [ -n "${STUB_FORCE_RC:-}" ] && [ "${STUB_FORCE_RC_RUN:-0}" = "${run}" ]; then
    exit "${STUB_FORCE_RC}"
fi
[ "${failed}" -eq 0 ] && exit 0
exit 101
STUB

    # The HEAD-side stub is a byte-identical copy under a different NAME: the two
    # sides must behave identically except for which verdict list they read, and
    # a second hand-maintained copy would drift.
    cp "${box}/bin/stub-replay-base" "${box}/bin/stub-replay-head"

    chmod +x "${box}/bin/cargo" "${box}/bin/git" \
        "${box}/bin/stub-replay-base" "${box}/bin/stub-replay-head"
    printf '%s' "${box}"
}

# run_case <name> <expected_rc> <expected_substring> [VAR=VAL ...]
#
# Runs the driver for lane `auditd` against base ref `BASEREF` inside a fresh
# sandbox, asserting BOTH the exit code and a substring of output.
# The substring matters: many distinct defects all produce rc 2, and a case that
# only checked the number would pass for the wrong reason.
run_case() {
    local name="$1" want_rc="$2" want_sub="$3"
    shift 3

    # Sandbox-shaping knobs are properties of the box, not the run, so they are
    # read here before it is built.
    local kv
    local head_corpus_empty=0 precreate_wt=0
    for kv in "$@"; do
        [ "${kv}" = "STUB_HEAD_CORPUS_EMPTY=1" ] && head_corpus_empty=1
        [ "${kv}" = "STUB_PRECREATE_WT=1" ] && precreate_wt=1
    done

    local box
    box="$(STUB_HEAD_CORPUS_EMPTY="${head_corpus_empty}" STUB_PRECREATE_WT="${precreate_wt}" \
        make_sandbox "${DRIVER_UNDER_TEST}")" || {
        echo "SUITE ERROR: sandbox creation failed" >&2
        exit 2
    }

    local out rc
    out="$(
        env -i \
            PATH="${box}/bin:${box}/sysbin" \
            TMPDIR="${box}/tmp" \
            STUB_BASE_TEST_BIN="${box}/bin/stub-replay-base" \
            STUB_HEAD_TEST_BIN="${box}/bin/stub-replay-head" \
            "$@" \
            bash "${box}/scripts/rs-branch-diff.sh" auditd BASEREF 2>&1
    )"
    rc=$?
    OBSERVED_RCS="${OBSERVED_RCS} ${rc}"

    local ok=1
    [ "${rc}" -eq "${want_rc}" ] || ok=0
    if [ "${want_sub}" != "-" ] && [[ "${out}" != *"${want_sub}"* ]]; then
        ok=0
    fi

    # THE DRIVER'S OWN TOOLING MUST NOT BE BROKEN, checked on every case rather
    # than asserted anywhere in particular.
    #
    # Round 7 found two defects of the same shape, both invisible to 74 cases:
    # `tail -30 "${err}" "${out}"` is rejected outright by GNU coreutils when
    # given two FILE operands ("option used in invalid context"), and the sandbox
    # never provided `head`, so the driver's two `| head -N` pipes failed with
    # `command not found`. In BOTH cases the driver printed its verdict with an
    # EMPTY transcript, and every case still passed - because a case asserts an rc
    # and one substring of the `die` message, never that the evidence arrived.
    #
    # This check is its own positive control: it fires on the pre-round-7 driver
    # and is silent on the current one, which is why it is worth more than a case
    # per site. A tool that could not run must never look like a tool that ran and
    # found nothing.
    case "${out}" in
    *'option used in invalid context'* | *'command not found'* | *'No such file or directory'*)
        ok=0
        printf '%s %s: the driver invoked a tool that could not run; its diagnostics are empty\n' \
            "$(case_marker)" "${name}" >&2
        ;;
    esac

    if [ "${ok}" -eq 1 ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_CASES+=("${name}")
        printf '%s %s: want rc=%s sub=%q; got rc=%s\n' \
            "$(case_marker)" "${name}" "${want_rc}" "${want_sub}" "${rc}" >&2
        dump_output "${out}"
    fi
}

# run_argcase <name> <expected_rc> <expected_substring> [args...]
# For argument validation, which passes something other than `auditd BASEREF`.
run_argcase() {
    local name="$1" want_rc="$2" want_sub="$3"
    shift 3

    local box
    box="$(make_sandbox "${DRIVER_UNDER_TEST}")" || exit 2

    local out rc
    out="$(env -i PATH="${box}/bin:${box}/sysbin" TMPDIR="${box}/tmp" \
        bash "${box}/scripts/rs-branch-diff.sh" "$@" 2>&1)"
    rc=$?
    OBSERVED_RCS="${OBSERVED_RCS} ${rc}"

    if [ "${rc}" -eq "${want_rc}" ] && [[ "${out}" == *"${want_sub}"* ]]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        FAILED_CASES+=("${name}")
        printf '%s %s: want rc=%s sub=%q; got rc=%s\n' \
            "$(case_marker)" "${name}" "${want_rc}" "${want_sub}" "${rc}" >&2
        dump_output "${out}"
    fi
}

# The three verdict sets, named for readability at the call sites below.
#   R1 = base binary against the BASE corpus   (baseline)
#   R2 = base binary against HEAD's corpus     (does the new corpus discriminate?)
#   R3 = HEAD binary against HEAD's corpus     (does HEAD still agree?)
ALL_OK='replay_alpha:ok replay_beta:ok'

# Cases every positive control's seeded driver must STILL pass. Each removes one
# guard, and none of these three inputs reaches any of those guards, so a seeded
# driver that fails them is broken rather than merely weakened. See
# run_positive_control for why this matters more than it looks.
CONTROL_MUST_STILL_PASS=(clean_no_discrimination discrimination_reported regression_is_rc1)

run_all_cases() {
    # --- argument validation -------------------------------------------------
    run_argcase no_lane 2 "no lane given"
    run_argcase unknown_lane 2 "unknown lane 'fapolicyd'" fapolicyd HEAD
    run_argcase no_base_ref 2 "no base ref given" auditd

    # --- the happy paths -----------------------------------------------------
    # Nothing discriminated: a branch that did not touch this lane. Reported
    # loudly but rc 0, because failing it would fail every unrelated branch.
    run_case clean_no_discrimination 0 "OK (0 regressions, 0 discriminated" \
        "STUB_R1_TESTS=${ALL_OK}" "STUB_R2_TESTS=${ALL_OK}" "STUB_R3_TESTS=${ALL_OK}"

    # THE payload case. Base was green on its own corpus, goes red on HEAD's, and
    # HEAD is green: the corpus this branch added actually catches the old code.
    run_case discrimination_reported 0 "OK (0 regressions, 1 discriminated" \
        "STUB_R1_TESTS=${ALL_OK}" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R3_TESTS=${ALL_OK}"

    # THE SAME RUN, asserting the evidence SURVIVES it.
    #
    # A round-8 mutation probe found `finish`'s retention branch entirely
    # unwitnessed: reverting it to `if [ "${rc}" -eq 0 ]` - the defect this branch
    # ALREADY SHIPPED ONCE, which discarded the DISCRIMINATED run's logs - left 74
    # of 74 cases green, and so did deleting the evidence on every rc.
    #
    # It has to be THIS shape. On rc 1 and rc 2 both the correct code and the
    # reverted defect retain, so only a run that is rc 0 AND discriminated can tell
    # them apart, and that is exactly the run whose R2 stderr is the artifact the
    # documented per-round ATL use wants. A case asserting the rc alone is blind to
    # it: the verdict was never wrong, only the record of how it was reached.
    #
    # Recorded because the standing ruling reads "a case per guard whose absence
    # produces a false clean", and this one does not - it produces evidence LOSS
    # with a true verdict. The operator ruled that harm in scope; A (`worktree
    # prune`, whose verdict stays true when removed) and C (`cargo said:`, still
    # vacuous) stay accepted residue.
    run_case discriminated_run_retains_its_evidence 0 "evidence retained in" \
        "STUB_R1_TESTS=${ALL_OK}" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R3_TESTS=${ALL_OK}"

    # --- regressions are rc 1 ------------------------------------------------
    run_case regression_is_rc1 1 "REGRESSION" \
        "STUB_R1_TESTS=${ALL_OK}" "STUB_R2_TESTS=${ALL_OK}" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:FAILED"

    # A regression must still be rc 1 when the same round also discriminated.
    # A driver that returned early on the good news would ship the bad news.
    run_case regression_beats_discrimination 1 "REGRESSION" \
        "STUB_R1_TESTS=${ALL_OK}" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R3_TESTS=replay_alpha:FAILED replay_beta:ok"

    # --- THE guard: a run that read its OWN corpus instead of the one handed --
    #     to it. Exit code 0, counts fine, table fully populated; only the
    #     banner's corpus path can reveal that nothing was actually compared.
    run_case base_baseline_ignores_override 2 "did not read the corpus it was handed" \
        STUB_IGNORES_ENV=1
    run_case base_on_head_corpus_ignores_override 2 "did not read the corpus it was handed" \
        STUB_IGNORES_ENV=2
    run_case head_run_ignores_override 2 "did not read the corpus it was handed" \
        STUB_IGNORES_ENV=3
    run_case no_banner_at_all 2 "did not read the corpus it was handed" \
        STUB_NO_BANNER=2
    # THE SAME GUARD, on the transcript that pins the `0 failed;` half of the
    # `ran_any` conjunct. The case above cannot: it leaves the test lists at their
    # ALL-OK default, so its summary is `2 passed; 0 failed` and a weakening of
    # `'0 passed; 0 failed;'` to `'0 passed;'` never matches it.
    #
    # That weakening is a FALSE CLEAN of the worst sub-class. `ran_any` would read
    # 0 for any run with zero passes and one or more failures, standing down THE
    # anti-vacuity guard, so a run that never announced reading the corpus it was
    # handed is accepted and every FAILED row is then classified DISCRIMINATED.
    # Measured against a seeded driver: rc 0 with `OK (0 regressions, 2
    # discriminated)`. Not an under-report - a FABRICATED payload claim.
    #
    # The transcript is reachable, not a stub artifact.
    # `rulesteward-core/src/oracle_corpus.rs` panics on a resolution failure
    # BEFORE it announces (`Err(e) => panic!("{e}")` precedes the banner
    # `eprintln!`), so a test that fails to resolve emits NO banner while libtest
    # still prints a complete result line for it. The guard has to hold on any
    # transcript of that shape, whatever else ran alongside it.
    #
    # This used to add "and every lane resolves inside a `#[test]` body, so a bad
    # corpus root fails every test: exactly `0 passed; N failed`". That inference
    # was false for three of the four lanes. auditd (15 tests, 2 `#[cfg(test)]`
    # mods), sysctld (18) and sudoers (27) all carry corpus-INDEPENDENT tests that
    # pass regardless of the root, measured at `13 passed; 2 failed`,
    # `17 passed; 1 failed` and `22 passed; 5 failed`. Only selinux, the one lane
    # with no unit-test module, gives `0 passed`. The summary SHAPE was never what
    # made the case legitimate, so the claim is gone rather than narrowed to the
    # single lane where it happens to hold - a sentence pinned to selinux's current
    # test composition would go silently false the day selinux gains a
    # `#[cfg(test)]` mod, with nothing to flag it.
    #
    # The hole is younger than the guard. The pre-round-8 derivation was a row
    # regex, which matched `test x ... FAILED` structurally and so had no conjunct
    # to lose; round 8's summary tally is better in every other way and shipped
    # this one unpinned.
    run_case no_banner_on_an_all_failed_run 2 "did not read the corpus it was handed" \
        STUB_NO_BANNER=2 \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:FAILED"
    # The guard above is EXISTENTIAL: it proves something read the handed tree,
    # never that nothing read a different one. A binary resolving the corpus
    # correctly in one place and from a compiled-in CARGO_MANIFEST_DIR in another
    # satisfies it completely, and the comparison quietly becomes part
    # self-comparison. `rulesteward-selinux`'s `policy_corpus::archive_path` was
    # that exact shape until this branch, and the instrument could not see it -
    # it was found by reading the code. Now every resolution announces, so the
    # second read announces committed mode and the negative half catches it.
    run_case second_committed_read_is_refused 2 "ALSO resolved a corpus in committed mode" \
        STUB_SECOND_COMMITTED_READ=2

    # --- vacuity -------------------------------------------------------------
    run_case zero_scenarios 2 "'nothing fired' and 'nothing ran' are not the same" \
        STUB_R2_SCENARIOS=0
    # A GREEN run with no announcement is still vacuous and still rc 2. Paired
    # with failing_run_may_lack_a_count below, these two pin the exact boundary:
    # the count is required where, and only where, its absence is unfalsifiable.
    run_case missing_count_line 2 "for a green run" STUB_NO_COUNT=3
    # THE SAME GATE, ASKED OF R1 AND OF A GREEN R2. `STUB_NO_COUNT` was only ever
    # set to 3, or to 2 alongside a FAILING R2 (`failing_run_may_lack_a_count`,
    # which asserts the gate must NOT fire), so the gate's application to the other
    # two runs was unwitnessed: a run-scope conjunct could be added to it and the
    # whole suite would stay green.
    #
    # The shipped driver already refuses both, so these are pure witness and cost
    # the implementer nothing. They are here because round 9's worst finding was
    # exactly this shape - a guard present, correct, and under-specified, which a
    # mutation sweep is structurally blind to because there is no wrong branch to
    # flip. `run_positive_control count_seen_gate_scoped_to_r3` below is what makes
    # them load-bearing rather than decorative.
    run_case r1_green_without_a_count 2 "for a green run" STUB_NO_COUNT=1
    run_case r2_green_without_a_count 2 "for a green run" STUB_NO_COUNT=2
    run_case unparseable_count 2 "unparseable scenario count" \
        STUB_R1_SCENARIOS=many

    # One vacuous announcement among several live ones must still be rc 2, and
    # the zero line is emitted FIRST with a healthy count LAST: exactly the
    # thread ordering under which sampling only the final line reports success.
    run_case zero_count_among_live_ones 2 "an announcement reported 0 scenarios" \
        STUB_ZERO_COUNT_FIRST=3

    # A run that produced no parseable per-test line executed nothing. An empty
    # table is not a clean table.
    run_case no_test_lines_at_all 2 "printed no parseable 'test <name> ... ' line" \
        "STUB_R3_TESTS="
    run_case no_test_lines_in_baseline 2 "printed no parseable 'test <name> ... ' line" \
        "STUB_R1_TESTS="

    # --- the table must reconcile with libtest's own tally --------------------
    # THE regression test for the defect the first real run hit: a row whose
    # progress line was mangled by the test's own output simply does not match
    # the anchored pattern, so it goes MISSING rather than wrong. Silence and
    # absence are indistinguishable without a second count, and a silently
    # narrowed table would draw a verdict from fewer rows than it claims.
    run_case mangled_row_is_caught 2 "the table is incomplete" STUB_MANGLE_ROW=2
    run_case mangled_row_in_baseline 2 "the table is incomplete" STUB_MANGLE_ROW=1
    run_case summary_disagrees 2 "the table is incomplete" STUB_SUMMARY_BAD=3
    run_case no_summary_line 2 "printed no 'test result:' summary line" STUB_NO_SUMMARY=1

    # R3 is the direction where the cross-check is the SOLE guard. A mangled row
    # in R1 or R2 is double-covered by the R1/R2 cardinality assertion, so those
    # two cases pass even with the cross-check removed and credit it with catches
    # it did not make. Here the row would silently vanish from R3 and be filed as
    # `base-only (removed at HEAD)`, a reported NON-failing verdict: a HEAD test
    # that really ran, relabelled "removed", and the run reported clean.
    run_case mangled_row_in_HEAD 2 "the table is incomplete" STUB_MANGLE_ROW=3

    # --- a FAILING run need not have announced a count -----------------------
    # The instrument's own payload case. Some lanes announce the scenario COUNT
    # after parsing the corpus (they cannot know it earlier), so a base binary
    # that chokes on HEAD's GROWN corpus during enumeration never reaches the
    # announcement. The BANNER is not in that position: it comes from
    # `resolve_corpus_root` and precedes the LANE's first filesystem read. The
    # resolver's own `is_dir` check is ahead of it and panics without a banner.
    # Demanding the count unconditionally turned exactly that - the R2-FAILED
    # signal this driver exists to report - into rc 2. A green run still must
    # announce, because there "nothing fired" and "nothing ran" are one transcript.
    run_case failing_run_may_lack_a_count 0 "DISCRIMINATED" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" STUB_NO_COUNT=2

    # --- attribution ---------------------------------------------------------
    # A base that was already red on its OWN corpus cannot attribute anything:
    # its failure predates the branch. Those rows are excluded, and if EVERY row
    # is excluded nothing was compared at all.
    run_case all_rows_unattributable 2 "no row could be compared" \
        "STUB_R1_TESTS=replay_alpha:FAILED replay_beta:FAILED"

    # One unattributable row must NOT poison the others: the remaining row is
    # still a real comparison, so this is rc 0 with the exclusion reported.
    run_case partial_unattributable_still_compares 0 "UNATTRIBUTABLE" \
        "STUB_R1_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R2_TESTS=${ALL_OK}" "STUB_R3_TESTS=${ALL_OK}"

    # An unattributable row must not be counted as a regression even when HEAD
    # also fails it: base was already red there, so the branch did not break it.
    run_case unattributable_is_not_a_regression 0 "0 regressions" \
        "STUB_R1_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R3_TESTS=replay_alpha:FAILED replay_beta:ok"

    # --- test sets that do not line up ---------------------------------------
    # A branch that RENAMED every test leaves nothing to compare. That is rc 2
    # and it must NOT be reported as "the base was already red", which is a
    # different cause pointing at a different file.
    run_case disjoint_test_sets 2 "no test name appears in BOTH" \
        "STUB_R3_TESTS=renamed_alpha:ok renamed_beta:ok"

    # A branch that ADDED a test still compares the rows it shares, and reports
    # the new one rather than silently dropping it.
    run_case head_added_a_test 0 "HEAD-only (added by the branch)" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ok replay_gamma:ok"

    # A branch that REMOVED a test likewise: the survivor is still comparable.
    run_case head_removed_a_test 0 "base-only (removed at HEAD)" \
        "STUB_R3_TESTS=replay_alpha:ok"

    # A test the branch ADDED and left RED has no base counterpart, so it cannot
    # be a REGRESSION by definition - and it was therefore collected under the
    # neutral "added by the branch" label and never consulted for the verdict.
    # rc 0 while R3's libtest exited 101.
    run_case head_only_test_that_fails 1 "have no baseline verdict and are" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ok replay_gamma:FAILED"

    # The same shape with R3 red BEFORE it announces. RENAMED for what it actually
    # pins: a real failure above must be reported AS ITSELF and must not be
    # converted into "no announcements". It reaches `finish 1` on the head-only
    # gate and never gets near the final count gate, so it is NOT that gate's
    # witness - the name it used to carry said otherwise, and a mutant run proved
    # the claim false by neutering `SCEN[3] -eq 0` and watching every case still
    # pass. A case named after a guard it cannot reach is worse than no case: it
    # is what tells the next person the guard is already covered.
    run_case head_only_failure_beats_the_count_check 1 "have no baseline verdict and are" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ok replay_gamma:FAILED" STUB_NO_COUNT=3

    # The ACTUAL witness for the final rc-0 contract gate, constructed to reach it.
    # Every earlier exit must be avoided: no regression (beta was already red at
    # base, so it is UNATTRIBUTABLE), no head-only row, no silenced row, and one
    # surviving comparable row so the "everything is unattributable" gate stays
    # quiet. R3 is red, which is what relaxes validate_run's green-run-only count
    # requirement and leaves SCEN[3] at zero on the path to OK.
    run_case rc_zero_contract_refuses_zero_count 2 "requires the success line to carry a non-zero count" \
        "STUB_R1_TESTS=replay_alpha:ok replay_beta:FAILED" \
        "STUB_R2_TESTS=replay_alpha:ok replay_beta:FAILED" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:FAILED" STUB_NO_COUNT=3

    # --- a test SILENCED at HEAD is not a test removed at HEAD ----------------
    # `ignored) continue` dropped the row from the table outright, so a test the
    # branch put `#[ignore]` on vanished from R3, was filed as present-in-base-only
    # and printed "base-only (removed at HEAD)" at rc 0 - asserting a deletion that
    # never happened and calling the run clean. `cargo test` skips `#[ignore]` by
    # default, so neither `just test` nor `just ci` sees the transition either.
    # rc 1, symmetric with head_only_test_that_fails above.
    run_case head_silenced_a_test 1 "ran at base" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ignored"
    # The other direction is NOT a silencing: a test already ignored at the base
    # has no baseline verdict to lose, so it is reported and excluded, not failed.
    run_case ignored_at_base_is_not_a_silencing 0 "ignored at base (no baseline)" \
        "STUB_R1_TESTS=replay_alpha:ok replay_beta:ignored" \
        "STUB_R2_TESTS=replay_alpha:ok replay_beta:ignored" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ignored"
    # ...UNLESS it is red at HEAD. The first version of that arm excluded on R1
    # alone and never read R3, so a test parked at the base that the branch
    # un-parks and leaves red printed `FAILED` in the R3HEAD column and `OK` on
    # the verdict line, from one run, at rc 0 while libtest exited 101. That is
    # ONLY_HEAD_FAILING's case by a quieter route. The repo has this exact history
    # (`e2e_auditd_lint.rs`, parked during Phase 0 while its bodies were `todo!()`).
    run_case base_ignored_but_failing_at_head 1 "have no baseline verdict and are" \
        "STUB_R1_TESTS=replay_alpha:ok replay_beta:ignored" \
        "STUB_R2_TESTS=replay_alpha:ok replay_beta:ignored" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:FAILED"

    # --- `#[ignore = "reason"]`, which is the form this repo actually uses ------
    # libtest renders it `test <name> ... ignored, <reason>` (measured, rustc
    # 1.97.0). The driver's `$`-anchored regex rejected that for two rounds, so the
    # row went missing from the table while libtest still tallied it and the
    # three-column cross-check fired with a message blaming the parser. Both
    # directions are pinned, because the base side is the worse one: it cannot be
    # fixed by the branch, since the attribute lives at the fork point.
    run_case head_silenced_with_a_reason 1 "ran at base" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ignoredr"
    run_case base_carries_a_reasoned_ignore 0 "ignored at base (no baseline)" \
        "STUB_R1_TESTS=replay_alpha:ok replay_beta:ignoredr" \
        "STUB_R2_TESTS=replay_alpha:ok replay_beta:ignoredr" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ignoredr"

    # --- zero comparable rows must name the cause it actually found ------------
    # The zero-comparable gate predates SILENCED and BASE_IGNORED, and both landed
    # in its final `die`: a branch parking every replay row was told "no test name
    # appears in BOTH the base and HEAD runs (0 base-only, 0 HEAD-only)", a
    # sentence its own two counts refute, and sent after a rename that never
    # happened. SILENCED now wins outright - every row silenced is the strongest
    # instance of the thing that gate exists to fail, not a diagnostic dead end.
    run_case every_row_silenced_at_head 1 "ran at base" \
        "STUB_R3_TESTS=replay_alpha:ignored replay_beta:ignored"
    # THE SAME LANE, with a reason string that used to change the answer.
    #
    # The all-parked carve-out derived "did a test body run" from a second pass over
    # the per-test ROWS, `grep -qE '^test .+ \.\.\. (ok|FAILED)$'`. `.+` is greedy
    # and unanchored in the middle, so a reason containing " ... ok" matched:
    #
    #   test replay_alpha ... ignored, blocked on #677 ... ok       <- MATCHED
    #
    # The carve-out then did not fire, the sentinel guard did, and an all-parked
    # lane came back rc 2 ("its exit code and per-test table therefore mean
    # nothing") about a table that is complete and meaningful. Same shape as the
    # `$`-anchor lockout an earlier round routed: a second, weaker parse of
    # something the driver reads correctly elsewhere. It now reads libtest's own
    # `0 passed; 0 failed` tally, which cannot express that ambiguity.
    #
    # Zero in-tree reachability today - no `#[ignore]` reason under `crates/`
    # contains " ... " - so this pins a latent contradiction, not a live break.
    run_case every_row_silenced_with_a_dotted_reason 1 "ran at base" \
        "STUB_R3_TESTS=replay_alpha:ignoredr replay_beta:ignoredr" \
        "STUB_IGNORE_REASON=blocked on #677 ... ok"
    # The substring is ARM-UNIQUE and THEN discriminating, in that order. Round 6
    # changed this from an arm-unique phrase to bare bucket counts so that this
    # case and `base_ignored_with_renamed_rows` would differ from EACH OTHER - and
    # succeeded, while silently destroying what mattered more: those counts are
    # rendered identically by the fall-through arm three lines below, so gutting
    # the base-ignored arm left both cases green. Two round-7 reviewers found it.
    # Optimising for the distinction you are thinking about can destroy one you
    # are not.
    run_case every_row_ignored_at_base 2 "so have no baseline verdict, alongside 0 base-only" \
        "STUB_R1_TESTS=replay_alpha:ignored replay_beta:ignored" \
        "STUB_R2_TESTS=replay_alpha:ignored replay_beta:ignored" \
        "STUB_R3_TESTS=replay_alpha:ignored replay_beta:ignored"

    # --- a branch defect must not be reported as a tool error -----------------
    # Exactly two rc-1 buckets skip COMPARABLE: SILENCED and ONLY_HEAD_FAILING.
    # Round 4 taught the zero-comparable gate to stand down for the first and not
    # the second, while WIDENING the second by adding the un-parked-and-red arm.
    # A branch defect then came back as rc 2, "these two builds cannot be
    # compared", which routes the operator to change their base ref rather than fix
    # the red test - and the per-test table naming it was never printed, because
    # every `die 2` in that gate precedes the report block. All three round-5
    # reviewers found this independently. Both routes into the bucket are pinned.
    run_case unparked_failing_with_no_comparable_row 1 "have no baseline verdict and are" \
        "STUB_R1_TESTS=replay_alpha:ignored replay_beta:ignored" \
        "STUB_R2_TESTS=replay_alpha:ignored replay_beta:ignored" \
        "STUB_R3_TESTS=replay_alpha:ignored replay_beta:FAILED"
    run_case added_failing_with_no_comparable_row 1 "have no baseline verdict and are" \
        "STUB_R1_TESTS=replay_alpha:FAILED replay_beta:FAILED" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:FAILED" \
        "STUB_R3_TESTS=replay_alpha:FAILED replay_beta:FAILED replay_gamma:FAILED"

    # --- R1 and R2 are the SAME BINARY, so they must report the same test set --
    # The guard's own comment names the false clean it prevents: a name present in
    # R1 but absent from R2 is read as CLEAN via the `${R2[...]-}` default. A
    # mutation probe showed BOTH halves of it (cardinality and containment)
    # survived all 64 cases, so the guard was documented, correct, and unwitnessed.
    # The stub can express it - STUB_R1_TESTS and STUB_R2_TESTS are independent -
    # and no case did.
    # Equal SIZE, different KEYS: caught only by the containment half.
    run_case r2_reports_a_different_test_set 2 "must report the same test set" \
        "STUB_R1_TESTS=replay_alpha:ok replay_beta:ok" \
        "STUB_R2_TESTS=replay_alpha:ok replay_gamma:ok" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ok"
    # R2 a strict SUPERSET of R1: containment holds (every R1 name is in R2), so
    # only the cardinality half can catch it. Both halves are witnessed separately
    # and by inputs the other cannot see, because "equal size is not equal set" is
    # the whole reason the second one exists. An R2 with FEWER tests would trip
    # BOTH, leaving whichever ran second uncontrolled while looking covered.
    run_case r2_reports_an_extra_test 2 "must report the same test set" \
        "STUB_R1_TESTS=replay_alpha:ok" \
        "STUB_R2_TESTS=replay_alpha:ok replay_beta:ok" \
        "STUB_R3_TESTS=replay_alpha:ok"

    # --- "git could not say" must never become an answer ----------------------
    # Both guards below were CORRECT in the driver and structurally unwitnessable:
    # a round-6 mutation probe over 20 single-guard mutants found exactly two that
    # survive all 68 cases AND fail OPEN when removed, i.e. yield `OK` at rc 0.
    # These are those two. The other eight survivors fail closed and deliberately
    # get no case, because a case per unwitnessed guard is not the goal - a case
    # per guard whose absence produces a false clean is.
    run_case wt_status_cannot_answer 2 "refusing to treat 'git could not say'" \
        STUB_PRECREATE_WT=1 STUB_GIT_STATUS_RC=128
    run_case tree_diff_cannot_answer 2 "refusing to assume they differ" \
        STUB_GIT_DIFF_RC=128

    # --- a zero-comparable diagnostic must name every bucket it holds ---------
    # Round 4 split this gate into three messages BECAUSE one was refuted by its
    # own counts, gave the third arm every bucket, and wrote "every bucket is
    # named, so the reader is never handed a count that contradicts the sentence
    # around it" - then did not apply that rule to the two arms the same repair
    # created. Both fire here with base-only and HEAD-only rows unnamed, and the
    # second one used to end "that is a property of <base>, not of this branch"
    # when the branch's own rename is what emptied the comparable set.
    run_case unattributable_with_renamed_rows 2 "UNATTRIBUTABLE (the base was already red" \
        "STUB_R1_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R3_TESTS=replay_alpha:FAILED replay_gamma:ok"
    run_case base_ignored_with_renamed_rows 2 "so have no baseline verdict, alongside 1 base-only" \
        "STUB_R1_TESTS=replay_alpha:ignored replay_beta:ok" \
        "STUB_R2_TESTS=replay_alpha:ignored replay_beta:ok" \
        "STUB_R3_TESTS=replay_alpha:ignored replay_gamma:ok"

    # --- absent-at-HEAD wins over the R1 column, which the table now says -----
    # The classification loop tests `R3` absence FIRST, so a row that was FAILED or
    # #[ignore]d at the base and is gone at HEAD is base-only, NOT unattributable
    # and NOT ignored-at-base. Round 5 asserted the table was EXHAUSTIVE without
    # re-deriving it, which turned that gap into a provable falsehood; three
    # round-6 reviewers found it. These two pin the precedence so the table cannot
    # drift back.
    run_case failed_at_base_and_removed_at_head 0 "base-only (removed at HEAD)" \
        "STUB_R1_TESTS=replay_alpha:ok replay_beta:FAILED" \
        "STUB_R2_TESTS=replay_alpha:ok replay_beta:FAILED" \
        "STUB_R3_TESTS=replay_alpha:ok"
    run_case ignored_at_base_and_removed_at_head 0 "base-only (removed at HEAD)" \
        "STUB_R1_TESTS=replay_alpha:ok replay_beta:ignored" \
        "STUB_R2_TESTS=replay_alpha:ok replay_beta:ignored" \
        "STUB_R3_TESTS=replay_alpha:ok"

    # --- a test ADDED already parked gets its own label, at rc 0 ---------------
    # It previously got the byte-identical verdict to a passing addition, so the
    # column asserted the same thing about a test that ran and one that did not.
    # rc 0 rather than rc 1 by operator ruling: adding a parked pin for a
    # known-open bug is this repo's documented convention (#669/#677), unlike
    # silencing a test that WAS running.
    run_case head_only_test_that_is_parked 0 "HEAD-only and PARKED" \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:ok replay_gamma:ignored"

    # --- rc must agree with the table ----------------------------------------
    # rc IS the gate and a derived count is never the pass condition; a count
    # that disagrees with rc is a defect in the INSTRUMENT, not a detail to wave
    # through. Both directions are wrong and neither may be interpreted.
    run_case rc_zero_but_table_failed 2 "disagrees with its own per-test table" \
        "STUB_R3_TESTS=replay_alpha:FAILED replay_beta:ok" \
        STUB_FORCE_RC=0 STUB_FORCE_RC_RUN=3
    run_case rc_101_but_table_clean 2 "disagrees with its own per-test table" \
        STUB_FORCE_RC=101 STUB_FORCE_RC_RUN=3
    run_case unexpected_rc 2 "which is neither 0 nor 101" \
        STUB_FORCE_RC=134 STUB_FORCE_RC_RUN=1

    # --- a broken oracle is neither clean nor a regression -------------------
    run_case oracle_broken_beats_clean 2 "the oracle itself is broken" \
        STUB_ORACLE_BROKEN=2
    run_case oracle_broken_beats_regression 2 "the oracle itself is broken" \
        STUB_ORACLE_BROKEN=3 \
        "STUB_R3_TESTS=replay_alpha:ok replay_beta:FAILED"

    # --- base resolution and builds are rc 2, never a skip and never clean ---
    run_case unresolvable_base 2 "cannot resolve base ref" STUB_GIT_REVPARSE_RC=128
    run_case worktree_add_failure 2 "could not create the base worktree" \
        STUB_GIT_WORKTREE_RC=128
    # A LOCKED worktree whose directory has since been swept - the default cache
    # lives under TMPDIR, so a /tmp sweep produces exactly this - is the one case
    # `prune` cannot heal, because refusing to prune a locked worktree is
    # precisely what locking is for. The two ended up in the same function without
    # anyone noticing they cancel: after the lock was added, a swept cache made
    # `git worktree add` fail 128 and the driver refused that base sha FOREVER,
    # naming neither the cause nor the remedy. git documents the recovery ("To add
    # a missing but locked worktree path, specify --force twice"), and this case
    # pins that the driver uses it. Reproduced end to end against real git first.
    run_case locked_but_missing_worktree_is_recovered 0 "OK (0 regressions" \
        STUB_WT_LOCKED_MISSING=1

    # --- there must be something to vary -------------------------------------
    # A base ref resolving to this tree's own commit builds the same source
    # twice and compares it with itself. Every anti-vacuity guard passes on that
    # run - sentinels fire with the exact paths, counts are healthy, tables
    # reconcile - and it prints OK. That is #572 in a new file, one step away via
    # `just diff-<lane>-branch HEAD`.
    #
    # These four cases are a 2x2 over the two questions git can be asked, and the
    # pairing is the point. `git diff --quiet <base> -- <paths>` (ONE ref) compares
    # the base commit to the WORKING TREE, which is the pair this driver actually
    # builds. `git diff --quiet <base> <head> -- <paths>` (TWO refs) compares two
    # COMMITS, a pair the driver never builds. Cases 1 and 4 are cells where the
    # two answers AGREE and any implementation passes them; cases 2 and 3 are the
    # cells where they DISAGREE, so a driver consulting the wrong one fails exactly
    # one of them. Only those two cells discriminate, and neither existed until
    # round 3 - which is how a guard pointed at the wrong operand survived four
    # repairs and three review rounds with every case green.

    # 1. Both agree the sources are the same. Refuse.
    run_case worktree_matches_base_is_refused 2 "there is nothing to vary" \
        STUB_WORKTREE_MATCHES_BASE=1 STUB_TREES_IDENTICAL=1
    # 2. DISAGREE: the commits differ, the working tree does not. This is the live
    # defect round 3 found, and it is this instrument's own documented use case:
    # `git checkout <base> -- crates/` is how an operator asks "would my new corpus
    # really have caught the old code?", and an in-flight `git stash` has the same
    # shape. Both leave the tree byte-identical to the base while the two COMMITS
    # still differ, so the two-ref guard stood down and the driver compared a tree
    # with itself, printing OK at rc 0.
    run_case reverted_worktree_refused_though_commits_differ 2 "there is nothing to vary" \
        STUB_WORKTREE_MATCHES_BASE=1
    # 3. DISAGREE the other way: two commits carrying identical sources are NOT a
    # reason to refuse once the working tree has uncommitted work on top. This is
    # the legitimate "diff my uncommitted work against the commit I am sitting on"
    # mode, and it is what stops the fix for case 2 from over-firing.
    run_case identical_commits_but_dirty_worktree_proceeds 0 "OK (0 regressions" \
        STUB_TREES_IDENTICAL=1
    # 4. Both agree the sources differ. The ordinary case; proceed.
    run_case worktree_differs_from_base_proceeds 0 "OK (0 regressions"
    # UNTRACKED files are not part of the build and must not make the tree read as
    # varying. Found by running the real recipe on a tree that looked clean and
    # getting rc 0: a single `?? .serena/` was enough to disable the whole guard.
    #
    # PINNED BY CONSTRUCTION, NOT BY THIS KNOB, and saying so is the point.
    # `git diff` reads tracked content, so `STUB_TREE_UNTRACKED` reaches no driver
    # path at all and this run is identical to the case above. It is kept as a
    # named regression marker for the `?? .serena/` incident: it will start
    # discriminating again only if the guard ever reverts to a `status`-based
    # form. Calling it a witness would be the exact defect this file's header
    # warns about, committed in the same diff that restates the rule.
    run_case untracked_only_is_still_refused 2 "there is nothing to vary" \
        STUB_WORKTREE_MATCHES_BASE=1 STUB_TREE_UNTRACKED=1

    # --- the cached base worktree must BE the base ---------------------------
    # Directory existence was the whole reuse predicate, while the report kept
    # printing `base=<sha>`. All three of these were rc 0 before the cache
    # validation landed.
    run_case cached_worktree_at_wrong_sha 2 "not the requested base" \
        STUB_PRECREATE_WT=1 STUB_WT_SHA=deadbeefdeadbeefdeadbeefdeadbeef00000000
    run_case cached_worktree_is_dirty 2 "has uncommitted changes" \
        STUB_PRECREATE_WT=1 STUB_WT_DIRTY=1
    # An UNTRACKED file in the cached base worktree is part of the base's replay
    # input, because the corpus is read from the filesystem and not from git.
    # Measured on the real driver: one untracked scenario dir dropped into the
    # cached base turned "2 discriminated" into "0 discriminated" at rc 0.
    run_case cached_worktree_has_untracked_corpus_file 2 "has uncommitted changes" \
        STUB_PRECREATE_WT=1 STUB_WT_UNTRACKED=1
    # THE SAME BUG ONE STEP FURTHER OUT, and the case above cannot reach it.
    #
    # `git status --porcelain` omits IGNORED paths, and `read_dir` ignores nothing,
    # so the untracked check above answers only half its own stated question. The
    # driver now asks the other half with a corpus-scoped `--ignored` call.
    #
    # Reproduced against the REAL driver before this case existed: the same scenario
    # directory named `zz-adversary-probe` gives rc 2, and named `docs` (a bare
    # unanchored entry in this repo's own .gitignore) gives rc 0 with `0
    # discriminated` - the contaminating scenario turns R1 red for exactly the rows
    # that would otherwise have been DISCRIMINATED, so the instrument's whole
    # payload evaporates while it reports success.
    run_case cached_worktree_has_ignored_corpus_path 2 "git is ignoring" \
        STUB_PRECREATE_WT=1 STUB_WT_IGNORED=1
    # Its rc guard, which fails open exactly like the whole-tree one: git fails,
    # stdout is empty, and "could not check" reads as "checked, and uncontaminated".
    run_case wt_ignored_status_cannot_answer 2 "the corpus is uncontaminated" \
        STUB_PRECREATE_WT=1 STUB_GIT_STATUS_IGNORED_RC=128
    # THE DEVELOPER'S GIT CONFIG, which silently turned BOTH guards above off.
    #
    # `status.showUntrackedFiles=no` is a documented performance knob read from
    # `~/.gitconfig`, `$XDG_CONFIG_HOME/git/config`, `/etc/gitconfig` and the MAIN
    # CLONE's `.git/config` - which reaches every cached worktree through the
    # common dir, for the same reason `.git/info/exclude` does. Under it the
    # whole-tree call loses its `??` rows and the `--ignored` call returns ZERO
    # BYTES, both AT RC 0, so neither rc guard fires: git said nothing
    # SUCCESSFULLY. Measured end to end on the real driver before `-unormal` was
    # pinned: a contaminated cache gave rc 2 with the config unset and rc 0,
    # `OK (2 discriminated)`, with it set.
    #
    # Two cases because the config breaks two different guards and each `-unormal`
    # has to be witnessed where it sits; one case would leave the other flag free
    # to be deleted.
    run_case config_hides_an_ignored_corpus_path 2 "git is ignoring" \
        STUB_PRECREATE_WT=1 STUB_WT_IGNORED=1 STUB_GIT_UNTRACKED_NO=1
    run_case config_hides_an_untracked_corpus_file 2 "has uncommitted changes" \
        STUB_PRECREATE_WT=1 STUB_WT_UNTRACKED=1 STUB_GIT_UNTRACKED_NO=1
    # THE INDEX ITSELF, which is the third and last member of that set and the one
    # no flag at either `status` call can reach.
    #
    # `core.ignoreStat` true at `git worktree add` time burns the assume-unchanged
    # bit into the new linked worktree's index, and `git sparse-checkout` sets
    # `skip-worktree`. Both make a MODIFIED TRACKED FILE invisible to `status`:
    # zero bytes at rc 0. Measured on git 2.55.0, and measured again on the
    # already-built worktree to establish that this is STATE and not configuration:
    # `git config --unset core.ignoreStat` leaves it blind, and
    # `git -c core.ignoreStat=false ... status` leaves it blind. That is why the
    # driver reads `ls-files -v` FLAGS instead of pinning a third flag - a remedy
    # aimed at the config protects only caches created afterwards, which is the
    # failure this file already records at the `worktree lock` call.
    #
    # Two cases because the two flags are different suppression mechanisms that a
    # single-cause remedy would split; the driver's guard is deliberately
    # mechanism-agnostic and both cases pin that.
    run_case cached_worktree_index_assume_unchanged 2 "assume-unchanged or skip-worktree" \
        STUB_PRECREATE_WT=1 STUB_WT_SUPPRESSED=assume
    run_case cached_worktree_index_skip_worktree 2 "assume-unchanged or skip-worktree" \
        STUB_PRECREATE_WT=1 STUB_WT_SUPPRESSED=skip
    # Its rc guard, the same shape as the two above it.
    run_case wt_lsfiles_cannot_answer 2 "git can see this tree" \
        STUB_PRECREATE_WT=1 STUB_GIT_LSFILES_RC=128
    # AND ITS VACUITY GUARD, which is the one this guard could most easily have
    # got wrong: a suppressed-entry COUNT over a zero-line answer is zero, so
    # without it the new check would report "nothing is suppressed" on a worktree
    # where nothing was examined - re-creating, inside the fix, the exact shape the
    # fix exists to close.
    run_case wt_lsfiles_reports_no_tracked_files 2 "no tracked files at all" \
        STUB_PRECREATE_WT=1 STUB_WT_LSFILES_EMPTY=1
    # A hand-made directory at the cache path means `git worktree add` never runs,
    # so even its failure is unobservable. Pairing the pre-created tree with a
    # creation failure proves the driver is validating rather than trusting.
    run_case cached_worktree_never_created_by_git 2 "not the requested base" \
        STUB_PRECREATE_WT=1 STUB_WT_SHA=deadbeefdeadbeefdeadbeefdeadbeef00000000 \
        STUB_GIT_WORKTREE_RC=128
    run_case base_build_failure 2 "cannot compare" STUB_CARGO_BASE_RC=101
    run_case head_build_failure 2 "cannot compare" STUB_CARGO_HEAD_RC=101
    run_case json_phase_failure 2 "--message-format=json exited" STUB_CARGO_JSON_RC=1
    run_case ambiguous_executables 2 "expected exactly 1 test binary" \
        STUB_CARGO_EXTRA_EXE=/bin/true

    # --- corpus preconditions ------------------------------------------------
    # A base predating the corpus cannot be replayed against it. That is the
    # issue's "cannot compare" path and it is rc 2, never a silent skip: a
    # harness that exits 0 with a skip message on every run is #572.
    run_case base_corpus_missing 2 "corpus is missing at the base" \
        STUB_BASE_CORPUS_MISSING=1
    run_case head_corpus_empty 2 "no regular files" STUB_HEAD_CORPUS_EMPTY=1
}

# ---------------------------------------------------------------------------
# Pass 1: the real driver.
# ---------------------------------------------------------------------------
DRIVER_UNDER_TEST="${DRIVER}"
run_all_cases

if [ "${FAIL}" -ne 0 ]; then
    printf '\nrs-branch-diff-test: %d passed, %d FAILED (%s)\n' \
        "${PASS}" "${FAIL}" "${FAILED_CASES[*]}" >&2
    exit 1
fi

# A suite that parsed nothing must not report clean.
if [ "${PASS}" -eq 0 ]; then
    echo "SUITE ERROR: zero cases ran; the case table is empty or unreachable" >&2
    exit 2
fi
BASELINE_PASS="${PASS}"

# The rc contract says this instrument has NO rc 3. It is OFFLINE tier - no
# docker, no root, no live oracle - so it has no legitimate precondition to skip
# on, and inventing one would rebuild #572, where a harness exited 0 with a skip
# message on every run while checking nothing. Asserted against observed
# behaviour rather than left as a comment.
case " ${OBSERVED_RCS} " in
*" 3 "*)
    echo "SUITE ERROR: the driver exited 3; this instrument has no legitimate skip path" >&2
    exit 2
    ;;
esac

# ---------------------------------------------------------------------------
# Pass 2: the positive controls.
#
# Each control seeds ONE real defect back into a COPY of the driver and requires
# that NAMED cases catch it. Asserting merely that "some case failed" would be
# satisfied by a typo in the sandbox builder, which is the
# count-as-the-pass-condition mistake this project has already made once.
#
# One control per guard, rather than one copy with every guard removed: a single
# multiply-broken driver could have one case failing for another guard's reason,
# and the suite would still call the control satisfied.
#
# run_positive_control <label> <sed-expression> <must-catch-case>...
# ---------------------------------------------------------------------------
run_positive_control() {
    local label="$1" sed_expr="$2"
    shift 2
    local must_catch=("$@")

    local broken="${SANDBOX_BASE}/rs-branch-diff-FAIL-OPEN-${label}.sh"
    sed "${sed_expr}" "${DRIVER}" >"${broken}"
    local sed_rc=$?
    # THREE WAYS A SEED CAN LIE, and `cmp` alone only catches the first.
    #
    # 1. It matched nothing, so the driver is unmodified and every case passes:
    #    indistinguishable from a guard that held. That is the `cmp -s` check
    #    below, and it has already fired for real (round 8, when the `ran_any`
    #    rework moved a seeded source line).
    # 2. `sed` ERRORED and wrote a truncated file. `cmp` sees a difference and is
    #    satisfied, but the seeded "driver" is a fragment that fails every case,
    #    so the control reports CAUGHT for reasons having nothing to do with the
    #    guard. Found in round 10, when a seed's `|` delimiter collided with the
    #    `|` inside `0 | 101` and sed died; the probe scored it a catch, and it is
    #    really a survivor.
    # 3. It inserted or deleted lines rather than substituting in place, which
    #    silently moves every line number the rest of the suite reasons about.
    #
    # rc and a structural invariant catch 2 and 3. Both are cheap and neither can
    # be satisfied by a seed that did the right thing.
    if [ "${sed_rc}" -ne 0 ]; then
        echo "SUITE ERROR: positive control '${label}' sed exited ${sed_rc}; a truncated driver 'catches' every case for the wrong reason" >&2
        exit 2
    fi
    if [ "$(wc -l <"${DRIVER}")" -ne "$(wc -l <"${broken}")" ]; then
        echo "SUITE ERROR: positive control '${label}' changed the driver's line count; seeds must substitute in place" >&2
        exit 2
    fi
    if cmp -s "${DRIVER}" "${broken}"; then
        echo "SUITE ERROR: positive control '${label}' edited nothing; its guard's source line moved" >&2
        exit 2
    fi

    PASS=0
    FAIL=0
    FAILED_CASES=()
    DRIVER_UNDER_TEST="${broken}"
    CONTROL_PHASE=1
    run_all_cases
    CONTROL_PHASE=0

    # THE CONTROL NEEDS ITS OWN CONTROL.
    #
    # `must_catch` asserts only that named cases FAILED, and a case fails when
    # either rc or the substring mismatches. A driver that cannot run at all -
    # a sed anchor that moved and now breaks syntax, a quoting slip - exits 2 for
    # every case, mismatches every substring, and is therefore credited with
    # catching everything. `cmp -s` proves sed edited a byte, not that the result
    # is still a driver.
    #
    # Reproduced: injecting a bash syntax error into `usage()` while leaving the
    # sentinel guard fully intact made every control then in the suite report
    # "caught" (there were six at the time; quoting a live count here is the
    # very thing this file's header forbids) and the
    # suite exit 0, with `just instrument-test` unable to see it (the control
    # phase prints CAUGHT, not FAIL). That is this project's own "positive-control
    # any instrument you write" rule, left unapplied to the controls themselves.
    #
    # Two cheap assertions close it: some cases must still PASS, and specifically
    # the ones the removed guard cannot see must still behave correctly.
    if [ "${PASS}" -eq 0 ]; then
        printf 'SUITE ERROR: positive control %s left ZERO cases passing.\n' "${label}" >&2
        printf '             A driver with one guard removed still classifies every input that\n' >&2
        printf '             guard does not see; zero passes means the seeded driver cannot run,\n' >&2
        printf '             so "caught" here certifies nothing.\n' >&2
        exit 2
    fi
    local still want got found
    for still in "${CONTROL_MUST_STILL_PASS[@]}"; do
        for got in "${FAILED_CASES[@]+"${FAILED_CASES[@]}"}"; do
            if [ "${got}" = "${still}" ]; then
                printf 'SUITE ERROR: positive control %s broke %s, which its guard does not touch.\n' \
                    "${label}" "${still}" >&2
                printf '             The seeded driver is not merely missing one guard; it is broken,\n' >&2
                printf '             so every "caught" it produced is an artefact.\n' >&2
                exit 2
            fi
        done
    done

    local missed=() found
    for want in "${must_catch[@]}"; do
        found=0
        for got in "${FAILED_CASES[@]+"${FAILED_CASES[@]}"}"; do
            [ "${got}" = "${want}" ] && found=1
        done
        [ "${found}" -eq 1 ] || missed+=("${want}")
    done

    if [ "${#missed[@]}" -ne 0 ]; then
        printf 'SUITE ERROR: positive control %s did not catch: %s\n' "${label}" "${missed[*]}" >&2
        printf '             a fail-open driver passed these cases, so a green result\n' >&2
        printf '             from this suite proves nothing.\n' >&2
        exit 2
    fi
    printf '  control %-30s caught %s\n' "${label}" "${must_catch[*]}"
}

printf 'rs-branch-diff-test: %d cases passed against the real driver.\n' "${BASELINE_PASS}"

# Every sed pattern below is matched against the DRIVER'S SOURCE, where the shell
# variable names appear unexpanded, so they must stay single-quoted. Double
# quoting would expand them in THIS shell and match nothing - which the `cmp`
# check inside run_positive_control then catches.

# shellcheck disable=SC2016
run_positive_control sentinel-guard-removed \
    's|^    if \[ "${ran_any}" -eq 1 \] &&|    if false \&\&|' \
    base_baseline_ignores_override base_on_head_corpus_ignores_override \
    head_run_ignores_override no_banner_at_all

# The NEGATIVE half of that guard, which is a separate `if` and therefore needs
# its own control: seeding one does not disturb the other, and a suite where only
# the positive half is controlled would report full coverage of a guard that is
# half uncontrolled.
# shellcheck disable=SC2016
run_positive_control committed-mode-guard-removed \
    's|^    if grep -qF "${SENTINEL}: mode=committed" "${err}" "${out}"; then|    if false; then|' \
    second_committed_read_is_refused

# shellcheck disable=SC2016
run_positive_control zero-count-guard-removed \
    's|^        if \[ "${one}" -eq 0 \]; then|        if false; then|' \
    zero_scenarios zero_count_among_live_ones

# shellcheck disable=SC2016
run_positive_control test-line-guard-removed \
    's|^    if \[ "${seen}" -eq 0 \]; then|    if false; then|' \
    no_test_lines_at_all no_test_lines_in_baseline

# One `if`, two diagnostics, so both of its causes are named here: removing the
# guard must let BOTH a fully-red baseline and a disjoint test set through.
# shellcheck disable=SC2016
run_positive_control unattributable-guard-removed \
    's|^if \[ "${COMPARABLE}" -eq 0 \] &&|if false \&\&|' \
    all_rows_unattributable disjoint_test_sets every_row_ignored_at_base

# The conjunct that stops a BRANCH DEFECT being reported as a TOOL ERROR. Seeded
# on its own line so it is independent of the gate control above: removing it
# leaves the gate live and only the rc-1 bucket unprotected, which is exactly the
# state round 4 shipped.
# shellcheck disable=SC2016
run_positive_control head_failing_beats_zero_comparable_removed \
    's|^    \[ "${#ONLY_HEAD_FAILING\[@\]}" -eq 0 \]; then|    true; then|' \
    unparked_failing_with_no_comparable_row added_failing_with_no_comparable_row

# The R1/R2 same-test-set guard, whose own comment names the false clean it
# prevents and which a mutation probe found surviving all 64 cases of round 4.
# shellcheck disable=SC2016
run_positive_control r1_r2_cardinality_guard_removed \
    's|^if \[ "${#R1\[@\]}" -ne "${#R2\[@\]}" \]; then|if false; then|' \
    r2_reports_an_extra_test

# The containment half, controlled separately: equal cardinality with different
# keys passes the size check, and the missing name then reads as CLEAN via the
# `${R2[...]-}` default. One control over both halves would have left this one
# uncontrolled while looking covered.
# shellcheck disable=SC2016
run_positive_control r1_r2_containment_guard_removed \
    's#^    \[ -n "${R2\[${name}\]+set}" \] || die 2 .*#    :#' \
    r2_reports_a_different_test_set

# The all-parked carve-out. Neutering the arm that clears `ran_any` leaves it at
# its default 1, restoring the pre-carve-out behaviour where a lane whose replay
# tests are ALL `#[ignore]`d was refused at rc 2 ("its exit code and per-test table
# therefore mean nothing") about a table that is complete and meaningful -
# contradicting three specifications that promise rc 1 SILENCED. Seeded on the
# case arm rather than the `if`, so it is independent of `sentinel-guard-removed`
# above, which removes the guard outright.
#
# This seed was `s|^    local ran_any=0|    local ran_any=1|` until round 8 changed
# the derivation, at which point it silently matched nothing. The
# control-of-the-control is what caught that ("edited nothing; its guard's source
# line moved"), which is the whole reason it exists.
# shellcheck disable=SC2016
run_positive_control all_parked_carveout_removed \
    's|ran_any=0 ;;|: ;;|' \
    every_row_silenced_at_head

# `ran_any` SOURCED FROM A PER-TEST ROW rather than from libtest's summary tally.
# That is the CLASS of the round-7 defect: any row-shaped derivation inherits the
# ambiguity of a reason string, because `#[ignore = "..."]` renders the reason into
# the same line as the verdict. The summary line cannot express that ambiguity, and
# this control is what pins the difference.
# shellcheck disable=SC2016
run_positive_control ran_any_read_from_rows \
    's|^    ran_tally="$(grep -m1 -E .*|    ran_tally="$(grep -m1 -E '"'"'^test '"'"' "${out}" \|\| true)"|' \
    every_row_silenced_with_a_dotted_reason

# A round-6 mutation probe found exactly two guards, of 20, that both survive the
# whole suite and fail OPEN when removed: gutting either yields `OK (0
# regressions, 0 discriminated)` at rc 0. They are **`wt_status_rc_guard_removed`
# and `tree_diff_catchall_removed`**, named here rather than pointed at, and both
# were correct in the driver but unwitnessable, because the stub `git` could not
# express a status or a diff that FAILED - only ones that answered.
#
# NAMED, NOT POSITIONAL, because "the two controls immediately below" has now
# been falsified TWICE by two different insertions. Round 7 spliced the all-parked
# block between this paragraph and its subjects. Round 8's repair moved the
# paragraph back and then inserted THREE more controls below it in the same
# commit, putting `tree_diff_catchall_removed` 30 lines and three controls away
# again - and exactly ONE of those three (`wt_ignored_rc_guard_removed`) is about
# stub `git` failing, so a reader following the paragraph downward lands on the
# wrong control twice before reaching the right one. Re-ordering only holds until
# the next insertion; a name does not move.
#
# That sentence said "two of those three" until round 10, and the commit that
# wrote it contradicted itself 15 lines further down, where
# `wt_ignored_guard_removed` is correctly described as the twin of
# `cache-dirty-guard-removed`: its case emits `!! .../docs/` and exits 0, so git
# ANSWERS and the guard's absence discards a non-empty answer. `git failed` and
# `git answered, and the answer was discarded` are different shapes, and this
# paragraph's whole argument depends on the distinction it blurred.
# shellcheck disable=SC2016
run_positive_control wt_status_rc_guard_removed \
    's|^if \[ "${wt_status_rc}" -ne 0 \]; then|if false; then|' \
    wt_status_cannot_answer

# The IGNORED-path half of the same question, and its own rc guard. Neither is
# reachable through the whole-tree call, which dies first.
#
# They fail open by DIFFERENT mechanisms, and conflating them is an argument for
# deleting one as redundant. `wt_ignored_rc_guard_removed` is the "git says
# nothing, and nothing reads as clean" shape, the twin of
# `wt_status_rc_guard_removed`. `wt_ignored_guard_removed` is not: its case emits
# `!! .../docs/` and exits 0, so git says something and the guard's absence
# DISCARDS A NON-EMPTY ANSWER - structurally the twin of `cache-dirty-guard-removed`
# below, which is also an `-n` test.
# shellcheck disable=SC2016
run_positive_control wt_ignored_guard_removed \
    's|^if \[ -n "${wt_ignored}" \]; then|if false; then|' \
    cached_worktree_has_ignored_corpus_path
# shellcheck disable=SC2016
run_positive_control wt_ignored_rc_guard_removed \
    's|^if \[ "${wt_ignored_rc}" -ne 0 \]; then|if false; then|' \
    wt_ignored_status_cannot_answer

# The index-flag guard and its two supporting refusals. All three are `die 2`
# sites on the cached worktree, but they fail open in three different ways and so
# get three controls: `wt_index_flag_guard_removed` discards a NON-EMPTY answer
# (the `cache-dirty-guard-removed` shape), `wt_lsfiles_rc_guard_removed` accepts
# "git could not say" (the `wt_ignored_rc_guard_removed` shape), and
# `wt_lsfiles_vacuity_guard_removed` accepts a count taken over nothing (the shape
# every other guard in this file exists to prevent, re-created inside the newest
# one if its vacuity check were dropped).
# shellcheck disable=SC2016
run_positive_control wt_index_flag_guard_removed \
    's|^if \[ "${wt_suppressed}" -ne 0 \]; then|if false; then|' \
    cached_worktree_index_assume_unchanged cached_worktree_index_skip_worktree
# shellcheck disable=SC2016
run_positive_control wt_lsfiles_rc_guard_removed \
    's|^if \[ "${wt_lsfiles_rc}" -ne 0 \]; then|if false; then|' \
    wt_lsfiles_cannot_answer
# shellcheck disable=SC2016
run_positive_control wt_lsfiles_vacuity_guard_removed \
    's|^if \[ -z "${wt_lsfiles}" \]; then|if false; then|' \
    wt_lsfiles_reports_no_tracked_files

# The `-unormal` on each status call, controlled SEPARATELY because the two flags
# sit on two different commands and a single control would leave the other free to
# be deleted. Without them `status.showUntrackedFiles=no` silences both guards at
# rc 0.
# shellcheck disable=SC2016
run_positive_control wt_status_untracked_mode_unpinned \
    's|status --porcelain -unormal|status --porcelain|' \
    config_hides_an_untracked_corpus_file
# shellcheck disable=SC2016
run_positive_control wt_ignored_untracked_mode_unpinned \
    's|status --porcelain --ignored -unormal|status --porcelain --ignored|' \
    config_hides_an_ignored_corpus_path

# The `0 failed;` half of the `ran_any` pattern. Weakening it to `'0 passed;'`
# makes any zero-pass run look parked, standing down THE anti-vacuity guard and
# turning a run that never announced its corpus into `2 discriminated` at rc 0.
# NOT covered by `all_parked_carveout_removed`, which seeds the `;;` arm that this
# weakening leaves intact.
# shellcheck disable=SC2016
run_positive_control ran_any_conjunct_weakened \
    "s|^    '0 passed; 0 failed;'|    '0 passed;'|" \
    no_banner_on_an_all_failed_run

# The count-seen gate applied to ALL THREE runs, not just R3. This seeds the one
# weakening its existing cases could not see: a run-scope conjunct, which leaves
# `missing_count_line` (R3) green while R1 and a green R2 stop being checked.
#
# Unlike every other control in this file it does not REMOVE a conjunct, it ADDS
# one - because the gate's defect shape is narrowing rather than deletion. That is
# also why the mutation sweep could never have found it: there is no wrong branch
# to flip, only a right branch that was never asked about two of its three inputs.
# shellcheck disable=SC2016
run_positive_control count_seen_gate_scoped_to_r3 \
    's|\[ "${count_seen}" -eq 0 \]; then|[ "${count_seen}" -eq 0 ] \&\& [ "${run}" -eq 3 ]; then|' \
    r1_green_without_a_count r2_green_without_a_count

# Evidence retention on the DISCRIMINATED run. Reverting to `rc -eq 0` alone is the
# defect this branch already shipped once: it deletes the logs for the one outcome
# the instrument exists to produce. A round-8 probe found both this and the
# delete-always form leaving all cases green.
# shellcheck disable=SC2016
run_positive_control evidence_retention_removed \
    's|^    if \[ "${rc}" -eq 0 \] && \[ "${#DISCRIMINATED\[@\]}" -eq 0 \]; then|    if [ "${rc}" -eq 0 ]; then|' \
    discriminated_run_retains_its_evidence

# Seeded on the `die 2` itself, NOT on the `git diff` invocation. The
# nothing-to-vary control above replaces that invocation with `false`, which exits
# 1 and therefore drives the "they differ, proceed" arm - so it exercises the
# gate's proceed path and cannot reach this catch-all at all. A control that looks
# adjacent is not a control.
# shellcheck disable=SC2016
run_positive_control tree_diff_catchall_removed \
    's#^    die 2 "could not compare base ref .*#    :#' \
    tree_diff_cannot_answer

# The split inside the base-ignored arm. Without it the arm excludes on R1 alone
# and a test red at HEAD rides out at rc 0 with `FAILED` printed in its own row.
# shellcheck disable=SC2016
run_positive_control base_ignored_r3_split_removed \
    's|^        if \[ "${R3\[${name}\]}" = "FAILED" \]; then|        if false; then|' \
    base_ignored_but_failing_at_head

# The reasoned-ignore rendering. Reverting the regex to the bare-only form is
# exactly the state the driver shipped in for two rounds, and it must not be
# reachable again silently: both directions of the reasoned form have to fail.
# shellcheck disable=SC2016
run_positive_control reasoned_ignore_parse_removed \
    's#(ok|FAILED|ignored(, .\*)?)#(ok|FAILED|ignored)#' \
    head_silenced_with_a_reason base_carries_a_reasoned_ignore

# shellcheck disable=SC2016
run_positive_control rc-consistency-guard-removed \
    's|^    if \[ "${inconsistent}" -eq 1 \]; then|    if false; then|' \
    rc_zero_but_table_failed rc_101_but_table_clean

# The cross-check against libtest's own tally. Without it, a row the anchored
# pattern skipped is indistinguishable from a row that never ran, and the driver
# would report a confident verdict over a silently narrowed table.
# shellcheck disable=SC2016
run_positive_control summary-crosscheck-removed \
    's|^    if \[ "$((lt_passed + lt_failed + lt_ignored))" -ne "${seen}" \]; then|    if false; then|' \
    mangled_row_is_caught mangled_row_in_baseline summary_disagrees mangled_row_in_HEAD

# The guard that stops the driver comparing something with itself. It was absent
# until an adversarial review reproduced a green `OK (0 regressions, 0
# discriminated, ...)` from two builds of identical source.
#
# Seeded by neutering the COMPARISON rather than the `die`, because after round 3
# the whole guard is one `git diff` and its case arms: forcing rc 1 ("they
# differ") is exactly what a driver missing this guard would do.
# shellcheck disable=SC2016
run_positive_control nothing-to-vary-guard-removed \
    's|^git diff --quiet "${BASE_SHA}" -- crates/ Cargo.toml Cargo.lock 2>"${WORK}/tree-diff.err"$|false|' \
    worktree_matches_base_is_refused reverted_worktree_refused_though_commits_differ \
    untracked_only_is_still_refused

# shellcheck disable=SC2016
run_positive_control cache-sha-guard-removed \
    's|^if \[ "${wt_sha}" != "${BASE_SHA}" \]; then|if false; then|' \
    cached_worktree_at_wrong_sha cached_worktree_never_created_by_git

# The final rc-0 contract gate. It had NO control and NO witness until round 3: a
# mutant that neutered it left all 52 cases of the day passing, because the only
# case NAMED for it exited earlier on the head-only gate and never reached it.
# That is the failure this whole file exists to prevent, found in this file.
# shellcheck disable=SC2016
run_positive_control rc-zero-contract-gate-removed \
    's|^if \[ "${SCEN\[3\]}" -eq 0 \]; then|if false; then|' \
    rc_zero_contract_refuses_zero_count

# shellcheck disable=SC2016
run_positive_control cache-dirty-guard-removed \
    's|^if \[ -n "${wt_dirty}" \]; then|if false; then|' \
    cached_worktree_is_dirty cached_worktree_has_untracked_corpus_file

exit 0
