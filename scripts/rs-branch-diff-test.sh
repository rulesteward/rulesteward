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
# controls, and they are not all controlled. Saying "each" would invite the next
# person to skip adding a control for a new guard, on the strength of a comment
# claiming one already exists. No exact count is quoted for EITHER number,
# deliberately: both drift with almost every commit, and a stale figure quoted as
# current is its own defect class. Count them today with `grep -c 'die 2 '` and
# `grep -cE '^run_positive_control '`.
#
# A control proves a guard is WITNESSED, which a case NAME does not: a guard whose
# only named case exits earlier never reaches it, and neutering that guard leaves
# every case passing. If you add a guard, add a control, and check the control
# fails when the guard is gone.
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

# Which cases the current pass runs. Empty selects the whole table, which is what
# pass 1 against the real driver uses; a positive control sets it to the only
# cases it asserts on.
#
# A control asserts its `must_catch` names plus CONTROL_MUST_STILL_PASS, an
# average of 4.6 of the 93 cases, so running the full table per control did ~93%
# no-op work: 93 cases x 38 passes = 3534 executions, ~20 minutes. Scoped, the
# same assertions cost 262 executions.
CASE_FILTER=""

# The case names the current pass actually reached, so a control can prove the
# names it selected on are real. See the CASES_RUN check in run_positive_control.
CASES_RUN=""

case_selected() {
    [ -z "${CASE_FILTER}" ] && return 0
    case " ${CASE_FILTER} " in *" $1 "*) return 0 ;; esac
    return 1
}

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

    # A PRE-EXISTING cache directory, which is the driver's common path: it is run
    # every round against one fork point. Without this, every sandbox gets a fresh
    # TMPDIR and the reuse branch is never taken. Built here WITHOUT going through
    # the stub `git worktree add`, which is exactly the state that makes the
    # creation path's failure unobservable.
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
    # EVERY ENTRY IS LOAD-BEARING, and an omission fails in the direction that
    # looks like a pass. Without `head`, the driver's `| head -N` pipes fail with
    # `command not found` inside EVERY case and nothing notices: the suite asserts
    # an rc and one substring of the `die` message, never that the transcript
    # arrived. Without `tr`, the `cargo said: $(tail -3 ... | tr '\n' ' ')`
    # diagnostic that stops stderr being discarded produces an EMPTY tail inside
    # the sandbox, and `json_phase_failure` passes regardless because it asserts
    # only the substring BEFORE that interpolation. The driver is fine in
    # production, where `tr` is on PATH; the CASE is vacuous for the half it
    # exists to pin.
    # `awk` and `wc` are here for the content check, which also uses `tail` and
    # `head` in its refusal paths.
    # Keeping this list short is the point of it - every entry is a binary that has
    # to exist wherever the driver runs, and this check has already caught `tr`,
    # `head`, and a multi-operand `tail` that printed nothing.
    for tool in mktemp mkdir rm tail head tr grep cut env bash dirname cat cp awk wc; do
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

    # Stub git. The subcommands the driver uses: `rev-parse`, `status`,
    # `ls-files`, `hash-object`, `diff` and `worktree`.
    #
    # LISTED, NOT COUNTED. A count phrased as prose scans as boilerplate rather
    # than as a claim, so it rots quietly: it is not hard to get right, it is hard
    # to keep right, because the thing that falsifies it is always a feature
    # somewhere else. A list has to be extended by the same edit that adds an arm.
    #
    # `worktree add` materialises a base tree carrying its own committed corpus,
    # so that R1 (base binary against the BASE corpus) has something real to read.
    # STUB_BASE_CORPUS_MISSING models a base sha that predates the corpus.
    cat >"${box}/bin/git" <<'STUB'
#!/usr/bin/env bash
# Stub git. Distinguishes calls made INSIDE the cached base worktree (`git -C
# <dir> ...`) from calls against the repo, because the driver now validates the
# cache and those two must be able to disagree.
#
# GLOBAL OPTIONS ARE CONSUMED IN A LOOP, not with a single `-C` test, because the
# driver now passes `-c core.fsmonitor=` as well and real git accepts them in any
# order before the subcommand. A stub that consumed only `-C` would see `-c` as
# the subcommand and fall through every arm, which fails in the direction that
# looks like a passing test.
in_worktree=0
fsmon_pinned=0
while :; do
    case "${1-}" in
    -C)
        in_worktree=1
        shift 2
        ;;
    -c)
        # Only the pin the driver actually relies on is modelled; any other `-c`
        # is consumed and ignored, exactly as an unrelated config would be.
        case "${2-}" in
        core.fsmonitor=*) fsmon_pinned=1 ;;
        esac
        shift 2
        ;;
    *)
        break
        ;;
    esac
done

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
    # Retained for a driver that resolves HEAD; the current one does NOT (the
    # nothing-to-vary guard is a one-ref `git diff`, so there is no
    # `rev-parse HEAD^{commit}` call), and no case sets STUB_HEAD_SHA. Kept because
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
    # The driver does not pass `-uno` ANYWHERE. Its nothing-to-vary guard is a
    # one-ref `git diff`, which reads tracked content by construction, so no
    # untracked handling arises there. Its TWO `status` calls are both
    # on the cached worktree: `status --porcelain -unormal`, and
    # `status --porcelain --ignored -unormal -- <CORPUS_SUBPATH>`. Both deliberately
    # omit `-uno` and pin `-unormal`, because the corpus is enumerated from the
    # filesystem and an untracked or ignored scenario dir IS part of the base's
    # replay input.
    #
    # TWO driver call sites reach the `status` branch below, not one. Reading it as
    # serving a single call site is the misreading that makes
    # `STUB_GIT_STATUS_IGNORED_RC` look unnecessary; the paragraph beginning
    # "`--ignored` is the SECOND question the driver asks of this command" sits
    # below and says why the second one needs its own rc knob.
    #
    # That referent is NAMED rather than pointed at with a line offset,
    # deliberately. An offset is the only part of a reference that can rot, and
    # verifying a pointer has two halves - does a target exist there, and is it the
    # one you named - neither of which a line count checks unless you also check
    # the anchor.
    #
    # So every `status` reaching this stub arrives with `-C`, and the `else` arm
    # below is currently unreachable. Both are kept so a future caller that does
    # pass `-uno`, or that asks about the repo rather than the worktree, is
    # modelled rather than silently mis-answered.
    uno=0
    for a in "$@"; do case "${a}" in -uno|--untracked-files=no) uno=1 ;; esac; done
    # `--ignored` is the SECOND question the driver asks of this command, and this
    # stub has to be able to express its answer.
    #
    # Real `git status --porcelain` OMITS ignored paths (git-status(1): `--ignored`
    # is what "show ignored files as well" takes), while the lanes enumerate the
    # corpus with `read_dir`, which ignores nothing. So a scenario directory whose
    # name `.gitignore` matches is replay input AND invisible - and with only
    # STUB_WT_DIRTY and STUB_WT_UNTRACKED there is no way to state "a file is
    # present that `git status` does not report", which is precisely the bug.
    # A stub that cannot state the bug cannot catch it.
    ign=0
    for a in "$@"; do case "${a}" in --ignored|--ignored=*) ign=1 ;; esac; done
    # `status.showUntrackedFiles=no`, modelled. The stub has to express not only
    # what the driver ASKED but what the developer's git CONFIG does to the answer
    # - that config is unversioned, reaches every cached worktree through the
    # common dir, and silently turns BOTH cleanliness guards off.
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
        # THE ` M` ROW, and the FOURTH thing that can suppress it. An
        # under-reporting `core.fsmonitor` makes git skip the stat entirely and
        # report the entry clean, so this row vanishes at rc 0 with the file
        # modified on disk. Measured: it eats ONLY this row - the `??` and `!!`
        # rows below are unaffected - which is why the suppression is modelled
        # here rather than in the `uno` path those two share.
        [ -n "${STUB_WT_DIRTY:-}" ] &&
            { [ -z "${STUB_GIT_FSMONITOR:-}" ] || [ "${fsmon_pinned}" -eq 1 ]; } &&
            echo " M crates/rulesteward-auditd/src/lib.rs"
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
    # A FAILING `git status`, which this arm has to be able to express. A
    # mutation probe showed the driver's rc guard on this command surviving the
    # whole case table when removed, and removing it yields `OK` at rc 0: a
    # failing status writes nothing to stdout, so the driver's `-n "${wt_dirty}"`
    # test reads "could not check" as "checked, and clean". The reachable trigger
    # is a corrupt index in the long-lived cached worktree (`git status` refreshes
    # and writes the index; `rev-parse --verify HEAD` reads refs only, so the
    # earlier guard passes). Measured on git 2.55.0: a corrupt index gives rc 128
    # with EMPTY stdout and `fatal: .../index: index file smaller than expected`,
    # which is exactly this knob's shape. NOT a stale `index.lock`: status takes
    # that lock non-blocking and simply skips writing, returning rc 0 and empty
    # output.
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
    # THE THIRD MEMBER OF THE SUPPRESSED-ROW SET. The `status` arm above hides the
    # `!!` row and the `??` row; this is the ` M` row - a TRACKED file that is
    # modified and that `git status` does not report, because the index says stop
    # looking at it.
    #
    # It needs its own arm rather than another `status` knob, because the driver
    # asks a different COMMAND: `status` reports what git can see, and no answer
    # from it can describe what git has been told not to look at. Modelling the
    # blindness inside the `status` arm would make the two indistinguishable, and
    # a stub that cannot state the bug cannot catch it.
    #
    # `-v` prefixes each path with its index flag. `H` is the normal cached entry;
    # any LOWERCASE letter is assume-unchanged (what `core.ignoreStat` burns in at
    # `worktree add` time), and `S` is skip-worktree (what `git sparse-checkout`
    # sets). Both suppress identically, so both get a case - a remedy aimed at one
    # cause would leave the other open, which is why the driver reads the FLAGS
    # rather than guarding any single mechanism.
    # THIS ARM READS ITS ARGUMENTS, which is what makes the `-v` flag and the
    # call's SCOPE witnessable at all. An arm that ignored them leaves seeding
    # `-v` -> `-t` green across the whole case table while re-opening the
    # `core.ignoreStat` half the guard exists for; so does scoping the call to the
    # corpus, because the suppressed entry below sits outside it. The `status` arm
    # scans `"$@"` in three places for exactly this reason, and each of its flags
    # gets its own control. A guard has a QUESTION and a VERDICT, and controls that
    # attack only the verdict leave the question free to drift.
    lsv=0
    scoped=0
    lss=0
    for a in "$@"; do
        case "${a}" in
        -v) lsv=1 ;;
        -s) lss=1 ;;
        --) scoped=1 ;;
        esac
    done
    # `-s` is the CONTENT check's question: `<mode> <sha> <stage>\t<path>`, where
    # the path is everything after the TAB and the sha is the INDEX's blob. The
    # driver pairs these against `hash-object` output below, so the two arms have
    # to agree on both the path set and its ORDER.
    if [ "${lss}" -eq 1 ]; then
        if [ -n "${STUB_WT_LSFILES_EMPTY:-}" ]; then
            exit "${STUB_GIT_LSFILES_RC:-0}"
        fi
        # A NON-BLOB index entry, which the driver refuses rather than hashing or
        # skipping. `120000` is a symlink (the blob holds the link TARGET STRING,
        # while `hash-object` follows the link and hashes the target's CONTENTS,
        # so they can never agree) and `160000` is a gitlink (a commit, with no
        # file to hash at all). Two values on one knob because the driver's guard
        # is written as "not a known blob mode" rather than as a list of bad
        # modes, and both cases pin that.
        case "${STUB_WT_NONBLOB:-}" in
        symlink) printf '120000 dddd000000000000000000000000000000000004 0\t%s\n' \
            "crates/rulesteward-auditd/tests/corpus/auditd-oracle/aa-one/link" ;;
        gitlink) printf '160000 eeee000000000000000000000000000000000005 0\t%s\n' \
            "vendor/sub" ;;
        esac
        printf '100644 aaaa000000000000000000000000000000000001 0\t%s\n' \
            "crates/rulesteward-auditd/src/lib.rs"
        printf '100644 bbbb000000000000000000000000000000000002 0\t%s\n' \
            "crates/rulesteward-auditd/src/parser.rs"
        printf '100644 cccc000000000000000000000000000000000003 0\t%s\n' \
            "crates/rulesteward-auditd/tests/corpus/auditd-oracle/aa-one/input.rules"
        exit "${STUB_GIT_LSFILES_RC:-0}"
    fi
    if [ -n "${STUB_WT_LSFILES_EMPTY:-}" ]; then
        # No tracked files at all. A count over zero lines is zero, so without the
        # driver's vacuity guard this reads as "nothing is suppressed" when it
        # means "nothing was examined".
        exit "${STUB_GIT_LSFILES_RC:-0}"
    fi
    if [ "${scoped}" -eq 1 ]; then
        # Scoped to the corpus by a pathspec: the `src/` entries are outside it
        # and real git would not list them, so the suppressed one vanishes too.
        # That is the whole harm of narrowing this call, and it is invisible
        # unless the stub honours the pathspec.
        echo "H crates/rulesteward-auditd/tests/corpus/auditd-oracle/aa-one/input.rules"
        exit "${STUB_GIT_LSFILES_RC:-0}"
    fi
    echo "H crates/rulesteward-auditd/src/lib.rs"
    echo "H crates/rulesteward-auditd/tests/corpus/auditd-oracle/aa-one/input.rules"
    case "${STUB_WT_SUPPRESSED:-}" in
    # `-v` is what lowercases an assume-unchanged entry. Without it real git
    # prints `H` (measured: `ls-files -t` gives `H src/assume.rs`), so the guard
    # sees nothing. `S` is in the BASE tag set and appears with or without `-v`
    # (measured: `-t` still gives `S src/skip.rs`), so skip-worktree stays
    # visible under the weakening - which is why its case must NOT go red for
    # the `-v` control, and does not.
    assume)
        if [ "${lsv}" -eq 1 ]; then
            echo "h crates/rulesteward-auditd/src/parser.rs"
        else
            echo "H crates/rulesteward-auditd/src/parser.rs"
        fi
        ;;
    skip) echo "S crates/rulesteward-auditd/src/parser.rs" ;;
    esac
    exit "${STUB_GIT_LSFILES_RC:-0}"
fi

if [ "${1-}" = "hash-object" ]; then
    # THE WORKING TREE'S SIDE of the content comparison. `--stdin-paths` reads one
    # path per line and emits one sha per line, IN ORDER, which is what lets the
    # driver compare the two lists POSITIONALLY with a single `awk` - it does not
    # `paste` them, and the driver says so itself ("not joined with `paste`/`comm`,
    # deliberately"). `paste` appears in no executable position in either script
    # and is deliberately absent from the sandbox allowlist above, so a maintainer
    # restoring that join would be stopped by it.
    # Three knobs, because the three ways this comparison can go wrong are
    # genuinely different:
    #
    #   STUB_WT_CONTENT_DIRTY  a tracked file's content differs from the index -
    #                          the defect the whole check exists for, and the one
    #                          `git status` can be silenced about by at least
    #                          three unversioned config settings.
    #   STUB_HASH_SHORT        fewer hashes than paths, which is what a FAILING
    #                          hash-object produces. `paste` joins the short list
    #                          against the full names and the comparison silently
    #                          becomes nonsense. Measured for real while building
    #                          this check: `hash-object` has no `-z`, so it
    #                          errored and emitted ZERO hashes.
    #   STUB_GIT_HASHOBJ_RC    it could not answer at all.
    rc="${STUB_GIT_HASHOBJ_RC:-0}"
    if [ "${rc}" -ne 0 ]; then
        echo "fatal: stub hash-object failure" >&2
        exit "${rc}"
    fi
    n=0
    while IFS= read -r path; do
        n=$((n + 1))
        if [ -n "${STUB_HASH_SHORT:-}" ] && [ "${n}" -gt 1 ]; then
            break
        fi
        case "${path}" in
        */parser.rs)
            if [ -n "${STUB_WT_CONTENT_DIRTY:-}" ]; then
                echo "dead000000000000000000000000000000000bee"
            else
                echo "bbbb000000000000000000000000000000000002"
            fi
            ;;
        */lib.rs) echo "aaaa000000000000000000000000000000000001" ;;
        *) echo "cccc000000000000000000000000000000000003" ;;
        esac
    done
    exit 0
fi

if [ "${1-}" = "diff" ]; then
    # THE NUMBER OF REFS IS THE WHOLE POINT, so this stub counts them.
    #
    #   `git diff --quiet <base> -- <paths>`        ONE ref: base COMMIT vs WORKING TREE
    #   `git diff --quiet <base> <head> -- <paths>` TWO refs: commit vs commit
    #
    # The driver builds the WORKING TREE, so only the one-ref question is the one
    # it is entitled to act on. A stub that discarded its ref arguments and
    # answered both forms from a single variable would make the distinction
    # INEXPRESSIBLE in the suite, and a guard asking the wrong pair then passes
    # every case in this file. A stub that cannot state the bug cannot catch it.
    refs=0
    for a in "$@"; do
        case "${a}" in
        diff | --quiet) ;;
        --) break ;;
        *) refs=$((refs + 1)) ;;
        esac
    done
    # A git that could not ANSWER, which is neither 0 nor 1 and which this arm has
    # to be able to express. Without it the driver's `*)` catch-all is dead code
    # from the suite's point of view: a mutation probe found that gutting the
    # catch-all survived the whole case table and yields `OK` at rc 0.
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
        # everything" would hide the interaction between the two.
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
# A stub that announced unconditionally would let cases pin transcripts the real
# system cannot emit: an all-parked run that still produced a banner. A
# `must_catch` resting on such a case witnesses a fiction.
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
        # `boundary_substrate.rs` documents the convention. A suite whose every
        # case used the bare form would witness the SILENCED feature only on a
        # rendering the repo does not produce, while the driver's `$`-anchored
        # regex rejected the real one.
        # STUB_IGNORE_REASON exists because the REASON TEXT is load-bearing, which
        # is not obvious. A driver deriving "did a test body run" from
        # `grep -qE '^test .+ \.\.\. (ok|FAILED)$'` has a `.+` that is greedy and
        # unanchored in the middle, so a reason containing " ... ok" satisfies it
        # and an all-parked lane is refused at rc 2 instead of the rc 1 SILENCED
        # three specifications promise. Hardcoding one benign reason makes that
        # inexpressible.
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

    case_selected "${name}" || return 0
    CASES_RUN="${CASES_RUN} ${name}"

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
    # Two defects of the same shape are invisible to every case otherwise:
    # `tail -30 "${err}" "${out}"` is rejected outright by GNU coreutils when
    # given two FILE operands ("option used in invalid context"), and a sandbox
    # that does not provide `head` makes the driver's `| head -N` pipes fail with
    # `command not found`. In BOTH cases the driver prints its verdict with an
    # EMPTY transcript, and every case still passes - because a case asserts an rc
    # and one substring of the `die` message, never that the evidence arrived.
    #
    # This check is its own positive control: it fires on a driver carrying either
    # defect and is silent on this one, which is why it is worth more than a case
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

    case_selected "${name}" || return 0
    CASES_RUN="${CASES_RUN} ${name}"

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
    # Without this case `finish`'s retention branch is unwitnessed: a mutation
    # probe found that narrowing it to `if [ "${rc}" -eq 0 ]`, which discards the
    # DISCRIMINATED run's logs, left every case green, and so did deleting the
    # evidence on every rc.
    #
    # It has to be THIS shape. On rc 1 and rc 2 both the correct code and the
    # narrowed defect retain, so only a run that is rc 0 AND discriminated can tell
    # them apart, and that is exactly the run whose R2 stderr is the artifact the
    # documented per-round use wants. A case asserting the rc alone is blind to it:
    # the verdict is never wrong, only the record of how it was reached.
    #
    # RULING: the standing rule reads "a case per guard whose absence produces a
    # false clean", and this one does not - it produces evidence LOSS with a true
    # verdict. That harm is in scope. `worktree prune` (whose verdict stays true
    # when removed) and `cargo said:` (still vacuous) stay accepted residue.
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
    # Do NOT add "and every lane resolves inside a `#[test]` body, so a bad corpus
    # root fails every test: exactly `0 passed; N failed`". That inference is false
    # for three of the four lanes: auditd, sysctld and sudoers all carry
    # corpus-INDEPENDENT tests that pass regardless of the root, and only selinux
    # gives `0 passed`. The determinant is whether EVERY test in the target
    # resolves the corpus, not whether the file has a unit-test module
    # (`sudoers_corpus_oracle.rs` has no `mod` declaration of any kind and still
    # passes most of its tests). The summary SHAPE is not what makes this case
    # legitimate, and any such sentence is pinned to today's test composition and
    # would go silently false when that changes, with nothing to flag it. A cause
    # stated for a measurement is a second claim, and it needs its own check.
    run_case no_banner_on_an_all_failed_run 2 "did not read the corpus it was handed" \
        STUB_NO_BANNER=2 \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:FAILED"
    # The guard above is EXISTENTIAL: it proves something read the handed tree,
    # never that nothing read a different one. A binary resolving the corpus
    # correctly in one place and from a compiled-in CARGO_MANIFEST_DIR in another
    # satisfies it completely, and the comparison quietly becomes part
    # self-comparison. `rulesteward-selinux`'s `policy_corpus::archive_path` had
    # that exact shape, and the instrument could not see it - it was found by
    # reading the code. Every resolution now announces, so the second read
    # announces committed mode and the negative half catches it.
    run_case second_committed_read_is_refused 2 "ALSO resolved a corpus in committed mode" \
        STUB_SECOND_COMMITTED_READ=2

    # --- vacuity -------------------------------------------------------------
    run_case zero_scenarios 2 "'nothing fired' and 'nothing ran' are not the same" \
        STUB_R2_SCENARIOS=0
    # A GREEN run with no announcement is still vacuous and still rc 2. Paired
    # with failing_run_may_lack_a_count below, these two pin the exact boundary:
    # the count is required where, and only where, its absence is unfalsifiable.
    run_case missing_count_line 2 "for a green run" STUB_NO_COUNT=3
    # THE SAME GATE, ASKED OF R1 AND OF A GREEN R2. With `STUB_NO_COUNT` set only
    # to 3, or to 2 alongside a FAILING R2 (`failing_run_may_lack_a_count`, which
    # asserts the gate must NOT fire), the gate's application to the other two runs
    # is unwitnessed: a run-scope conjunct could be added to it and the whole suite
    # would stay green.
    #
    # The driver already refuses both, so these are pure witness. They pin a guard
    # that is present, correct, and under-specified, which a mutation sweep is
    # structurally blind to because there is no wrong branch to flip.
    # `run_positive_control count_seen_gate_scoped_to_r3` below is what makes them
    # load-bearing rather than decorative.
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

    # The same shape with R3 red BEFORE it announces. NAMED for what it actually
    # pins: a real failure above must be reported AS ITSELF and must not be
    # converted into "no announcements". It reaches `finish 1` on the head-only
    # gate and never gets near the final count gate, so it is NOT that gate's
    # witness - a mutant run neutering `SCEN[3] -eq 0` left every case still
    # passing. A case named after a guard it cannot reach is worse than no case: it
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
    # ...UNLESS it is red at HEAD. An arm excluding on R1 alone and never reading
    # R3 lets a test parked at the base that the branch un-parks and leaves red
    # print `FAILED` in the R3HEAD column and `OK` on the verdict line, from one
    # run, at rc 0 while libtest exited 101. That is ONLY_HEAD_FAILING's case by a
    # quieter route.
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
    # THE SAME LANE, with a reason string that can change the answer.
    #
    # An all-parked carve-out deriving "did a test body run" from a second pass over
    # the per-test ROWS, `grep -qE '^test .+ \.\.\. (ok|FAILED)$'`, has a `.+` that
    # is greedy and unanchored in the middle, so a reason containing " ... ok"
    # matches:
    #
    #   test replay_alpha ... ignored, blocked on #677 ... ok       <- MATCHED
    #
    # The carve-out then does not fire, the sentinel guard does, and an all-parked
    # lane comes back rc 2 ("its exit code and per-test table therefore mean
    # nothing") about a table that is complete and meaningful: a second, weaker
    # parse of something the driver reads correctly elsewhere. The driver reads
    # libtest's own `0 passed; 0 failed` tally instead, which cannot express that
    # ambiguity.
    #
    # Zero in-tree reachability today - no `#[ignore]` reason under `crates/`
    # contains " ... " - so this pins a latent contradiction, not a live break.
    run_case every_row_silenced_with_a_dotted_reason 1 "ran at base" \
        "STUB_R3_TESTS=replay_alpha:ignoredr replay_beta:ignoredr" \
        "STUB_IGNORE_REASON=blocked on #677 ... ok"
    # The substring is ARM-UNIQUE and THEN discriminating, in that order. Bare
    # bucket counts do distinguish this case from `base_ignored_with_renamed_rows`,
    # but they are rendered identically by the fall-through arm three lines below,
    # so gutting the base-ignored arm would leave both cases green. Optimising for
    # the distinction you are thinking about can destroy one you are not.
    run_case every_row_ignored_at_base 2 "so have no baseline verdict, alongside 0 base-only" \
        "STUB_R1_TESTS=replay_alpha:ignored replay_beta:ignored" \
        "STUB_R2_TESTS=replay_alpha:ignored replay_beta:ignored" \
        "STUB_R3_TESTS=replay_alpha:ignored replay_beta:ignored"

    # --- a branch defect must not be reported as a tool error -----------------
    # Exactly two rc-1 buckets skip COMPARABLE: SILENCED and ONLY_HEAD_FAILING. A
    # zero-comparable gate that stands down for the first and not the second
    # reports a branch defect as rc 2, "these two builds cannot be compared", which
    # routes the operator to change their base ref rather than fix the red test -
    # and the per-test table naming it is never printed, because every `die 2` in
    # that gate precedes the report block. Both routes into the bucket are pinned.
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
    # survived the whole case table, leaving the guard documented, correct, and
    # unwitnessed. The stub can express it: STUB_R1_TESTS and STUB_R2_TESTS are
    # independent, and these two cases use that.
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
    # Both guards below are CORRECT in the driver and structurally unwitnessable
    # without these cases: a mutation probe over 20 single-guard mutants found
    # exactly two that survive the whole case table AND fail OPEN when removed,
    # i.e. yield `OK` at rc 0. These are those two. The other eight survivors fail
    # closed and deliberately get no case, because a case per unwitnessed guard is
    # not the goal - a case per guard whose absence produces a false clean is.
    run_case wt_status_cannot_answer 2 "refusing to treat 'git could not say'" \
        STUB_PRECREATE_WT=1 STUB_GIT_STATUS_RC=128
    run_case tree_diff_cannot_answer 2 "refusing to assume they differ" \
        STUB_GIT_DIFF_RC=128

    # --- a zero-comparable diagnostic must name every bucket it holds ---------
    # The gate has three messages, and the rule "every bucket is named, so the
    # reader is never handed a count that contradicts the sentence around it"
    # applies to all three, not just the fall-through arm. Both arms exercised here
    # fire with base-only and HEAD-only rows present, so each must name them; and
    # neither may end with "that is a property of <base>, not of this branch" when
    # the branch's own rename is what emptied the comparable set.
    run_case unattributable_with_renamed_rows 2 "UNATTRIBUTABLE (the base was already red" \
        "STUB_R1_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R2_TESTS=replay_alpha:FAILED replay_beta:ok" \
        "STUB_R3_TESTS=replay_alpha:FAILED replay_gamma:ok"
    run_case base_ignored_with_renamed_rows 2 "so have no baseline verdict, alongside 1 base-only" \
        "STUB_R1_TESTS=replay_alpha:ignored replay_beta:ok" \
        "STUB_R2_TESTS=replay_alpha:ignored replay_beta:ok" \
        "STUB_R3_TESTS=replay_alpha:ignored replay_gamma:ok"

    # --- absent-at-HEAD wins over the R1 column, which the table says ---------
    # The classification loop tests `R3` absence FIRST, so a row that is FAILED or
    # #[ignore]d at the base and is gone at HEAD is base-only, NOT unattributable
    # and NOT ignored-at-base. These two pin the precedence so the table cannot
    # drift.
    run_case failed_at_base_and_removed_at_head 0 "base-only (removed at HEAD)" \
        "STUB_R1_TESTS=replay_alpha:ok replay_beta:FAILED" \
        "STUB_R2_TESTS=replay_alpha:ok replay_beta:FAILED" \
        "STUB_R3_TESTS=replay_alpha:ok"
    run_case ignored_at_base_and_removed_at_head 0 "base-only (removed at HEAD)" \
        "STUB_R1_TESTS=replay_alpha:ok replay_beta:ignored" \
        "STUB_R2_TESTS=replay_alpha:ok replay_beta:ignored" \
        "STUB_R3_TESTS=replay_alpha:ok"

    # --- a test ADDED already parked gets its own label, at rc 0 ---------------
    # A label shared with a passing addition would assert the same thing about a
    # test that ran and one that did not. RULING: rc 0 rather than rc 1, because
    # adding a parked pin for a known-open bug is this repo's documented convention
    # (#669/#677), unlike silencing a test that WAS running.
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
    # one of them. Only those two cells discriminate; without them a guard pointed
    # at the wrong operand passes every case in this file.

    # 1. Both agree the sources are the same. Refuse.
    run_case worktree_matches_base_is_refused 2 "there is nothing to vary" \
        STUB_WORKTREE_MATCHES_BASE=1 STUB_TREES_IDENTICAL=1
    # 2. DISAGREE: the commits differ, the working tree does not. This is this
    # instrument's own documented use case: `git checkout <base> -- crates/` is how
    # an operator asks "would my new corpus really have caught the old code?", and
    # an in-flight `git stash` has the same shape. Both leave the tree
    # byte-identical to the base while the two COMMITS still differ, so a two-ref
    # guard stands down and the driver compares a tree with itself, printing OK at
    # rc 0.
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
    # warns about.
    run_case untracked_only_is_still_refused 2 "there is nothing to vary" \
        STUB_WORKTREE_MATCHES_BASE=1 STUB_TREE_UNTRACKED=1

    # --- the cached base worktree must BE the base ---------------------------
    # Directory existence alone is not a sufficient reuse predicate: without the
    # cache validation the report keeps printing `base=<sha>` and all three of
    # these inputs come back rc 0.
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
    # single-cause remedy would split; the driver's guard is deliberately agnostic
    # about HOW either bit was set, and both cases pin that.
    #
    # It is NOT agnostic about which BITS it reads.
    # `ls-files` exposes assume-unchanged under `-v` and fsmonitor-clean under
    # `-f`; there are three suppression bits, not two. The third is handled by the
    # `-c core.fsmonitor=` pin on the status call, witnessed separately by
    # `config_hides_a_modified_tracked_file`.
    run_case cached_worktree_index_assume_unchanged 2 "assume-unchanged or skip-worktree" \
        STUB_PRECREATE_WT=1 STUB_WT_SUPPRESSED=assume
    run_case cached_worktree_index_skip_worktree 2 "assume-unchanged or skip-worktree" \
        STUB_PRECREATE_WT=1 STUB_WT_SUPPRESSED=skip
    # Its rc guard, the same shape as `cached_worktree_index_assume_unchanged` and
    # `cached_worktree_index_skip_worktree`.
    run_case wt_lsfiles_cannot_answer 2 "git can see this tree" \
        STUB_PRECREATE_WT=1 STUB_GIT_LSFILES_RC=128
    # AND ITS VACUITY GUARD, which is the one this guard could most easily have
    # got wrong: a suppressed-entry COUNT over a zero-line answer is zero, so
    # without it the new check would report "nothing is suppressed" on a worktree
    # where nothing was examined - re-creating, inside the fix, the exact shape the
    # fix exists to close.
    run_case wt_lsfiles_reports_no_tracked_files 2 "no tracked files at all" \
        STUB_PRECREATE_WT=1 STUB_WT_LSFILES_EMPTY=1
    # AN UNDER-REPORTING `core.fsmonitor`, the fourth suppressor and the one the
    # index-flag guard above cannot see: `ls-files -v` reports `H` for an
    # fsmonitor-clean entry, so only the `-c core.fsmonitor=` pin on the status
    # call catches this. Measured on git 2.55.0 with a v2 hook returning an empty
    # change list: contaminated tree, plain status ZERO BYTES rc 0; same tree with
    # the pin, ` M src/f3.rs`.
    run_case config_hides_a_modified_tracked_file 2 "has uncommitted changes" \
        STUB_PRECREATE_WT=1 STUB_WT_DIRTY=1 STUB_GIT_FSMONITOR=1
    # THE CONTENT CHECK, which is the guard that retires the pattern the three
    # cases above are instances of. It compares the worktree against the index by
    # HASH, so it does not care which config setting silenced `git status`.
    #
    # Note this case sets NO suppression knob at all: the point is that the answer
    # does not depend on one. Measured on git 2.55.0 against all four known
    # suppressors, this check reports the contamination in every case and reports
    # nothing on a clean tree in every case.
    run_case cached_worktree_content_differs_from_index 2 "CONTENT differs from its index" \
        STUB_PRECREATE_WT=1 STUB_WT_CONTENT_DIRTY=1
    # It could not answer.
    run_case wt_hash_object_cannot_answer 2 "could not hash the cached base" \
        STUB_PRECREATE_WT=1 STUB_GIT_HASHOBJ_RC=128
    # IT ANSWERED SHORT, which is the failure mode that produces a confident wrong
    # comparison rather than an error: `paste` joins a truncated hash list against
    # the full name list and every downstream row is garbage. This is not a
    # hypothetical - it happened while measuring the remedy, and only a clean-tree
    # control caught it.
    run_case wt_hash_object_answered_short 2 "the comparison would be meaningless" \
        STUB_PRECREATE_WT=1 STUB_HASH_SHORT=1
    # NON-BLOB INDEX ENTRIES, refused rather than hashed or skipped. SKIPPING
    # gitlinks drops them from both lists, which is precisely what stops the count
    # guard catching them; and HASHING a tracked symlink makes the check `die 2` on
    # a pristine tree on every run.
    run_case cached_worktree_has_a_tracked_symlink 2 "not regular files" \
        STUB_PRECREATE_WT=1 STUB_WT_NONBLOB=symlink
    run_case cached_worktree_has_a_submodule 2 "not regular files" \
        STUB_PRECREATE_WT=1 STUB_WT_NONBLOB=gitlink
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

# PASS 1 RUNS THE WHOLE TABLE, asserted rather than assumed.
#
# Before case selection existed this was structural: `run_all_cases` had no way
# to run a subset. It is now a property of CASE_FILTER being empty here, and a
# pass 1 that silently ran five of the cases would still print a plausible
# "N cases passed" line and exit 0, which is this project's "nothing fired reads
# the same as nothing ran" defect.
#
# Asserted as an INVARIANT and not as a count: the case total drifts with every
# commit that adds one, and a pinned numeral quoted as current is its own defect
# class. The `PASS -eq 0` guard below catches only the total wipeout.
if [ -n "${CASE_FILTER}" ]; then
    echo "SUITE ERROR: pass 1 ran with a case filter set; it must exercise the whole table" >&2
    exit 2
fi
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
    #    below, and it has already fired for real, when a rework moved a seeded
    #    source line.
    # 2. `sed` ERRORED and wrote a truncated file. `cmp` sees a difference and is
    #    satisfied, but the seeded "driver" is a fragment that fails every case,
    #    so the control reports CAUGHT for reasons having nothing to do with the
    #    guard. Hit for real when a seed's `|` delimiter collided with the `|`
    #    inside `0 | 101` and sed died; the probe scored it a catch, and it is
    #    really a survivor.
    # 3. It inserted or deleted lines rather than substituting in place. Nothing
    #    here reasons about driver line numbers, so this is not a correctness
    #    hazard today; it is a cheap structural check that a seed did what a seed
    #    is supposed to do, and it is what catches case 2 above.
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
    CASES_RUN=""
    DRIVER_UNDER_TEST="${broken}"
    # A control asserts on two sets and nothing else: the cases its removed guard
    # must make fail, and the cases that guard cannot see, which must still pass.
    # Every other case is a no-op here, so it is not run.
    CASE_FILTER="${must_catch[*]} ${CONTROL_MUST_STILL_PASS[*]}"
    CONTROL_PHASE=1
    run_all_cases
    CONTROL_PHASE=0
    CASE_FILTER=""

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
    # sentinel guard fully intact makes every control in the suite report "caught"
    # and the suite exit 0, with `just instrument-test` unable to see it (the
    # control phase prints CAUGHT, not FAIL). That is this project's own
    # "positive-control any instrument you write" rule, left unapplied to the
    # controls themselves.
    #
    # Two cheap assertions close it: some cases must still PASS, and specifically
    # the ones the removed guard cannot see must still behave correctly.
    #
    # EVERY SELECTED NAME MUST NAME A REAL CASE, checked before either of them.
    #
    # A name the case table does not define breaks both assertions below, in
    # OPPOSITE directions. `must_catch` fails loudly but blames the wrong thing:
    # it reports "did not catch" for a case that never ran, indicting the driver
    # for a typo in this file. CONTROL_MUST_STILL_PASS asks only that a name be
    # absent from FAILED_CASES, which is trivially true of a case that does not
    # exist, so it passes. Only the second is a fail-open - renaming a case
    # silently retires its must-still-pass check - and selecting on these names
    # makes both load-bearing, so they are proven real here.
    local want got
    for want in "${must_catch[@]}" "${CONTROL_MUST_STILL_PASS[@]}"; do
        case " ${CASES_RUN} " in
        *" ${want} "*) ;;
        *)
            printf 'SUITE ERROR: positive control %s selected case %s, which did not run.\n' \
                "${label}" "${want}" >&2
            printf '             Either the case table does not define that name, or case selection\n' >&2
            printf '             is broken. A control can only assert on cases that ran, so this\n' >&2
            printf '             verdict certifies nothing either way.\n' >&2
            exit 2
            ;;
        esac
    done

    if [ "${PASS}" -eq 0 ]; then
        printf 'SUITE ERROR: positive control %s left ZERO cases passing.\n' "${label}" >&2
        printf '             A driver with one guard removed still classifies every input that\n' >&2
        printf '             guard does not see; zero passes means the seeded driver cannot run,\n' >&2
        printf '             so "caught" here certifies nothing.\n' >&2
        exit 2
    fi
    local still
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
# leaves the gate live and only the rc-1 bucket unprotected.
# shellcheck disable=SC2016
run_positive_control head_failing_beats_zero_comparable_removed \
    's|^    \[ "${#ONLY_HEAD_FAILING\[@\]}" -eq 0 \]; then|    true; then|' \
    unparked_failing_with_no_comparable_row added_failing_with_no_comparable_row

# The R1/R2 same-test-set guard, whose own comment names the false clean it
# prevents and which a mutation probe found surviving the whole case table.
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
# its default 1, so a lane whose replay tests are ALL `#[ignore]`d is refused at
# rc 2 ("its exit code and per-test table therefore mean nothing") about a table
# that is complete and meaningful - contradicting three specifications that
# promise rc 1 SILENCED. Seeded on the case arm rather than the `if`, so it is
# independent of `sentinel-guard-removed` above, which removes the guard outright.
#
# A seed keyed on a source line the driver later moves silently matches nothing.
# The control-of-the-control is what catches that ("edited nothing; its guard's
# source line moved"), which is the whole reason it exists.
# shellcheck disable=SC2016
run_positive_control all_parked_carveout_removed \
    's|ran_any=0 ;;|: ;;|' \
    every_row_silenced_at_head

# `ran_any` SOURCED FROM A PER-TEST ROW rather than from libtest's summary tally.
# That is the whole defect CLASS: any row-shaped derivation inherits the
# ambiguity of a reason string, because `#[ignore = "..."]` renders the reason into
# the same line as the verdict. The summary line cannot express that ambiguity, and
# this control is what pins the difference.
# shellcheck disable=SC2016
run_positive_control ran_any_read_from_rows \
    's|^    ran_tally="$(grep -m1 -E .*|    ran_tally="$(grep -m1 -E '"'"'^test '"'"' "${out}" \|\| true)"|' \
    every_row_silenced_with_a_dotted_reason

# A mutation probe found exactly two guards, of 20, that both survive the whole
# suite and fail OPEN when removed: gutting either yields `OK (0 regressions, 0
# discriminated)` at rc 0. They are **`wt_status_rc_guard_removed` and
# `tree_diff_catchall_removed`**, named here rather than pointed at, and both are
# correct in the driver but unwitnessable unless the stub `git` can express a
# status or a diff that FAILED, rather than only ones that answered.
#
# NAMED, NOT POSITIONAL. "The two controls immediately below" stops being true the
# moment anything is inserted between this paragraph and its subjects, and a
# reader following it downward then lands on the wrong control. Re-ordering only
# holds until the next insertion; a name does not move.
#
# `git failed` and `git answered, and the answer was discarded` are DIFFERENT
# shapes, and this paragraph's whole argument depends on the distinction.
# `wt_ignored_guard_removed` is not a `git failed` control: its case emits
# `!! .../docs/` and exits 0, so git ANSWERS and the guard's absence discards a
# non-empty answer, which makes it the twin of `cache-dirty-guard-removed`.
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
# `wt_vacuity_guards_removed` accepts a count taken over nothing.
#
# A name only beats a pointer if it is updated with the thing it names: renaming
# a control and leaving the dead name here undoes the whole reason for naming it.
# The vacuity property has TWO guards, so `wt_vacuity_guards_removed` seeds both;
# removing either alone is not a false clean.
# shellcheck disable=SC2016
run_positive_control wt_index_flag_guard_removed \
    's|^if \[ "${wt_suppressed}" -ne 0 \]; then|if false; then|' \
    cached_worktree_index_assume_unchanged cached_worktree_index_skip_worktree
# shellcheck disable=SC2016
run_positive_control wt_lsfiles_rc_guard_removed \
    's|^if \[ "${wt_lsfiles_rc}" -ne 0 \]; then|if false; then|' \
    wt_lsfiles_cannot_answer
# THE VACUITY DEFENCE, seeded as a WHOLE rather than one guard at a time, and the
# reason is a real result rather than a preference.
#
# The content check brings a SECOND vacuity guard for the same hazard: a count
# taken over a zero-line answer is zero, so an empty tracked-file list must never
# read as "nothing is wrong". With two guards for one property, removing either
# ALONE produces no false clean - the other catches it - so a single-guard seed is
# permanently unsatisfiable and the suite says so out loud ("positive control did
# not catch"), which is the control-of-the-control doing exactly its job.
#
# Standing ruling 3 would permit dropping the control entirely, since neither
# guard's absence alone is a false clean. Seeding both is strictly better: the
# PROPERTY is "this driver refuses a worktree with no tracked files", and that
# property now has two implementations. A control that removes all of them
# witnesses the property; one that removes half of them witnesses nothing.
# shellcheck disable=SC2016
run_positive_control wt_vacuity_guards_removed \
    's|^if \[ -z "${wt_lsfiles}" \]; then|if false; then|
     s|^if \[ ! -s "${WORK}/wt-names" \]; then|if false; then|' \
    wt_lsfiles_reports_no_tracked_files

# The `ls-files` call's QUESTION. The three controls above all seed the guard's
# LOGIC (`if false; then`); these two seed what it ASKS. Both weakenings were
# measured to survive the whole suite until the stub was taught to read its
# arguments.
#
# `-v` -> `-t` re-opens the assume-unchanged half only, so exactly ONE index case
# goes red - `cached_worktree_index_skip_worktree` correctly stays green, because
# `S` is in the base tag set and real `ls-files -t` still prints it.
# shellcheck disable=SC2016
run_positive_control wt_lsfiles_v_flag_unpinned \
    's|ls-files -v 2>|ls-files -t 2>|' \
    cached_worktree_index_assume_unchanged
# Scoping the call to the corpus discards the SOURCE-file case the guard exists
# for, so both index cases go red.
# shellcheck disable=SC2016
run_positive_control wt_lsfiles_scope_narrowed \
    's|ls-files -v 2>|ls-files -v -- "${CORPUS_SUBPATH}" 2>|' \
    cached_worktree_index_assume_unchanged cached_worktree_index_skip_worktree

# The `-c core.fsmonitor=` pin on the whole-tree status call. Only this one is
# controlled: the `--ignored` call is SCOPED to the corpus, so any ` M` row
# fsmonitor could hide from it is also hidden from this unscoped call, where the
# guard fires first. Its absence cannot produce a false clean, which is the bar
# standing ruling 3 sets, and modelling one would mean a transcript real git
# cannot emit.
# shellcheck disable=SC2016
run_positive_control wt_status_fsmonitor_unpinned \
    's|-c core.fsmonitor= status --porcelain -unormal|status --porcelain -unormal|' \
    config_hides_a_modified_tracked_file

# The CONTENT check and its two supporting refusals. The first is the guard that
# closes the config-suppression class; the other two are what stop it becoming a
# confident wrong answer.
#
# `wt_content_alignment_guard_removed` is the one worth keeping: without it a
# SHORT hash list is pasted against the full name list, and the comparison reports
# whatever the misalignment happens to produce. In the measured instance that was
# "every entry differs" on a clean tree, which is loud; the same bug can just as
# easily produce "nothing differs" on a dirty one, which is not.
# shellcheck disable=SC2016
run_positive_control wt_content_guard_removed \
    's|^if \[ -n "${wt_content_diff}" \]; then|if false; then|' \
    cached_worktree_content_differs_from_index
# shellcheck disable=SC2016
run_positive_control wt_hash_rc_guard_removed \
    's|^if \[ "${wt_hash_rc}" -ne 0 \]; then|if false; then|' \
    wt_hash_object_cannot_answer
# shellcheck disable=SC2016
run_positive_control wt_content_alignment_guard_removed \
    's|^if \[ "${wt_n_names}" -ne "${wt_n_hashes}" \]; then|if false; then|' \
    wt_hash_object_answered_short

# The non-blob refusal, seeded on BOTH cases because the guard is deliberately
# written as "not a known blob mode" rather than as a list of the two bad modes.
# One case would leave the driver free to be narrowed to the other.
# shellcheck disable=SC2016
run_positive_control wt_nonblob_guard_removed \
    's|^if \[ -n "${wt_nonblob}" \]; then|if false; then|' \
    cached_worktree_has_a_tracked_symlink cached_worktree_has_a_submodule

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

# Evidence retention on the DISCRIMINATED run. Narrowing to `rc -eq 0` alone
# deletes the logs for the one outcome the instrument exists to produce. A
# mutation probe found both this and the delete-always form leaving all cases
# green.
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

# The guard that stops the driver comparing something with itself. Without it, two
# builds of identical source produce a green `OK (0 regressions, 0 discriminated,
# ...)`.
#
# Seeded by neutering the COMPARISON rather than the `die`, because the whole
# guard is one `git diff` and its case arms: forcing rc 1 ("they differ") is
# exactly what a driver missing this guard would do.
# shellcheck disable=SC2016
run_positive_control nothing-to-vary-guard-removed \
    's|^git diff --quiet "${BASE_SHA}" -- crates/ Cargo.toml Cargo.lock 2>"${WORK}/tree-diff.err"$|false|' \
    worktree_matches_base_is_refused reverted_worktree_refused_though_commits_differ \
    untracked_only_is_still_refused

# shellcheck disable=SC2016
run_positive_control cache-sha-guard-removed \
    's|^if \[ "${wt_sha}" != "${BASE_SHA}" \]; then|if false; then|' \
    cached_worktree_at_wrong_sha cached_worktree_never_created_by_git

# The final rc-0 contract gate. A mutant that neuters it leaves every case passing
# when the only case NAMED for it exits earlier on the head-only gate and never
# reaches it. That is the failure this whole file exists to prevent.
# shellcheck disable=SC2016
run_positive_control rc-zero-contract-gate-removed \
    's|^if \[ "${SCEN\[3\]}" -eq 0 \]; then|if false; then|' \
    rc_zero_contract_refuses_zero_count

# shellcheck disable=SC2016
run_positive_control cache-dirty-guard-removed \
    's|^if \[ -n "${wt_dirty}" \]; then|if false; then|' \
    cached_worktree_is_dirty cached_worktree_has_untracked_corpus_file

exit 0
