#!/usr/bin/env bash
# scripts/check-doc-citations.sh - CI gate (doc-truth: file:line citations)
#
# WHY: a comment citing `foo.rs:123` is a claim about the tree that decays silently.
# An INSERTION anywhere above the target invalidates it without touching the comment,
# so it survives fmt, clippy, the test suite, the mutation gate and code review.
# The tree carries these citations in the hundreds and a standing minority of them are
# provably dead at any given moment. The live counts are NOT repeated here: run
# `bash scripts/check-doc-citations.sh` and read its own summary line, which is derived
# rather than remembered.
#
# NOTE ON WIRING, since it is easy to assume otherwise: this guard is NOT part of
# `just ci`. The only reference to it in the justfile or any workflow is the
# `instrument-test` loop, which runs its SELF-TEST (`check-doc-citations-test.sh`), not
# the guard against this tree. It exits 1 on the current backlog, so wiring it into
# `just ci` is gated on that cleanup landing.
#
# That is a deliberate correction, not a stylistic one. This header used to state
# "220 such citations, 36 of them provably dead", measured 2026-07-31; the same script
# unmodified reported 246/42 one day later (#642). A doc-truth instrument whose own
# header had decayed into a false claim is the exact defect it exists to catch, and the
# stale figure had already been quoted downstream as the measured basis for a rule
# change. CLAUDE.md's Project Context took the same fix for the same reason, after a
# pinned version rotted from v0.1 through v0.7 unnoticed in always-loaded context.
#
# The worked example is timestamped and stays, because a dated anecdote does not decay
# the way a live count does: `fn color_enabled`'s citation was correct for five days,
# was falsified twice in 18 hours by insertions 300 lines away that never touched the
# comment, and was repaired 26 minutes after the last move - every gate green and blind
# throughout.
#
# WHAT IT CHECKS (only what cannot be argued with):
#   DEAD-FILE      - the cited path matches no tracked file.
#   OUT-OF-RANGE   - the cited path resolves uniquely but the line is past its EOF.
#   AMBIGUOUS      - the cited path matches 2+ tracked files and no same-crate
#                    candidate is unique. Reported as a WARNING by default; promote
#                    to a violation with STRICT=1.
#   UNWITNESSED-CLAIM - a comment asserting a TEST/MUTANT relationship ("goes RED",
#                    "kills the mutant", "fails if X removed", "the mutant survives",
#                    "is killed by") with no `verified: <sha-or-date>` on the claim
#                    line or the next three. The phrase list is measured; see the
#                    note at CLAIM for what was excluded and why.
# It does NOT check that the cited line says what the comment claims. That is not
# mechanically decidable and is the reviewer's job (see the doc-truth axis in
# .claude/agents/spec-reviewer.md).
#
# UNWITNESSED-CLAIM is a deliberately WEAKER check than the other three, and the
# header says so rather than letting the name imply more. `verified:` is an ACK
# SENTINEL: it proves a human typed it, not that anyone ran the mutant. The gate
# cannot tell the difference and does not pretend to. What it buys is that the
# claim and its evidence date sit together, so a reviewer can see a claim written
# in March carrying a January date, and that writing one costs a deliberate act.
#
# It exists because this class of comment is BOTH mechanically decidable and
# routinely written from reasoning instead of from a run. On the branch that
# prompted it, three comments asserting test/mutant relationships had been
# falsified by that same branch's own later commits, and every gate stayed green
# throughout: a false comment passes fmt, clippy, the test suite and the mutation
# gate alike.
#
# ESCAPE for this class specifically: `claim-exempt: <reason>` on the claim line.
# Separate from `doc-citation-exempt:` on purpose - a marker whose name says
# "citation" being used to wave through a mutant claim would itself be the
# doc-truth defect this gate is about.
#
# ESCAPE HATCH: put `old`, `former`, `previously` or `pre-<sha>` in the ONE OR TWO
# tokens immediately before the citation ("the old foo.rs:12"), or put
# `doc-citation-exempt: <reason>` anywhere on the line. Deliberately citing a deleted
# file as history is legitimate; the marker makes it reviewable. The positional
# restriction on the word-list is deliberate: matched anywhere on the line, a comment
# mentioning the old anything exempts every citation on it.
#
# Exit: 0 clean, 1 violation, 2 the instrument could not run (no tracked files, or
# zero citations scanned - either means it checked nothing and must not report clean).
set -uo pipefail
# Resolved to an ABSOLUTE path. The same string is later handed to `git ls-files`
# as cwd and to os.path.join, so a relative argument would resolve a second time
# against the already-changed cwd and raise FileNotFoundError. Python exits 1 on
# an uncaught traceback, and rc 1 in this repo's table means "violation" - a tool
# error reported as a finding.
root="$(cd "${1:-$PWD}" 2>/dev/null && pwd)" || {
    echo "check-doc-citations: cannot enter '${1:-$PWD}'" >&2
    exit 2
}
cd "$root" || exit 2

python3 - "$root" <<'PY'
import subprocess, sys, re, os
root = sys.argv[1]
tracked = subprocess.run(['git','ls-files'],capture_output=True,text=True,cwd=root).stdout.split()
if not tracked:
    print('check-doc-citations: git ls-files returned nothing; instrument failed, not a pass', file=sys.stderr)
    sys.exit(2)
rs = [p for p in tracked if p.endswith('.rs')]
cite = re.compile(r'\b([A-Za-z0-9_./-]+\.rs):(\d+)(?:-(\d+))?')
# Historical-reference words only count BEFORE the citation ("the old foo.rs:12"), but
# `doc-citation-exempt:` counts anywhere on the line: it is a deliberate marker and
# requiring it to precede the citation makes the documented escape hatch not work.
EXEMPT_PREFIX = re.compile(r'\b(old|former|previously|pre-[0-9a-f]{7})\b', re.I)
EXEMPT_LINE = re.compile(r'doc-citation-exempt:', re.I)
# Class 2, UNWITNESSED-CLAIM. A comment asserting a TEST/MUTANT relationship is a
# claim about behaviour that is MECHANICALLY DECIDABLE - delete the guard in a
# scratch worktree, run the named test, see whether it goes red - and the 9o
# retrospective's finding is that these were written from reasoning rather than
# from a run, then cited downstream as evidence. Three of that branch's comments
# had been falsified by its own later commits.
# The phrase list is MEASURED, not guessed. A bare `pins (the|this)` was the first
# cut and it matched 204 lines in 89 files, almost all of them ordinary prose about
# semantics ("the Eq value pins the field", "pins the b32 selector") rather than any
# claim about a test. At 204 against the 42 violations the other three classes find,
# the new class would have been 83% of the report and would have buried them. The
# list below matches 14 lines in 13 files, and all 14 were read: every one is a
# genuine test/mutant relationship claim, none is prose.
#
# So `pins` is deliberately absent even though it is the verb this codebase reaches
# for most. It is absent BECAUSE it is that verb: it describes what a value or a
# guard does far more often than what a test does.
CLAIM = re.compile(
    r'goes RED|kills (this|that|the) mutant|fails if .* (removed|deleted)'
    r'|mutant .{0,30}surviv|is killed by', re.I)
VERIFIED = re.compile(r'verified:\s*\S')
CLAIM_EXEMPT = re.compile(r'claim-exempt:', re.I)
lens = {}
def nlines(p):
    if p not in lens:
        with open(os.path.join(root,p),'rb') as fh: lens[p] = sum(1 for _ in fh)
    return lens[p]

viol = warn = scanned = claims = 0
for p in rs:
    with open(os.path.join(root,p),encoding='utf-8',errors='replace') as fh:
        # Materialised rather than streamed: class 2 needs a 3-line LOOKAHEAD, and
        # the `for` below stays at this indent deliberately so the self-test's
        # positive-control sed anchors keep matching.
        flines = fh.readlines()
        for i, line in enumerate(flines, 1):
            s = line.strip()
            if not s.startswith(('//','*','/*')): continue
            if CLAIM.search(line):
                # Counted BEFORE the exemption check, for the same reason `scanned`
                # is: excluding exempted claims lets a file whose claims are all
                # exempt trip the vacuity guard and report a tool error.
                claims += 1
                if not CLAIM_EXEMPT.search(line):
                    # The marker may sit on the claim line itself or within the
                    # next three. Anything wider stops being "next to the claim"
                    # and starts matching an unrelated marker further down.
                    if not VERIFIED.search(''.join(flines[i-1:i+3])):
                        print(f'{p}:{i}: UNWITNESSED-CLAIM `{s[:60]}` (no `verified: <sha-or-date>` within 3 lines)')
                        viol += 1
            for m in cite.finditer(line):
                # Counted BEFORE the exemption checks. An exempted citation was
                # still scanned; excluding it from the count lets a tree whose
                # citations are all exempt trip the zero-scanned vacuity guard
                # and report a tool error instead of a pass.
                scanned += 1
                if EXEMPT_LINE.search(line): continue
                # Only the two tokens IMMEDIATELY before the citation, not the
                # whole prefix. The documented hatch is "prefix the citation
                # with old/former/...", and searching the entire left side means
                # `// the old parser is gone; see live.rs:9999` silently exempts
                # a citation the sentence is not talking about.
                if EXEMPT_PREFIX.search(' '.join(line[:m.start()].split()[-2:])): continue
                ref = m.group(1); hi = max(int(m.group(2)), int(m.group(3) or m.group(2)))
                c = [x for x in tracked if x == ref or x.endswith('/'+ref)]
                if not c:
                    print(f'{p}:{i}: DEAD-FILE citation `{m.group(0)}` (no tracked file matches `{ref}`)')
                    viol += 1; continue
                if len(c) > 1:
                    parts = p.split('/')
                    same = [x for x in c if len(parts) > 1 and x.startswith(parts[0]+'/'+parts[1]+'/')]
                    if len(same) != 1:
                        print(f'{p}:{i}: AMBIGUOUS citation `{m.group(0)}` matches {len(c)} files; qualify the path')
                        warn += 1; continue
                    c = same
                if hi > nlines(c[0]):
                    print(f'{p}:{i}: OUT-OF-RANGE citation `{m.group(0)}` -> {c[0]} has {nlines(c[0])} lines')
                    viol += 1

if scanned == 0 and claims == 0:
    print('check-doc-citations: scanned 0 citations and 0 witnessed-claim comments; instrument failed, not a pass', file=sys.stderr)
    sys.exit(2)
print(f'check-doc-citations: {scanned} citations scanned, {claims} claims scanned, {viol} violations, {warn} ambiguous', file=sys.stderr)
if os.environ.get('STRICT') == '1': viol += warn
sys.exit(1 if viol else 0)
PY
