# OpenWolf

@.wolf/OPENWOLF.md

This project uses OpenWolf for context management. Read and follow .wolf/OPENWOLF.md every session. Check .wolf/cerebrum.md before generating code. Check .wolf/anatomy.md before reading files.


# RTK (Rust Token Killer) - Token-Optimized Commands

@.rtk/RTK.md


# Build / Test / Lint Commands

Canonical commands live in the `justfile` (each recipe mirrors a CI gate verbatim). `just --list` shows all.

- `just ci` - full local gate in CI order: fmt + clippy + dac-guard + codes-guard + no-mnt-guard + capture-guard + instrument-test + tools-gate + test + cov. Run before every push. (`instrument-test` runs every gate script's own self-test; `tools-gate` builds the workspace-EXCLUDED `tools/*` crates with `--locked`, which `just ci` otherwise never touches.)
- `just fmt` / `just fmt-fix` - `cargo fmt --all --check` / apply. clippy does NOT enforce formatting; fmt is a separate gate.
- `just clippy` - `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- `just test` / `just cov` - workspace tests / llvm-cov with the 80% line floor.
- `just musl` - static `x86_64-unknown-linux-musl` release binary (the distribution target).

Prefix noisy commands with `rtk`; use `rtk proxy <cmd>` when output is parsed by another tool (a diff fed to `cargo mutants --in-diff`, JSON fed to `jq`).

## Additional cargo tooling installed (use when relevant)

Beyond the `just` recipes above, these cargo subcommands are on PATH. They are
not part of the standard `just ci` gate; reach for them for the specific job:

- `cargo-nextest` - faster local test runner (`cargo nextest run`). Good for quick
  iteration, but the CI gate runs `cargo test` via `just test`, so match that
  before pushing.
- `cargo-deny` - dependency advisories + license/ban policy (`cargo deny check`).
  Complements `cargo audit`; run before a dependency change.
- `cargo-insta` - snapshot-test review (`cargo insta review`) for `.snap` fixtures.
- `cargo-about` - SPDX license attribution; relevant to the `-license` crate and
  distribution attribution.
- `cargo-cyclonedx` / `cargo-auditable` - SBOM generation and embedded dependency
  audit metadata for the release binary / supply-chain.
- `cargo-fuzz` - fuzz targets for correctness work.
- `cargo-generate-rpm` - RPM packaging of the release binary (a distribution
  option alongside the musl static binary).

Run noisy invocations through `rtk` (generic passthrough); use `rtk proxy <cmd>`
when the output feeds another tool.

## Differential verification (dev-only)

**Corpora and harnesses live IN GIT, never under `/mnt`.** This is enforced
mechanically by `just no-mnt-guard` (`scripts/check-no-mnt-paths.sh`), which fails
on any `/mnt/` path in executable position. The rule exists because the wave3
fapolicyd corpus lived at an absolute `/mnt` path, was destroyed in the 2026-07-13
NFS rebuild (#572), and `just diff-fapolicyd` then exited 0 with a skip message on
every run: reporting success while checking nothing.

Every differential is built in two tiers, and **only the live tier may skip**:

- **OFFLINE (the gate).** A Rust integration test replaying a committed corpus of
  `(input, recorded-oracle-verdict)` against the lint engine. No docker, no root,
  no tool on PATH, so there is no skip path at all. Runs in `just test` / `just ci`
  and in every CI EL container. Model: `crates/rulesteward-selinux/tests/selinux_corpus_oracle.rs`.
- **LIVE (opt-in).** Re-derives the oracle from the real subsystem and fails on
  drift. Model: `just diff-sshd` + `tools/sshd-probe-update`.

A missing docker daemon therefore degrades the guarantee from "nothing was checked"
to "the oracle was not re-derived". Harness exit codes: `0` clean (and the success
line MUST carry a non-zero count), `1` drift, `2` tool error, `3` precondition
unmet. See CONTRIBUTING "Differential oracle contract".

| backend | live oracle | status |
|---|---|---|
| fapolicyd | `fagenrules --load` + `fapolicyd --debug --permissive` in `fapolicyd8/9/10` | corpus pending (session 9k-2, #572) |
| selinux | `checkmodule -M -m` compile oracle; libsepol vs vendored binary policies | corpus in git; CI wiring in this session |
| sshd | `sshd -G` / `ssh -Q` probes in `sshd-probe8/9/10` | shipped (`just diff-sshd`) |
| auditd | `auditctl -R`, one rule line per invocation, in `rs-oracle8/9/10`; rc gates, stderr discriminates | `just diff-auditd` (session 9k-1) |
| sysctld | `systemd-sysctl` `--cat-config` + `SYSTEMD_LOG_LEVEL=debug` apply, in `rs-oracle8/9/10` | `just diff-sysctld` (session 9k-1) |
| sudoers | `visudo -c -f -` (+ `-s`) and `cvtsudoers -f json` (+ `-e`), all on stdin, in `rs-oracle8/9/10` | `just diff-sudoers` (session 9k-1) |

The three `rs-oracle{8,9,10}` images are built from committed Dockerfiles in
`tools/oracle-images/` and carry all three oracles; see that README for the build
command, the measured version triple, and the Lane A netlink safety rules.

**Measured auditd oracle facts (2026-07-25), so no later session re-derives them:**
- **`--cap-add=AUDIT_CONTROL` is required, and `auditctl -s` is the mandatory
  canary.** Audit netlink is NOT namespaced, so a container that can reach it
  mutates the HOST ruleset. Never `--privileged`, never `--network host`, never
  `-v /:/host`. The canary is a status READ with zero blast radius: if it SUCCEEDS,
  netlink is live and the capture must refuse with **rc 2**, never rc 3. rc 3 means
  "precondition unmet, a legitimate skip" (CONTRIBUTING "Exit codes"), and
  `rs-oracle-diff.sh` honours it as a skip on any box without `RS_ORACLE_REQUIRED=1`.
  Encoding a host-mutation safety abort as rc 3 would convert a fail-closed stop into
  a silent pass. rc 2 is a tool/environment error and is never promoted to a skip.
- Without the capability `auditctl` bails BEFORE parsing, so a valid and an invalid
  rule are byte-identical (`rc 4`, `You must be root to run this program.`). With
  it, the canary still gets EPERM and a valid rule's add is refused with
  `Error sending add rule data request (Operation not permitted)` - nothing reaches
  the host kernel.
- **rc gates, stderr discriminates.** rc 4 = never ran (UNUSABLE); rc 0 = the rule
  LOADED, so netlink is live (ABORT); rc 1 = ran, and then stderr decides:
  `Error sending add rule data request` means it PARSED (ACCEPT), a parse complaint
  means REJECT.
- **`-R` swallows many parse diagnostics.** Fed via `-R`, both `-p zz` and a garbage
  line give rc 1 with empty stdout AND stderr on all three EL majors, while
  `-F perm=zz` and `-F nosuchfield=1` do emit complaints. The same `-p zz` passed
  DIRECTLY does print `Permission z isn't supported`, which is how #601's truth
  table was recorded - so `-p zz` cannot be the reject-side positive control under
  `-R`. Use `-F nosuchfield=1`, which is the `control-reject` scenario
  `capture_auditd.sh` actually ships. `-F perm=zz` was the original choice and had to
  move off: a positive control must not double as a product-divergence row, and
  RuleSteward's own parser accepted `perm=zz` at the time, so a broken control and a
  real XFAIL were indistinguishable. It survives as its own grounding scenario
  (`f-perm-invalid-letter`), which both sides now reject; it is not the control.
- `-R` is still the correct oracle: a rules FILE reaches the kernel via
  `augenrules` -> `auditctl -R` -> `audit_strsplit` (splits only on the literal
  space byte, quotes are literal), and that raw reader IS the subject of #584.
  Direct argv invocation would exercise shell tokenization instead.

**Measured sysctld oracle facts (2026-07-25):**
- **`systemd-sysctl` has NO `--root`** on el8/el9/el10 (`--help` lists only
  `--cat-config`, `--prefix=PATH`, `--no-pager`; el10 adds `--tldr`). The fixture
  tree must therefore BE the container's `/`, via one throwaway
  `docker run --rm --network=none` per scenario.
- **`--cat-config` is a byte-cat** and cannot observe key grammar at all, and it
  DISAGREES with the real applier on degenerate entries (it aborts on a
  `.conf`-named directory or a dangling symlink where the applier logs and
  continues). RuleSteward models the applier, so `SYSTEMD_LOG_LEVEL=debug` apply
  mode is authoritative for masking / read-order / merge / grammar, and
  `--cat-config` only for file bytes and the filesystem-determined rc.
- Apply mode WRITES, so the capture must assert `/proc/sys` is mounted `ro` and
  refuse `--privileged` / `--network=host`.

**Measured fapolicyd daemon facts (2026-07-25), so no later session re-derives them:**
- ACCEPT iff a `Loaded N rules` line appears. `fapolicyd-cli --check-rules` does NOT
  exist on any shipping RHEL (a v1.5+ upstream feature, absent from 1.3.2 and
  1.4.5), so the daemon itself is the only rule-syntax oracle.
- **The exit code is useless**: the unprivileged teardown exits 1 on accept and
  reject alike.
- **fapolicyd 1.3.2 (el8) emits no `[ LEVEL ]` tags at all**, so `grep ERROR` is
  inert there. Only `Loaded N rules` is portable across 1.3.2 and 1.4.5.
- An empty ruleset is a **third** outcome (`No rules in file - exiting`), neither an
  accept nor a parse-reject. A two-valued gate mislabels it.


# MCP Servers - tool-augmented lookups

Prefer these over training-recall or hand-rolled `gh`/`curl` sequences (see also
`~/.claude/rules/skills-plugins-mcp.md`). These are developer-machine plugins
(`enabledPlugins`), not a committed repo `.mcp.json` - this is by design (#288;
see the Parallel Development Protocol section for the rationale). Schemas load on
demand via `ToolSearch`.

- `cratesio` - crates.io registry. Reach for it BEFORE adding or bumping a
  dependency: `search_crates`, `get_crate_info` / `get_crate_features`,
  `compare_crates` / `find_alternatives`, `crate_health_check`,
  `audit_dependencies` (OSV.dev advisories), `get_dependency_tree`. Authoritative
  for crate metadata; pairs with the locked-crates list in Project Context.
- `docsrs` - Rust API docs from docs.rs (`search_crate`, `lookup_crate_items`,
  `lookup_item`, `lookup_impl_block`). Use for exact dependency API shapes
  (chumsky, ariadne, heed, clap, jsonwebtoken) instead of guessing signatures.
- `context7` - broader library / framework / CLI docs (`resolve-library-id` then
  `query-docs`). docsrs is sharper for Rust crates; context7 for cross-ecosystem.
- `serena` - Rust symbol navigation / LSP-backed find-symbol, references, and
  symbol-scoped edits.
- `github` - GitHub issue / PR / release operations. Prefer over the `gh` CLI for
  GitHub ops (issue read/write, pull_request_read, create/merge PR, list_issues);
  plain `git` and `rtk gh` stay fine for local and read-only use.
  **Always pass `owner: "rulesteward"`, `repo: "rulesteward"` explicitly.** Do not
  infer the owner from `get_me`, which returns the account name (`ErstBlack`): 12 of
  53 GitHub MCP calls in the 2026-07-17..31 window passed the account as owner and all
  12 returned 404. Those failures are why the `gh` CLI displaced the MCP 210 calls to
  53, against a standing preference for the MCP.
- `claude-mem` (mcp-search) - cross-session memory / search. Use to recall prior
  sessions' decisions and findings before re-deriving them.


# Superpowers - Development Skills

Make use of /superpowers skills whenever feasible.

- /brainstorming
- /writing-plans
- /subagent-driven-development
- /executing-plans
- /systematic-debugging
- /finishing-a-development-branch
- /dispatching-parallel-agents
- /using-git-worktrees
- /verification-before-completion
- /test-driven-development
- /requesting-code-review
- /receiving-code-review
- /writing-skills

# Global Rules - All of these rules MUST be followed at all times.

- If two rules ever conflict, ask the user to resolve.
- If a rule would lead to poor quality code, ask the user to resolve.
- Always ask questions rather than make assumptions.
    - Questions are encouraged. Ask in as many rounds as necessary; do NOT truncate to the AskUserQuestion tool's 4-question maximum. Batch what fits, then open another round for the rest until everything ambiguous is resolved.
- Use skill, plugins, and mcp servers when feasible.
- "Do one thing and do it well." Unix Philosophy.
    - Functions, modules, etc. should ideally do one thing and be reusable where needed, rather than sprawling out and overlapping.
- Small, modular services are better than monoliths.
    - Interfaces/Abstractions should be used to separate the signature from the implementation.
- "Keep it simple, stupid." K.I.S.S.
    - Don't overengineer things when there isn't a reason.
- Run now, optimize later.
    - Unless there are shown/known bottlenecks, a simpler and less performant implementation should be preferred to one that is incredibly complicated yet faster.
- When building something, first check if there is an existing, license compliant, tool that can handle the same functionality.  We don't need to reinvent the wheel if someone else already built it for us.
- Suggest when to compact a session or begin a new one to prevent context bloat/minimize hallucinations/keep things focused.
    - 10 small, focused sessions are better than 1 sprawling session, so long as things stay on track.
- When presenting options, always present a long form version of the question/comparions with pros, cons, and a recommendation.
- Make use of subagents when a clean context is needed for research.
- Tokens are cheap, rework isn't.
    - It's better to spend more time, context, and thinking than to implement something that needs to be constantly reworked in the future.

# Project Context - RuleSteward

- **Spec + research lives in `.private-docs/`** - a gitignored symlink to `/home/runner/rulesteward-docs/`. Not in the GitHub repo. Start every session by reading `.private-docs/rulesteward-cli-tool-spec.md` (the v0.2 spec) and any `handoff-session-N.md` for the current milestone.
- **Locked design decisions** are enumerated in spec §3 (19 of them). Do not re-litigate. If you find evidence contradicting one, surface it as `[QUESTION FOR USER]` and pause.
- **Status:** deliberately NOT hardcoded here. A pinned version and backend list sat in this line from v0.1 through v0.7 without anyone noticing, in a file loaded into every session. Read it from the repo instead: shipped version = newest `git tag`, working version = `[workspace.package] version` in `Cargo.toml`, live backend set = `ls crates/`. The active milestone tracker is issue #499.
- **Crate plan** (per spec §17.1): `rulesteward-core`, `-fapolicyd`, `-selinux`, `-auditd`, `-license`, `-sink`, `-cli`. Cargo workspace, `edition = "2024"`, `resolver = "3"`, MSRV `1.88` (workspace `rust-version`; dev/release stay on latest stable via `rust-toolchain.toml`).
- **Locked crates:** parser `chumsky = "0.13"` + `ariadne = "0.6"`; LMDB `heed = "0.22.1"`; CLI `clap = "4"` (derive); license (post-v0.1) `jsonwebtoken >= 10.3` with `rust_crypto`.
- **Distribution target:** `x86_64-unknown-linux-musl` static binary.
- **License:** Engine Apache-2.0; rule templates BSD-3-Clause (separate repo).
- **Commits are user-authored only. Never add `Co-Authored-By: Claude` or any AI-attribution trailer.** Branch + PR for every change; no commits to `main` directly.
- **No telemetry. Read-only by default.** Every write/mutation flag must be opt-in.

# Operating facts (measured 2026-07-17..31, session 9n retrospective)

Each of these cost real time or shipped a real defect. They are here because narrative
memory demonstrably failed to prevent the repeat.

- **Every fan-out dispatch prompt sets `TMPDIR=/mnt/side-projects/<session-id>/tmp`.**
  The per-UID `/tmp` tmpfs quota, not the filesystem, is what fills: `df` reports the
  filesystem and will look healthy while every shell dies. Exhaustion caused 80 of one
  session's 146 unique errors (55%), and the identical failure was already in the bug
  log from 17 days earlier under a mis-scoped title.
- **`dangerouslyDisableSandbox` is per-command, not per-session.** Set it only on the
  one call that needs it. Measured: after a single NFS-git diagnosis it was carried by
  123 of 348 main-loop Bash calls (35%), including `rm -rf` cleanups. More than a third
  of a session's calls carrying it means the allowlist needs fixing, not the flag.
- **Analyze, review, audit, advise, recommend and investigate are READ-ONLY verbs.**
  A task phrased with one of them does not authorize an edit. One "advise" task
  produced an unrequested `Edit` downgrading a third-party plugin's model tier; the
  only thing that stopped it was a permission prompt.
- **Fix-then-sweep.** No parser, reader or predicate defect closes its issue until a
  `git grep -n '<primitive>'` sweep of every call site is PASTED into the issue, with
  each site marked fixed, clean, or filed as #N. An issue closed without the pasted
  sweep gets reopened. 31 of 62 escaped defects in the window were the 2nd to 5th call
  site of a defect already fixed once.
- **Fidelity audit every second milestone.** Report-only, surface-scoped rather than
  diff-scoped, against a pinned SHA in a detached worktree with its own
  `CARGO_TARGET_DIR`, including a regression-census lane. One such audit was the sole
  first-finder of 16 of 62 escapes (26%), including the only Critical, which had been
  shipping for roughly 51 days. Skipping a scheduled one requires a recorded operator
  decision, not silence.

# Parallel Development Protocol + reusable artifacts

The project's parallel-development discipline is now captured as reusable artifacts
(built 2026-05-29). Note on where these live, because the previous wording was wrong in
a way that mattered: `.claude` is gitignored IN THIS REPO and is a symlink to
`/home/runner/rulesteward-docs/.claude`, so a fresh clone or CI run will not have the
artifacts below. They are NOT disposable local scratch, though - **24 of them are
git-tracked in the docs repo**. Editing `.claude/**` dirties a tracked working tree in
the OTHER repository and has to be committed there. The protocol doc lives in the same
docs tree. Load these when a milestone fans out 2+ independent features:

- **Protocol (frozen design):** `.private-docs/orchestration/parallel-orchestration-protocol.md`
  (in the gitignored docs tree). The source of truth for the barrier / HALT / Phase-0
  foundation / dedup / adversarial-test / model-tiering design.
- **Always-loaded rule:** `~/.claude/rules/parallel-orchestration.md` (global), with the
  `[ARCHITECTURE-HALT]` tier in `subagent-bubble-up.md` and the per-pipeline-vs-global
  skills mapping + mutation-adequacy gate in `engineering-chain.md`.
- **Session plans:** run `/rs-session-plan` to scaffold a new plan pre-wired to the
  protocol (do not hand-write the skeleton).
- **Reviewer subagents** (`.claude/agents/`): `spec-reviewer`, `idiomatic-rust-reviewer`,
  `adversarial-test-reviewer` (barrier, impl-BLIND), `adversarial-impl-reviewer`
  (post-GREEN, impl-AWARE). Each bakes in the bubble-up preamble and runs on `opus`.
- **Workflow binding:** `.claude/workflows/rs-milestone-fanout.js` (+ `README.md`) is the
  accelerator binding: `parallel()` barrier, then `pipeline()` runs impl -> Adversarial
  Testing Loop (impl-aware review + mutation gate) -> spec/idiomatic review, with a
  structured HALT early-return. The manual binding is always the floor.

**Adversarial Testing Loop (post-implementation):** after a feature first reaches GREEN
and before spec/idiomatic review, run the named loop: (1) an impl-AWARE adversarial
review (the `adversarial-impl-reviewer` agent reads the REAL impl + diff for an input the
frozen tests miss; distinct from the impl-BLIND barrier reviewer) and (2) the mutation
gate. Both route findings to the TEST-AUTHOR to STRENGTHEN tests (never weaken; the
implementer only makes them green); loop until both come up clean. Never trust a DONE
report (4a / PR #118: the gate caught a test-author over-claiming a kill twice, only the
mandatory RE-RUN surfaced it). Same step applies in single-pipeline work (same person may
author + impl).

**Mutation gate, two layers:** the per-pipeline LOCAL gate (`cargo mutants` after GREEN,
survivors route back to the test-author) is half of the Adversarial Testing Loop above and
the adversarial-adequacy measure during a milestone; the CI `mutants.yml` nightly run
remains the project-wide net. They are complementary, not redundant.

**MCP servers (context7, serena, cratesio, docsrs, github, claude-mem):** see the
`# MCP Servers` section above for when to reach for each. They back the "prefer
Context7/docsrs over training recall" guidance, Rust symbol navigation, crate
registry lookups, and GitHub ops. They are developer-machine plugins
(`enabledPlugins`), NOT a committed repo `.mcp.json` - this is by design (#288,
investigated and closed by-design). The fresh-clone plugin-sufficiency question was
investigated: `cratesio` and `docsrs` are platform built-ins (they survive a fresh
clone); `context7` / `serena` / `github` live in the machine-global plugin cache, not
the repo; `claude-mem` is path-dependent on the plugin cache and cannot be made
clone-sufficient via a repo file. A committed `.mcp.json` is intentionally NOT
provided: it could only cover `context7` (npx), `serena` (needs `uv` + network at
startup), and `github` (needs a `GITHUB_PERSONAL_ACCESS_TOKEN` env var) - none safe to
assume in CI or on a fresh contributor machine - so it would give false reassurance
rather than real clone-sufficiency.