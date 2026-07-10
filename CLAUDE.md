# OpenWolf

@.wolf/OPENWOLF.md

This project uses OpenWolf for context management. Read and follow .wolf/OPENWOLF.md every session. Check .wolf/cerebrum.md before generating code. Check .wolf/anatomy.md before reading files.


# RTK (Rust Token Killer) - Token-Optimized Commands

@.rtk/RTK.md


# Build / Test / Lint Commands

Canonical commands live in the `justfile` (each recipe mirrors a CI gate verbatim). `just --list` shows all.

- `just ci` - full local gate in CI order: fmt + clippy + dac-guard + test + cov. Run before every push.
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

## Differential verification (fapolicyd, dev-only)

The three prebuilt docker images `fapolicyd8`, `fapolicyd9`, `fapolicyd10` run
Rocky Linux 8/9/10 with fapolicyd pre-installed. Their Dockerfiles live in the
docs tree (`/home/runner/rulesteward-docs/`). The cross-version validation harness
lives at `/mnt/side-projects/fapolicyd-corpus/20260601T013116Z-wave3-combined/tools/validate.sh`
alongside the wave3 corpus (135 valid + 20 rejected scenarios). Run it via:
`just diff-fapolicyd /mnt/side-projects/fapolicyd-corpus/20260601T013116Z-wave3-combined 'adversarial/*'`
(override the harness path: `just validate_sh=/other/path diff-fapolicyd /corpus 'glob/*'`).
The recipe skips gracefully with a clear message if docker, the images, or validate.sh
are absent. Note: `fapolicyd-cli --check-rules` does NOT exist on any shipping RHEL
image (it is a v1.5+ upstream feature absent from RHEL 1.3.2 and 1.4.5); the harness
uses `fapolicyd --debug --permissive` as the ground-truth parse gate instead.


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
- **Status:** `v0.1.0` shipped 2026-06-02; now targeting **v0.2** (the active spec). Implemented crates: `-core`, `-fapolicyd` (the only lint backend today), `-sink`, `-cli`. `-selinux` / `-auditd` / `-license` are placeholder stubs.
- **Crate plan** (per spec §17.1): `rulesteward-core`, `-fapolicyd`, `-selinux`, `-auditd`, `-license`, `-sink`, `-cli`. Cargo workspace, `edition = "2024"`, `resolver = "3"`, MSRV `1.88` (workspace `rust-version`; dev/release stay on latest stable via `rust-toolchain.toml`).
- **Locked crates:** parser `chumsky = "0.13"` + `ariadne = "0.6"`; LMDB `heed = "0.22.1"`; CLI `clap = "4"` (derive); license (post-v0.1) `jsonwebtoken >= 10.3` with `rust_crypto`.
- **Distribution target:** `x86_64-unknown-linux-musl` static binary.
- **License:** Engine Apache-2.0; rule templates BSD-3-Clause (separate repo).
- **Commits are user-authored only. Never add `Co-Authored-By: Claude` or any AI-attribution trailer.** Branch + PR for every change; no commits to `main` directly.
- **No telemetry. Read-only by default.** Every write/mutation flag must be opt-in.

# Parallel Development Protocol + reusable artifacts

The project's parallel-development discipline is now captured as reusable artifacts
(built 2026-05-29). Note: the `.claude/` artifacts below are LOCAL-ONLY (`.claude` is
gitignored), so a fresh clone or CI run will not have them; they live on the working
machine. The protocol doc lives in the gitignored docs tree (its own repo). Load these
when a milestone fans out 2+ independent features:

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