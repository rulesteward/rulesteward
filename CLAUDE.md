# OpenWolf

@.wolf/OPENWOLF.md

This project uses OpenWolf for context management. Read and follow .wolf/OPENWOLF.md every session. Check .wolf/cerebrum.md before generating code. Check .wolf/anatomy.md before reading files.


# RTK (Rust Token Killer) - Token-Optimized Commands

@.rtk/RTK.md


# Build / Test / Lint Commands

Canonical commands live in the `justfile` (each recipe mirrors a CI gate verbatim). `just --list` shows all.

- `just ci` - full local gate in CI order: fmt + clippy + test + cov. Run before every push.
- `just fmt` / `just fmt-fix` - `cargo fmt --all --check` / apply. clippy does NOT enforce formatting; fmt is a separate gate.
- `just clippy` - `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- `just test` / `just cov` - workspace tests / llvm-cov with the 80% line floor.
- `just musl` - static `x86_64-unknown-linux-musl` release binary (the distribution target).

Prefix noisy commands with `rtk`; use `rtk proxy <cmd>` when output is parsed by another tool (a diff fed to `cargo mutants --in-diff`, JSON fed to `jq`).


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
- This specific project uses Rust, which the user does not have a deep understanding of.  Idiomatic Rust should be explained when being written.
- Tokens are cheap, rework isn't.
    - It's better to spend more time, context, and thinking than to implement something that needs to be constantly reworked in the future.

# Project Context - RuleSteward

- **Spec + research lives in `.private-docs/`** - a gitignored symlink to `/home/runner/rulesteward-docs/`. Not in the GitHub repo. Start every session by reading `.private-docs/rulesteward-cli-tool-spec.md` (the v0.2 spec) and any `handoff-session-N.md` for the current milestone.
- **Locked design decisions** are enumerated in spec §3 (19 of them). Do not re-litigate. If you find evidence contradicting one, surface it as `[QUESTION FOR USER]` and pause.
- **Status:** `v0.1.0` shipped 2026-06-02; now targeting **v0.2** (the active spec). Implemented crates: `-core`, `-fapolicyd` (the only lint backend today), `-sink`, `-cli`. `-selinux` / `-auditd` / `-license` are placeholder stubs.
- **Crate plan** (per spec §14.1): `rulesteward-core`, `-fapolicyd`, `-selinux`, `-auditd`, `-license`, `-sink`, `-cli`. Cargo workspace, `edition = "2024"`, `resolver = "3"`, MSRV `1.88` (workspace `rust-version`; dev/release stay on latest stable via `rust-toolchain.toml`).
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
  `adversarial-test-reviewer`. Each bakes in the bubble-up preamble and runs on `opus`.
- **Workflow binding:** `.claude/workflows/rs-milestone-fanout.js` (+ `README.md`) is the
  accelerator binding (`parallel()` barrier, `pipeline()` impl->mutation->review,
  structured HALT early-return). The manual binding is always the floor.

**Mutation gate, two layers:** the per-pipeline LOCAL gate (`cargo mutants` after GREEN,
survivors route back to the test-author) is the adversarial-adequacy measure during a
milestone; the CI `mutants.yml` nightly run remains the project-wide net. They are
complementary, not redundant.

**MCP servers (context7 + serena):** these back the "prefer Context7 over training
recall" guidance and Rust symbol navigation. They are currently installed as Claude
plugins (`enabledPlugins`), NOT as a committed repo `.mcp.json`. A repo `.mcp.json`
(the deferred Task 3) is tracked as a follow-up pending a fresh-clone test of whether
the plugin form survives a clone/CI without the plugins; do not assume a committed
`.mcp.json` exists yet.