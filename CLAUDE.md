# OpenWolf

@.wolf/OPENWOLF.md

This project uses OpenWolf for context management. Read and follow .wolf/OPENWOLF.md every session. Check .wolf/cerebrum.md before generating code. Check .wolf/anatomy.md before reading files.


# RTK (Rust Token Killer) - Token-Optimized Commands

@.rtk/RTK.md


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
- If a rule would lead to poor quality code, as the user to resolve.
- Always ask questions rather than make assumptions.
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

# Project Context — RuleSteward

- **Spec + research lives in `.private-docs/`** — a gitignored symlink to `/home/runner/rulesteward-docs/`. Not in the GitHub repo. Start every session by reading `.private-docs/rulesteward-cli-tool-spec.md` (the v0.2 spec) and any `handoff-session-N.md` for the current milestone.
- **Locked design decisions** are enumerated in spec §3 (19 of them). Do not re-litigate. If you find evidence contradicting one, surface it as `[QUESTION FOR USER]` and pause.
- **Crate plan** (per spec §14.1): `rulesteward-core`, `-fapolicyd`, `-selinux`, `-auditd`, `-license`, `-sink`, `-cli`. Cargo workspace, `edition = "2024"`, `resolver = "3"`.
- **Locked crates:** parser `chumsky = "0.13"` + `ariadne = "0.6"`; LMDB `heed = "0.22.1"`; CLI `clap = "4"` (derive); license (post-v0.1) `jsonwebtoken >= 10.3` with `rust_crypto`.
- **Distribution target:** `x86_64-unknown-linux-musl` static binary.
- **License:** Engine Apache-2.0; rule templates BSD-3-Clause (separate repo).
- **Commits are user-authored only. Never add `Co-Authored-By: Claude` or any AI-attribution trailer.** Branch + PR for every change; no commits to `main` directly.
- **No telemetry. Read-only by default.** Every write/mutation flag must be opt-in.