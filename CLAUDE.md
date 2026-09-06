# rulesteward

audit2why/audit2allow for host policy systems. Read fapolicyd denial records on
stdin, write the rules that would allow them on stdout. `DESIGN.md` is the
contract; this file is the short list of things that are counterintuitive, where
the obvious helpful action is the wrong one.

Anchor every reference to a name -- a symbol, a heading, a filename -- never to
`file:NN`. A line number drifts on the next insertion above it and nothing checks
it.

## Exit 0 covers "parsed it, nothing to suggest"

`EXIT_OK`, `EXIT_USAGE` and `EXIT_UNPARSEABLE` in `src/main.rs` are the whole
contract (DESIGN.md section 9): `1` is usage or I/O, `2` is "input arrived and no
line yielded a single `name=value` field", `0` is everything else **including a
log full of allow records with nothing to suggest**. clap's own default exits `2`
on a usage error, which is why `main` uses `try_parse` and maps the kinds by
hand; `help_and_version_are_successes_not_usage_errors`,
`unparseable_input_exits_2` and
`a_log_with_no_denials_is_a_success_not_a_parse_failure` in `tests/cli.rs` pin
all three.

## The command surface is `rulesteward <domain> <action>`, with no shortcuts

No aliases, no abbreviations, no bare-action form, no default domain: the domain
slot has to stay spendable for the next policy system. `there_is_no_bare_action_form`,
`the_domain_cannot_be_abbreviated` and `the_action_is_not_spelled_the_other_way`
in `tests/cli.rs` fail the build if one is added, so adding a convenience alias
is a test failure and not a style discussion.

## Purity is a lint, not a convention

`[lints.clippy]` in `Cargo.toml` sets `print_stdout` and `print_stderr` to
`deny`. Everything under `src/fapolicyd/` returns diagnostics as data;
`src/main.rs` is the one place permitted to touch fs, io, env or the clock, and
`read_syslog_format` there is the only file read in the tree. A diagnostic that
needs printing gets returned to `main` instead of printed where it was found.

## `UPDATE_GOLDEN=1`, then read the diff

`tests/golden.rs` says it: a golden test that gets blessed unread is just a
changelog. Regenerate with `UPDATE_GOLDEN=1 cargo test`, read the whole diff, and
only then commit. The command is in `permissions.deny` in
`.claude/settings.json`, so an agent cannot run it -- ask the developer to.

## The reload-probe fixture is the tail of its capture, not the head

`FIXTURES` in `xtask/sync-fixtures.sh` truncates
`rocky8-base-reload-probe-empty-ruleset-daemon.log` to `tail:250`. The corruption
in that capture starts *after* the failed reload, so its corrupted field names
are the last records in the file: a `head:` cap would vendor only the clean ones
and the fixture would test nothing. The same reasoning applies to any new
truncated fixture -- keep the end that carries the hazard.

## `research` is a gitignored symlink into a private repo

The 121-log corpus lives in `rulesteward-research`, which is private, so the
sweep is local-only and public CI never runs it. `just corpus` builds
`tests/corpus.rs` behind the `full-corpus` feature and
`every_capture_is_either_acted_on_or_explained` panics naming the symlink when it
is absent, which is deliberate: a sweep that passes because it did not run is
worse than no sweep. Make it with `ln -s ../rulesteward-research research`; a
worktree gets one from `.claude/hooks/worktree-create.sh`, and the SessionStart
probe says so when it is missing.

## Three tiers, and a local green is not a CI green

The `check` recipe in the `justfile` carries the split: the `Stop` hook runs
`just lint` once per agent turn, `just check` adds the suite and is what a
developer runs before pushing, and mutation testing runs only in CI. Do not read
a green `just check` as a green pipeline.

## Cite names, never a co-author, and read the ledger before proposing a tool

Commit subjects are imperative and sentence-length; the body says what was
**measured** and corrects prior wrong claims by name. No `Co-Authored-By`
trailer, ever. Tooling that was already investigated and rejected -- with
measurements -- is written up in `docs/research/tooling-2026-09-06.md` in the
`rulesteward-research` repo. Read the rejection before reopening it; re-proposing
one is re-deriving settled work.

## Commands

| | |
|---|---|
| `just` | List the recipes |
| `just lint` | Every static gate in one pass, all verdicts reported (`xtask/lint.sh`) |
| `just check` | `lint` plus the suite; run before pushing |
| `just corpus` | The full 121-log sweep through the `research` symlink |
| `just musl` | The musl release build plus the static-binary assertion |
| `./xtask/install-tools.sh` | Installs the pinned `just`, `cargo-deny`, `cargo-mutants` and `typos` into `.tools/bin`; run directly, never through `just` |
| `./xtask/sync-fixtures.sh` | Re-vendor the fixtures out of `research`; `--check` reports drift |

The pinned tools live in `.tools/bin`, which the `justfile` prepends to `PATH`
for recipes and CI spells out as `./.tools/bin/just <recipe>`.

## `.claude/` holds two settings files with opposite tracking status

`.claude/settings.json` is committed: the three hooks and `permissions.deny`,
reviewable like every other gate here. `.claude/settings.local.json` is the
machine-local `allow` list and is **not** tracked, so a clean `git status` is not
evidence that it is unmodified -- `git check-ignore -v` is. A deny matcher is a
prefix and not a boundary: an absolute path or a new recipe wrapping the flag
routes around it silently. It guards against the obvious helpful action, nothing
more.
