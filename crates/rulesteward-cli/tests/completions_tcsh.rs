//! Structural end-to-end tests for `rulesteward completions tcsh`.
//!
//! These tests assert the shape of a correct tcsh completion script without
//! pinning every byte of output, so they remain stable across minor generator
//! changes. They are authored RED: the stub generator in completions.rs emits
//! an empty string, so all assertions about non-empty output and required
//! keywords will fail until a real tcsh generator is implemented.
//!
//! Ground truth for tcsh(1) completion syntax (man tcsh, "complete" builtin):
//!
//!   complete <command> [word/pattern/list[:select]/] ...
//!
//! A useful completion registers at least one SELECTOR, which takes the form
//! `p/N/(word-list)/` (positional), `c/prefix/(list)/` (current-word prefix),
//! `n/word/(list)/` (next-word), or `N/word/(list)/` (next-next-word).
//! A bare `complete <command>` with NO selector merely lists the existing
//! spec and registers nothing. So the strongest feasible static check (we
//! cannot run tcsh here) is to require real selector syntax plus representative
//! flags and nested subcommands.

use assert_cmd::Command;

// ---------------------------------------------------------------------------
// Helper: run `rulesteward completions tcsh` and return stdout as a String.
// ---------------------------------------------------------------------------
fn tcsh_output() -> String {
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "tcsh"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "exit code must be 0; got: {:?}",
        out.status.code()
    );
    std::str::from_utf8(&out.stdout).expect("utf8").to_owned()
}

// ---------------------------------------------------------------------------
// [KEEP GREEN] Pipe to `head -1` must not panic (EpipeSwallowingWriter path).
//
// With the stub the output is empty so head exits immediately; the real
// generator will produce enough bytes to trigger a genuine pipe-close.
// This test must stay green through both phases (stub and real impl).
// ---------------------------------------------------------------------------
#[test]
fn tcsh_completions_pipe_to_head_does_not_panic() {
    use std::process::{Command as StdCommand, Stdio};

    let mut completions = StdCommand::new(assert_cmd::cargo::cargo_bin("rulesteward"))
        .args(["completions", "tcsh"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn rulesteward");

    let head_status = StdCommand::new("head")
        .arg("-1")
        .stdin(completions.stdout.take().expect("piped stdout"))
        .status()
        .expect("spawn head");

    let status = completions.wait().expect("wait rulesteward");
    assert!(
        head_status.success(),
        "head must exit 0; got: {:?}",
        head_status.code()
    );
    assert!(
        status.success(),
        "rulesteward must exit 0 even after pipe close; got: {:?}",
        status.code()
    );
}

// ---------------------------------------------------------------------------
// [RED] Non-empty output.
// ---------------------------------------------------------------------------

/// `rulesteward completions tcsh` must exit 0 and produce non-empty output.
/// RED with the stub (empty output).
#[test]
fn tcsh_completions_exit_zero_and_non_empty() {
    let s = tcsh_output();
    assert!(
        !s.is_empty(),
        "stdout must not be empty; stub emits nothing"
    );
}

// ---------------------------------------------------------------------------
// [RED - BLOCKER 4] `complete rulesteward` directive (anchored form).
//
// The previous assertion was `s.contains("complete")`, which matches the
// substring inside "completions" (the subcommand name). The anchored form
// `complete rulesteward` requires the tcsh directive to name the binary,
// so a script that merely lists the subcommand name cannot satisfy it.
// ---------------------------------------------------------------------------

/// The output must contain the tcsh `complete rulesteward` directive (the
/// directive form), not merely the word "complete" as a substring.
/// RED with the stub (no output at all).
#[test]
fn tcsh_completions_contains_complete_rulesteward_directive() {
    let s = tcsh_output();
    assert!(
        s.contains("complete rulesteward"),
        "tcsh completion script must contain `complete rulesteward` directive; got:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// [RED - BLOCKER 1] At least one tcsh slash-pattern SELECTOR must appear.
//
// A selector token has the form `p/N/...`, `c/prefix/...`, `n/word/...`, or
// `N/word/...` (see tcsh(1)). A bare `complete rulesteward` with no selector
// neither registers flags nor nested subcommands. We require the script to
// contain `/(` (the start of a word-list `p/N/(words)/` or equivalent) OR
// a regex-matched `[pcnN]/` prefix selector so that a no-op one-liner cannot
// pass. The regex `[pcnN]/` matches any of the four selector start tokens.
//
// Grounded in tcsh(1): "word/pattern/list[:select]/" where `p` `c` `n` `N`
// are the selector type characters defined by the man page.
// ---------------------------------------------------------------------------

/// The output must contain at least one tcsh selector token. Selectors take
/// the form `p/N/(word-list)/` (positional), `c/prefix/(list)/` (current-word),
/// `n/word/(list)/` (next-word), or `N/word/(list)/` (next-next-word). All of
/// these open with `/(` after the pattern. This cannot be satisfied by a bare
/// `complete rulesteward` or a no-op one-liner.
///
/// Grounded in tcsh(1): "complete word/pattern/list[:select]/" where `/(` is
/// the opening of a word-list in any of the four selector types.
/// RED with the stub (empty output).
#[test]
fn tcsh_completions_contains_slash_pattern_selector() {
    let s = tcsh_output();
    // `/(` opens the word-list in a tcsh selector, e.g. `p/1/(fapolicyd selinux ...)/`.
    // A no-op `complete rulesteward` has no `/(` and cannot pass.
    // A correct generator must emit at least one selector for tab-completion to work.
    let has_open_parens = s.contains("/(");
    // Belt-and-suspenders: accept any of the four selector type characters followed
    // by `/` using simple string checks (no regex dep needed).
    let has_selector_prefix =
        s.contains("p/") || s.contains("c/") || s.contains("n/") || s.contains("N/");
    assert!(
        has_open_parens || has_selector_prefix,
        "tcsh completion script must contain at least one slash-pattern selector \
         (e.g. `p/1/(fapolicyd selinux auditd completions)/`); \
         neither `/(` nor a `[pcnN]/` prefix was found.\nGot:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// [RED - BLOCKER 2] At least one representative flag must appear.
//
// Grounded in cli.rs LintArgs: `--file`, `--format`, `--against-trustdb`,
// `--report-orphans`. Any one of these appearing in the script proves the
// generator walked the clap arg tree rather than just emitting subcommand
// names. We assert `--format` (the most universally present flag) and also
// accept `--file`, `--against-trustdb`, or `--report-orphans` to give the
// generator latitude in which flags it surfaces.
// ---------------------------------------------------------------------------

/// Task 5: the `completions <shell>` positional must offer its `ValueEnum` set
/// (the shell names), at parity with the bash/zsh backends (which complete it
/// automatically). The flat tcsh model surfaces it as an `n/completions/(...)/`
/// next-word rule. RED today: the generator lists only a command's child
/// subcommands + long flags, so `completions` shows just its `--help` flag.
#[test]
fn tcsh_completes_completions_shell_value_set() {
    let s = tcsh_output();
    let line = s
        .lines()
        .find(|l| l.contains("n/completions/"))
        .unwrap_or_else(|| {
            panic!("tcsh script must emit an `n/completions/(...)/` rule for the shell value set;\nGot:\n{s}")
        });
    // clap renders the PowerShell variant in kebab-case (`power-shell`), so the
    // emitted value set matches the literal `rulesteward completions <value>` tokens.
    for shell in ["bash", "zsh", "fish", "elvish", "power-shell", "tcsh"] {
        assert!(
            line.contains(shell),
            "the n/completions/ rule must list the `{shell}` value; got: {line}"
        );
    }
}

/// The output must reference at least one real flag from `LintArgs` so the
/// generator is proven to have walked the clap arg tree.
/// Verified against cli.rs: `--format`, `--file`, `--against-trustdb`,
/// `--report-orphans`.
/// RED with the stub (empty output).
#[test]
fn tcsh_completions_contains_lint_flag() {
    let s = tcsh_output();
    let has_flag = s.contains("--format")
        || s.contains("--file")
        || s.contains("--against-trustdb")
        || s.contains("--report-orphans");
    assert!(
        has_flag,
        "tcsh completion script must reference at least one flag from `fapolicyd lint` \
         (`--format`, `--file`, `--against-trustdb`, or `--report-orphans`); \
         none found.\nGot:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// [RED - BLOCKER 3] Second-level subcommand depth: `lint` must appear.
//
// Grounded in cli.rs FapolicydCommand: `lint` is a child of `fapolicyd`.
// A depth-1-only generator (one that only emits top-level subcommand names)
// cannot satisfy this assertion because `lint` is not a top-level subcommand.
// ---------------------------------------------------------------------------

/// The output must reference the `lint` subcommand (child of `fapolicyd`),
/// proving the generator descends at least two levels into the command tree.
/// Verified against cli.rs: `FapolicydCommand::Lint` is a direct child of
/// `TopCommand::Fapolicyd`, and `lint` is not a top-level subcommand name.
/// RED with the stub (empty output).
#[test]
fn tcsh_completions_contains_second_level_subcommand_lint() {
    let s = tcsh_output();
    assert!(
        s.contains("lint"),
        "tcsh completion script must reference the second-level subcommand `lint` \
         (child of `fapolicyd`); a depth-1-only generator cannot satisfy this.\nGot:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// [RED] Top-level subcommand coverage: `fapolicyd`, `selinux`, `auditd`.
//
// Grounded in cli.rs TopCommand: Fapolicyd, Selinux, Auditd, Completions.
// All three non-completions top-level subcommands must appear.
// ---------------------------------------------------------------------------

/// The output must reference `fapolicyd` (top-level subcommand).
/// RED with the stub.
#[test]
fn tcsh_completions_references_fapolicyd_subcommand() {
    let s = tcsh_output();
    assert!(
        s.contains("fapolicyd"),
        "tcsh completion script must reference the `fapolicyd` subcommand; got:\n{s}"
    );
}

/// The output must reference `selinux` (top-level subcommand).
/// RED with the stub.
#[test]
fn tcsh_completions_references_selinux_subcommand() {
    let s = tcsh_output();
    assert!(
        s.contains("selinux"),
        "tcsh completion script must reference the `selinux` subcommand; got:\n{s}"
    );
}

/// The output must reference `auditd` (top-level subcommand).
/// RED with the stub.
#[test]
fn tcsh_completions_references_auditd_subcommand() {
    let s = tcsh_output();
    assert!(
        s.contains("auditd"),
        "tcsh completion script must reference the `auditd` subcommand; got:\n{s}"
    );
}

/// The output must reference `completions` (the completions subcommand itself,
/// so tab-completing `rulesteward comp<TAB>` works).
/// RED with the stub.
#[test]
fn tcsh_completions_references_completions_subcommand() {
    let s = tcsh_output();
    // "completions" appears as a subcommand name; the `complete rulesteward`
    // directive cannot be the source of this match because we anchor the
    // directive check separately.
    assert!(
        s.contains("completions"),
        "tcsh completion script must reference the `completions` subcommand; got:\n{s}"
    );
}

#[test]
fn tcsh_completions_completes_help_subcommand() {
    // Parity with the bash/zsh/fish backends, which all complete `help`.
    // There must be a consolidated `n/help/(...)/` rule whose list offers real
    // subcommand names so `rulesteward help <TAB>` suggests a subcommand.
    let s = tcsh_output();
    assert!(
        s.contains("'n/help/("),
        "tcsh completion must offer `help` argument completion via an n/help/ rule; got:\n{s}"
    );
    // The help rule's list must contain at least one real subcommand.
    let help_rule = s
        .lines()
        .find(|l| l.contains("'n/help/("))
        .expect("an n/help/ rule line");
    assert!(
        help_rule.contains("fapolicyd"),
        "the n/help/ rule must list subcommands (e.g. fapolicyd); got:\n{help_rule}"
    );
    // `help` should also be offered as a top-level completable word (it is a
    // real subcommand), like the other shells list it.
    assert!(
        s.contains("'p/1/(")
            && s.lines()
                .any(|l| l.contains("'p/1/(") && l.contains("help")),
        "tcsh top-level completion (p/1) must include `help`; got:\n{s}"
    );
}

#[test]
fn tcsh_completions_has_no_duplicate_next_word_rules() {
    // Regression guard: clap's synthetic `help` subtree (flag-less shadow copies
    // of every sibling) must NOT be recursed into, or it emits duplicate
    // `n/<word>/` rules that shadow the real ones in tcsh's flat model. Assert
    // each `n/<word>/` key appears at most once.
    let s = tcsh_output();
    let mut keys: Vec<String> = Vec::new();
    for line in s.lines() {
        if let Some(rest) = line.split("'n/").nth(1) {
            if let Some(word) = rest.split('/').next() {
                keys.push(word.to_owned());
            }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let dups: Vec<&String> = keys.iter().filter(|k| !seen.insert((*k).clone())).collect();
    assert!(
        dups.is_empty(),
        "duplicate n/<word>/ rules would shadow each other in tcsh; dups: {dups:?}\nfull output:\n{s}"
    );
}
