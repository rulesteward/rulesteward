//! End-to-end tests for `rulesteward completions <shell>`. Verifies the
//! emitted script is non-empty and contains a per-shell sentinel
//! substring. Sentinel-only assertions keep tests stable across
//! `clap_complete` minor bumps.

use assert_cmd::Command;

#[test]
fn bash_completions_emit_non_empty_script() {
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "bash"])
        .output()
        .expect("run");
    assert!(out.status.success(), "exit code {:?}", out.status.code());
    assert!(!out.stdout.is_empty(), "stdout empty");
    let s = std::str::from_utf8(&out.stdout).expect("utf8");
    assert!(
        s.contains("_rulesteward"),
        "bash completion should define _rulesteward; got: {s}"
    );
}

#[test]
fn zsh_completions_emit_non_empty_script() {
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "zsh"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let s = std::str::from_utf8(&out.stdout).expect("utf8");
    assert!(
        s.contains("#compdef rulesteward"),
        "zsh completion should start with #compdef; got: {s}"
    );
}

#[test]
fn fish_completions_emit_non_empty_script() {
    let out = Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "fish"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let s = std::str::from_utf8(&out.stdout).expect("utf8");
    assert!(
        s.contains("complete -c rulesteward"),
        "fish completion should call `complete -c rulesteward`; got: {s}"
    );
}

// NOTE: there are no longer any hidden `#[command(hide = true)]` no-op stubs -
// migrate shipped in #187 (asserted visible in
// cli_help.rs::all_fapolicyd_subcommands_visible_in_help). Every subcommand is a
// real command, so it legitimately appears in both --help and the generated
// bash/zsh/fish completions; no "absent from completions" carve-out is needed.

#[test]
fn unknown_shell_value_exits_three() {
    Command::cargo_bin("rulesteward")
        .expect("binary")
        .args(["completions", "nushell"])
        .assert()
        .code(3);
    // `nushell` is not in `CompletionShell`; clap rejects it as a usage
    // error, main.rs remaps to `EXIT_TOOL_FAILURE` = 3.
}
