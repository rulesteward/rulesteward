//! End-to-end tests for `rulesteward sysctl lint --system` (issue #420), authored
//! at the test-author barrier BEFORE the impl. `rulesteward_sysctld::system::
//! lint_system` is a Phase-0 stub that always returns an empty result, so the
//! finding-producing test here is RED against the stub (a correct enumerate/
//! mask/merge + `sysctld-W03` pass is required to turn it green). The two clap
//! surface tests (mutually-exclusive flags) exercise ONLY argument parsing and
//! are expected to be GREEN already, since `SysctlLintArgs`'s `conflicts_with`/
//! `requires` wiring is part of this same test-author commit's stub scaffolding
//! (design doc section 6; #420).
//!
//! Mirrors the structure of `e2e_sysctl_lint.rs` (the v1 F01/W01/W02 barrier
//! tests) and the grounded container-experiment fixtures used in the crate-level
//! `rulesteward-sysctld/tests/system.rs`.

use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("binary built")
}

/// Write `body` into `<root>/<rel>`, creating parent directories as needed.
fn write_at(root: &std::path::Path, rel: &str, body: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir -p");
    std::fs::write(&path, body).expect("write fixture file");
}

// ---------------------------------------------------------------------------
// `--system --root <tempdir>` renders a real ariadne snippet at the offending
// line, with no `<source>`/placeholder leakage (functional-smoke convention;
// design doc section 9). RED against the Phase-0 stub (which reports nothing).
// ---------------------------------------------------------------------------

#[test]
fn system_root_renders_ariadne_snippet_for_a_w03a_finding_with_no_leakage() {
    // The W03-a grounded fixture (design section 2/5, reused from the crate-level
    // system.rs test): a lower-precedence directory (/usr/lib/sysctl.d) wins on a
    // lexicographically-later basename over the highest-precedence directory
    // (/etc/sysctl.d). The DEAD assignment is anchored at line 1 of
    // /etc/sysctl.d/10-early.conf.
    let root = tempfile::tempdir().expect("temp root");
    write_at(
        root.path(),
        "etc/sysctl.d/10-early.conf",
        "kernel.sysrq = 1\n",
    );
    write_at(
        root.path(),
        "usr/lib/sysctl.d/90-late.conf",
        "kernel.sysrq = 0\n",
    );

    let out = bin()
        .env("NO_COLOR", "1")
        .args([
            "sysctl",
            "lint",
            "--system",
            "--root",
            root.path().to_str().unwrap(),
        ])
        .output()
        .expect("binary ran");

    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("sysctld-W03"),
        "the cross-directory precedence surprise must emit sysctld-W03; \
         stdout: {stdout} (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains('\u{2500}'),
        "the --system finding must render a real ariadne snippet (box-drawing \
         underline), not a placeholder; stdout: {stdout}"
    );
    assert!(
        stdout.contains("kernel.sysrq = 1"),
        "the snippet must include the real dead source line text; stdout: {stdout}"
    );
    assert!(
        stdout.contains(":1:"),
        "the snippet header must anchor at the real line 1 of 10-early.conf; \
         stdout: {stdout}"
    );

    // Functional-smoke leakage sweep: no internal placeholders / debug tokens
    // ever reach operator-facing output.
    for leak in [
        "<source>",
        "<unknown>",
        "<placeholder>",
        "<TODO>",
        "TODO",
        "panic",
        "dbg!",
    ] {
        assert!(
            !stdout.contains(leak),
            "output must not leak the internal placeholder/debug token {leak:?}; \
             stdout: {stdout}"
        );
    }

    assert_eq!(
        out.status.code(),
        Some(1),
        "a warning-only --system run exits 1 (EXIT_WARNINGS); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// clap surface: --system is mutually exclusive with the positional <path>, and
// --root requires --system. (design doc section 6.)
// ---------------------------------------------------------------------------

#[test]
fn system_and_positional_path_together_is_rejected() {
    let out = bin()
        .args(["sysctl", "lint", "/etc/sysctl.conf", "--system"])
        .output()
        .expect("binary ran");

    // clap usage errors are remapped to EXIT_TOOL_FAILURE (3) by main.rs, NOT
    // clap's own default of 2 (spec: exit 2 is reserved for real lint findings).
    assert_eq!(
        out.status.code(),
        Some(3),
        "a clap conflicts_with violation is a usage error -> exit 3 \
         (EXIT_TOOL_FAILURE); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--system") || stderr.contains("cannot be used with"),
        "the clap error must reference the conflicting --system flag; \
         stderr: {stderr}"
    );
}

#[test]
fn root_without_system_is_rejected() {
    let out = bin()
        .args(["sysctl", "lint", "--root", "/tmp/nonexistent-root-420"])
        .output()
        .expect("binary ran");

    assert_eq!(
        out.status.code(),
        Some(3),
        "a clap requires violation is a usage error -> exit 3 \
         (EXIT_TOOL_FAILURE); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--system"),
        "the clap error must name the missing required --system flag; \
         stderr: {stderr}"
    );
}

#[test]
fn help_lists_the_system_and_root_flags() {
    let out = bin()
        .args(["sysctl", "lint", "--help"])
        .output()
        .expect("binary ran");
    assert_eq!(out.status.code(), Some(0), "--help exits 0");
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("--system"),
        "sysctl lint --help must advertise --system; stdout: {stdout}"
    );
    assert!(
        stdout.contains("--root"),
        "sysctl lint --help must advertise --root; stdout: {stdout}"
    );
}
