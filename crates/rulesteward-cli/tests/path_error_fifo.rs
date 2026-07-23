//! End-to-end pins for #560: a lint target that is a FIFO (a named pipe with
//! no writer) must fail FAST instead of hanging forever waiting for a writer
//! that will never come.
//!
//! # Reproduced against main `142282b` (2026-07-23) before the fix
//!
//! ```text
//! $ timeout 5 rulesteward fapolicyd lint --file /tmp/myfifo
//! (nothing printed; the process is still running when `timeout` kills it)
//! $ echo $?
//! 124
//! $ timeout 5 rulesteward sudoers lint /tmp/sudoers_fifo
//! (same: exit 124, killed by timeout)
//! ```
//!
//! `sshd lint`, `sysctl lint`, and `auditd lint` do NOT reproduce a hang on a
//! bare top-level FIFO argument today: each already gates on
//! `path.is_file()`/`path.is_dir()` BEFORE ever calling `std::fs::read_to_string`,
//! so a FIFO (which is neither) is already rejected without blocking --
//! confirmed live: `sshd lint <fifo>` -> "not a file or directory" (exit 3, no
//! hang); `sysctl lint <fifo>` -> same; `auditd lint <fifo>` -> "path does not
//! exist" (exit 3, no hang, though that specific wording is arguably
//! misleading for a path that demonstrably exists). Only `fapolicyd lint
//! --file` (no pre-check at all in single-file mode) and `sudoers lint`
//! (`resolve::resolve_target`'s non-directory branch calls
//! `std::fs::read_to_string` unconditionally) hang TODAY without the #560
//! fix, so those are the two backends pinned here as the load-bearing RED
//! regression tests. The shared `rulesteward_core::fsread::read_to_string`
//! contract every backend is expected to route through (including
//! sshd/sysctl/auditd, per the #560 brief's call-site list) is pinned at the
//! unit level in `rulesteward-core/src/fsread.rs`: regular files, symlinks
//! to regular files, directories, FIFOs, character devices (`/dev/null`,
//! plus a bounded-thread `/dev/zero` case mirroring the FIFO hang guard
//! below), and Unix domain sockets are all covered there.

use std::time::Duration;

use assert_cmd::Command;

fn bin() -> Command {
    Command::cargo_bin("rulesteward").expect("binary built")
}

/// Create a FIFO at `dir/name` via the `mkfifo(1)` coreutil. No writer is ever
/// opened on it -- reading it in blocking mode is exactly the #560 hang
/// trigger (opening a read-only FIFO blocks until a writer appears).
fn make_fifo(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let fifo = dir.join(name);
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo(1) available on the Linux distribution target");
    assert!(
        status.success(),
        "mkfifo must succeed for {}",
        fifo.display()
    );
    fifo
}

/// Run `args` bounded by a generous timeout, panicking loudly (naming the
/// hang explicitly) rather than letting the test binary wedge forever if the
/// special-file guard regresses.
fn run_bounded(args: &[&str]) -> std::process::Output {
    bin()
        .args(args)
        .timeout(Duration::from_secs(15))
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "command {args:?} did not complete within 15s -- this IS the \
                 #560 hang bug (a blocking FIFO read that never returns \
                 because no writer ever opens the other end): {e}"
            )
        })
}

fn assert_fast_tool_failure(out: &std::process::Output, fifo: &std::path::Path) {
    assert_eq!(
        out.status.code(),
        Some(3),
        "a FIFO target must be a tool failure (EXIT_TOOL_FAILURE=3), not a \
         hang or a different exit code; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&fifo.display().to_string()),
        "the diagnostic must name the offending FIFO path; stderr: {stderr}"
    );
}

/// The exact reproduction from issue #560 ("fapolicyd lint --file /dev/zero
/// hangs"): `--file` on a FIFO must no longer hang.
#[test]
fn fapolicyd_lint_file_fifo_fails_fast() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = make_fifo(dir.path(), "policy.rules");
    let out = run_bounded(&["fapolicyd", "lint", "--file", fifo.to_str().unwrap()]);
    assert_fast_tool_failure(&out, &fifo);
}

/// `sudoers lint <fifo>`: `resolve::resolve_target`'s single-file branch
/// calls `std::fs::read_to_string` with no prior type check (resolve.rs:88),
/// so this hangs identically to the fapolicyd case above before the fix.
#[test]
fn sudoers_lint_fifo_fails_fast() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = make_fifo(dir.path(), "sudoers");
    let out = run_bounded(&["sudoers", "lint", fifo.to_str().unwrap()]);
    assert_fast_tool_failure(&out, &fifo);
}
