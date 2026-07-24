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
//!
//! # A THIRD hang: `sshd lint <dir>`'s directory-mode main-config read
//!
//! The "no top-level-FIFO hang" claim above is about the ARGUMENT itself
//! being a FIFO. It does not cover a DIRECTORY argument whose main config
//! FILE inside it is a FIFO. `sshd lint <dir>`'s directory dispatch
//! (`commands/sshd.rs:64`, `path.is_dir()`) runs BEFORE the single-file arm's
//! `!path.is_file()` fast-fail (`commands/sshd.rs:84`) and the #560
//! `rulesteward_core::fsread` guard it routes through (`commands/sshd.rs:93`).
//! `lint_drop_in`/`lint_merged` (`rulesteward-sshd/src/lints/drop_in.rs:118`,
//! `:231`) each call raw `std::fs::read_to_string(dir.join("sshd_config"))`
//! directly, unguarded -- so a FIFO named `sshd_config` inside a directory
//! target hangs forever on the blocking `open()` (man fifo(7): a read-only
//! open of a FIFO blocks until a writer appears), exactly like the two cases
//! above, and is pinned as a third load-bearing regression test below.
//!
//! # A FOURTH hang: `sysctl lint --system`'s masked-file read
//!
//! `sysctl lint --system --root <root>` enumerates the standard `sysctl.d`
//! search-path directories and applies same-basename directory masking
//! (`etc/sysctl.d` beats `run/sysctl.d`, highest precedence first). The
//! masked-file push in `rulesteward-sysctld/src/system.rs`'s `enumerate` has
//! no `is_file()` filter before it collects a masked entry, unlike the
//! surviving-file push a few lines below it, which IS gated by `path.is_file()`.
//! `w03c_masked_key_drops` (same file) then calls raw `std::fs::read_to_string`
//! on every masked entry to check whether it silently drops a key. A masked
//! `.conf`-named FIFO with no writer hangs forever on that blocking `open()`
//! (man fifo(7): a read-only open of a FIFO blocks until a writer appears),
//! exactly like the cases above, and is pinned as a fourth load-bearing
//! regression test below.

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

/// Run `args` bounded by a generous timeout. NOTE: `assert_cmd`'s
/// `.timeout()` does NOT make `.output()` return an `Err` when the bound is
/// hit -- it kills the child and `.output()` still returns `Ok(Output)`,
/// with `status.code() == None` (the process was killed by a signal rather
/// than exiting normally). That `None` IS the hang signal in this suite; see
/// `assert_fast_tool_failure` below, which asserts on it explicitly. The
/// `unwrap_or_else` panic here is therefore dead for the timeout case (kept
/// only for a genuine spawn/IO failure, an unrelated error class).
fn run_bounded(args: &[&str]) -> std::process::Output {
    bin()
        .args(args)
        .timeout(Duration::from_secs(15))
        .output()
        .unwrap_or_else(|e| {
            panic!("command {args:?} failed to run (spawn/IO error, not a timeout): {e}")
        })
}

fn assert_fast_tool_failure(out: &std::process::Output, fifo: &std::path::Path) {
    assert!(
        out.status.code().is_some(),
        "hang: child killed by 15s timeout (status.code() is None, meaning \
         the process was killed by a signal rather than exiting normally) -- \
         this IS the #560 hang bug (a blocking FIFO read that never returns \
         because no writer ever opens the other end); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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

/// The impl-aware adversarial review's miss (9i lane-2 closeout):
/// `sshd lint <dir>` where `<dir>/sshd_config` (the main config the
/// directory-mode dispatch always reads first) is a FIFO with no writer.
/// Unlike a bare top-level FIFO argument (already rejected without blocking
/// by the `is_dir()`/`is_file()` gates in `commands/sshd.rs`, see the module
/// docs above), the directory dispatch (`commands/sshd.rs:64`) is entered
/// BEFORE any special-file check, and `lint_drop_in`/`lint_merged`
/// (`rulesteward-sshd/src/lints/drop_in.rs:118`, `:231`) each read the main
/// config with raw `std::fs::read_to_string`, not
/// `rulesteward_core::fsread::read_to_string` -- so this hangs identically
/// to the two cases above. A wedged process yields `status.code() == None`
/// (killed by the bounded timeout, not exited normally);
/// `assert_fast_tool_failure` treats that `None` as the hang signal, exactly
/// as it does for the fapolicyd/sudoers cases above.
#[test]
fn sshd_lint_directory_main_config_fifo_fails_fast() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = make_fifo(dir.path(), "sshd_config");
    let out = run_bounded(&["sshd", "lint", dir.path().to_str().unwrap()]);
    assert_fast_tool_failure(&out, &fifo);
}

/// The masked-file read miss (9i lane-2 closeout round 3, issue #560):
/// `sysctl lint --system --root <root>` where `<root>/run/sysctl.d/50-x.conf`
/// is a FIFO masked by a same-basename regular file at
/// `<root>/etc/sysctl.d/50-x.conf` (etc/sysctl.d has higher precedence than
/// run/sysctl.d). `w03c_masked_key_drops` reads every masked entry with raw
/// `std::fs::read_to_string`, so the masked FIFO hangs exactly like the
/// cases above. After the fix, the masked FIFO read is skipped cleanly (a
/// FIFO has no assignments to drop, so no `sysctld-W03` fires for it) and
/// the single surviving assignment is clean, so the run must exit 0
/// (`EXIT_CLEAN`) -- never hang, never any other code.
#[test]
fn sysctl_lint_system_masked_fifo_fails_fast() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(root.path().join("etc/sysctl.d")).expect("mkdir etc/sysctl.d");
    std::fs::create_dir_all(root.path().join("run/sysctl.d")).expect("mkdir run/sysctl.d");
    std::fs::write(
        root.path().join("etc/sysctl.d/50-x.conf"),
        "kernel.pid_max = 65536\n",
    )
    .expect("write etc/sysctl.d/50-x.conf");
    let fifo = make_fifo(&root.path().join("run/sysctl.d"), "50-x.conf");

    let out = run_bounded(&[
        "sysctl",
        "lint",
        "--system",
        "--root",
        root.path().to_str().unwrap(),
    ]);

    assert!(
        out.status.code().is_some(),
        "hang: child killed by 15s timeout (status.code() is None, meaning \
         the process was killed by a signal rather than exiting normally) -- \
         this IS the #560 miss (w03c_masked_key_drops's raw \
         std::fs::read_to_string on a masked FIFO with no writer, at {}); \
         stderr: {}",
        fifo.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the masked FIFO must be skipped cleanly (a FIFO has no assignments \
         to drop, so no sysctld-W03-c fires for it) and the single surviving \
         etc/sysctl.d/50-x.conf assignment is clean, so the run must exit 0; \
         stdout: {}, stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
