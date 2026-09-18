//! The one thing every integration test does: run the binary over a stdin.
//!
//! `cli.rs`, `golden.rs` and `corpus.rs` each carried their own spawn, and a copy that
//! forgets to pipe a stream is a test reading the developer's terminal. One copy here,
//! and nothing else: `tests/common` is compiled into every crate that declares it, so a
//! second helper only one of them called would be dead code in the other two and clippy
//! runs with `-D warnings`.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// The binary under test, `args` on the command line and `stdin` on its stdin, all three
/// streams piped. The raw `Output` is what comes back because the three callers want the
/// exit code, the stdout and the stderr in three different shapes -- lossy strings, raw
/// bytes, and a code that may be absent when a signal killed the run.
pub fn run(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rulesteward"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write");
    child.wait_with_output().expect("wait")
}
