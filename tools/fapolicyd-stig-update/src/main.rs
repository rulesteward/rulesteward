//! `fapolicyd-stig-update` - derive + drift-check the fapolicyd #519 STIG
//! control table (`ControlFamily::{Installed,Enabled,DenyAll}`,
//! `crates/rulesteward-fapolicyd/src/lints/stig.rs`) against the official
//! DISA XCCDF.
//!
//! SKELETON ONLY (session 9d, test-author lane 2a): this binary does not yet
//! parse XCCDF, derive anything, or drift-check anything. It exists so the
//! FROZEN `tests/cli.rs` suite (and the fixtures it exercises) compile and
//! run against a REAL binary. It unconditionally prints a generic
//! "not yet implemented" message and exits 2, regardless of arguments -
//! every test in `tests/cli.rs` is RED against this stub (both the exit code
//! AND the message content it pins are wrong until a real implementation
//! lands).
//!
//! The eventual shape (subcommands `check [--product P] [--file X]` /
//! `derive [--product P] [--file X]`, exit-code contract 0 in-sync / 1 drift
//! / 2 error) mirrors `tools/auditd-stig-update`'s established pattern; see
//! that crate's `src/{main,config,derive,source,xccdf}.rs` for the shape to
//! follow. Filling this in is the #519 implementation pipeline's job, not
//! this scaffolding's.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "fapolicyd-stig-update: not yet implemented (session 9d skeleton; see \
         tools/fapolicyd-stig-update/src/main.rs)"
    );
    ExitCode::from(2)
}
