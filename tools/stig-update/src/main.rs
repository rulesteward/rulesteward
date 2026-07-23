//! `stig-update` CLI - derive + drift-check the sysctld STIG baseline tables.
//!
//! #512 (session 9h-v0_8-wave4 Lane B, GROUNDING + TEST-AUTHOR): the CaC-fetch-based
//! `check`/`derive` subcommand wiring this binary previously had (git-tree lookup,
//! `--ref`/`--latest`, `Config.exclude_rules`) does not type-check against the new
//! DISA zip/base_url `config::Config` shape this lane's tests pin (see
//! `config.rs`/`xccdf.rs`) - and re-designing the CLI's subcommand/flag shape
//! (curl+unzip the pinned DISA zip, `--file` for offline fixture testing, etc.) is
//! itself part of the port implementation, which this lane does NOT write (test-
//! author only, per the barrier brief). Deliberately left as a `todo!()` pointing at
//! the two sibling tools that already made this exact design call, rather than
//! guessing at a CLI shape here: `tools/sshd-stig-update/src/main.rs` and
//! `tools/auditd-stig-update/src/main.rs` are the precedent to mirror.

use std::process::ExitCode;

fn main() -> ExitCode {
    todo!(
        "#512: wire the DISA-sourced config::Config / xccdf::parse_baseline (this \
         lane pinned their shapes + tests) into check/derive subcommands, mirroring \
         tools/sshd-stig-update/src/main.rs and tools/auditd-stig-update/src/main.rs"
    )
}
