//! `selinux-stig-update` - derive + drift-check the selinux `se-W01`/`se-W02`
//! STIG control table (`rulesteward-selinux`'s `stig.rs`) against the official
//! DISA XCCDF.
//!
//! STUB (session 9d lane 2b, test-author dispatch): this is a bare skeleton
//! that always exits 2, mirroring the exit-code CONTRACT `tools/{sshd,auditd}-
//! stig-update` establish (0 in-sync / 1 drift / 2 error) without yet
//! implementing the `check`/`derive` subcommands, XCCDF extraction, or the
//! table-diff logic. `tests/cli.rs` documents the intended future contract
//! against the fixtures in `tests/fixtures/`; it is RED against this stub -
//! that is the frozen contract the impl pipeline builds to.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "selinux-stig-update: not yet implemented (session 9d lane 2b test-author \
         scaffold); see tests/cli.rs for the intended check/derive contract"
    );
    ExitCode::from(2)
}
