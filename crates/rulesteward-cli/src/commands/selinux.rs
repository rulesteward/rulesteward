//! Body of `rulesteward selinux <subcommand>`. v0.1.0-dev stubs;
//! real implementation lands in later sessions.

use crate::cli::SelinuxCommand;
use crate::exit_code::EXIT_NO_OP;

#[must_use]
pub fn run(_cmd: SelinuxCommand) -> i32 {
    eprintln!("rulesteward selinux: not yet implemented in v0.1.0-dev");
    EXIT_NO_OP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selinux_triage_stub_returns_exit_no_op() {
        assert_eq!(run(SelinuxCommand::Triage), EXIT_NO_OP);
    }
}
