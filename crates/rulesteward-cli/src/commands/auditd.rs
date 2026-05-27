//! Body of `rulesteward auditd <subcommand>`. v0.1.0-dev stubs;
//! real implementation lands in later sessions.

use crate::cli::AuditdCommand;
use crate::exit_code::EXIT_NO_OP;

pub fn run(_cmd: AuditdCommand) -> anyhow::Result<i32> {
    eprintln!("rulesteward auditd: not yet implemented in v0.1.0-dev");
    Ok(EXIT_NO_OP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auditd_cost_stub_returns_exit_no_op() {
        assert_eq!(
            run(AuditdCommand::Cost).expect("stub never errors"),
            EXIT_NO_OP
        );
    }
}
