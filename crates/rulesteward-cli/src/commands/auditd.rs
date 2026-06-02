//! Body of `rulesteward auditd <subcommand>`. Stubs; the real implementation
//! lands in a later session.

use crate::cli::AuditdCommand;
use crate::exit_code::EXIT_NO_OP;

pub fn run(_cmd: AuditdCommand) -> anyhow::Result<i32> {
    eprintln!(
        "rulesteward auditd: not yet implemented in v{}",
        env!("CARGO_PKG_VERSION")
    );
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
