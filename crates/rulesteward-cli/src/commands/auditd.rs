//! Body of `rulesteward auditd <subcommand>`. Pipeline bodies land in later sessions.

use crate::cli::AuditdCommand;

pub fn run(cmd: AuditdCommand) -> anyhow::Result<i32> {
    match cmd {
        AuditdCommand::Cost(_args) => {
            todo!("P2 #90 fills auditd cost")
        }
    }
}
