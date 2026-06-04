//! Body of `rulesteward selinux <subcommand>`. Pipeline bodies land in later sessions.

use crate::cli::SelinuxCommand;

pub fn run(cmd: SelinuxCommand) -> anyhow::Result<i32> {
    match cmd {
        SelinuxCommand::Triage(_args) => {
            todo!("P3 #99 fills selinux triage; P4 #103 adds the --emit-te branch")
        }
    }
}
