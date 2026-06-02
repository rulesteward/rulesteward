//! Body of `rulesteward selinux <subcommand>`. Stubs; the real implementation
//! lands in a later session.

use crate::cli::SelinuxCommand;
use crate::exit_code::EXIT_NO_OP;

pub fn run(_cmd: SelinuxCommand) -> anyhow::Result<i32> {
    eprintln!(
        "rulesteward selinux: not yet implemented in v{}",
        env!("CARGO_PKG_VERSION")
    );
    Ok(EXIT_NO_OP)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selinux_triage_stub_returns_exit_no_op() {
        assert_eq!(
            run(SelinuxCommand::Triage).expect("stub never errors"),
            EXIT_NO_OP
        );
    }
}
