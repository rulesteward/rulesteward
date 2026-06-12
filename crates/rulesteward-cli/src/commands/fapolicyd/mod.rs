//! Body of `rulesteward fapolicyd <subcommand>`.

mod lint;
mod trustdb;

pub use lint::ResolveError;

use crate::cli::FapolicydCommand;

pub fn run(cmd: FapolicydCommand) -> anyhow::Result<i32> {
    match cmd {
        FapolicydCommand::Lint(args) => lint::run_lint(&args),
        FapolicydCommand::Trustdb(cmd) => trustdb::run_trustdb(cmd),
        FapolicydCommand::Explain(args) => crate::commands::explain::run(args),
        FapolicydCommand::Simulate(args) => crate::commands::simulate::run(args),
        FapolicydCommand::Report(args) => crate::commands::report::run(args),
        FapolicydCommand::Doctor(args) => crate::commands::doctor::run(&args),
        FapolicydCommand::ContainerCheck(args) => crate::commands::container_check::run(&args),
        FapolicydCommand::Migrate(args) => crate::commands::migrate::run(args),
    }
}
