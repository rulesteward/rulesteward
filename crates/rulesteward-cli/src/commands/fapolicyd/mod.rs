//! Body of `rulesteward fapolicyd <subcommand>`.

mod lint;
mod trustdb;

pub use lint::ResolveError;

use crate::cli::FapolicydCommand;
use rulesteward_core::Framework;

pub fn run(cmd: FapolicydCommand, profile: Option<Framework>) -> anyhow::Result<i32> {
    match cmd {
        // Only `lint` carries a `Vec<Diagnostic>` seam; the `--profile` filter is
        // threaded into it. The other fapolicyd verbs (trustdb / explain / simulate
        // / report / doctor / container-check / migrate) have no findings, so the
        // globally-accepted `--profile` is inert for them.
        FapolicydCommand::Lint(args) => lint::run_lint(&args, profile),
        FapolicydCommand::Trustdb(cmd) => trustdb::run_trustdb(cmd),
        FapolicydCommand::Explain(args) => crate::commands::explain::run(args),
        FapolicydCommand::Simulate(args) => crate::commands::simulate::run(args),
        FapolicydCommand::Report(args) => crate::commands::report::run(args),
        FapolicydCommand::Doctor(args) => crate::commands::doctor::run(&args),
        FapolicydCommand::ContainerCheck(args) => crate::commands::container_check::run(&args),
        FapolicydCommand::Migrate(args) => crate::commands::migrate::run_with_probe(
            args,
            &crate::commands::migrate::LiveMigrateProbe,
        ),
    }
}
