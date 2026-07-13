//! Internal library for the `rulesteward` binary. Exposes the clap derive
//! types, output renderers, exit-code mapper, and command bodies so
//! integration tests can import them without going through `main.rs`.

pub mod cli;
pub mod commands;
pub mod exit_code;
pub mod output;
pub mod profile;
