//! Internal library for the `rulesteward` binary. Exposes the clap derive
//! types, output renderers, and exit-code mapper so integration tests can
//! import them without going through `main.rs`. Subsequent tasks will add
//! `commands` (Task 9) here.

pub mod cli;
pub mod exit_code;
pub mod output;
