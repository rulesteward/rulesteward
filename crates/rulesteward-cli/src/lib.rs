//! Internal library for the `rulesteward` binary. Exposes the clap derive
//! types and output renderers so integration tests can import them without
//! going through `main.rs`. Subsequent tasks will add `exit_code` (Task 8)
//! and `commands` (Task 9) modules here.

pub mod cli;
pub mod output;
