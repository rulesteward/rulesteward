//! Subcommand bodies. Each module's `run` function takes the parsed
//! args struct and returns the appropriate exit code.

pub mod auditd;
pub mod completions;
pub mod conf;
pub mod container_check;
pub mod doctor;
pub mod explain;
pub mod fapolicyd;
pub mod mangen;
pub mod migrate;
pub mod report;
pub mod selinux;
pub mod simulate;
pub mod trustdb_compute;
