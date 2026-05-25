//! Subcommand bodies. Each module's `run` function takes the parsed
//! args struct and returns the appropriate exit code.

pub mod auditd;
pub mod fapolicyd;
pub mod selinux;
