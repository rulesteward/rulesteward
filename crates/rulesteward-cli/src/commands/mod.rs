//! Subcommand bodies. Each module's `run` function takes the parsed
//! args struct and returns the appropriate exit code. Task 10 adds
//! `selinux` and `auditd` modules.

pub mod fapolicyd;
