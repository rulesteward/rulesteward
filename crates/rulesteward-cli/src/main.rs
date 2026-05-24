//! `rulesteward` — top-level CLI binary.
//!
//! Session 1 ships a placeholder. The clap subcommand tree (`fapolicyd lint`,
//! `selinux …`, `auditd …`) lands in session 2 alongside the first real
//! parser. See `.private-docs/handoff-session-2.md`.
//!
//! Exit code `9` matches the upstream `fapolicyd-cli` "no-op" code per
//! spec §9.4.

fn main() {
    eprintln!("rulesteward 0.1.0-dev — not yet implemented");
    std::process::exit(9);
}
