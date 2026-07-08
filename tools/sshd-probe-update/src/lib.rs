//! `sshd-probe-update` - probe a real `sshd` binary in Rocky Linux 8/9/10
//! containers and drift-check three shipped `rulesteward-sshd` lint tables
//! (E01 known-keywords, E04 Match-permitted, W04 deprecated) against what the
//! daemon actually does (#372).
//!
//! Library half (the testable, `Command`-free core): [`transcript`] models and
//! parses a probe transcript (JSONL for the offline `--transcript` path, TSV for
//! the docker output); [`classify`] turns one keyword's stderr into the
//! per-family verdicts; [`overlay`] is the W04 hand-curated honesty layer;
//! [`derive`] classifies a transcript and diffs it against the shipped
//! projections. The docker probe is isolated behind the [`probe`] seam so the
//! core is tested offline with fixtures. The `main` binary wires these into the
//! `check` / `derive` subcommands.

pub mod classify;
pub mod derive;
pub mod overlay;
pub mod probe;
pub mod transcript;
