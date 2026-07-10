//! `fapolicyd-probe-update` - probe the prebuilt `fapolicyd8` / `fapolicyd9` /
//! `fapolicyd10` docker images (Rocky Linux 8/9/10 with fapolicyd pre-installed; see
//! this repo's CLAUDE.md "Differential verification (fapolicyd, dev-only)" section -
//! these images are NOT built by this tool, unlike `tools/sshd-probe-update`'s
//! `dockerfiles/`, since fapolicyd already ships on the base differential image) and
//! drift-check three shipped `rulesteward-fapolicyd` tables (#478):
//!
//! - (a) the RHEL-major -> fapolicyd version map
//!   (`crates/rulesteward-fapolicyd/src/version.rs::TargetVersion::fapolicyd_version`),
//! - (b) the per-version `pattern=` accepted-value sets
//!   (`crates/rulesteward-fapolicyd/src/lints/version_target.rs`),
//! - (c) the fapd-E07 type-category table
//!   (`crates/rulesteward-fapolicyd/src/attrs.rs::type_category_for`).
//!
//! Library half (the testable, `Command`-free core): [`transcript`] models and parses
//! the shared 5-column TSV probe format (one committed fixture file per RHEL target x
//! dataset - 9 total, `dataset\tid\tverdict\tloaded_n\tevidence` with a `#`-commented
//! documentation header); [`derive`] turns a parsed transcript into a derived dataset
//! value and diffs it against the shipped projection. The docker probe is isolated
//! behind the [`probe`] seam so the core is tested offline with the committed
//! fixtures. The `main` binary (not part of this library) wires these into the
//! `check` / `derive` subcommands.
//!
//! NOTE (issue #478, session 7b-v0_6-wave2 pipeline P2): the RED-test-authoring pass
//! authored the crate skeleton, the committed fixtures, and a frozen RED test suite
//! (in `#[cfg(test)]` modules here and in `tests/cli.rs`) with `transcript::parse_tsv`,
//! `derive::derive_version` / `derive_pattern` / `derive_e07`, `derive::check_version`
//! / `check_pattern` / `check_e07` / `check_target`, and `probe::probe_live` all
//! `todo!()`-stubbed; a later implementer pass (same pipeline) filled in the parse /
//! derive / check / live-probe logic without weakening any authored assertion,
//! including adding a `pub` accessor to `rulesteward-fapolicyd` for dataset (b) (see
//! Cargo.toml's header comment).

pub mod derive;
pub mod probe;
pub mod transcript;
