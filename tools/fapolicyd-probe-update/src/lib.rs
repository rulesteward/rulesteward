//! `fapolicyd-probe-update` - probe the prebuilt `fapolicyd8` / `fapolicyd9` /
//! `fapolicyd10` docker images (Rocky Linux 8/9/10 with fapolicyd pre-installed; see
//! this repo's CLAUDE.md "Differential verification (dev-only)" section -
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

pub mod derive;
pub mod probe;
pub mod transcript;
