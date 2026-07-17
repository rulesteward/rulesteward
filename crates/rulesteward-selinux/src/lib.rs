//! `SELinux` module - AVC parsing, denial model, triage, TE emit, and categorization.
//!
//!
//! Module skeletons are wired here; real implementations land in their respective
//! Phase-0 tasks and pipelines (see per-module doc comments for issue references).

mod avc;
mod categorize;
mod denial;
mod te_emit;
mod triage;

// STIG boot-configuration surface (#520, session 9d lane 2b): the
// /etc/selinux/config reader, the se-W01/se-W02 lint passes, the RHEL target
// model, and the STIG control-family table. Feature-UNCONDITIONAL (the
// apache-only --no-default-features build must compile them; unlike the
// avc/denial/triage/te_emit/categorize modules above, none of this depends on
// libsepol).
pub mod config;
pub mod lints;
pub mod stig;
pub mod version;

#[cfg(test)]
mod avc_tests;

pub use avc::{AvcDenial, AvcParseError, Verdict, parse_avc};
pub use denial::{DenialGroup, DenialKind, group_denials, is_te_representable};
pub use te_emit::emit_te;
pub use triage::{
    TriageReport, build_report, build_report_with_already_allows, policy_reclassification_hint,
    render_human,
};
pub use version::TargetVersion;

// The authoritative libsepol categorizer (P5 / #105, now default-ON per #124):
// it links libsepol statically (#106/#107), gated behind the
// `authoritative-categorizer` feature (default = ["authoritative-categorizer"]
// in Cargo.toml). Re-exported only when the feature is enabled.
//
// `categorize_with_outcome` is the richer sibling of `categorize`: it returns
// both the `DenialKind` AND the underlying `ReplayOutcome`, letting the CLI
// distinguish the two `ContextInvalid` sub-cases (reason==0 "already allows"
// vs. BADSCON "does not define") without adding an 8th `DenialKind` variant
// (locked decision #122).
#[cfg(feature = "authoritative-categorizer")]
pub use categorize::{CategorizeError, Policy, categorize, categorize_with_outcome};
#[cfg(feature = "authoritative-categorizer")]
pub use rulesteward_selinux_sys::ReplayOutcome;
