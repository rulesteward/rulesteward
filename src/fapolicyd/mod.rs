//! Everything fapolicyd-specific. Pure: no fs, no io, no env, no clock.
//!
//! This module is the seam that becomes a top-level `fapolicyd/` crate once a second
//! domain exists (plan D4). Keep the submodule boundaries honest so the split stays a
//! move rather than a redesign.

pub mod analyze;
pub mod conf;
pub mod emit;
pub mod model;
pub mod parse;
pub mod policy;

pub use analyze::analyze;

/// DESIGN.md §6. Packaged as mode 750 root:fapolicyd, so an ordinary user's read of
/// this fails and the truncation ladder falls through to the 511-byte test.
pub const DEFAULT_CONF_PATH: &str = "/etc/fapolicyd/fapolicyd.conf";
