//! Structural lints: directive identity, duplication, Include resolution, and
//! Match-block legality. These need no STIG/crypto baseline tables, so the
//! parallel pipelines for sshd-E02/E03/E04 (Wave A) can start the moment the
//! Phase-0 foundation merges. sshd-E01 (registry-gated) and sshd-W05 (which
//! reuses the W01 required-set) are grouped here as the structural family.
//!
//! sshd-E01, -E02, -E03, -E04, -W05, and -W07 ship real bodies here. The lint
//! codes are children of epic #149.
//!
//! Split into one submodule per pass plus a shared [`matching`] geometry/glob
//! toolkit used only by sshd-W07. Each pass fn is re-exported so the historical
//! paths `structural::e01` .. `structural::w07` still resolve.

mod e01;
mod e02;
mod e03;
mod e04;
mod matching;
mod w05;
mod w07;

pub use e01::e01;
pub use e02::e02;
pub use e03::e03;
pub use e04::e04;
pub use w05::w05;
pub use w07::w07;

/// Keywords sshd accumulates (unions) across multiple lines rather than
/// first-value-wins, so a repeat is legitimate and must NOT be flagged by
/// sshd-E02. Lowercased and sorted (matched via [`slice::contains`] on the
/// lowercased keyword).
///
/// Grounded in `sshd_config(5)` (OpenSSH 10.2p1) and confirmed with an `sshd -T`
/// effective-config differential: each keyword below shows BOTH values when set
/// twice. `SetEnv` is deliberately ABSENT - the differential showed a second
/// `SetEnv` line is dropped (first wins), so a repeated `SetEnv` IS a shadow.
///
/// `Subsystem` is also absent: it accumulates across DIFFERENT names but is
/// first-value-wins for the SAME name, so it gets name-keyed handling in [`e02`]
/// rather than a blanket exemption.
pub(super) const E02_ALLOW_REPEAT: &[&str] = &[
    "acceptenv",
    "allowgroups",
    "allowusers",
    "denygroups",
    "denyusers",
    "hostkey",
    "include",
    "listenaddress",
    "port",
];
