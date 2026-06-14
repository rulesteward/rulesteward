//! Crypto-algorithm lints: weak algorithms in the `Ciphers` / `MACs` /
//! `KexAlgorithms` / `HostKeyAlgorithms` lists, and prefix-operator (`+`/`-`/`^`)
//! interactions with the per-version default lists. These consume the NIST/FIPS
//! weak-algorithm denylist and the per-OpenSSH-version default-algorithm lists
//! from the Wave-B grounding task.
//!
//! Phase 0: every pass is a `Vec::new()` stub with a frozen signature. The
//! tracking issues are children of epic #149.

use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Block;
use crate::lints::SshdLintContext;

/// sshd-W03: a weak algorithm appears in an algorithm-list directive (CBC
/// ciphers, HMAC-MD5/SHA1, diffie-hellman-group1-sha1, ssh-rsa).
///
/// TODO(#149, Wave B): gated on the NIST SP 800-131A / crypto-policies denylist.
#[must_use]
pub fn w03(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

/// sshd-W06: an algorithm-list prefix operator (`+`/`-`/`^`) may reintroduce a
/// weak algorithm from the OpenSSH defaults (e.g. `Ciphers +aes128-cbc`).
///
/// TODO(#149, Wave C): needs the per-OpenSSH-version default-algorithm lists.
#[must_use]
pub fn w06(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}
