//! Crypto-algorithm lints: weak algorithms in the `Ciphers` / `MACs` /
//! `KexAlgorithms` and the signature-algorithm lists (`HostKeyAlgorithms` /
//! `HostbasedAcceptedAlgorithms` / `PubkeyAcceptedAlgorithms` /
//! `CASignatureAlgorithms`), and prefix-operator (`+`/`-`/`^`)
//! interactions with the per-version default lists. These consume the NIST/FIPS
//! weak-algorithm denylist and the per-OpenSSH-version default-algorithm lists
//! from the Wave-B grounding task.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{Block, Directive};
use crate::lints::{SshdLintContext, anchored};

// ---------------------------------------------------------------------------
// sshd-W03 denylist tables (grounding: sshd-stig-version-grounding.md section 6)
// ---------------------------------------------------------------------------
//
// All names are LOWERCASED for case-insensitive exact-token matching.
// The denylist is version-independent: an explicitly written weak algorithm
// is a finding regardless of `--target` (W03 fires with `target=None` too).

/// Weak `Ciphers` names: CBC-mode ciphers, RC4, 3DES.
///
/// Grounding: NIST SP 800-131A R2 Table 1 (TDEA "Disallowed after 2023");
/// crypto-policies DEFAULT excludes CBC/RC4/3DES on el9/el10.
const WEAK_CIPHERS: &[&str] = &[
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "rijndael-cbc@lysator.liu.se",
];

/// Weak `MACs` names: HMAC-MD5 and HMAC-SHA-1 variants (hardening baseline).
///
/// Grounding:
/// - MD5: Red Hat 3642912 ("MD5 in signatures removed since RHEL-7"); never in
///   any crypto-policies level.
/// - SHA-1 MACs: catalog text ("MD5/SHA1") encodes the hardening intent. Grounding
///   6.3: "catalog text implies SHA-1 MACs fire."
const WEAK_MACS: &[&str] = &[
    "hmac-md5",
    "hmac-md5-96",
    "hmac-md5-96-etm@openssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-sha1-96-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
];

/// Weak `KexAlgorithms` names: 1024-bit MODP group1 and SHA-1 KEX hash variants.
///
/// Grounding: NIST SP 800-131A R2 Table 4 ((1024,160) "Disallowed"); group14-sha1
/// and gex-sha1 are weak via the SHA-1 hash (NOT via key size -- group14-sha256
/// uses the same 2048-bit modulus and is fine). The gss-group1-sha1-* and
/// gss-gex-sha1-* patterns are matched by prefix (the suffix is a base64 OID
/// token); only these two SHA-1 gss prefix patterns are weak -- the SHA-2
/// variants (gss-curve25519-sha256-*, gss-group14-sha256-*) are strong (RFC 8732).
const WEAK_KEX_EXACT: &[&str] = &[
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
];

/// SHA-1 gss- KEX prefixes (matched as `starts_with`; suffix is a base64 OID).
///
/// Only the -sha1 gss variants are weak. The -sha256 variants (RFC 8732) are
/// strong and MUST NOT match. Using a prefix test keyed on the SHA-1 suffix in
/// the name ("group1-sha1", "gex-sha1") rather than a bare "gss-" prefix prevents
/// over-firing on gss-curve25519-sha256-* and gss-group14-sha256-*.
const WEAK_KEX_GSS_PREFIXES: &[&str] = &["gss-gex-sha1-", "gss-group1-sha1-"];

/// Weak `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`, and
/// `CASignatureAlgorithms` names: SHA-1 RSA signatures and DSA.
///
/// Grounding:
/// - `ssh-rsa` / `ssh-rsa-cert-v01@openssh.com`: SHA-1 RSA signature, NIST SP
///   800-131A R2 Table 8 (SHA-1 sig-gen "Disallowed"). `ssh-rsa` denotes the
///   SHA-1 signature algorithm (RFC 8332), NOT the RSA key type. `rsa-sha2-256`
///   and `rsa-sha2-512` use SHA-2 on the same RSA key and are FINE -- they must
///   NOT appear in this list.
/// - `ssh-dss` / `ssh-dss-cert-v01@openssh.com`: DSA, NIST SP 800-131A R2
///   Table 2 (DSA "Disallowed").
const WEAK_HOSTKEY: &[&str] = &[
    "ssh-dss",
    "ssh-dss-cert-v01@openssh.com",
    "ssh-rsa",
    "ssh-rsa-cert-v01@openssh.com",
];

// ---------------------------------------------------------------------------
// Algorithm-list directive families
// ---------------------------------------------------------------------------

/// Returns the denylist slice for a lowercased directive keyword, or `None` if
/// the keyword is not an algorithm-list directive that W03 checks.
///
/// `KexAlgorithms` uses a combined check (exact + prefix) handled separately in
/// [`is_weak_kex`]; this function returns the exact-only slice for KEX to support
/// the uniform iteration in `w03_directive`.
fn weak_exact_list(keyword: &str) -> Option<(&'static [&'static str], Weak03Kind)> {
    match keyword {
        "ciphers" => Some((WEAK_CIPHERS, Weak03Kind::Exact)),
        "macs" => Some((WEAK_MACS, Weak03Kind::Exact)),
        "kexalgorithms" => Some((WEAK_KEX_EXACT, Weak03Kind::Kex)),
        "hostkeyalgorithms"
        | "hostbasedacceptedalgorithms"
        | "pubkeyacceptedalgorithms"
        | "casignaturealgorithms" => Some((WEAK_HOSTKEY, Weak03Kind::Exact)),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Weak03Kind {
    /// Simple exact-match denylist only.
    Exact,
    /// KEX: exact-match denylist PLUS gss-prefix pattern matching.
    Kex,
}

/// Return `true` when the lowercased token is a weak KEX algorithm.
fn is_weak_kex(token: &str) -> bool {
    if WEAK_KEX_EXACT.contains(&token) {
        return true;
    }
    WEAK_KEX_GSS_PREFIXES
        .iter()
        .any(|pfx| token.starts_with(pfx))
}

/// Emit one W03 diagnostic per weak algorithm token found in a directive's args.
///
/// The directive's args are joined with commas to reconstruct the algorithm list
/// (the parser may present multi-word args as multiple elements), then split on
/// commas, and each token is trimmed and checked against the denylist. One
/// diagnostic is emitted per weak token.
fn w03_directive(directive: &Directive, file: &Path, diags: &mut Vec<Diagnostic>) {
    let Some((exact_list, kind)) = weak_exact_list(&directive.keyword_lower()) else {
        return;
    };

    // Reconstruct the comma-separated algorithm list from the parsed args.
    // The parser splits on whitespace, so a value like "aes256-ctr,aes128-cbc"
    // arrives as one arg element; a value with internal spaces around commas
    // may arrive similarly. Join with comma in case the parser split further,
    // then re-split on comma and trim each token.
    let joined = directive.args.join(",");
    for raw_token in joined.split(',') {
        let token = raw_token.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        let is_weak = match kind {
            Weak03Kind::Exact => exact_list.contains(&token.as_str()),
            Weak03Kind::Kex => is_weak_kex(&token),
        };
        if is_weak {
            diags.push(anchored(
                Severity::Warning,
                "sshd-W03",
                directive.span.clone(),
                format!(
                    "weak algorithm '{}' in '{}': CBC ciphers, HMAC-MD5/SHA-1, \
                     DH-group1/group14-sha1, or ssh-rsa/ssh-dss (NIST SP 800-131A R2)",
                    raw_token.trim(),
                    directive.keyword,
                ),
                file,
                directive.line,
            ));
        }
    }
}

/// sshd-W03: a weak algorithm appears in an algorithm-list directive (`Ciphers`,
/// `MACs`, `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`, or
/// `CASignatureAlgorithms`).
///
/// Fires on any of: CBC-mode ciphers, RC4/3DES, HMAC-MD5 and HMAC-SHA-1
/// variants, DH-group1-sha1 / DH-group14-sha1 / DH-gex-sha1 (and the gss- SHA-1
/// KEX variants), or SHA-1 RSA signatures (`ssh-rsa`) / DSA (`ssh-dss`).
///
/// The denylist is version-independent: an explicitly written weak algorithm is a
/// finding regardless of `--target` (W03 fires with `target=None`). W06 (prefix-
/// operator reintroduction) is a separate, Wave-C stub that handles `+`/`-`/`^`
/// interactions with the per-version default lists.
///
/// Scans the global block AND all Match block bodies (an admin can override
/// algorithm lists inside a Match block).
///
/// Grounding: sshd-stig-version-grounding.md section 6; NIST SP 800-131A R2
/// Tables 1/2/4/8; RFC 8332 (rsa-sha2-256/512); RFC 8732 (gss-sha256 KEX);
/// RHEL crypto-policies DEFAULT/FUTURE back-ends.
#[must_use]
pub fn w03(blocks: &[Block], file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for block in blocks {
        let directives = match block {
            Block::Global(directives) => directives,
            Block::Match(match_block) => &match_block.body,
        };
        for directive in directives {
            w03_directive(directive, file, &mut diags);
        }
    }
    diags
}

/// sshd-W06: an algorithm-list prefix operator (`+`/`-`/`^`) may reintroduce a
/// weak algorithm from the OpenSSH defaults (e.g. `Ciphers +aes128-cbc`).
///
/// TODO(#149, Wave C): needs the per-OpenSSH-version default-algorithm lists.
#[must_use]
pub fn w06(_blocks: &[Block], _file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    Vec::new()
}

#[cfg(test)]
mod w03_tests {
    //! sshd-W03: weak algorithm in `Ciphers` / `MACs` / `KexAlgorithms` /
    //! `HostKeyAlgorithms` / `PubkeyAcceptedAlgorithms` / `CASignatureAlgorithms`.
    //!
    //! # Grounding (sshd-stig-version-grounding.md section 6, primary source)
    //!
    //! Denylist is FIXED (version-independent): an algorithm an admin explicitly
    //! writes is weak regardless of the RHEL target, so W03 fires with
    //! `target=None`. Tests use `SshdLintContext::default()` (target=None).
    //!
    //! ## Critical negative assertions (prevent substring/contains over-fire)
    //!
    //! - `rsa-sha2-256`, `rsa-sha2-512`: SSH-2 RSA with SHA-2 signatures - FINE.
    //!   `ssh-rsa` is weak because it uses SHA-1 for the signature (RFC 8332 / NIST
    //!   SP 800-131A R2 Table 8), NOT because it uses RSA keys. A naive
    //!   `contains("ssh-rsa")` would misfire on "rsa-sha2-256".
    //! - `diffie-hellman-group14-sha256`, `diffie-hellman-group16-sha512`: strong KEX
    //!   (SHA-2 hash). Only the -sha1 variants are weak. A naive
    //!   `contains("group14")` would misfire.
    //! - `aes256-gcm@openssh.com`, `chacha20-poly1305@openssh.com`, `aes256-ctr`: strong
    //!   ciphers - none are CBC / RC4 / 3DES.
    //! - `hmac-sha2-256`, `hmac-sha2-512`: strong MACs.

    use super::w03;
    use crate::lints::SshdLintContext;
    use rulesteward_core::Severity;
    use std::path::Path;

    const FILE: &str = "/etc/ssh/sshd_config";

    fn parse(src: &str) -> Vec<crate::ast::Block> {
        crate::parser::parse_config_str_located(src, Path::new(FILE)).expect("fixture parses")
    }

    fn run(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        w03(&parse(src), Path::new(FILE), &SshdLintContext::default())
    }

    // --- Ciphers: CBC ciphers (grounding table section 6.1) ---

    #[test]
    fn ciphers_aes128_cbc_fires_w03() {
        // aes128-cbc: CBC mode, no integrity. NIST SP 800-131A R2 Table 1.
        let diags = run("Ciphers aes128-cbc\n");
        assert_eq!(diags.len(), 1, "one weak cipher => one diagnostic");
        assert_eq!(diags[0].code, "sshd-W03");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].line, 1, "flagged at the Ciphers directive line");
    }

    #[test]
    fn ciphers_3des_cbc_fires_w03() {
        // 3des-cbc: TDEA, disallowed after 2023 per NIST SP 800-131A R2 Table 1.
        let diags = run("Ciphers 3des-cbc\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn ciphers_aes192_cbc_fires_w03() {
        let diags = run("Ciphers aes192-cbc\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn ciphers_aes256_cbc_fires_w03() {
        let diags = run("Ciphers aes256-cbc\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn ciphers_arcfour_fires_w03() {
        // RC4 - cryptographically broken stream cipher.
        let diags = run("Ciphers arcfour\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn ciphers_arcfour128_fires_w03() {
        let diags = run("Ciphers arcfour128\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn ciphers_arcfour256_fires_w03() {
        let diags = run("Ciphers arcfour256\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn ciphers_blowfish_cbc_fires_w03() {
        let diags = run("Ciphers blowfish-cbc\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn ciphers_cast128_cbc_fires_w03() {
        let diags = run("Ciphers cast128-cbc\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn ciphers_rijndael_cbc_fires_w03() {
        let diags = run("Ciphers rijndael-cbc@lysator.liu.se\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    // --- Ciphers: strong ciphers must NOT fire ---

    #[test]
    fn ciphers_aes256_ctr_does_not_fire() {
        // aes256-ctr is counter mode (not CBC); strong.
        assert!(
            run("Ciphers aes256-ctr\n").is_empty(),
            "aes256-ctr is strong"
        );
    }

    #[test]
    fn ciphers_aes256_gcm_does_not_fire() {
        // AEAD - GCM mode with integrity.
        assert!(
            run("Ciphers aes256-gcm@openssh.com\n").is_empty(),
            "aes256-gcm@openssh.com is strong"
        );
    }

    #[test]
    fn ciphers_chacha20_poly1305_does_not_fire() {
        // AEAD - ChaCha20-Poly1305.
        assert!(
            run("Ciphers chacha20-poly1305@openssh.com\n").is_empty(),
            "chacha20-poly1305@openssh.com is strong"
        );
    }

    // --- MACs: MD5 MACs (grounding table section 6.1) ---

    #[test]
    fn macs_hmac_md5_fires_w03() {
        // MD5 is collision-broken; never in any RHEL crypto-policies level.
        let diags = run("MACs hmac-md5\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn macs_hmac_md5_96_fires_w03() {
        let diags = run("MACs hmac-md5-96\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn macs_hmac_md5_etm_fires_w03() {
        let diags = run("MACs hmac-md5-etm@openssh.com\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn macs_hmac_md5_96_etm_fires_w03() {
        let diags = run("MACs hmac-md5-96-etm@openssh.com\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    // --- MACs: SHA-1 MACs included per hardening-baseline scope (grounding 6.3) ---

    #[test]
    fn macs_hmac_sha1_fires_w03() {
        // SHA-1 MACs: hardening baseline. Catalog text explicitly lists SHA-1.
        // Grounding 6.3: "catalog text (MD5/SHA1) implies SHA-1 MACs fire."
        let diags = run("MACs hmac-sha1\n");
        assert_eq!(diags.len(), 1, "hmac-sha1 is in the denylist");
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn macs_hmac_sha1_96_fires_w03() {
        let diags = run("MACs hmac-sha1-96\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn macs_hmac_sha1_etm_fires_w03() {
        let diags = run("MACs hmac-sha1-etm@openssh.com\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn macs_hmac_sha1_96_etm_fires_w03() {
        let diags = run("MACs hmac-sha1-96-etm@openssh.com\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    // --- MACs: strong MACs must NOT fire ---

    #[test]
    fn macs_hmac_sha2_256_does_not_fire() {
        assert!(
            run("MACs hmac-sha2-256\n").is_empty(),
            "hmac-sha2-256 is strong"
        );
    }

    #[test]
    fn macs_hmac_sha2_512_does_not_fire() {
        assert!(
            run("MACs hmac-sha2-512\n").is_empty(),
            "hmac-sha2-512 is strong"
        );
    }

    // --- KexAlgorithms (grounding table section 6.1) ---

    #[test]
    fn kex_group1_sha1_fires_w03() {
        // 1024-bit MODP + SHA-1. NIST SP 800-131A R2 Table 4: (1024,160) disallowed.
        let diags = run("KexAlgorithms diffie-hellman-group1-sha1\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn kex_group14_sha1_fires_w03() {
        // 2048-bit MODP but SHA-1 hash - still weak via SHA-1.
        // Grounding 6.1: "do not justify denying it on key size; group14-sha256 is fine."
        let diags = run("KexAlgorithms diffie-hellman-group14-sha1\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn kex_gex_sha1_fires_w03() {
        // Group-exchange with SHA-1 hash.
        let diags = run("KexAlgorithms diffie-hellman-group-exchange-sha1\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn kex_gss_group1_sha1_fires_w03() {
        // GSSAPI group1 with SHA-1 - wildcard pattern gss-group1-sha1-*.
        let diags = run("KexAlgorithms gss-group1-sha1-toWS3vcntCHlLKZy4KYiSg==\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn kex_gss_gex_sha1_fires_w03() {
        // GSSAPI group-exchange with SHA-1 - wildcard pattern gss-gex-sha1-*.
        let diags = run("KexAlgorithms gss-gex-sha1-toWS3vcntCHlLKZy4KYiSg==\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    // --- KexAlgorithms: strong KEX must NOT fire (critical negative assertion) ---

    #[test]
    fn kex_group14_sha256_does_not_fire() {
        // 2048-bit MODP with SHA-256. Only the -sha1 variant is weak.
        // A naive contains("group14") would misfire here.
        assert!(
            run("KexAlgorithms diffie-hellman-group14-sha256\n").is_empty(),
            "diffie-hellman-group14-sha256 is strong (SHA-2 hash)"
        );
    }

    #[test]
    fn kex_group16_sha512_does_not_fire() {
        // 4096-bit MODP with SHA-512.
        assert!(
            run("KexAlgorithms diffie-hellman-group16-sha512\n").is_empty(),
            "diffie-hellman-group16-sha512 is strong"
        );
    }

    #[test]
    fn kex_group18_sha512_does_not_fire() {
        assert!(
            run("KexAlgorithms diffie-hellman-group18-sha512\n").is_empty(),
            "diffie-hellman-group18-sha512 is strong"
        );
    }

    #[test]
    fn kex_curve25519_does_not_fire() {
        assert!(
            run("KexAlgorithms curve25519-sha256\n").is_empty(),
            "curve25519-sha256 is strong"
        );
    }

    // --- HostKeyAlgorithms / PubkeyAcceptedAlgorithms / CASignatureAlgorithms ---

    #[test]
    fn hostkeyalgorithms_ssh_rsa_fires_w03() {
        // ssh-rsa: SHA-1 RSA signature. NIST SP 800-131A R2 Table 8 (SHA-1
        // sig-gen "Disallowed"); RFC 8332 defines rsa-sha2-256/512 as the
        // replacements.
        let diags = run("HostKeyAlgorithms ssh-rsa\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
        assert_eq!(diags[0].line, 1);
    }

    #[test]
    fn hostkeyalgorithms_ssh_rsa_cert_fires_w03() {
        let diags = run("HostKeyAlgorithms ssh-rsa-cert-v01@openssh.com\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn hostkeyalgorithms_ssh_dss_fires_w03() {
        // DSA / DSS: NIST SP 800-131A R2 Table 2 (DSA disallowed).
        let diags = run("HostKeyAlgorithms ssh-dss\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn hostkeyalgorithms_ssh_dss_cert_fires_w03() {
        let diags = run("HostKeyAlgorithms ssh-dss-cert-v01@openssh.com\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn pubkeyacceptedalgorithms_ssh_rsa_fires_w03() {
        // PubkeyAcceptedAlgorithms is a sibling of HostKeyAlgorithms in the
        // grounding table; same denylist applies.
        let diags = run("PubkeyAcceptedAlgorithms ssh-rsa\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn casignaturealgorithms_ssh_rsa_fires_w03() {
        let diags = run("CASignatureAlgorithms ssh-rsa\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    // HostbasedAcceptedAlgorithms is the 4th signature-algorithm directive (same
    // family as HostKeyAlgorithms / PubkeyAcceptedAlgorithms / CASignatureAlgorithms);
    // ssh-rsa (SHA-1 sig) and ssh-dss (DSA) are weak in it too. Scope ratified by
    // the owner: grounding 6.1 prose names it in-scope; the denylist table had
    // omitted it. NIST SP 800-131A R2 Table 8 (SHA-1 sig) / Table 2 (DSA).
    #[test]
    fn hostbasedacceptedalgorithms_ssh_rsa_fires_w03() {
        let diags = run("HostbasedAcceptedAlgorithms ssh-rsa\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    #[test]
    fn hostbasedacceptedalgorithms_ssh_dss_fires_w03() {
        let diags = run("HostbasedAcceptedAlgorithms ssh-dss\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
    }

    // --- Critical negative assertion: rsa-sha2-256 / rsa-sha2-512 (RFC 8332) ---

    #[test]
    fn hostkeyalgorithms_rsa_sha2_256_does_not_fire() {
        // rsa-sha2-256 is the SHA-256 RSA signature (strong). Only ssh-rsa
        // (SHA-1) is weak. A naive contains("ssh-rsa") or contains("rsa") would
        // misfire here.
        assert!(
            run("HostKeyAlgorithms rsa-sha2-256\n").is_empty(),
            "rsa-sha2-256 is a strong RSA signature algo (RFC 8332)"
        );
    }

    #[test]
    fn hostkeyalgorithms_rsa_sha2_512_does_not_fire() {
        assert!(
            run("HostKeyAlgorithms rsa-sha2-512\n").is_empty(),
            "rsa-sha2-512 is a strong RSA signature algo (RFC 8332)"
        );
    }

    #[test]
    fn pubkeyaccepted_rsa_sha2_256_does_not_fire() {
        assert!(
            run("PubkeyAcceptedAlgorithms rsa-sha2-256\n").is_empty(),
            "rsa-sha2-256 is strong in PubkeyAcceptedAlgorithms"
        );
    }

    // [STRENGTHEN] CASignatureAlgorithms: strong RSA algo must NOT fire (RFC 8332)
    //
    // CASignatureAlgorithms has a positive test (ssh-rsa fires) but no negative
    // test for the strong RSA variants. A naive contains("ssh-rsa") or starts_with("rsa")
    // impl could incorrectly fire on rsa-sha2-512 in this directive family.
    #[test]
    fn casignaturealgorithms_rsa_sha2_512_does_not_fire() {
        // rsa-sha2-512 is SHA-512 RSA (strong; RFC 8332). Only ssh-rsa (SHA-1) is weak.
        // CASignatureAlgorithms uses the same denylist as HostKeyAlgorithms; the
        // strong-RSA exemption must apply to this directive too.
        assert!(
            run("CASignatureAlgorithms rsa-sha2-512\n").is_empty(),
            "rsa-sha2-512 is a strong RSA signature algo in CASignatureAlgorithms"
        );
    }

    #[test]
    fn hostbasedacceptedalgorithms_rsa_sha2_512_does_not_fire() {
        assert!(
            run("HostbasedAcceptedAlgorithms rsa-sha2-512\n").is_empty(),
            "rsa-sha2-512 is a strong RSA signature algo in HostbasedAcceptedAlgorithms"
        );
    }

    #[test]
    fn hostbasedacceptedalgorithms_rsa_sha2_256_does_not_fire() {
        assert!(
            run("HostbasedAcceptedAlgorithms rsa-sha2-256\n").is_empty(),
            "rsa-sha2-256 is a strong RSA signature algo in HostbasedAcceptedAlgorithms"
        );
    }

    // [STRENGTHEN] gss- prefix over-fire guard (RFC 8732)
    //
    // The positive tests above (kex_gss_group1_sha1_fires_w03 and
    // kex_gss_gex_sha1_fires_w03) confirm that the -sha1 gss variants fire. But
    // they admit an impl that matches ANY token starting with "gss-" (a bare
    // prefix match), which would over-fire on the STRONG SHA-2 gss KEX algorithms
    // shipped in RHEL 9 / FIPS-compatible configurations. RFC 8732 defines
    // gss-curve25519-sha256-* and gss-group14-sha256-* as the strong replacements;
    // only the -sha1 variants are weak. The impl MUST key on the SHA-1 suffix, not
    // on the "gss-" prefix.
    #[test]
    fn kex_gss_curve25519_sha256_does_not_fire() {
        // gss-curve25519-sha256-*: RFC 8732 strong GSSAPI KEX method (SHA-256, Curve25519).
        // A bare "gss-" prefix match would incorrectly fire here.
        assert!(
            run("KexAlgorithms gss-curve25519-sha256-toWS3vcntCHlLKZy4KYiSg==\n").is_empty(),
            "gss-curve25519-sha256-* is a strong gss KEX method (RFC 8732); W03 must not fire"
        );
    }

    #[test]
    fn kex_gss_group14_sha256_does_not_fire() {
        // gss-group14-sha256-*: RFC 8732 strong GSSAPI KEX method (SHA-256, 2048-bit MODP).
        // A bare "gss-" prefix match would incorrectly fire here.
        assert!(
            run("KexAlgorithms gss-group14-sha256-toWS3vcntCHlLKZy4KYiSg==\n").is_empty(),
            "gss-group14-sha256-* is a strong gss KEX method (RFC 8732); W03 must not fire"
        );
    }

    // --- Strong-only config produces no diagnostics ---

    #[test]
    fn all_strong_ciphers_produces_zero_w03() {
        // A Ciphers line with only strong algorithms must be completely clean.
        let src =
            "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes128-ctr\n";
        assert!(
            run(src).is_empty(),
            "strong-only Ciphers line => zero W03 diagnostics"
        );
    }

    #[test]
    fn all_strong_macs_produces_zero_w03() {
        let src =
            "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256\n";
        assert!(
            run(src).is_empty(),
            "strong-only MACs line => zero W03 diagnostics"
        );
    }

    #[test]
    fn all_strong_kex_produces_zero_w03() {
        let src = "KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512\n";
        assert!(
            run(src).is_empty(),
            "strong-only KexAlgorithms line => zero W03 diagnostics"
        );
    }

    // --- Mixed strong+weak: only weak token(s) flagged ---

    #[test]
    fn ciphers_mixed_flags_only_weak_tokens() {
        // Strong (aes256-ctr) + weak (aes128-cbc). The weak entry fires; the
        // strong entry is clean. The diagnostic is on the directive line, not
        // per-token (algorithm names are comma-separated inside one arg or
        // comma-joined across multiple args - the directive line is the unit).
        let src = "Ciphers aes256-ctr,aes128-cbc\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "one directive with one weak algo => one diagnostic"
        );
        assert_eq!(diags[0].code, "sshd-W03");
        // The diagnostic message should name the offending algorithm.
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn macs_mixed_two_weak_tokens_on_one_line_fires_twice() {
        // hmac-md5 + hmac-sha1: two weak tokens on one MACs line.
        // W03 fires once per weak token (the caller sees each algorithm as a
        // distinct finding: different message text per weak name).
        let src = "MACs hmac-md5,hmac-sha1\n";
        let diags = run(src);
        // Each weak algorithm produces a separate diagnostic.
        assert_eq!(
            diags.len(),
            2,
            "two weak algos on one line => two diagnostics"
        );
        assert!(diags.iter().all(|d| d.code == "sshd-W03"));
    }

    #[test]
    fn kex_mixed_strong_and_group1_sha1() {
        // curve25519-sha256 (strong) + diffie-hellman-group1-sha1 (weak).
        let src = "KexAlgorithms curve25519-sha256,diffie-hellman-group1-sha1\n";
        let diags = run(src);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W03");
        assert!(
            diags[0].message.contains("diffie-hellman-group1-sha1"),
            "message names the offending algorithm"
        );
    }

    // --- Multiple directives: each fires independently ---

    #[test]
    fn multiple_directives_each_fires_on_correct_line() {
        // Two separate directives, one per family, each with a weak algo.
        // Diagnostics carry the correct line numbers.
        let src = "Ciphers aes128-cbc\nMACs hmac-md5\n";
        let diags = run(src);
        assert_eq!(diags.len(), 2, "one per weak directive");
        let lines: Vec<usize> = diags.iter().map(|d| d.line).collect();
        assert!(lines.contains(&1), "Ciphers line flagged");
        assert!(lines.contains(&2), "MACs line flagged");
    }

    // --- Keyword matching is case-insensitive ---

    #[test]
    fn keyword_match_is_case_insensitive() {
        // "ciphers" (all lowercase) is valid sshd_config (case-insensitive).
        let diags = run("ciphers aes128-cbc\n");
        assert_eq!(diags.len(), 1, "lowercased keyword still triggers W03");
        assert_eq!(diags[0].code, "sshd-W03");
    }

    // --- Version-independence: target=None fires the same as Rhel8/9/10 ---

    #[test]
    fn w03_fires_without_target_version() {
        // W03 is version-independent: the denylist is constant regardless of
        // --target. SshdLintContext::default() has target=None; the lint must
        // still fire (not gate on Some(target)).
        let diags = run("Ciphers aes128-cbc\n");
        assert_eq!(
            diags.len(),
            1,
            "W03 fires with target=None (version-independent)"
        );
    }

    // --- Algorithm value splitting: comma-separated ---

    #[test]
    fn comma_separated_list_splits_correctly() {
        // Three algos: two strong, one weak. Splitting on comma must produce
        // exactly one hit for aes256-cbc.
        let src = "Ciphers aes256-ctr,aes256-cbc,chacha20-poly1305@openssh.com\n";
        let diags = run(src);
        assert_eq!(diags.len(), 1, "only aes256-cbc is weak");
        assert!(diags[0].message.contains("aes256-cbc"));
    }

    #[test]
    fn whitespace_around_comma_is_trimmed() {
        // sshd_config algorithm lists sometimes appear with spaces around commas.
        // The lint must trim whitespace before matching.
        let src = "Ciphers aes256-ctr, aes128-cbc, chacha20-poly1305@openssh.com\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "aes128-cbc is weak even with surrounding spaces"
        );
        assert!(diags[0].message.contains("aes128-cbc"));
    }
}
