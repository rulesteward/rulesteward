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

/// The effective algorithm-list value for a directive's `args`, with any inline
/// `#` comment stripped and embedded double-quotes removed, or `None` if the
/// value is not a well-formed sshd-loading form.
///
/// # Inline `#` comment stripping
///
/// sshd treats a whitespace-delimited `#` as an end-of-line comment (verified
/// OpenSSH 9.9p1/10.2p1 `sshd -T`): `Ciphers aes128-cbc # legacy` is a VALID
/// line that loads `aes128-cbc` and must be linted. A genuinely malformed
/// multi-arg value (`+ aes128-cbc`, `aes128-cbc foo`) -- which sshd rejects
/// rc 255 -- still yields `None`. Only a whitespace-delimited `#`-started token
/// is a strippable comment; a `#` glued anywhere inside the value token (with or
/// without a comma, e.g. `aes128-cbc#legacy` or `aes128-cbc,#legacy`) makes it a
/// malformed cipher-spec sshd rejects (rc 255), so the value is NOT loaded and
/// the helper yields `None`.
///
/// # Embedded double-quote handling (issue #327, option b -- localized fix)
///
/// sshd strips double-quotes anywhere in a token before re-parsing the comma
/// list (verified OpenSSH 9.9p1/10.2p1 `sshd -T`). Two quote-induced arg
/// shapes reach this helper:
///
/// - **Embedded quotes in a single arg**: `Ciphers +"aes128-cbc"` -- the
///   leading `+` causes `read_arg` to read a bareword, yielding `+"aes128-cbc"`
///   (literal `"` chars) as a single arg. After stripping `"`, the effective
///   value is `+aes128-cbc`, which W06 then processes normally.
///
/// - **Quote-split multi-arg**: `Ciphers "aes128-cbc",aes256-ctr` -- `read_arg`
///   strips the outer quotes of `"aes128-cbc"` and yields `aes128-cbc`, then
///   `,aes256-ctr` (starting with `,`) becomes the next bareword token. The
///   parser therefore produces `args = ["aes128-cbc", ",aes256-ctr"]`. sshd loads
///   these as the comma-joined value `aes128-cbc,aes256-ctr`. This helper
///   recognizes the `,`-prefix signal and concatenates all effective args (no
///   separator) to reconstruct the sshd-equivalent value.
///
/// Counter-check: `Ciphers "aes128-cbc # x"` -- the parser strips outer quotes,
/// yielding the single arg `aes128-cbc # x` (which contains `#`). The `#` check
/// below suppresses it correctly, matching sshd's rejection (rc 255, verified
/// OpenSSH 10.2p1). The `,`-prefix join does not affect this case.
fn algo_list_value(args: &[String]) -> Option<String> {
    // Step 1: strip trailing inline `#` comment args.
    let effective = match args.iter().position(|a| a.starts_with('#')) {
        Some(i) => &args[..i],
        None => args,
    };

    // Step 2: assemble the raw value string.
    //
    // If all args from index 1 onward start with `,`, they were produced by the
    // tokenizer splitting a quoted-then-bareword sequence on token boundaries
    // (e.g. `"aes128-cbc",aes256-ctr` -> `["aes128-cbc", ",aes256-ctr"]`). In
    // that case, concatenate all effective args directly (no separator) to
    // reconstruct the logical comma-list sshd would see. Otherwise, two or more
    // genuinely whitespace-separated args is a real multi-arg value that sshd
    // rejects (rc 255); return None to suppress it.
    let raw: String = match effective {
        [one] => one.clone(),
        [_first, rest @ ..] if rest.iter().all(|a| a.starts_with(',')) => effective.concat(),
        _ => return None,
    };

    // Step 3a: guard against a hash inside a bareword-embedded quoted string
    // that was split by the tokenizer's whitespace boundary.
    //
    // Consider `Ciphers +"aes128-cbc # x"`: the leading `+` makes `read_arg`
    // read a bareword, which stops at the space inside the quoted part. The
    // tokenizer yields args=[`+"aes128-cbc`, `#`, `x"`]. The comment-strip
    // (step 1) removes `#` and `x"`, leaving effective=[`+"aes128-cbc`].
    // After stripping `"` we would get `+aes128-cbc` and W06 would fire --
    // a false positive, since sshd rejects `+"aes128-cbc # x"` (rc 255).
    //
    // Signal: the remaining raw value has an ODD number of `"` chars. Balanced
    // pairs (zero, two, four, ...) are fine; a lone `"` means the closing
    // quote of a quoted string was consumed by the comment-strip, which implies
    // a hash was inside the quoted string and the line is a sshd reject.
    if raw.chars().filter(|&c| c == '"').count() % 2 != 0 {
        return None;
    }

    // Step 3b: strip ALL embedded `"` characters to match sshd's quote-stripping
    // behavior. This handles single-arg forms like `+"aes128-cbc"` where the
    // leading `+` prevented quoted-string tokenization (option b localized fix).
    let value: String = raw.chars().filter(|&c| c != '"').collect();

    // Step 4: a `#` anywhere in the value (after quote-stripping) means the
    // cipher spec contains a hash character that sshd would reject (rc 255):
    // - bare glued hash: `aes128-cbc#x` (whole token, no whitespace to split on)
    // - hash-inside-quotes: `"aes128-cbc # x"` (outer quotes stripped by parser,
    //   inner ` # x` part retained in the arg, sshd rejects the whole spec)
    if value.contains('#') {
        return None;
    }

    Some(value)
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
/// [`algo_list_value`] strips a whitespace-delimited inline `#` comment and
/// enforces a single value token (rejecting any token that contains a `#`, which
/// is a non-loading sshd reject). That single value is then split on commas, and
/// each token is trimmed and checked against the denylist. One diagnostic is
/// emitted per weak token.
fn w03_directive(directive: &Directive, file: &Path, diags: &mut Vec<Diagnostic>) {
    let Some((exact_list, kind)) = weak_exact_list(&directive.keyword_lower()) else {
        return;
    };

    // Strip a trailing inline `#` comment then enforce the single-arg invariant.
    // A whitespace-delimited `#` is a valid end-of-line comment in sshd (verified
    // OpenSSH 9.9p1/10.2p1); the tokenizer keeps it literal, so
    // `Ciphers aes128-cbc # legacy` yields args=["aes128-cbc","#","legacy"]. After
    // stripping the comment, a genuinely malformed multi-arg value (which sshd
    // rejects rc 255) still yields `None` and is not flagged.
    let Some(value) = algo_list_value(&directive.args) else {
        return;
    };

    for raw_token in value.split(',') {
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

/// sshd-W06: an algorithm-list operator (`+` or `^`) names a W03-denylisted weak
/// algorithm, regardless of `--target`.
///
/// Per `sshd_config(5)`, the `+`/`-`/`^` operators act on OpenSSH's BUILT-IN
/// compile-time default set, which is DISTINCT from the crypto-policies effective
/// default visible via `sshd -T`. Some denylisted algorithms (e.g. CBC ciphers,
/// `hmac-md5`, `diffie-hellman-group1-sha1`) are absent from that built-in
/// default, so `+`/`^` genuinely reintroduces them; others
/// (`diffie-hellman-group14-sha1`, `ssh-rsa`, `hmac-sha1`) are present in the
/// built-in default on current OpenSSH, so `+`/`^` is redundant rather than
/// reintroducing.
///
/// `RuleSteward` does NOT distinguish these two cases: doing so would need per-
/// OpenSSH-version built-in default tables, and it cannot resolve crypto-policies
/// `Include` shadowing in a static single-file lint. Explicitly naming a known-
/// weak algorithm in a `+`/`^` operator is a hardening regression worth surfacing
/// either way, matching the catalog's "may reintroduce a weak default algorithm".
/// `-` (removal) is hardening and is never flagged. A bare value with no operator
/// is W03's domain and is not checked here. The denylist is scoped per-directive
/// via [`weak_exact_list`] so a cross-family algorithm (e.g. `ssh-rsa` on a
/// `Ciphers` line) does not fire.
///
/// Scans the global block AND all Match block bodies, mirroring W03.
///
/// Grounding: `sshd_config(5)` Rocky Linux 9 / OpenSSH 9.9p1 (primary source,
/// verified 2026-06-26); sshd-stig-version-grounding.md section 6.2; NIST SP
/// 800-131A R2; W03 denylist tables above.
#[must_use]
pub fn w06(blocks: &[Block], file: &Path, _ctx: &SshdLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for block in blocks {
        let directives = match block {
            Block::Global(directives) => directives,
            Block::Match(match_block) => &match_block.body,
        };
        for directive in directives {
            let Some((denylist, kind)) = weak_exact_list(&directive.keyword_lower()) else {
                continue;
            };
            // Strip a trailing inline `#` comment then enforce the single-arg
            // invariant. A whitespace-delimited `#` is a valid end-of-line comment
            // in sshd (verified OpenSSH 9.9p1/10.2p1); the tokenizer keeps it
            // literal. After stripping, a genuinely malformed value (e.g.
            // `Ciphers + aes128-cbc` or `Ciphers +a b`) -- which sshd rejects
            // rc 255 -- still yields `None` and is not flagged.
            let Some(value) = algo_list_value(&directive.args) else {
                continue;
            };
            // Determine the operator from the first non-empty comma-split token.
            // The parser tokenises on whitespace so `+algo1,algo2` arrives as a
            // single args element; after split the first token carries the operator
            // character and all remaining tokens do not.
            let mut tokens = value.split(',');
            let Some(first_raw) = tokens.next() else {
                continue;
            };
            let first_trimmed = first_raw.trim();
            let Some(operator) = first_trimmed.chars().next() else {
                continue;
            };
            if operator != '+' && operator != '^' {
                // `-` is hardening; bare value (no operator) is W03's job.
                continue;
            }
            // Strip the leading operator char from the first token and check it,
            // then check all remaining tokens (they carry no operator).
            let first_algo = first_trimmed[operator.len_utf8()..].trim();
            let all_tokens = std::iter::once(first_algo).chain(tokens.map(str::trim));
            for raw_tok in all_tokens {
                let tok = raw_tok.to_ascii_lowercase();
                if tok.is_empty() {
                    continue;
                }
                let is_weak = match kind {
                    Weak03Kind::Exact => denylist.contains(&tok.as_str()),
                    Weak03Kind::Kex => is_weak_kex(&tok),
                };
                if is_weak {
                    diags.push(anchored(
                        Severity::Warning,
                        "sshd-W06",
                        directive.span.clone(),
                        format!(
                            "operator '{operator}' names weak algorithm '{raw_tok}' in \
                             '{}': may reintroduce a weak default algorithm \
                             (NIST SP 800-131A R2)",
                            directive.keyword,
                        ),
                        file,
                        directive.line,
                    ));
                }
            }
        }
    }
    diags
}

#[cfg(test)]
mod w06_tests {
    //! sshd-W06: an algorithm-list operator (`+`/`^`) names a W03-denylisted weak
    //! algorithm, regardless of `--target`.
    //!
    //! # Grounding
    //!
    //! `sshd_config(5)` on Rocky Linux 9 / OpenSSH 9.9p1 (primary source,
    //! verified 2026-06-26): the `+`/`-`/`^` operators act on OpenSSH's BUILT-IN
    //! compile-time default set, which is DISTINCT from the crypto-policies
    //! effective default visible via `sshd -T`. `+X` appends X, `^X` prepends X,
    //! `-X` removes X. Some W03-denylisted algorithms (CBC ciphers, `hmac-md5`,
    //! `diffie-hellman-group1-sha1`) are absent from that built-in default, so
    //! `+`/`^` genuinely reintroduces them; others
    //! (`diffie-hellman-group14-sha1`, `ssh-rsa`, `hmac-sha1`) are present in the
    //! built-in default on current OpenSSH, so `+`/`^` is redundant rather than
    //! reintroducing (sshd-stig-version-grounding.md section 6.2). W06 does NOT
    //! distinguish these cases: explicitly naming a known-weak algorithm in a
    //! `+`/`^` operator is a hardening regression worth surfacing either way, so
    //! W06 fires on any `+`/`^` token in the W03 denylist (conservative, target-
    //! independent). `-` (removal) is hardening and NEVER fires W06. A value with
    //! no operator is W03's job (the bare token IS in the denylist); W06 must not
    //! fire on it. A non-algo directive (e.g. `PermitRootLogin yes`) never fires.
    //!
    //! # Parser shape (VERIFIED by reading parser.rs)
    //!
    //! The tokenizer splits on whitespace. A value like `+aes128-cbc,aes256-cbc`
    //! contains no whitespace, so it arrives as a single element in `args`:
    //! `args = ["+aes128-cbc,aes256-cbc"]`. After `algo_list_value(&args)` returns
    //! the single value token, `value.split(',')` makes the first token
    //! `"+aes128-cbc"` (operator attached) and the second `"aes256-cbc"` (no
    //! operator). The operator signal is therefore carried on the first comma-split
    //! token only.
    //!
    //! # W03/W06 interaction
    //!
    //! W06 is additive -- the impl does not suppress W03. For `Ciphers +aes128-cbc`
    //! W03 does NOT fire (the bare token `+aes128-cbc` is not in the denylist); W06
    //! must fire. For `Ciphers +aes128-cbc,aes256-cbc` W03 fires on the bare
    //! `aes256-cbc` (second token, no operator) and W06 must fire on the
    //! `+aes128-cbc` token. Tests call `w06` DIRECTLY to isolate W06.
    //!
    //! # Match-block coverage
    //!
    //! W06 scans ALL blocks (global + Match bodies), mirroring W03. An algo list
    //! with `+<weak>` inside a Match block fires W06. Pinned by a dedicated test.
    //!
    //! # Discriminating tests
    //!
    //! A trivial impl (always-empty, fire-on-any-operator, fire-on-`-`, fire-on-
    //! no-operator) must fail at least one test below. The negative assertions for
    //! `-`, no-operator, non-algo-directive, and all-strong-algo cover these axes.

    use super::w06;
    use crate::ast::Block;
    use crate::lints::SshdLintContext;
    use rulesteward_core::Severity;
    use std::path::Path;

    const FILE: &str = "/etc/ssh/sshd_config";

    fn parse(src: &str) -> Vec<Block> {
        crate::parser::parse_config_str_located(src, Path::new(FILE)).expect("fixture parses")
    }

    fn run(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        w06(&parse(src), Path::new(FILE), &SshdLintContext::default())
    }

    // -----------------------------------------------------------------------
    // FIRES: `+` operator with weak algorithm(s) in the list
    // -----------------------------------------------------------------------

    #[test]
    fn ciphers_plus_aes128_cbc_fires_w06() {
        // `+aes128-cbc` appends a CBC cipher to the default set.
        // W03 does NOT fire here (bare token "+aes128-cbc" != "aes128-cbc").
        // W06 MUST fire (after stripping `+`, token is in WEAK_CIPHERS).
        let diags = run("Ciphers +aes128-cbc\n");
        assert_eq!(diags.len(), 1, "one weak `+` cipher => one W06 diagnostic");
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(diags[0].severity, Severity::Warning);
        assert_eq!(diags[0].line, 1, "diagnostic anchored to the Ciphers line");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the reintroduced weak algorithm, got: {}",
            diags[0].message
        );
        assert!(
            diags[0].message.contains('+'),
            "message names the operator, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn ciphers_caret_aes256_cbc_fires_w06() {
        // `^aes256-cbc` prepends a CBC cipher to the default set.
        // Both `+` and `^` reintroduce to the default; `^` must also fire.
        let diags = run("Ciphers ^aes256-cbc\n");
        assert_eq!(diags.len(), 1, "`^` with weak cipher => one W06 diagnostic");
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(diags[0].line, 1);
        assert!(
            diags[0].message.contains("aes256-cbc"),
            "message names the reintroduced weak algorithm, got: {}",
            diags[0].message
        );
        assert!(
            diags[0].message.contains('^'),
            "message names the `^` operator, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn spaced_operator_does_not_fire_w06() {
        // `Ciphers + aes128-cbc` (a space after the operator) is a fatal parse
        // error in sshd ("Bad SSH2 cipher spec '+'", rc 255 on rocky9), so the
        // daemon never loads it. RuleSteward's tolerant parser splits it into
        // multiple args; W06 must NOT flag a "reintroduction" on a line the daemon
        // rejects. A well-formed algorithm list is a single comma-separated arg.
        assert!(
            run("Ciphers + aes128-cbc\n").is_empty(),
            "a space-separated (malformed, non-loading) algo line must not fire W06"
        );
    }

    #[test]
    fn operator_with_extra_arg_does_not_fire_w06() {
        // `Ciphers +aes256-ctr aes128-cbc` has an extra whitespace-separated arg,
        // which sshd rejects ("extra arguments at end of line", rc 255 on rocky9).
        // W06 only evaluates the single-arg (well-formed) algorithm-list form.
        assert!(
            run("Ciphers +aes256-ctr aes128-cbc\n").is_empty(),
            "a multi-arg (malformed, non-loading) algo line must not fire W06"
        );
    }

    #[test]
    fn macs_plus_hmac_md5_fires_w06() {
        // `+hmac-md5` appends an MD5 MAC to the default set.
        let diags = run("MACs +hmac-md5\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(diags[0].line, 1);
        assert!(
            diags[0].message.contains("hmac-md5"),
            "message names the reintroduced weak MAC, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn kex_plus_group1_sha1_fires_w06() {
        // `+diffie-hellman-group1-sha1` appends a 1024-bit MODP/SHA-1 KEX.
        let diags = run("KexAlgorithms +diffie-hellman-group1-sha1\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(diags[0].line, 1);
        assert!(
            diags[0].message.contains("diffie-hellman-group1-sha1"),
            "message names the reintroduced weak KEX, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn hostbasedacceptedalgorithms_plus_ssh_rsa_fires_w06() {
        // `+ssh-rsa` on HostbasedAcceptedAlgorithms (signature family). Only
        // HostKeyAlgorithms was previously pinned for W06; this pins the other
        // signature families so a mutant narrowing weak_exact_list's match arm
        // to drop hostbasedacceptedalgorithms dies.
        let diags = run("HostbasedAcceptedAlgorithms +ssh-rsa\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(diags[0].line, 1);
        assert!(
            diags[0].message.contains("ssh-rsa"),
            "message names the reintroduced weak signature algo, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn casignaturealgorithms_plus_ssh_rsa_fires_w06() {
        // `+ssh-rsa` on CASignatureAlgorithms (signature family). Kills a mutant
        // narrowing weak_exact_list to drop casignaturealgorithms.
        let diags = run("CASignatureAlgorithms +ssh-rsa\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(diags[0].line, 1);
        assert!(
            diags[0].message.contains("ssh-rsa"),
            "message names the reintroduced weak signature algo, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn pubkeyacceptedalgorithms_plus_ssh_rsa_fires_w06() {
        // `+ssh-rsa` on PubkeyAcceptedAlgorithms (signature family). Kills a
        // mutant narrowing weak_exact_list to drop pubkeyacceptedalgorithms.
        let diags = run("PubkeyAcceptedAlgorithms +ssh-rsa\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(diags[0].line, 1);
        assert!(
            diags[0].message.contains("ssh-rsa"),
            "message names the reintroduced weak signature algo, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn hostkeyalgorithms_plus_ssh_rsa_fires_w06() {
        // `+ssh-rsa` appends SHA-1 RSA signature algorithm.
        let diags = run("HostKeyAlgorithms +ssh-rsa\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(diags[0].line, 1);
        assert!(
            diags[0].message.contains("ssh-rsa"),
            "message names the reintroduced weak hostkey algo, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn kex_caret_gss_group1_sha1_fires_w06() {
        // `^gss-group1-sha1-<oid>` prepends a weak GSS KEX (SHA-1 variant).
        // The gss-prefix matching from W03 must also apply after stripping `^`.
        let diags = run("KexAlgorithms ^gss-group1-sha1-toWS3vcntCHlLKZy4KYiSg==\n");
        assert_eq!(
            diags.len(),
            1,
            "`^` with gss-sha1 KEX => one W06 diagnostic"
        );
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(diags[0].line, 1);
        assert!(
            diags[0].message.contains("gss-group1-sha1-"),
            "message names the reintroduced gss-sha1 KEX, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn ciphers_plus_mixed_weak_and_strong_fires_w06_for_weak() {
        // `Ciphers +aes128-cbc,aes256-ctr`: the first comma-split token is
        // `+aes128-cbc` (weak), the second is `aes256-ctr` (strong, no operator).
        // Parser shape: `args = ["+aes128-cbc,aes256-ctr"]`; after join+split on
        // comma the first token carries the operator, second does not.
        // W06 must fire for the weak token. The presence of a strong algo in the
        // same list must NOT suppress the finding.
        let diags = run("Ciphers +aes128-cbc,aes256-ctr\n");
        assert_eq!(
            diags.len(),
            1,
            "weak `+` token in mixed list => one W06 diagnostic"
        );
        assert_eq!(diags[0].code, "sshd-W06");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the reintroduced weak cipher, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn ciphers_plus_strong_then_weak_fires_w06_for_tail_weak() {
        // `Ciphers +aes256-ctr,aes128-cbc`: the operator-bearing FIRST token is
        // STRONG (aes256-ctr) and the weak token (aes128-cbc) is later in the
        // chain. W06 must scan the whole list under the operator, not just the
        // first comma-split token. Pins the chained-tail scan: a mutant that
        // checks only the operator-bearing first token (and never the rest of the
        // list) would miss the weak tail and die on this test.
        let diags = run("Ciphers +aes256-ctr,aes128-cbc\n");
        assert_eq!(
            diags.len(),
            1,
            "weak tail token under `+` operator => one W06 diagnostic"
        );
        assert_eq!(diags[0].code, "sshd-W06");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak tail cipher, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn ciphers_plus_two_later_weak_tokens_fires_twice() {
        // `Ciphers +aes256-ctr,aes128-cbc,aes192-cbc`: strong first token, then
        // TWO weak tokens later in the chain. W06 must fire once per weak token
        // (two diagnostics). Pins per-token emission over the chained tail; a
        // mutant that emits at most one diagnostic, or stops after the first weak
        // hit, dies here.
        let diags = run("Ciphers +aes256-ctr,aes128-cbc,aes192-cbc\n");
        assert_eq!(
            diags.len(),
            2,
            "two weak tail tokens under `+` => two W06 diagnostics"
        );
        assert!(
            diags.iter().all(|d| d.code == "sshd-W06"),
            "both diagnostics are sshd-W06"
        );
        assert!(
            diags.iter().any(|d| d.message.contains("aes128-cbc")),
            "one diagnostic names aes128-cbc"
        );
        assert!(
            diags.iter().any(|d| d.message.contains("aes192-cbc")),
            "one diagnostic names aes192-cbc"
        );
    }

    // -----------------------------------------------------------------------
    // DOES NOT FIRE: `-` operator (removal = hardening)
    // -----------------------------------------------------------------------

    #[test]
    fn ciphers_minus_aes128_cbc_does_not_fire_w06() {
        // `-aes128-cbc` REMOVES a cipher from the default. Removal is hardening.
        // W06 must NEVER fire on `-`. This is the critical discriminator against
        // a trivial "fire on any prefix operator" impl.
        assert!(
            run("Ciphers -aes128-cbc\n").is_empty(),
            "removal operator `-` is hardening; W06 must not fire"
        );
    }

    // -----------------------------------------------------------------------
    // DOES NOT FIRE: no operator (bare algo, W03's job)
    // -----------------------------------------------------------------------

    #[test]
    fn ciphers_bare_aes128_cbc_does_not_fire_w06() {
        // `Ciphers aes128-cbc` has no operator - this is W03's domain, not W06.
        // W06 must NOT fire on a bare (no-prefix-operator) weak algorithm.
        // This is the critical discriminator against a "fire when weak algo present"
        // impl that ignores the operator.
        assert!(
            run("Ciphers aes128-cbc\n").is_empty(),
            "no operator: bare weak cipher is W03's domain, W06 must not fire"
        );
    }

    // -----------------------------------------------------------------------
    // DOES NOT FIRE: operator present but only strong algorithms
    // -----------------------------------------------------------------------

    #[test]
    fn ciphers_plus_only_strong_does_not_fire_w06() {
        // `+aes256-gcm@openssh.com`: operator present but the algo is strong.
        // An impl that fires on any `+`/`^` regardless of the denylist check
        // would incorrectly fire here.
        assert!(
            run("Ciphers +aes256-gcm@openssh.com\n").is_empty(),
            "`+` with a strong cipher only; W06 must not fire"
        );
    }

    #[test]
    fn ciphers_caret_only_strong_does_not_fire_w06() {
        // `^aes256-gcm@openssh.com,chacha20-poly1305@openssh.com`: operator
        // present, all algos strong. W06 must not fire.
        assert!(
            run("Ciphers ^aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n").is_empty(),
            "`^` with all-strong ciphers; W06 must not fire"
        );
    }

    // -----------------------------------------------------------------------
    // DOES NOT FIRE: cross-family algorithm (denylist is scoped PER-DIRECTIVE)
    // -----------------------------------------------------------------------

    #[test]
    fn ciphers_plus_cross_family_algo_does_not_fire_w06() {
        // `Ciphers +ssh-rsa`: ssh-rsa is in WEAK_HOSTKEY but NOT in WEAK_CIPHERS.
        // W06 must scope the denylist PER-DIRECTIVE via weak_exact_list(keyword):
        // for `Ciphers` the relevant denylist is WEAK_CIPHERS, and ssh-rsa is not
        // in it, so W06 must NOT fire. This kills a wrong impl that strips the
        // operator and checks the stripped token against the UNION of all
        // denylists (which would incorrectly fire here because ssh-rsa is weak in
        // some OTHER directive family).
        assert!(
            run("Ciphers +ssh-rsa\n").is_empty(),
            "ssh-rsa is weak for hostkey algos, not for Ciphers; W06 must scope \
             the denylist per-directive and not fire here"
        );
    }

    #[test]
    fn macs_plus_cipher_algo_does_not_fire_w06() {
        // Symmetric cross-family check: `MACs +aes128-cbc`. aes128-cbc is in
        // WEAK_CIPHERS but NOT in WEAK_MACS. For the `MACs` directive the relevant
        // denylist is WEAK_MACS, so W06 must NOT fire. A union-checking impl would
        // wrongly fire here.
        assert!(
            run("MACs +aes128-cbc\n").is_empty(),
            "aes128-cbc is weak for Ciphers, not for MACs; W06 must scope the \
             denylist per-directive and not fire here"
        );
    }

    // -----------------------------------------------------------------------
    // DOES NOT FIRE: non-algorithm directive
    // -----------------------------------------------------------------------

    #[test]
    fn permit_root_login_does_not_fire_w06() {
        // `PermitRootLogin yes` is not an algorithm-list directive; W06 must
        // not fire on it regardless of value content.
        assert!(
            run("PermitRootLogin yes\n").is_empty(),
            "non-algorithm directive must not trigger W06"
        );
    }

    // -----------------------------------------------------------------------
    // Match block: W06 scans Match bodies (mirrors W03 behavior)
    // -----------------------------------------------------------------------

    #[test]
    fn match_block_plus_weak_cipher_fires_w06() {
        // An algo list with `+<weak>` inside a Match block must fire W06.
        // W03 scans all blocks (global + Match); W06 must mirror this behavior.
        // Pinning this prevents an impl that only scans the global block.
        let src = "Match Address 192.168.1.0/24\n    Ciphers +aes128-cbc\n";
        let diags = run(src);
        assert_eq!(
            diags.len(),
            1,
            "`+<weak>` inside a Match block must fire W06"
        );
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(
            diags[0].line, 2,
            "diagnostic anchored to the Ciphers line inside Match"
        );
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the reintroduced weak cipher, got: {}",
            diags[0].message
        );
    }

    // -----------------------------------------------------------------------
    // Line number anchoring
    // -----------------------------------------------------------------------

    #[test]
    fn w06_diagnostic_is_anchored_to_correct_line() {
        // Multiple directives; the W06 diagnostic must report the line of the
        // offending algo-list directive, not line 1 or some other line.
        let src = "PermitRootLogin no\nMaxAuthTries 4\nCiphers +aes128-cbc\n";
        let diags = run(src);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "sshd-W06");
        assert_eq!(
            diags[0].line, 3,
            "W06 anchored to the Ciphers line (line 3)"
        );
    }

    // -----------------------------------------------------------------------
    // Code is exactly "sshd-W06" and severity is Warning
    // -----------------------------------------------------------------------

    #[test]
    fn w06_code_is_sshd_w06_and_severity_is_warning() {
        let diags = run("MACs +hmac-sha1\n");
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].code, "sshd-W06",
            "diagnostic code must be exactly sshd-W06"
        );
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "W06 is a Warning-level diagnostic"
        );
    }

    // -----------------------------------------------------------------------
    // Inline comment: a VALID sshd-loading `+weak` line must still fire W06
    // -----------------------------------------------------------------------

    #[test]
    fn inline_comment_line_still_fires_w06() {
        // `Ciphers +aes128-cbc # legacy` -- the ` # legacy` is a whitespace-delimited
        // inline comment; sshd strips it and processes `+aes128-cbc`, reintroducing a
        // weak CBC cipher (rc=0, OpenSSH 9.9p1 / 10.2p1). RuleSteward's tokenizer does
        // NOT strip inline comments, so this tokenizes to args=["+aes128-cbc","#",
        // "legacy"] (3 args) and the W06 `args.len() != 1` guard currently suppresses
        // it -- a FALSE NEGATIVE on a valid reintroduction line. W06 must fire and
        // name the `+` operator + aes128-cbc. RED until the shared comment-strip
        // helper lands. (Contrast `spaced_operator_does_not_fire_w06` /
        // `operator_with_extra_arg_does_not_fire_w06`: those have NO `#` and are real
        // sshd rc-255 rejects that must STAY suppressed.)
        let diags = run("Ciphers +aes128-cbc # legacy\n");
        assert_eq!(
            diags.len(),
            1,
            "valid (comment-stripped) `+weak` line => one W06"
        );
        assert_eq!(diags[0].code, "sshd-W06");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the reintroduced weak algorithm, got: {}",
            diags[0].message
        );
        assert!(
            diags[0].message.contains('+'),
            "message names the operator, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn comma_glued_hash_does_not_fire_w06() {
        // A `#` glued AFTER a comma (no whitespace before it) is NOT an inline
        // comment: the operator value stays ONE token (`+aes128-cbc,#legacy`), and
        // sshd parses it as a single malformed cipher spec, REJECTING the line
        // ("Bad SSH2 cipher spec", rc 255 on OpenSSH 10.2p1) -- the daemon never
        // loads it. Only a WHITESPACE-delimited `#` starts a comment (see
        // `inline_comment_line_still_fires_w06`). The comment-strip helper only
        // strips a `#` that STARTS its own arg, so it leaves the bare weak token
        // exposed and W06 currently FIRES -- a false positive in the #325 class.
        // W06 must NOT fire on these non-loading lines.
        assert!(
            run("Ciphers +aes256-ctr,aes128-cbc,#x\n").is_empty(),
            "comma-glued # after a `+` list (one malformed token, sshd rc 255) must not fire W06"
        );
        assert!(
            run("Ciphers +aes128-cbc,#legacy\n").is_empty(),
            "comma-glued # in a `+` value (one malformed token, sshd rc 255) must not fire W06"
        );
    }

    // -----------------------------------------------------------------------
    // Embedded double-quotes inside algo-list value (issue #327, option b)
    // -----------------------------------------------------------------------
    //
    // sshd strips double-quotes anywhere in a token before re-parsing the cipher
    // spec (verified OpenSSH 9.9p1 / 10.2p1 `sshd -T -f <fixture>`). Embedded
    // quotes can reach W06 in two ways:
    //
    //   1. `Ciphers +"aes128-cbc"`: the leading `+` prevents read_arg from
    //      entering quoted-string mode, so the whole token `+"aes128-cbc"` (with
    //      literal embedded quotes) arrives as a single arg. sshd sees `+aes128-cbc`
    //      (quotes stripped) and reintroduces aes128-cbc -- W06 must fire.
    //      Grounding: `sshd -T -f <fixture>` -> `ciphers ...,aes128-cbc` (exit 0).
    //
    //   2. Counter-check: `Ciphers +"aes128-cbc # x"` -- the token after `+` has
    //      hash-inside-quotes; the tokenizer produces args=[`+"aes128-cbc # x"`].
    //      sshd rejects "Bad SSH2 cipher spec" (rc 255) -- W06 must NOT fire.

    #[test]
    fn quoted_plus_weak_algo_fires_w06() {
        // `Ciphers +"aes128-cbc"` -- the `+` prevents quoted-string tokenization;
        // the parser produces args=[`+"aes128-cbc"`] (literal embedded quotes).
        // sshd strips the quotes and loads the default set plus aes128-cbc (exit 0,
        // verified OpenSSH 10.2p1 `sshd -T`). W06 must fire on aes128-cbc.
        let diags = run("Ciphers +\"aes128-cbc\"\n");
        assert_eq!(
            diags.len(),
            1,
            "`+\"aes128-cbc\"` reintroduces weak aes128-cbc => one W06; got: {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W06");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
        assert!(
            diags[0].message.contains('+'),
            "message names the operator, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn quoted_plus_hash_inside_quotes_does_not_fire_w06() {
        // `Ciphers +"aes128-cbc # x"` -- embedded `#` inside the quoted part.
        // The parser yields args=[`+"aes128-cbc # x"`] (literal embedded quotes and
        // a hash). sshd sees the whole thing as one malformed spec (rc 255, verified
        // OpenSSH 10.2p1) and rejects it. W06 must NOT fire.
        assert!(
            run("Ciphers +\"aes128-cbc # x\"\n").is_empty(),
            "embedded hash inside operator-quoted value is a non-loading sshd rc-255 reject; \
             W06 must not fire"
        );
    }

    // -----------------------------------------------------------------------
    // Glued-hash-after-closing-quote regression (issue #327 fix regression)
    // -----------------------------------------------------------------------
    //
    // sshd_config tokenization (verified OpenSSH 10.2p1 `sshd -T`):
    //   - `Ciphers +"aes128-cbc"#x`  -> Bad SSH2 cipher spec '+aes128-cbc#x' (rc 255)
    //     The `+` forces bareword mode; the whole token `+"aes128-cbc"#x` is one arg.
    //     After stripping `"`, value = `+aes128-cbc#x`; the `#` embedded in the value
    //     is caught by step 4 of algo_list_value and suppresses the finding. CORRECT.
    //   - `Ciphers +"aes128-cbc" #x` -> ciphers includes aes128-cbc (rc 0, exit 0).
    //     The `+` bareword ends at the space; args = [`+"aes128-cbc"`, `#x`].
    //     After comment-strip and quote-strip, value = `+aes128-cbc`; W06 fires. CORRECT.
    //
    // These killing tests confirm the W06 glued/spaced discrimination works correctly:

    #[test]
    fn glued_hash_after_closing_quote_plus_prefix_does_not_fire_w06() {
        // `Ciphers +"aes128-cbc"#x` -- `#x` glued directly to the closing quote.
        // The leading `+` forces bareword tokenization; the whole token
        // `+"aes128-cbc"#x` arrives as ONE arg with embedded `"` and `#`.
        // After quote-strip: `+aes128-cbc#x`; the `#` is in the cipher spec.
        // sshd rejects: "Bad SSH2 cipher spec '+aes128-cbc#x'" (rc 255, verified
        // OpenSSH 10.2p1 `sshd -T`). W06 must NOT fire.
        assert!(
            run("Ciphers +\"aes128-cbc\"#x\n").is_empty(),
            "glued `#` after closing quote with `+` prefix: sshd rc 255 => W06 must not fire"
        );
    }

    #[test]
    fn spaced_hash_after_closing_quote_plus_prefix_fires_w06() {
        // `Ciphers +"aes128-cbc" #x` -- SPACE before `#x` (inline comment).
        // The `+` forces bareword mode; the bareword ends at the space, yielding
        // args=[`+"aes128-cbc"`, `#x`]. After comment-strip (removes `#x`) and
        // quote-strip (removes `"`), value = `+aes128-cbc`. sshd strips quotes and
        // loads the default set plus aes128-cbc (rc 0, verified OpenSSH 10.2p1
        // `sshd -T`). W06 must fire on aes128-cbc.
        let diags = run("Ciphers +\"aes128-cbc\" #x\n");
        assert_eq!(
            diags.len(),
            1,
            "`+\"aes128-cbc\"` with spaced inline comment loads aes128-cbc => one W06; \
             got: {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W06");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
        assert!(
            diags[0].message.contains('+'),
            "message names the operator, got: {}",
            diags[0].message
        );
    }
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
    fn spaces_around_commas_do_not_fire_w03() {
        // Spaces AFTER the commas (`aes256-ctr, aes128-cbc, ...`) make this a
        // multi-arg value: the whitespace tokenizer yields three args. sshd
        // REJECTS it as a fatal parse error ("keyword Ciphers extra arguments at
        // end of line", rc 255 on rocky9.8 / OpenSSH 9.9p1), so the daemon never
        // loads the line. W03 must NOT flag a non-loading line -- this is the
        // exact #325 bug class. A well-formed algorithm list is a SINGLE
        // comma-separated token with no internal whitespace (see
        // `comma_separated_list_splits_correctly` and
        // `ciphers_mixed_flags_only_weak_tokens` for the valid single-arg form).
        // RED today (the unguarded lint wrongly fires on `aes128-cbc`); GREEN
        // once `w03_directive` adds the `args.len() != 1` guard.
        assert!(
            run("Ciphers aes256-ctr, aes128-cbc, chacha20-poly1305@openssh.com\n").is_empty(),
            "spaces around commas => multiple args => sshd rejects rc 255 => W03 must not fire"
        );
    }

    // --- Multi-arg guard: malformed (non-loading) lines must NOT fire W03 ---
    //
    // A well-formed algorithm-list value is a SINGLE comma-separated token with
    // no internal whitespace. Internal whitespace (e.g. `Ciphers + aes128-cbc`
    // or `Ciphers aes128-cbc foo`) is a FATAL sshd parse error (rc 255 on
    // rocky9 / OpenSSH 9.9p1) -- "Bad SSH2 cipher spec" / "extra arguments at
    // end of line". The daemon never loads such a line, so W03 must not flag it.
    // W06 already enforces this via `args.len() != 1`; W03 is missing that guard
    // (issue #325). These tests are RED until `w03_directive` adds the same check.
    //
    // Regression guard (GREEN, already passes): `ciphers_mixed_flags_only_weak_tokens`
    // covers `Ciphers aes256-ctr,aes128-cbc\n` -- a valid single-arg comma-list
    // that MUST still fire W03. The guard below confirms the future fix does not
    // over-suppress that case; no duplicate is needed here.

    #[test]
    fn spaced_operator_does_not_fire_w03() {
        // `Ciphers + aes128-cbc` has a space after `+`, which sshd rejects as
        // "Bad SSH2 cipher spec '+'", rc 255 on rocky9 / OpenSSH 9.9p1. The
        // tolerant parser splits this into args=["+", "aes128-cbc"]; W03 must
        // NOT flag the non-loading line. (Mirrors W06 guard `spaced_operator_does_not_fire_w06`.)
        assert!(
            run("Ciphers + aes128-cbc\n").is_empty(),
            "a space-separated (malformed, non-loading) algo line must not fire W03"
        );
    }

    #[test]
    fn extra_arg_does_not_fire_w03() {
        // `Ciphers aes128-cbc foo` has an extra whitespace-separated arg, which
        // sshd rejects as "extra arguments at end of line", rc 255 on rocky9.
        // W03 must NOT flag it. (Mirrors W06 guard `operator_with_extra_arg_does_not_fire_w06`.)
        assert!(
            run("Ciphers aes128-cbc foo\n").is_empty(),
            "a multi-arg (malformed, non-loading) algo line must not fire W03"
        );
    }

    #[test]
    fn macs_extra_arg_does_not_fire_w03() {
        // `MACs hmac-md5 extra` -- extra whitespace-separated arg, fatal sshd
        // parse error ("extra arguments at end of line", rc 255 on rocky9).
        // W03 must NOT emit a diagnostic for the non-loading line.
        assert!(
            run("MACs hmac-md5 extra\n").is_empty(),
            "a multi-arg MACs line (malformed, non-loading) must not fire W03"
        );
    }

    #[test]
    fn kex_extra_arg_does_not_fire_w03() {
        // `KexAlgorithms diffie-hellman-group1-sha1 foo` -- extra arg, fatal sshd
        // parse error ("extra arguments at end of line", rc 255 on rocky9).
        // W03 covers KexAlgorithms via `is_weak_kex` (see `kex_group1_sha1_fires_w03`
        // confirming the single-arg form fires); the multi-arg form must NOT fire.
        assert!(
            run("KexAlgorithms diffie-hellman-group1-sha1 foo\n").is_empty(),
            "a multi-arg KexAlgorithms line (malformed, non-loading) must not fire W03"
        );
    }

    // --- Inline comments: VALID sshd-loading lines that must still fire W03 ---
    //
    // sshd treats a WHITESPACE-delimited `#` as an end-of-line comment and loads
    // the directive normally (verified rc=0 with the weak value taking effect on
    // OpenSSH 9.9p1 and 10.2p1). RuleSteward's tokenizer does NOT strip inline
    // comments (parser.rs: "There are no inline comments"; `tokenize_line("Banner
    // x#y")` keeps `x#y` as one token), so a commented line tokenizes to >1 arg
    // and the `args.len() != 1` multi-arg guard wrongly suppresses W03 on a VALID,
    // sshd-loading weak-cipher line. These must-fire tests are RED until the impl
    // adds a comment-strip helper (shared by W03 and W06). Contrast the genuinely
    // malformed multi-arg guard tests above (no `#`): those are real sshd rc-255
    // rejects and must STAY suppressed.

    #[test]
    fn inline_comment_line_still_fires_w03() {
        // `Ciphers aes128-cbc # legacy` -- the ` # legacy` is a whitespace-delimited
        // inline comment; sshd strips it and loads `aes128-cbc` (rc=0, OpenSSH
        // 9.9p1 / 10.2p1). The tolerant tokenizer yields args=["aes128-cbc","#",
        // "legacy"] (3 args), so the multi-arg guard currently suppresses W03 -- a
        // FALSE NEGATIVE on a valid weak-cipher line. W03 must fire and name aes128-cbc.
        let diags = run("Ciphers aes128-cbc # legacy\n");
        assert_eq!(
            diags.len(),
            1,
            "valid (comment-stripped) weak line => one W03"
        );
        assert_eq!(diags[0].code, "sshd-W03");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn inline_comment_no_space_still_fires_w03() {
        // `Ciphers aes128-cbc #legacy` -- no space between `#` and the comment word,
        // but there IS a space BEFORE the `#`, so `#legacy` is a separate token and
        // sshd treats it as a comment, loading aes128-cbc (rc=0, OpenSSH 9.9p1 /
        // 10.2p1). The tokenizer yields args=["aes128-cbc","#legacy"] (2 args), so
        // the multi-arg guard currently suppresses W03 (false negative). Must fire.
        let diags = run("Ciphers aes128-cbc #legacy\n");
        assert_eq!(
            diags.len(),
            1,
            "comment token after value still leaves a valid weak line"
        );
        assert_eq!(diags[0].code, "sshd-W03");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn comma_list_with_inline_comment_fires_w03() {
        // `Ciphers aes256-ctr,aes128-cbc # note` -- a valid single comma-list value
        // (one token `aes256-ctr,aes128-cbc`) followed by a whitespace-delimited
        // inline comment. sshd strips ` # note` and loads the list (rc=0, OpenSSH
        // 9.9p1 / 10.2p1). The tokenizer yields args=["aes256-ctr,aes128-cbc","#",
        // "note"] (3 args); the multi-arg guard currently suppresses W03. The line
        // is valid and contains weak aes128-cbc -- W03 must fire.
        let diags = run("Ciphers aes256-ctr,aes128-cbc # note\n");
        assert_eq!(
            diags.len(),
            1,
            "comma-list + comment is a valid weak line => one W03"
        );
        assert_eq!(diags[0].code, "sshd-W03");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn glued_hash_does_not_fire_w03() {
        // `Ciphers aes128-cbc#legacy` -- NO whitespace before `#`, so the tokenizer
        // keeps it as ONE token `aes128-cbc#legacy` (parser.rs
        // `tokenize_line_keeps_hash_inside_a_bare_token`). sshd does NOT treat a
        // glued `#` as a comment: it parses the whole token as a cipher spec and
        // REJECTS it ("Bad SSH2 cipher spec", rc 255 on OpenSSH 9.9p1 / 10.2p1), so
        // the daemon never loads the line. The token does not exactly match the weak
        // denylist entry `aes128-cbc` either. W03 must NOT fire -- this stays a guard.
        assert!(
            run("Ciphers aes128-cbc#legacy\n").is_empty(),
            "a glued value#comment token is a non-loading sshd reject and must not fire W03"
        );
    }

    // -----------------------------------------------------------------------
    // Embedded double-quotes inside algo-list value (issue #327, option b)
    // -----------------------------------------------------------------------
    //
    // sshd strips double-quotes anywhere in a token before re-parsing the cipher
    // spec (verified OpenSSH 9.9p1 / 10.2p1 `sshd -T -f <fixture>`). The
    // parser may produce either: a single arg with embedded `"` chars (for the
    // `+"aes128-cbc"` case, where the leading `+` means read_arg reads a
    // bareword), or multiple args (for `"aes128-cbc",aes256-ctr`, where
    // read_arg strips the outer quotes -> `aes128-cbc`, then `,aes256-ctr` is
    // the next bareword token starting with `,`). Both cases must fire W03 when
    // the underlying algorithm is in the denylist; counter-checks must still hold.
    //
    // Grounding: `sshd -T -f <fixture>` (OpenSSH 10.2p1, run 2026-06-29):
    //   - `Ciphers "aes128-cbc",aes256-ctr` -> ciphers aes128-cbc,aes256-ctr (exit 0)
    //   - `Ciphers "aes256-ctr,aes128-cbc"` -> ciphers aes256-ctr,aes128-cbc (exit 0)
    //   - `Ciphers "aes128-cbc # x"` -> Bad SSH2 cipher spec (exit 255)
    //   - `Ciphers "aes128-cbc # x",aes256-ctr` -> Bad SSH2 cipher spec (exit 255)

    #[test]
    fn quoted_mixed_weak_algo_fires_w03() {
        // `Ciphers "aes128-cbc",aes256-ctr` -- the quoted `"aes128-cbc"` part is
        // tokenized as one arg (`aes128-cbc`, quotes stripped by read_arg), then
        // `,aes256-ctr` (starting with `,`) is the next bareword token. The parser
        // yields args=["aes128-cbc", ",aes256-ctr"]. sshd strips quotes and loads
        // the comma-joined cipher list including aes128-cbc (exit 0, OpenSSH 10.2p1
        // `sshd -T`). W03 must fire on aes128-cbc.
        let diags = run("Ciphers \"aes128-cbc\",aes256-ctr\n");
        assert_eq!(
            diags.len(),
            1,
            "quoted-arg+bareword list with weak aes128-cbc => one W03; got: {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W03");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn hash_inside_quotes_does_not_fire_w03() {
        // `Ciphers "aes128-cbc # x"` -- hash INSIDE the quoted part.
        // The parser strips the outer quotes and yields args=["aes128-cbc # x"].
        // sshd rejects "Bad SSH2 cipher spec 'aes128-cbc # x'" (exit 255, verified
        // OpenSSH 10.2p1). The daemon never loads this line; W03 must NOT fire.
        assert!(
            run("Ciphers \"aes128-cbc # x\"\n").is_empty(),
            "hash inside quotes is a non-loading sshd rc-255 reject; W03 must not fire"
        );
    }

    #[test]
    fn hash_inside_quotes_with_continuation_does_not_fire_w03() {
        // `Ciphers "aes128-cbc # x",aes256-ctr` -- hash-inside-quotes with a
        // comma-prefixed continuation. The parser yields args=["aes128-cbc # x",
        // ",aes256-ctr"]. sshd sees the whole joined value as one malformed spec
        // (exit 255, verified OpenSSH 10.2p1). W03 must NOT fire.
        assert!(
            run("Ciphers \"aes128-cbc # x\",aes256-ctr\n").is_empty(),
            "hash inside quotes with comma continuation is a sshd rc-255 reject; \
             W03 must not fire"
        );
    }

    #[test]
    fn fully_quoted_value_still_fires_w03() {
        // `Ciphers "aes256-ctr,aes128-cbc"` -- whole value in one quoted token.
        // The parser yields args=["aes256-ctr,aes128-cbc"] (no embedded `"`).
        // sshd loads aes256-ctr,aes128-cbc (exit 0, OpenSSH 10.2p1). W03 already
        // fires without the quote fix, but must still fire after (no regression).
        let diags = run("Ciphers \"aes256-ctr,aes128-cbc\"\n");
        assert_eq!(
            diags.len(),
            1,
            "fully-quoted list with weak aes128-cbc => one W03; got: {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W03");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn comma_glued_hash_does_not_fire_w03() {
        // A `#` glued AFTER a comma (no whitespace before it) is NOT an inline
        // comment: the tokenizer keeps the whole value as ONE arg
        // (`aes128-cbc,#legacy`), and sshd parses it as a single malformed cipher
        // spec, REJECTING the line ("Bad SSH2 cipher spec", rc 255 on OpenSSH
        // 10.2p1), so the daemon never loads it. Only a WHITESPACE-delimited `#`
        // starts a comment (see `inline_comment_line_still_fires_w03`); a
        // comma-glued `#` is part of the malformed token. The comment-strip helper
        // only strips a `#` that STARTS its own arg, so it leaves the bare weak
        // token before the `#` exposed and W03 currently FIRES -- a false positive
        // in the #325 class. W03 must NOT fire on these non-loading lines.
        assert!(
            run("Ciphers aes128-cbc,#legacy\n").is_empty(),
            "comma-glued # (one malformed token, sshd rc 255) must not fire W03"
        );
        assert!(
            run("Ciphers aes256-ctr,aes128-cbc,#x\n").is_empty(),
            "comma-glued # after a list (one malformed token, sshd rc 255) must not fire W03"
        );
    }

    // -----------------------------------------------------------------------
    // Glued-hash-after-closing-quote (issue #327 fix + #348 parser fix)
    // -----------------------------------------------------------------------
    //
    // sshd tokenization (verified OpenSSH 10.2p1 `sshd -T`):
    //   - `Ciphers "aes128-cbc"#x`  -> "Bad SSH2 cipher spec 'aes128-cbc#x'" (rc 255)
    //   - `Ciphers "aes128-cbc" #x` -> ciphers aes128-cbc (rc 0, loads aes128-cbc)
    //
    // Since #348, read_arg uses the quote-concatenation model: it scans the entire
    // whitespace-delimited token, stripping every `"` and concatenating the runs.
    // This means `"aes128-cbc"#x` (glued `#`) becomes the single invalid token
    // `aes128-cbc#x`; algo_list_value sees the `#` embedded in the value and
    // returns None, so W03 correctly does NOT fire (sshd rejects the line at rc 255).
    // The spaced form `"aes128-cbc" #x` still produces two tokens: `aes128-cbc`
    // (the space ends the token) and `#x` (a separate token) -- glued vs. spaced
    // ARE now distinguishable at the tokenizer level.
    //
    // Note: this is distinct from the `+"aes128-cbc"#x` case (W06), where the `+`
    // forces bareword mode and the `#` IS already embedded in the single-arg bareword
    // token after quote-strip -- that case was never a limitation of the old parser.
    // See glued_hash_after_closing_quote_plus_prefix_does_not_fire_w06 in w06_tests.

    #[test]
    fn glued_hash_after_closing_quote_no_prefix_does_not_fire_w03() {
        // `Ciphers "aes128-cbc"#x` -- `#x` glued directly to the closing `"`.
        // Under the concatenation model, the parser yields ONE arg `aes128-cbc#x`
        // (not two args). algo_list_value sees `#` in the value and returns None;
        // W03 must NOT fire because sshd rejects the line ("Bad SSH2 cipher spec
        // 'aes128-cbc#x'", rc 255, verified OpenSSH 10.2p1 `sshd -T`).
        // RED until read_arg implements the quote-concatenation model (#348).
        assert!(
            run("Ciphers \"aes128-cbc\"#x\n").is_empty(),
            "glued `#` after closing quote (no prefix): sshd rc 255 => W03 must not fire"
        );
    }

    // -----------------------------------------------------------------------
    // Quote-concatenation false-negative tests (issue #348)
    //
    // When the parser implements the concatenation model (stripping `"` and
    // concatenating runs within one whitespace-delimited token), these forms
    // that sshd loads as `aes128-cbc` will reach algo_list_value as a single
    // clean arg and W03 must fire. They are RED today because the current
    // read_arg stops at the first closing `"`, producing multiple args that
    // algo_list_value rejects as ambiguous (None -> no W03 -> false negative).
    // -----------------------------------------------------------------------

    #[test]
    fn empty_quoted_prefix_fires_w03() {
        // `Ciphers ""aes128-cbc` -- an empty quoted prefix followed by a bareword
        // run `aes128-cbc`. Under the concatenation model the parser yields one
        // arg `aes128-cbc`; W03 must fire on the weak cipher.
        // Grounding: sshd -T loads aes128-cbc (rc 0, verified OpenSSH 10.2p1).
        // RED until read_arg implements the quote-concatenation model (#348).
        let diags = run("Ciphers \"\"aes128-cbc\n");
        assert_eq!(
            diags.len(),
            1,
            "empty quoted prefix + bareword is a valid sshd-loading weak line => one W03; \
             got: {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W03");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn quote_pair_splitting_a_token_fires_w03() {
        // `Ciphers "aes128""-cbc"` -- two adjacent quoted runs with no whitespace.
        // sshd strips both quote pairs and concatenates to `aes128-cbc` (rc 0,
        // verified OpenSSH 10.2p1). Under the concatenation model the parser
        // yields one arg `aes128-cbc`; W03 must fire on the weak cipher.
        // RED until read_arg implements the quote-concatenation model (#348).
        let diags = run("Ciphers \"aes128\"\"-cbc\"\n");
        assert_eq!(
            diags.len(),
            1,
            "adjacent quoted runs concatenate to aes128-cbc => one W03; got: {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W03");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
    }

    #[test]
    fn spaced_hash_after_closing_quote_no_prefix_fires_w03() {
        // `Ciphers "aes128-cbc" #x` -- SPACE before `#x` (inline comment).
        // The parser yields args=["aes128-cbc", "#x"] (same as the glued case, but
        // sshd accepts this: the space makes `#x` a comment, so aes128-cbc is loaded).
        // W03 must fire. Grounding: sshd -T yields `ciphers aes128-cbc` (rc 0,
        // verified OpenSSH 10.2p1).
        let diags = run("Ciphers \"aes128-cbc\" #x\n");
        assert_eq!(
            diags.len(),
            1,
            "\"aes128-cbc\" with spaced inline comment loads aes128-cbc => one W03; \
             got: {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W03");
        assert!(
            diags[0].message.contains("aes128-cbc"),
            "message names the weak algorithm, got: {}",
            diags[0].message
        );
    }
}
