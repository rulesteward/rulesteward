//! The live upstream fetch (a `curl` shell-out) for `subject-attr.c` /
//! `object-attr.c` at a pinned tag, plus the sha256 pin-verification guard.
//! Isolated here behind a thin seam so the derivation core ([`crate::parse`],
//! [`crate::registry`]) is tested fully offline with the committed
//! `tests/fixtures/`; this module is exercised only by the live `check` /
//! `derive` runs (network fetching is out of this crate's test scope - see
//! `../attr-refs.toml`'s header comment for the update workflow).
//!
//! Unlike `tools/stig-update`, no git-tree lookup is needed: both pinned tags
//! carry `src/library/{subject,object}-attr.c` at the IDENTICAL path (confirmed
//! via the GitHub recursive git-tree API, 2026-07-10 grounding recon for #479),
//! so the raw file URL is constructed directly from the pinned tag.

use std::process::Command;

const REPO: &str = "linux-application-whitelisting/fapolicyd";

/// `curl -fsSL <url>` -> body. Errors carry curl's stderr.
pub fn curl(url: &str) -> Result<String, String> {
    let out = Command::new("curl")
        .args(["-fsSL", url])
        .output()
        .map_err(|e| format!("spawn curl (is it installed?): {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("curl {url}: non-utf8 body: {e}"))
}

/// Fetch `src/library/<file>` (`subject-attr.c` or `object-attr.c`) at `tag`,
/// then verify it against `expected_sha256` via [`verify_sha256`] before
/// returning it - the fetch is REJECTED (fails closed), not just logged, on a
/// hash mismatch (a truncated transfer, a CDN serving stale/corrupted bytes, or
/// upstream force-pushing the tag all look identical to a caller that skips
/// this check).
pub fn fetch_source(tag: &str, file: &str, expected_sha256: &str) -> Result<String, String> {
    let url = format!("https://raw.githubusercontent.com/{REPO}/{tag}/src/library/{file}");
    let body = curl(&url)?;
    verify_sha256(&body, expected_sha256)?;
    Ok(body)
}

/// Compute the sha256 of `content` and compare (case-insensitively) against
/// `expected_hex`. Fails CLOSED (`Err`) on any mismatch - this is the guard that
/// makes a truncated or corrupted fetch a hard error rather than a silently
/// wrong (incomplete) derived registry, mirroring
/// `tools/stig-update/src/source.rs`'s `reject_if_truncated` guard (the
/// analogous fail-closed check on that tool's git-tree fetch path).
pub fn verify_sha256(content: &str, expected_hex: &str) -> Result<(), String> {
    let _ = (content, expected_hex);
    todo!("compute sha256(content), compare (case-insensitive) to expected_hex, Err on mismatch")
}

#[cfg(test)]
mod tests {
    use super::verify_sha256;

    /// Known-answer sha256 of the literal byte string `"abc"`:
    /// `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
    /// (FIPS 180-4 / NIST test vector, and reproducible via
    /// `printf abc | sha256sum`). Case-insensitive match must succeed for both
    /// lower- and upper-case hex.
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn verify_sha256_accepts_a_matching_hash() {
        verify_sha256("abc", ABC_SHA256).expect("abc's real sha256 must verify");
    }

    #[test]
    fn verify_sha256_accepts_uppercase_hex() {
        verify_sha256("abc", &ABC_SHA256.to_uppercase())
            .expect("hex case must not matter for the comparison");
    }

    #[test]
    fn verify_sha256_fails_closed_on_a_mismatch() {
        let err = verify_sha256(
            "abc",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect_err("a wrong expected hash must be rejected, not silently accepted");
        assert!(!err.is_empty());
    }

    #[test]
    fn verify_sha256_fails_closed_on_truncated_content() {
        // "ab" is NOT "abc" - a truncated fetch must not verify against the full
        // file's pinned hash.
        let err = verify_sha256("ab", ABC_SHA256)
            .expect_err("truncated content must not match the full file's pinned hash");
        assert!(!err.is_empty());
    }
}
