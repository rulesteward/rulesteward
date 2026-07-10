//! The live upstream fetch (a `curl` shell-out) for the three pinned headers,
//! plus the sha256 pin-verification guard. Isolated here behind a thin seam so
//! the derivation core ([`crate::parse`], [`crate::registry`]) is tested fully
//! offline with the committed `tests/fixtures/`; the fetch functions are
//! exercised only by the live (non---fixtures) `check` / `derive` runs
//! (network fetching is out of this crate's test scope - see
//! `../msgtype-refs.toml`'s header comment for the update workflow).
//!
//! URL shapes (two DISTINCT upstreams - never blur the provenances):
//! * audit-userspace files:
//!   `https://raw.githubusercontent.com/linux-audit/audit-userspace/<commit>/lib/<file>`
//!   for `msg_typetab.h` / `audit-records.h` at the pinned commit.
//! * kernel header:
//!   `https://raw.githubusercontent.com/torvalds/linux/<tag>/include/uapi/linux/audit.h`
//!   at the pinned tag.

/// `curl -fsSL <url>` -> body. Errors carry curl's stderr. Mirrors
/// `tools/fapolicyd-attr-update/src/source.rs`.
pub fn curl(_url: &str) -> Result<String, String> {
    todo!("implementer: shell out to curl -fsSL")
}

/// Fetch `lib/<file>` (`msg_typetab.h` or `audit-records.h`) from
/// audit-userspace at `commit`, then verify it against `expected_sha256` via
/// [`verify_sha256`] before returning it - the fetch is REJECTED (fails
/// closed), not just logged, on a hash mismatch (a truncated transfer, a CDN
/// serving stale/corrupted bytes, or upstream rewriting history all look
/// identical to a caller that skips this check).
pub fn fetch_userspace_source(
    _commit: &str,
    _file: &str,
    _expected_sha256: &str,
) -> Result<String, String> {
    todo!("implementer: curl the raw audit-userspace URL + verify_sha256")
}

/// Fetch `include/uapi/linux/audit.h` from the Linux kernel at `tag`, then
/// verify it against `expected_sha256` via [`verify_sha256`] before returning
/// it - same fail-closed contract as [`fetch_userspace_source`].
pub fn fetch_kernel_header(_tag: &str, _expected_sha256: &str) -> Result<String, String> {
    todo!("implementer: curl the raw kernel URL + verify_sha256")
}

/// Compute the sha256 of `content` and compare (case-insensitively) against
/// `expected_hex`. Fails CLOSED (`Err`) on any mismatch - this is the guard
/// that makes a truncated or corrupted fetch (or a tampered committed fixture
/// on the offline `--fixtures` path, which verifies through this SAME
/// function) a hard error rather than a silently wrong derived table. The
/// error must carry BOTH hashes verbatim: the expected (pinned) hex and the
/// actual computed hex (see the frozen tests below). NOTE for the
/// implementer: in the `digest` 0.11 line the finalize output type does not
/// implement `std::fmt::LowerHex`; hand-roll the hex encoding (see
/// `tools/fapolicyd-attr-update/src/source.rs`'s `to_hex`).
pub fn verify_sha256(_content: &str, _expected_hex: &str) -> Result<(), String> {
    todo!("implementer: sha2 digest + case-insensitive hex compare, Err carries both hashes")
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

    /// Known-answer sha256 of the literal byte string `"ab"` (reproducible via
    /// `printf ab | sha256sum`) - the ACTUAL hash the truncated-content test's
    /// error message must carry.
    const AB_SHA256: &str = "fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603";

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
        // The error must carry BOTH sides of the comparison VERBATIM - the
        // expected hex we passed in AND the real computed hash of the content
        // (the NIST "abc" vector, hardcoded above, NOT recomputed through the
        // impl's own hex encoder). An implementation whose hex encoding is
        // broken (e.g. an empty string from a gutted encoder) cannot produce
        // ABC_SHA256 in its message, and a verify that silently returns Ok(())
        // never produces an Err at all. (Frozen contract inherited from the
        // fapolicyd-attr-update ATL round-1 strengthening.)
        let zeros = "0000000000000000000000000000000000000000000000000000000000000000";
        let err = verify_sha256("abc", zeros)
            .expect_err("a wrong expected hash must be rejected, not silently accepted");
        assert!(
            err.contains(ABC_SHA256),
            "the mismatch error must carry the ACTUAL computed sha256 of the content \
             (the known-answer abc vector) verbatim: {err:?}"
        );
        assert!(
            err.contains(zeros),
            "the mismatch error must carry the EXPECTED (pinned) hash verbatim: {err:?}"
        );
    }

    #[test]
    fn verify_sha256_fails_closed_on_truncated_content() {
        // "ab" is NOT "abc" - a truncated fetch must not verify against the
        // full file's pinned hash. Same verbatim-content discipline as the
        // mismatch test.
        let err = verify_sha256("ab", ABC_SHA256)
            .expect_err("truncated content must not match the full file's pinned hash");
        assert!(
            err.contains(AB_SHA256),
            "the error must carry the ACTUAL computed sha256 of the truncated \
             content verbatim: {err:?}"
        );
        assert!(
            err.contains(ABC_SHA256),
            "the error must carry the EXPECTED (pinned) hash verbatim: {err:?}"
        );
    }
}
