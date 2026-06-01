//! fapd-W11 weak-hash surfacing for trust-DB entries.
//!
//! One capped summary diagnostic (Warning) when the attached trust DB holds
//! entries whose digest length implies a weak algorithm (MD5 = 32-hex, SHA1 =
//! 40-hex). Invoked from the CLI's lint path when `--against-trustdb` is set
//! (NOT from `lint_with_context`), mirroring `cross_db::lint_orphans` (fapd-X01).
//! Reuses the shared `trustdb::weak_digest_algorithm` length->algorithm map.

use rulesteward_core::{Diagnostic, Severity};

use crate::trustdb::{TrustDb, weak_digest_algorithm};

/// Max sample paths shown in the summary message (mirrors fapd-X01).
const SAMPLE_CAP: usize = 10;

/// Emit at most one fapd-W11 summary diagnostic (Warning) naming how many
/// trust-DB entries use a weak hash algorithm, with a capped sample of paths.
/// Returns an empty vec when the DB cannot be read or holds no weak digests.
#[must_use]
pub fn lint_weak_digests(db: &TrustDb) -> Vec<Diagnostic> {
    // A txn/read failure is treated as "nothing to report" (fail-safe: the
    // other trust-DB lints, X01/W06, take the same conservative stance).
    let Ok(entries) = db.iter_entries() else {
        return Vec::new();
    };
    let mut weak: Vec<&str> = entries
        .iter()
        .filter(|e| weak_digest_algorithm(&e.digest).is_some())
        .map(|e| e.path.as_str())
        .collect();
    if weak.is_empty() {
        return Vec::new();
    }
    // DUPSORT can surface the same path twice; sort+dedup so the count and
    // sample reflect distinct paths.
    weak.sort_unstable();
    weak.dedup();
    let n = weak.len();
    let sample: Vec<&str> = weak.iter().take(SAMPLE_CAP).copied().collect();
    let plural = if n == 1 { "entry" } else { "entries" };
    // Only claim "showing first K of N" when the sample is actually truncated;
    // otherwise the listing IS the whole set and a "showing first" clause would
    // misstate it (mirrors fapd-X01's listing shape).
    let listing = if n > SAMPLE_CAP {
        format!(
            " (showing first {SAMPLE_CAP} of {n}): {}",
            sample.join(", ")
        )
    } else {
        format!(": {}", sample.join(", "))
    };
    // Trust-DB-level diagnostic: span 0..0, no source_id, keyed to the DB path
    // (same shape as fapd-X01 via the shared `file_level` helper).
    vec![super::file_level(
        Severity::Warning,
        "fapd-W11",
        format!(
            "trust DB has {n} {plural} using a weak hash algorithm (MD5/SHA1); \
             prefer SHA256 (64-hex) or SHA512 (128-hex){listing}"
        ),
        db.path(),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trustdb::{open_trustdb_readonly, weak_digest_algorithm, write_trustdb_fixture_kv};
    use tempfile::tempdir;

    // Build the canonical fapolicyd value bytes "<src_int> <size> <hexdigest>".
    fn value(src: u32, size: u64, hex: &str) -> Vec<u8> {
        format!("{src} {size} {hex}").into_bytes()
    }

    // ---------------------------------------------------------------------
    // Direct map test for the shared helper. Pins 32->MD5, 40->SHA1, and the
    // strong/other lengths -> None. RED against the stub (returns None always,
    // so the MD5/SHA1 asserts fail).
    // ---------------------------------------------------------------------
    #[test]
    fn weak_digest_algorithm_maps_lengths() {
        assert_eq!(weak_digest_algorithm(&"a".repeat(32)), Some("MD5"));
        assert_eq!(weak_digest_algorithm(&"a".repeat(40)), Some("SHA1"));
        assert_eq!(
            weak_digest_algorithm(&"a".repeat(64)),
            None,
            "SHA256 is strong"
        );
        assert_eq!(
            weak_digest_algorithm(&"a".repeat(128)),
            None,
            "SHA512 is strong"
        );
        assert_eq!(
            weak_digest_algorithm("abc"),
            None,
            "off-length is not 'weak'"
        );
        assert_eq!(weak_digest_algorithm(""), None);
    }

    // ---------------------------------------------------------------------
    // A trust DB with one MD5 (32-hex) entry -> exactly one fapd-W11 Warning
    // summary naming the count. RED against the stub (returns []).
    // ---------------------------------------------------------------------
    #[test]
    fn md5_entry_fires_one_w11_summary() {
        let tmp = tempdir().expect("tempdir");
        let md5 = "a".repeat(32);
        write_trustdb_fixture_kv(tmp.path(), &[("/usr/bin/weak", &value(1, 10, &md5))]);
        let db = open_trustdb_readonly(tmp.path()).expect("open db");

        let diags = lint_weak_digests(&db);
        assert_eq!(
            diags.len(),
            1,
            "one weak (MD5) trust-DB entry must yield exactly one fapd-W11 summary; got {diags:?}",
        );
        assert_eq!(diags[0].code.as_ref(), "fapd-W11");
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "trust-DB weak-hash must be a Warning",
        );
        assert!(
            diags[0].message.contains("1 entry"),
            "summary must name the count (\"1 entry\"); got: {}",
            diags[0].message,
        );
        assert!(
            diags[0].message.contains("/usr/bin/weak"),
            "summary must sample the offending path; got: {}",
            diags[0].message,
        );
    }

    // ---------------------------------------------------------------------
    // A SHA1 (40-hex) entry also fires (algorithm-agnostic on weakness). And a
    // mixed DB with two weak entries collapses to ONE summary naming "2 entries"
    // (not one-per-entry), mirroring X01. RED against the stub.
    // ---------------------------------------------------------------------
    #[test]
    fn two_weak_entries_collapse_to_one_summary() {
        let tmp = tempdir().expect("tempdir");
        let md5 = "b".repeat(32);
        let sha1 = "c".repeat(40);
        let strong = "d".repeat(64);
        write_trustdb_fixture_kv(
            tmp.path(),
            &[
                ("/bin/a", &value(1, 10, &md5)),
                ("/bin/b", &value(1, 20, &sha1)),
                ("/bin/strong", &value(1, 30, &strong)),
            ],
        );
        let db = open_trustdb_readonly(tmp.path()).expect("open db");

        let diags = lint_weak_digests(&db);
        assert_eq!(
            diags.len(),
            1,
            "two weak entries must collapse to ONE summary diagnostic; got {diags:?}",
        );
        assert!(
            diags[0].message.contains("2 entries"),
            "summary must count both weak entries (\"2 entries\"); got: {}",
            diags[0].message,
        );
    }

    // ---------------------------------------------------------------------
    // Truncation wording: with MORE than SAMPLE_CAP weak entries, the summary
    // must state the total ("showing first 10 of 12") and must NOT imply the
    // sample is the whole set. With n <= SAMPLE_CAP there is no truncation, so
    // the message must NOT carry a "showing first" clause at all. RED against
    // the prior wording ("showing first {sample.len()}: ...") which omits the
    // total when truncating and falsely says "showing first N" when N == n.
    // ---------------------------------------------------------------------
    #[test]
    fn over_cap_weak_entries_name_the_total_when_truncating() {
        let tmp = tempdir().expect("tempdir");
        // 12 distinct MD5 (32-hex) entries > SAMPLE_CAP (10).
        let entries: Vec<(String, Vec<u8>)> = (0..12)
            .map(|i| {
                let md5 = format!("{i:032x}");
                (format!("/bin/weak{i:02}"), value(1, 10, &md5))
            })
            .collect();
        let kv: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(p, v)| (p.as_str(), v.as_slice()))
            .collect();
        write_trustdb_fixture_kv(tmp.path(), &kv);
        let db = open_trustdb_readonly(tmp.path()).expect("open db");

        let diags = lint_weak_digests(&db);
        assert_eq!(diags.len(), 1, "still exactly one summary; got {diags:?}");
        let msg = &diags[0].message;
        assert!(
            msg.contains("12 entries"),
            "summary must name the total count; got: {msg}",
        );
        assert!(
            msg.contains("showing first 10 of 12"),
            "truncated summary must state the total omitted; got: {msg}",
        );
    }

    // n <= SAMPLE_CAP must NOT carry a "showing first" clause (no truncation).
    #[test]
    fn at_or_under_cap_has_no_showing_first_clause() {
        let tmp = tempdir().expect("tempdir");
        let md5 = "a".repeat(32);
        write_trustdb_fixture_kv(tmp.path(), &[("/usr/bin/weak", &value(1, 10, &md5))]);
        let db = open_trustdb_readonly(tmp.path()).expect("open db");

        let diags = lint_weak_digests(&db);
        assert_eq!(diags.len(), 1);
        assert!(
            !diags[0].message.contains("showing first"),
            "no truncation -> no 'showing first' clause; got: {}",
            diags[0].message,
        );
    }

    // Boundary: EXACTLY SAMPLE_CAP weak entries is the whole set (no truncation),
    // so still no "showing first" clause. Pins the `>` in `n > SAMPLE_CAP` against
    // `>=`/`==` mutants (which would truncate at n == SAMPLE_CAP).
    #[test]
    fn exactly_cap_weak_entries_has_no_showing_first_clause() {
        let tmp = tempdir().expect("tempdir");
        let entries: Vec<(String, Vec<u8>)> = (0..SAMPLE_CAP)
            .map(|i| {
                (
                    format!("/bin/weak{i:02}"),
                    value(1, 10, &format!("{i:032x}")),
                )
            })
            .collect();
        let kv: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(p, v)| (p.as_str(), v.as_slice()))
            .collect();
        write_trustdb_fixture_kv(tmp.path(), &kv);
        let db = open_trustdb_readonly(tmp.path()).expect("open db");

        let diags = lint_weak_digests(&db);
        assert_eq!(diags.len(), 1);
        let msg = &diags[0].message;
        assert!(
            msg.contains("10 entries"),
            "summary must name the count; got: {msg}",
        );
        assert!(
            !msg.contains("showing first"),
            "n == SAMPLE_CAP is the whole set -> no 'showing first' clause; got: {msg}",
        );
    }

    // ---------------------------------------------------------------------
    // Non-vacuity: a DB with only strong (SHA256/SHA512) digests yields NO
    // diagnostic. A stub that always emits would fail here; a correct impl is
    // silent. (Stub returns [] -> passes; this guards the real impl.)
    // ---------------------------------------------------------------------
    #[test]
    fn strong_only_db_is_clean() {
        let tmp = tempdir().expect("tempdir");
        let sha256 = "e".repeat(64);
        let sha512 = "f".repeat(128);
        write_trustdb_fixture_kv(
            tmp.path(),
            &[
                ("/bin/x", &value(1, 10, &sha256)),
                ("/bin/y", &value(1, 20, &sha512)),
            ],
        );
        let db = open_trustdb_readonly(tmp.path()).expect("open db");
        let diags = lint_weak_digests(&db);
        assert!(
            diags.is_empty(),
            "a strong-only trust DB must produce no fapd-W11; got {diags:?}",
        );
    }
}
