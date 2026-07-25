//! Shared `fapolicyd.conf` key reader.
//!
//! `fapolicyd.conf` is a flat `key = value` file (full-line `#` comments). Before
//! this helper existed, three hand-rolled scanners parsed it with three different
//! acceptance sets, and two of them (in `doctor/probe.rs`) DISAGREED on whitespace
//! variants like `permissive =1` -- so doctor's mode probe and its misconfiguration
//! check could report different modes for the same line (issue #192, D2). This is
//! the single, comment-aware, whitespace-tolerant reader they all use.

/// Look up `key` in `fapolicyd.conf`-style text and return the trimmed value of
/// the LAST matching `key = value` line, mirroring how the fapolicyd daemon itself
/// resolves its config (`daemon-config.c`: each keyword handler overwrites with no
/// early-exit, so duplicate keys are last-wins). Resolving duplicates differently
/// from the daemon would make `doctor`/`container-check` misreport the effective
/// config.
///
/// Tolerant of a run of ASCII space (0x20) characters around `=` (`permissive=1`,
/// `permissive = 1`, `permissive =1`, `permissive= 1` all read as value `"1"`).
/// The key is matched EXACTLY (so `permissive_debug=1` is NOT read as the
/// `permissive` key). Only WHOLE-LINE `#` comments are skipped (a line whose
/// first token starts with `#` is dropped entirely); a trailing `#` on an
/// otherwise-live line is NOT stripped, so this function returns the RAW
/// remainder verbatim, including any inline comment text.
///
/// Only ASCII space is trimmed from the value's edges (issue #582): a
/// CRLF-edited file's trailing `\r` (and any tab) is deliberately preserved
/// verbatim, mirroring the real daemon's `get_line`, which strips only a
/// trailing `0x0a` -- see the `#582` test-block comment below for the full
/// `daemon-config.c` grounding. The scan splits on a bare `'\n'` (not
/// `str::lines`, which would silently conflate a `\r\n` terminator and drop
/// the `\r` before this function ever saw it).
///
/// IMPORTANT (doc-truth-decay correction, ATL round 2 MISS 1): this raw
/// remainder is NOT the same string the fapolicyd daemon itself uses as the
/// key's value. `daemon-config.c`'s `nv_split`/`_strsplit` whitespace-
/// tokenizes each line and binds `nv.value` to ONLY the FIRST token after
/// `=` - a trailing `# comment` (or any further token) is separately logged
/// as "Wrong number of arguments" but does NOT change which token the
/// keyword's parser receives (verified live on fapolicyd 1.3.2 and 1.4.5:
/// `permissive = 1 # temporarily on` -> the daemon applies permissive=1 and
/// runs permissive; `conf_value` on that same line returns
/// `"1 # temporarily on"`, not `"1"`). `conf_value` is a RAW per-line
/// extractor, one layer below the daemon's actual interpretation; any
/// caller that needs the daemon-INTERPRETED value (e.g. the permissive
/// fail-open predicate) must do that first-whitespace-token split itself -
/// see `doctor/probe.rs::read_fapolicyd_mode_from`.
/// Returns `None` when the key is absent.
#[must_use]
pub(crate) fn conf_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut value = None;
    // Split on a bare `'\n'`, never `str::lines()` (which silently strips a
    // trailing `\r` from each line, conflating a CRLF terminator into a
    // single line ending): issue #582 requires a CRLF file's trailing `\r`
    // to survive into the returned value.
    for line in text.split('\n') {
        // Whole-line comments only: fapolicyd skips a line whose first token starts
        // with `#`. A trailing inline comment on a live line is NOT stripped here -
        // this function's contract is the raw remainder, not the daemon's
        // interpreted value (see the function doc above). See daemon-config.c
        // `nv_split`.
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            // Last occurrence wins (fapolicyd parity): keep overwriting. ASCII
            // space (0x20) only, both ends - never a Unicode `.trim()`, which
            // would also eat a CRLF file's trailing `\r` (issue #582); a run of
            // leading spaces mirrors the daemon's own retry-on-leading-space
            // skip in `_strsplit`.
            value = Some(v.trim_matches(' '));
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conf_value_tolerates_all_whitespace_variants_around_equals() {
        // The D2 fix: every spacing variant of `permissive=1` yields the same
        // value, so the mode probe and the misconfig check cannot disagree.
        for line in [
            "permissive=1",
            "permissive = 1",
            "permissive =1",
            "permissive= 1",
        ] {
            assert_eq!(
                conf_value(line, "permissive"),
                Some("1"),
                "variant {line:?} must read as 1"
            );
        }
    }

    #[test]
    fn conf_value_requires_exact_key_match() {
        // A key that merely starts with the search key must NOT match.
        assert_eq!(conf_value("permissive_debug=1", "permissive"), None);
    }

    #[test]
    fn conf_value_last_occurrence_wins() {
        // fapolicyd's config loader overwrites on each duplicate key, so the LAST
        // occurrence determines the effective value (daemon-config.c per-keyword
        // parsers `free(); strdup()` with no early-exit). The reader must resolve
        // duplicates the same way or doctor/container-check would misreport the
        // effective config (issue #192 adversarial finding).
        assert_eq!(
            conf_value("permissive=0\npermissive=1\n", "permissive"),
            Some("1")
        );
    }

    #[test]
    fn conf_value_skips_whole_line_comments() {
        assert_eq!(
            conf_value("# permissive=1\npermissive=0\n", "permissive"),
            Some("0")
        );
    }

    #[test]
    fn conf_value_does_not_strip_inline_comment() {
        // Pins `conf_value`'s RAW EXTRACTION layer only: it skips a line
        // ONLY when the line's first token starts with `#` (a whole-line
        // comment); it does not strip a trailing inline comment, so the
        // whole post-`=` remainder - including any `# ...` tail - comes
        // back verbatim (issue #192 adversarial finding, still true of this
        // function).
        //
        // RE-GROUNDED (ATL round 2, MISS 1, 2026-07-18): this test does NOT
        // pin what the fapolicyd DAEMON does with that raw text next. The
        // daemon's own `nv_split`/`_strsplit` (daemon-config.c) further
        // whitespace-tokenizes the remainder and uses ONLY the first token
        // as the interpreted value ("1", not "1 # default off") -
        // live-verified on fapolicyd 1.3.2 and 1.4.5. `conf_value` and the
        // daemon's interpreted value are different layers; a caller that
        // needs the daemon's INTERPRETED value must tokenize this raw
        // remainder itself (see `doctor/probe.rs`'s permissive-evaluation
        // seam). Do not read this test as "fapolicyd treats the whole
        // trailing text as the literal value" - it does not.
        assert_eq!(
            conf_value("permissive=1 # default off\n", "permissive"),
            Some("1 # default off")
        );
    }

    #[test]
    fn conf_value_absent_key_is_none() {
        assert_eq!(
            conf_value("integrity=sha256\nrpm_integrity_check=1\n", "permissive"),
            None
        );
    }

    #[test]
    fn conf_value_reads_a_list_value_verbatim() {
        // watch_fs is a comma list the caller splits; conf_value returns the
        // trimmed raw value.
        assert_eq!(
            conf_value("watch_fs = ext4,tmpfs,xfs\n", "watch_fs"),
            Some("ext4,tmpfs,xfs")
        );
    }

    // -------------------------------------------------------------------------
    // Issue #582: `conf_value` must return the RAW byte-exact remainder,
    // preserving a CRLF file's trailing '\r'.
    //
    // Ground truth (fapolicyd's `daemon-config.c` `get_line`, the same
    // citation already grounded for the sibling fapd-W14 lint's #569 fix at
    // `rulesteward-fapolicyd/src/lints/conf.rs` -- see its
    // `crlf_line_ending_leaves_a_trailing_cr_in_the_value` test, the
    // already-fixed gold behavior at that sibling `lint_conf` seam):
    // `get_line` strips ONLY a trailing 0x0a byte; a CRLF-edited conf file
    // leaves the '\r' byte bound to the value, and `unsigned_int_parser`'s
    // byte-exact `isdigit` walk later rejects it.
    //
    // These pins exist because an earlier `conf_value` scanned with
    // `text.lines()`, which conflates a `\r\n` terminator into a single line
    // ending and silently drops the '\r' -- breaking this function's own
    // documented "RAW remainder verbatim" contract (see the doc comment
    // above) and producing a fail-open miss for every one of its callers
    // (`doctor/probe.rs`, `fapolicyd/trustdb.rs`, `container_check/probe.rs`,
    // and `target_probe.rs`). `conf_value` now splits on a bare `'\n'`; these
    // pins hold that fix in place.
    //
    // SCOPE NOTE (adversarial review round 2, doc-truth-decay correction):
    // the pins below cover VALUE tokenization only -- leading/trailing
    // ASCII-space trimming and CR retention at the `conf_value` layer, plus
    // the downstream space-splitting and byte-exact digit walk in
    // `doctor/probe.rs::permissive_value_is_effectively_permissive`. They do
    // NOT pin fapolicyd's `nv_split` requirement that `=` itself be its own
    // whitespace-delimited token (a config line like `permissive=1`, with no
    // space around `=`, is a fatal config-load abort in the real daemon).
    // That divergence is real but is being tracked as its own follow-up
    // issue, separate from #582, and is deliberately NOT pinned here -- do
    // not read these tests as certifying full byte-exact parity with
    // daemon-config.c's `=` handling.
    // -------------------------------------------------------------------------

    #[test]
    fn conf_value_crlf_retains_trailing_cr_in_the_value() {
        // RED: `get_line` strips only the trailing 0x0a; the '\r' stays
        // bound to the value. `text.lines()` wrongly conflates the CRLF
        // terminator and drops it.
        assert_eq!(
            conf_value("permissive = 1\r\n", "permissive"),
            Some("1\r"),
            "a CRLF line ending must leave the trailing '\\r' bound to the \
             raw value, mirroring the real daemon's get_line (#582)"
        );
    }

    #[test]
    fn conf_value_crlf_last_wins_still_retains_cr_on_the_winning_line() {
        // RED: combines the already-correct last-wins contract (this
        // function's own doc comment, and
        // `conf_value_last_occurrence_wins` above) with CR retention -- the
        // WINNING (second) line's trailing '\r' must survive, not just a
        // single-line fixture's.
        assert_eq!(
            conf_value("permissive=0\r\npermissive=1\r\n", "permissive"),
            Some("1\r"),
            "last-wins resolution must still preserve the winning line's \
             trailing '\\r' (#582)"
        );
    }

    #[test]
    fn conf_value_crlf_with_inline_comment_retains_trailing_cr() {
        // RED: combines the already-correct "does not strip inline comment"
        // contract (`conf_value_does_not_strip_inline_comment` above) with
        // CR retention -- both the comment text AND the trailing '\r' must
        // be preserved together, verbatim.
        assert_eq!(
            conf_value("permissive = 1 # note\r\n", "permissive"),
            Some("1 # note\r"),
            "an inline comment and a trailing CRLF '\\r' must both be \
             preserved verbatim in the raw value (#582)"
        );
    }

    #[test]
    fn conf_value_crlf_whole_line_comment_still_skipped() {
        // RED: combines the already-correct whole-line-comment skip
        // (`conf_value_skips_whole_line_comments` above) with CR retention
        // -- the commented-out line is still skipped regardless of CRLF,
        // and the real answer line's trailing '\r' is preserved.
        assert_eq!(
            conf_value("# permissive=1\r\npermissive=0\r\n", "permissive"),
            Some("0\r"),
            "a whole-line comment must still be skipped under CRLF line \
             endings, and the real answer line's trailing '\\r' must \
             survive (#582)"
        );
    }

    // -------------------------------------------------------------------------
    // Adversarial review round 2, BLOCKER 4: the CR-retention pins above
    // force `v.trim()` to go, but `conf_value` has collateral callers doing
    // exact string compares / byte-position assumptions with NO tokenization
    // of their own (`container_check/probe.rs`'s `parse_effective_conf`
    // compares `== Some("1")` exactly; `target_probe.rs`'s `parse_os_release`
    // assumes the closing quote is the value's LAST byte). A fix shaped as
    // "just stop trimming the end" (e.g. `v.trim_start_matches(' ')` alone)
    // would leave a trailing ASCII space in the value and silently regress
    // both of those callers -- neither owned by this lane, so nothing would
    // catch it. The correct shape is `v.trim_matches(' ')`: ASCII space only,
    // BOTH ends, never `\r` or `\t`. It is daemon-correct too: for
    // `permissive = 1 ` the real `_strsplit` treats the trailing space as a
    // separator and binds `nv.value` to `"1"`, not `"1 "`.
    // -------------------------------------------------------------------------

    #[test]
    fn conf_value_trailing_ascii_space_is_still_trimmed_control() {
        // GREEN control: a trailing ASCII space is a real daemon separator
        // and must still be trimmed; only the CR must survive. Regression
        // guard for `container_check/probe.rs::parse_effective_conf`'s
        // exact `== Some("1")` compare and `target_probe.rs`'s
        // `parse_os_release`/`strip_quotes`, both of which assume no
        // trailing space in the raw value (#582 adversarial round 2,
        // BLOCKER 4).
        assert_eq!(
            conf_value("permissive = 1 \n", "permissive"),
            Some("1"),
            "a trailing ASCII space is a real daemon separator and must \
             still be trimmed; only the CR must survive (#582)"
        );
    }

    #[test]
    fn conf_value_multiple_leading_spaces_all_collapsed_control() {
        // GREEN control (CONCERN): the daemon's `_strsplit` has a
        // `goto retry` (daemon-config.c:292-294) that skips a whole RUN of
        // consecutive spaces, not just one. A fix shaped as
        // `v.strip_prefix(' ')` (removes only ONE leading space) instead of
        // `v.trim_matches(' ')` / `trim_start_matches(' ')` (removes the
        // whole run) would leave a residual leading space in the raw value
        // here, which a naive `split(' ').next()` downstream would then read
        // as an EMPTY first token (`""`) -- silently reporting enforcing for
        // a daemon that is actually permissive.
        assert_eq!(
            conf_value("permissive =  1\n", "permissive"),
            Some("1"),
            "a run of multiple leading spaces must be collapsed entirely, \
             mirroring the daemon's _strsplit retry-on-leading-space skip \
             (#582)"
        );
    }
}
