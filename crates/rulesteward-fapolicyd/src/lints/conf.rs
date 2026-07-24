//! fapd-W14: `fapolicyd.conf` resolves an effectively-permissive
//! `permissive=` value (fail-open instead of enforcing - not just the
//! literal `permissive=1`; see `is_effectively_permissive`'s doc for the
//! exact daemon-matching predicate). Operates on an explicitly-supplied
//! conf file (CLI `--conf` path, `commands/fapolicyd/lint.rs`); NOT wired
//! into the default per-file `lint_with_context` pass list (a conf file is
//! not a `rules.d/*.rules` file and has no `--file`/directory relationship
//! to one).
//!
//! Version-INDEPENDENT: `permissive=1` fail-open is wrong on every supported
//! fapolicyd release, so this fires even with `target: None` - unlike
//! fapd-W13 (`Condition::RequiresTarget`), fapd-W14 is gated on
//! `Condition::RequiresConf` (fires whenever `--conf` is given at all; see
//! `lints::catalog`). The STIG `ControlRef` (`DenyAll` family - a permissive
//! daemon defeats the deny-all/permit-by-exception policy regardless of what
//! the rules themselves say) is attached only when a benchmark `target` IS
//! resolved, mirroring every other doctor/lint control-attachment site.
//!
//! Duplicate-key resolution is LAST-WINS, mirroring
//! `crates/rulesteward-cli/src/commands/conf.rs::conf_value` (fapolicyd's own
//! `daemon-config.c` keyword handlers overwrite with no early-exit) - this is
//! an IN-CRATE scanner, not a call into that CLI helper: `rulesteward-fapolicyd`
//! must not depend on `rulesteward-cli` (the dependency runs the other way).
//! Only WHOLE-LINE `#` comments are skipped (a line whose first non-whitespace
//! token starts with `#`); a trailing `#` is not stripped.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use crate::lints::stig::ControlFamily;
use crate::version::TargetVersion;

/// fapd-W14: an effectively-permissive `permissive=` value set in the
/// `fapolicyd.conf` text at `path`.
///
/// Fires whenever the LAST-WINS resolved value of the `permissive` key,
/// reduced to its FIRST whitespace token (issue #569 - the daemon's
/// `nv_split`/`_strsplit` binds `nv.value` to only the first token after
/// `=`; a trailing `# comment` or other junk token is logged separately but
/// never reaches the keyword's parser, so it must not be considered), is a
/// non-empty, all-ASCII-digit string containing at least one nonzero digit -
/// the daemon's `strtoul`-then-clamp semantics (see `is_effectively_permissive`
/// below): `"1"`, `"2"`, `"10"`, `"01"`, `"007"`, etc. all fire - regardless
/// of `target` (version-independent). Anchored at the WINNING line (the last
/// non-whole-line-comment occurrence of the key, last-wins per fapolicyd's
/// own config-loader semantics - see the module doc). Absent key, an
/// all-zero digit string (e.g. `"0"`, `"00"`), or a non-numeric FIRST token
/// (e.g. `"1x"`, `"foo 1"`) is clean.
#[must_use]
pub fn lint_conf(text: &str, path: &Path, target: Option<TargetVersion>) -> Vec<Diagnostic> {
    // Last-wins scan, mirroring `commands/conf.rs::conf_value` exactly (whole-line
    // `#` comments only; whitespace-tolerant around `=`; a trailing `#` is part of
    // the literal value, never stripped). Tracked separately here (rather than
    // calling into that CLI helper) because this crate must not depend on
    // `rulesteward-cli` - the dependency runs the other way.
    let mut winner: Option<(usize, std::ops::Range<usize>, &str)> = None;
    let mut offset = 0usize;
    for (idx, line) in text.split('\n').enumerate() {
        let start = offset;
        let end = start + line.len();
        offset = end + 1; // account for the consumed '\n' separator.
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == "permissive"
        {
            winner = Some((idx + 1, start..end, v.trim()));
        }
    }

    let Some((line, span, value)) = winner else {
        return Vec::new();
    };
    // Issue #569: mirror `rulesteward-cli`'s
    // `doctor::probe::permissive_value_is_effectively_permissive` exactly.
    // Ground truth (`daemon-config.c`'s `nv_split`/`_strsplit`, live-verified
    // on fapolicyd 1.3.2 and 1.4.5): a config line is whitespace-tokenized
    // and `nv.value` is bound to ONLY the FIRST token after `=` - a trailing
    // `# comment` (or any further token) is separately logged as "Wrong
    // number of arguments" but does not change which token the keyword's
    // parser (`permissive_parser`) receives. So the value must be reduced to
    // its first whitespace token BEFORE the digit-clamp predicate runs, not
    // treated as effectively-permissive if ANY token qualifies.
    let first_token = value.split_whitespace().next();
    if !first_token.is_some_and(is_effectively_permissive) {
        return Vec::new();
    }

    let controls = target
        .map(|t| crate::lints::stig::control_refs(ControlFamily::DenyAll, t))
        .unwrap_or_default();

    vec![
        super::anchored(
            Severity::Warning,
            "fapd-W14",
            span,
            "fapolicyd.conf sets a permissive (fail-open) value instead of enforcing",
            path,
            line,
        )
        .with_controls(controls),
    ]
}

/// True iff `value` is fapolicyd's on-wire representation of a permissive
/// (fail-open) `permissive=` setting.
///
/// Adversarial round 2 (impl-aware, grounded on upstream
/// `src/library/daemon-config.c`): the daemon's `permissive_parser`
/// delegates to `unsigned_int_parser` - a base-10 `strtoul` of the WHOLE
/// value - then CLAMPS any parsed value greater than 1 down to 1. So the
/// daemon runs permissive for `"1"`, `"2"`, `"10"`, `"01"` (leading zeros
/// are valid decimal syntax to `strtoul`), `"007"`, and so on: any string
/// that is non-empty, entirely ASCII digits, and contains at least one
/// nonzero digit. A non-numeric value (trailing garbage after the digits,
/// e.g. `"1x"`) is a parse error and leaves the enforcing default in
/// place; an all-zero digit string (`"0"`, `"00"`) parses to 0
/// (enforcing).
///
/// Deliberately NOT `value.parse::<u64>().is_ok_and(|n| n >= 1)`: an
/// absurdly long all-digit string (more digits than fit in a `u64`) would
/// overflow `parse` and return `Err`, wrongly reporting "clean" even
/// though the real daemon's `strtoul` saturates such a value to
/// `ULONG_MAX` on overflow and still clamps it to permissive. Checking
/// "all digits and at least one nonzero digit" needs no integer parse at
/// all, so it matches `strtoul`'s clamped behavior regardless of the
/// input's length.
#[must_use]
pub fn is_effectively_permissive(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.bytes().any(|b| b != b'0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("/etc/fapolicyd/fapolicyd.conf")
    }

    fn codes(diags: &[Diagnostic]) -> Vec<&str> {
        diags.iter().map(|d| d.code.as_ref()).collect()
    }

    // ---------------------------------------------------------------------
    // Version-independence: fires under target=None too.
    // ---------------------------------------------------------------------

    #[test]
    fn permissive_one_fires_even_without_a_target() {
        let diags = lint_conf("permissive = 1\n", &p(), None);
        assert_eq!(
            diags.len(),
            1,
            "permissive=1 is version-independent and must fire under target=None: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W14");
        assert!(
            diags[0].controls.is_empty(),
            "no target resolved -> no STIG control attached: {:?}",
            diags[0].controls
        );
    }

    // ---------------------------------------------------------------------
    // Last-wins anchoring (kills a first-wins wrong impl in BOTH directions).
    // ---------------------------------------------------------------------

    #[test]
    fn zero_then_one_fires_anchored_at_the_second_winning_line() {
        // Last-wins: line 2's `permissive=1` overrides line 1's `permissive=0`,
        // so the daemon is actually permissive -> fires, anchored at line 2 (the
        // WINNING occurrence), not line 1.
        let diags = lint_conf("permissive=0\npermissive=1\n", &p(), None);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(
            diags[0].line, 2,
            "must anchor at the WINNING (second, last) line, not the first"
        );
    }

    #[test]
    fn one_then_zero_is_clean() {
        // Reversed order: the LAST occurrence resolves to 0, so the daemon is
        // enforcing, not permissive -> clean. This is the direct kill of a
        // first-wins wrong impl (which would wrongly fire here, having seen
        // `permissive=1` first).
        let diags = lint_conf("permissive=1\npermissive=0\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "last-wins resolves to 0 (enforcing); a first-wins impl would \
             wrongly fire here: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------
    // Absent / zero -> clean.
    // ---------------------------------------------------------------------

    #[test]
    fn absent_key_is_clean() {
        let diags = lint_conf("integrity=sha256\nrpm_integrity_check=1\n", &p(), None);
        assert!(codes(&diags).is_empty(), "{diags:?}");
    }

    #[test]
    fn permissive_zero_alone_is_clean() {
        let diags = lint_conf("permissive=0\n", &p(), None);
        assert!(codes(&diags).is_empty(), "{diags:?}");
    }

    #[test]
    fn whole_line_commented_permissive_is_ignored() {
        // Mirrors `commands/conf.rs::conf_value_skips_whole_line_comments`: a
        // whole-line `#`-prefixed occurrence never counts, so the REAL
        // (uncommented) `permissive=0` below is the only vote and resolves
        // clean.
        let diags = lint_conf("# permissive=1\npermissive=0\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "a commented-out permissive=1 must not count: {diags:?}"
        );
    }

    #[test]
    fn inline_hash_after_permissive_one_still_fires_first_token_wins() {
        // CORRECTED (issue #569, doc-truth-decay fix): the scanner-level
        // claim ("a trailing `#` is not stripped") is still true and
        // unchanged - `winner`'s captured value is the raw, untrimmed-of-
        // comment remainder `"1 # note"`. What was WRONG in the original
        // version of this test (Adversarial round 1, Finding 3) was the
        // conclusion drawn from that raw value: it assumed the daemon
        // treats a non-exact-"1" raw remainder as a parse error and stays
        // enforcing. Issue #567/#569's ATL round 2 grounding (live-verified
        // on fapolicyd 1.3.2 and 1.4.5, see
        // `rulesteward-cli/src/commands/doctor/probe.rs`'s
        // `permissive_value_is_effectively_permissive` doc, ~line 280-298,
        // and its `daemon-config.c` `nv_split`/`_strsplit` citation) proved
        // the opposite: the daemon whitespace-tokenizes the raw remainder
        // and binds `nv.value` to ONLY the FIRST token ("1"); a trailing
        // `# note` (or any further token) is separately logged as "Wrong
        // number of arguments" but does NOT stop `permissive_parser` from
        // being called with the first-token value. So the real daemon runs
        // PERMISSIVE for this line, and `lint_conf` must fire fapd-W14
        // here, not report clean. The doctor probe was already corrected
        // for this (9e-wave2c); this lint (`fapd-W14`, from PR #565) has
        // the IDENTICAL miss and is fixed by the same first-token
        // tokenization before `is_effectively_permissive` (issue #569).
        let diags = lint_conf("permissive = 1 # note\n", &p(), None);
        assert_eq!(
            diags.len(),
            1,
            "the daemon's nv_split takes only the first whitespace token \
             (\"1\") as the value and runs permissive despite the trailing \
             \"# note\" text (live-verified fapolicyd 1.3.2/1.4.5, issue \
             #567/#569); lint_conf must fire fapd-W14: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(diags[0].line, 1, "must anchor at the winning line");

        // And the inline-comment line must not shadow a LATER bare
        // occurrence: last-wins resolves line 2's `permissive = 1` to
        // exactly "1" -> fires, anchored at that later WINNING line (this
        // outcome is unchanged by the #569 fix: both lines resolve
        // permissive, but only the LAST occurrence is evaluated at all).
        let diags = lint_conf("permissive = 1 # note\npermissive = 1\n", &p(), None);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(
            diags[0].line, 2,
            "must anchor at the later uncommented winning line, not the \
             inline-comment line"
        );
    }

    // -------------------------------------------------------------------
    // Issue #569: first-token tokenization before `is_effectively_permissive`,
    // mirroring the already-fixed doctor probe
    // (`rulesteward-cli/src/commands/doctor/probe.rs::
    // permissive_value_is_effectively_permissive`, 9e-wave2c / ATL round 2
    // MISS 1). Ground truth: fapolicyd's `daemon-config.c` `nv_split`/
    // `_strsplit` whitespace-tokenizes the value text and binds `nv.value`
    // to ONLY the first token after `=`; any further token (a `# comment`
    // or otherwise) is logged as "Wrong number of arguments" but does NOT
    // change which token the keyword's parser (here `permissive_parser`)
    // receives. Live-verified on fapolicyd 1.3.2 (Rocky 8) and 1.4.5
    // (Rocky 9) per the probe's grounding. These pins mirror the probe's
    // `read_fapolicyd_mode_from_permissive_{one,five,zero}_with_inline_
    // comment_returns_*` fixtures exactly, at the `lint_conf` surface.
    // -------------------------------------------------------------------

    #[test]
    fn conf_inline_permissive_one_with_trailing_comment_fires() {
        // First token "1" -> effectively permissive -> daemon runs
        // permissive despite "Wrong number of arguments" being logged for
        // the extra token.
        let diags = lint_conf("permissive = 1 # temporarily on\n", &p(), None);
        assert_eq!(
            diags.len(),
            1,
            "first token \"1\" is effectively permissive in the real \
             daemon (nv_split/_strsplit); the trailing comment text must \
             not mask it: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(diags[0].line, 1, "must anchor at the winning line");
    }

    #[test]
    fn conf_inline_permissive_five_with_trailing_comment_fires() {
        // First token "5" -> strtoul("5") = 5, clamped to 1 by
        // `permissive_parser`'s range check -> the real daemon runs
        // permissive (live-confirmed WARNING "permissive value reset to 1"
        // on fapolicyd9 for this exact fixture per the probe's grounding).
        let diags = lint_conf("permissive = 5 # comment\n", &p(), None);
        assert_eq!(
            diags.len(),
            1,
            "first token \"5\" clamps to permissive-mode in the real \
             daemon; the trailing comment text must not mask it: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(diags[0].line, 1, "must anchor at the winning line");
    }

    #[test]
    fn conf_inline_permissive_zero_with_trailing_comment_is_clean() {
        // Control (must pass both before and after the #569 fix): first
        // token "0" -> strtoul("0") = 0 -> the daemon stays enforcing
        // regardless of the trailing comment text ("Wrong number of
        // arguments" is still logged, but no permissive/reset warning
        // follows, per the probe's live-verified grounding).
        let diags = lint_conf("permissive = 0 # off\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "first token \"0\" is enforcing in the real daemon regardless \
             of the trailing comment text: {diags:?}"
        );
    }

    #[test]
    fn conf_inline_permissive_one_with_trailing_word_fires() {
        // Non-`#` trailing junk is the SAME daemon code path as an inline
        // comment: `nv_split` tokenizes on whitespace generically, not on
        // `#` specifically, so any second token (comment or otherwise)
        // triggers the identical "Wrong number of arguments" logging while
        // the first token ("1") still reaches `permissive_parser`. This
        // pin defeats a narrow fix that special-cases only a `#`-prefixed
        // trailing token instead of doing a true first-whitespace-token
        // split.
        let diags = lint_conf("permissive = 1 anything\n", &p(), None);
        assert_eq!(
            diags.len(),
            1,
            "first token \"1\" is effectively permissive regardless of \
             what non-comment trailing token follows it: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(diags[0].line, 1, "must anchor at the winning line");
    }

    #[test]
    fn conf_inline_permissive_zero_with_trailing_one_stays_clean() {
        // ATL rework round (adversarial review, BLOCKER): pins the
        // FIRST-token-only binding against a plausible-but-wrong
        // "any token is effectively permissive" impl (e.g.
        // `value.split_whitespace().any(is_effectively_permissive)`), which
        // would wrongly fire here having found "1" as the SECOND token.
        // Ground truth (`daemon-config.c`'s `nv_split`/`_strsplit`, same
        // citation as `permissive_value_is_effectively_permissive` in
        // `rulesteward-cli/src/commands/doctor/probe.rs`): `nv.value` is
        // bound to ONLY the first whitespace token after `=` ("0"); the
        // trailing "1" is a second token that only trips the daemon's
        // separate "Wrong number of arguments" logging and is never passed
        // to `permissive_parser`. So the real daemon stays enforcing for
        // this line, and a correct first-token impl must report clean.
        let diags = lint_conf("permissive = 0 1\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "the daemon binds nv.value to the FIRST token (\"0\", \
             enforcing) and never inspects the trailing \"1\"; an \
             any-token impl would wrongly fire here: {diags:?}"
        );
    }

    #[test]
    fn conf_inline_permissive_non_numeric_with_trailing_one_stays_clean() {
        // Mirror of the pin above with a non-numeric first token: "foo" is
        // not all-ASCII-digits, so `is_effectively_permissive` rejects it
        // (parse error, daemon stays at the enforcing default) regardless
        // of the trailing "1" - again defeating an any-token impl that
        // would find "1" as the second token and wrongly fire.
        let diags = lint_conf("permissive = foo 1\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "the daemon binds nv.value to the FIRST token (\"foo\", a \
             parse error that leaves the enforcing default in place) and \
             never inspects the trailing \"1\": {diags:?}"
        );
    }

    // ---------------------------------------------------------------------
    // Byte-accurate span on a later line (mutation-kill: the scanner's
    // `start`/`end`/`offset` arithmetic, round 2).
    // ---------------------------------------------------------------------

    #[test]
    fn span_and_line_are_byte_accurate_on_a_later_line() {
        // Mutation round 2 (survivors 1-3): the scanner's byte-offset
        // arithmetic - `end = start + line.len()` and the next line's
        // `offset = end + 1` (skipping the consumed `\n`) - was never pinned
        // by an exact-span assertion, only by `.line`. A `+` -> `*` or
        // `+` -> `-` mutation in either expression drifts the computed span
        // away from the real byte range while often leaving the winning
        // LINE NUMBER unchanged (a same-line-index-0 winner can't
        // distinguish them at all, since a `line`-only check never reads
        // `.span`). Anchoring the winner on line 2 (not line 1) forces the
        // `offset` carry-over from line 1 to matter, and asserting the
        // exact byte range catches all three mutants:
        //   - `start * line.len()` for line 1 (idx 0) collapses `end` to 0
        //     (since `start == 0`), corrupting the carried `offset`.
        //   - `end * 1` (the `*` mutant of `end + 1`) drops the `+1` for the
        //     consumed `\n`, shifting every later line's `start` back by 1.
        //   - `end - 1` shifts it back by 2.
        // "foo=bar" is 7 bytes (indices 0..7), byte 7 is the consumed `\n`,
        // so "permissive=1" (12 bytes) starts at byte 8 and ends at byte 20.
        let text = "foo=bar\npermissive=1\n";
        let diags = lint_conf(text, &p(), None);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].line, 2, "permissive=1 is on line 2");
        assert_eq!(
            diags[0].span,
            8..20,
            "span must be the EXACT byte range of `permissive=1` on line 2 \
             (bytes 0..7 are `foo=bar`, byte 7 is the consumed `\\n`): {:?}",
            diags[0].span
        );
    }

    // ---------------------------------------------------------------------
    // Adversarial round 2 (impl-aware, grounded on upstream
    // src/library/daemon-config.c): the daemon's `permissive_parser`
    // delegates to `unsigned_int_parser` - a base-10 `strtoul` of the WHOLE
    // value - then CLAMPS any parsed value > 1 down to 1. So the daemon
    // runs permissive (fail-open) for ANY non-empty all-ASCII-digit value
    // that isn't all zeros: "1", "2", "10", "01" (leading zeros are valid
    // decimal syntax to `strtoul`), not just the exact string "1". A
    // non-numeric value (trailing garbage after the digits, e.g. "1x") is
    // a parse error and leaves the enforcing default; an all-zero digit
    // string parses to 0 (enforcing). The old exact-string `value != "1"`
    // guard was a false negative on every nonzero-numeric-but-not-"1"
    // value.
    // ---------------------------------------------------------------------

    #[test]
    fn permissive_two_fires() {
        // strtoul("2", ...) = 2, clamped to 1 by unsigned_int_parser's
        // range check in daemon-config.c -> the daemon runs permissive.
        let diags = lint_conf("permissive = 2\n", &p(), None);
        assert_eq!(
            diags.len(),
            1,
            "permissive=2 clamps to permissive-mode in the real daemon; must fire: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(diags[0].line, 1, "must anchor at the winning line");
    }

    #[test]
    fn permissive_leading_zero_one_fires() {
        // strtoul("01", ...) = 1 (leading zeros are valid decimal syntax to
        // strtoul) -> the daemon runs permissive.
        let diags = lint_conf("permissive = 01\n", &p(), None);
        assert_eq!(
            diags.len(),
            1,
            "permissive=01 parses to 1 in the real daemon; must fire: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(diags[0].line, 1, "must anchor at the winning line");
    }

    #[test]
    fn permissive_ten_fires() {
        // strtoul("10", ...) = 10, clamped to 1 by the same range check ->
        // the daemon runs permissive.
        let diags = lint_conf("permissive = 10\n", &p(), None);
        assert_eq!(
            diags.len(),
            1,
            "permissive=10 clamps to permissive-mode in the real daemon; must fire: {diags:?}"
        );
        assert_eq!(diags[0].code, "fapd-W14");
        assert_eq!(diags[0].line, 1, "must anchor at the winning line");
    }

    #[test]
    fn permissive_all_zeros_is_clean() {
        // strtoul("00", ...) = 0 -> the daemon stays enforcing.
        let diags = lint_conf("permissive = 00\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "permissive=00 parses to 0 (enforcing) in the real daemon: {diags:?}"
        );
    }

    #[test]
    fn permissive_non_numeric_is_clean() {
        // "1x" has trailing non-digit garbage after the leading digit, a
        // parse error in the real daemon's config-value parsing -> the
        // enforcing default is left in place.
        let diags = lint_conf("permissive = 1x\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "permissive=1x is a parse error in the real daemon (stays enforcing): {diags:?}"
        );
    }

    // ---------------------------------------------------------------------
    // Adversarial round 3 (impl-aware, grounded on upstream
    // src/library/daemon-config.c): the daemon's own tokenizer, `_strsplit`,
    // splits a value ONLY on the ASCII space byte (`ptr = strchr(str, ' ');`)
    // and `get_line` strips ONLY a trailing 0x0a, never 0x0d. So a tab (or a
    // stray `\r` from a CRLF-edited conf file) is NOT a token separator to
    // the real daemon - it is part of the single value token handed to
    // `unsigned_int_parser`, which does a byte-exact `isdigit` walk and
    // rejects the whole token the moment it hits a non-digit byte, leaving
    // the enforcing default in place. An impl that tokenizes with Rust's
    // Unicode-whitespace-aware `split_whitespace()` / `.trim()` (which both
    // treat TAB and CR as whitespace) diverges from that byte-exact
    // behavior and wrongly fires on values the daemon itself would reject
    // as unparsable. These pins are BLIND to the fix shape (they only
    // assert observable behavior), so they hold regardless of whether the
    // fix tokenizes by hand or reuses a shared byte-exact-digit predicate.
    // ---------------------------------------------------------------------

    #[test]
    fn tab_separated_second_token_does_not_leak_into_the_value() {
        // The daemon's `_strsplit` splits only on the ASCII space byte, so
        // "1\t2" is bound as ONE token to `unsigned_int_parser`, which
        // rejects it outright at the tab byte (not a digit) -> parse error
        // -> the enforcing default stays in place -> clean. A `split_whitespace()`-
        // based impl would wrongly split off "1" as the first token and fire.
        let diags = lint_conf("permissive = 1\t2\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "a TAB (not a space) between tokens is not a real daemon \
             separator; the whole value \"1\\t2\" is an unsigned_int_parser \
             error and must stay clean: {diags:?}"
        );
    }

    #[test]
    fn tab_before_inline_hash_does_not_leak_a_bare_digit_value() {
        // Same root cause as the bare-tab case above, but with the value
        // followed by an inline `#` comment (which the daemon's `nv_split`
        // never strips - see `inline_hash_is_part_of_the_value_not_a_comment`
        // above). The raw resolved value is "1\t# note", which
        // `unsigned_int_parser` rejects at the tab byte -> stays clean.
        let diags = lint_conf("permissive = 1\t# note\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "\"1\\t# note\" is not a bare digit-only value to the real \
             daemon's byte-exact parser; must stay clean: {diags:?}"
        );
    }

    #[test]
    fn crlf_line_ending_leaves_a_trailing_cr_in_the_value() {
        // `get_line` in the real daemon strips ONLY the trailing 0x0a; a
        // CRLF-edited conf file leaves a trailing '\r' byte bound to the
        // value token, e.g. "1\r". `unsigned_int_parser`'s byte-exact
        // isdigit walk rejects that '\r' -> parse error -> the enforcing
        // default stays in place -> clean. An impl whose scanner splits on
        // '\n' and then Unicode-`.trim()`s the resulting line strips the
        // '\r' as whitespace, wrongly recovering the bare value "1" and
        // firing.
        let diags = lint_conf("permissive = 1\r\n", &p(), None);
        assert!(
            codes(&diags).is_empty(),
            "a CRLF line ending leaves a trailing '\\r' bound to the value \
             in the real daemon, which unsigned_int_parser rejects; must \
             stay clean: {diags:?}"
        );
    }

    // ---------------------------------------------------------------------
    // ControlRefs: DenyAll family, ONLY when target resolves.
    // ---------------------------------------------------------------------

    #[test]
    fn control_attached_only_when_target_resolves() {
        // With a resolved target: exactly one DenyAll STIG control (G7/G8
        // rhel9 row: RHEL-09-433016 / V-270180), hardcoded here rather than
        // sourced from `lints::stig::control_refs` so this test's RED status
        // does not depend on T1's (also not-yet-implemented) table.
        let with_target = lint_conf("permissive=1\n", &p(), Some(TargetVersion::Rhel9));
        assert_eq!(with_target.len(), 1, "{with_target:?}");
        assert_eq!(
            with_target[0].controls.len(),
            1,
            "a resolved target must attach the DenyAll STIG control: {:?}",
            with_target[0].controls
        );
        assert_eq!(with_target[0].controls[0].id, "RHEL-09-433016");
        assert_eq!(
            with_target[0].controls[0].alias.as_deref(),
            Some("V-270180")
        );

        // Without a target: same finding, but NO control (nothing to map to a
        // benchmark baseline without one).
        let without_target = lint_conf("permissive=1\n", &p(), None);
        assert_eq!(without_target.len(), 1, "{without_target:?}");
        assert!(
            without_target[0].controls.is_empty(),
            "target=None must attach no controls: {:?}",
            without_target[0].controls
        );
    }
}
