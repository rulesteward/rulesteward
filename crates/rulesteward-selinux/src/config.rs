//! `/etc/selinux/config` reader (issue #520).
//!
//! CRITICAL (see `grounding/g4-g6-selinux-config.md`, section G4): libselinux
//! parses this file with TWO INDEPENDENT readers carrying DIFFERENT per-key
//! semantics - `selinux_getenforcemode()` for `SELINUX=` and
//! `init_selinux_config()` for `SELINUXTYPE=`. A uniform `KEY=VALUE` map with
//! one duplicate/case/whitespace policy CANNOT reproduce both; this reader
//! encodes each key's rules separately. Every test below traces to a numbered
//! "G4 frozen-test implications" item in the grounding doc.

use rulesteward_core::span::Span;

/// One matched `SELINUX=`/`SELINUXTYPE=` line: the raw value text (verbatim,
/// never case-normalized), its 1-based source line, and its byte span in the
/// original text. Both anchor a lint finding at the winning assignment (see
/// `crate::lints::boot`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigValue {
    pub value: String,
    pub line: usize,
    pub span: Span,
}

/// The two directives this reader extracts from `/etc/selinux/config`. `None`
/// when the respective key never had a matching line (see each field's own
/// per-key rules for what counts as a match).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelinuxConfig {
    /// `SELINUX=` per `selinux_getenforcemode()` (G4): key case-SENSITIVE at
    /// column 0 (no leading whitespace allowed before the key); the FIRST
    /// line whose value is a recognized case-insensitive PREFIX of
    /// `enforcing`/`permissive`/`disabled` wins (an unrecognized value does
    /// NOT stop the scan - a later recognized line still wins); quotes are
    /// NOT stripped (so a quoted value is itself unrecognized); space BEFORE
    /// `=` is never accepted; space AFTER `=` IS modeled as accepted here
    /// (the rhel9/10 libselinux 3.6+ behavior - se-W01, the only consumer, is
    /// rhel9/10-only per G4's version-divergence note).
    pub selinux: Option<ConfigValue>,
    /// `SELINUXTYPE=` per `init_selinux_config()` (G4): key case-INSENSITIVE;
    /// leading whitespace before the key IS allowed; the LAST matching line
    /// wins; the value is the remainder after the tag, right-trimmed of
    /// trailing whitespace/control bytes only (an inline `# comment` is part
    /// of the value - NOT stripped, since only WHOLE-LINE comments are
    /// recognized before the key match); space BEFORE `=` is never accepted;
    /// space AFTER `=` is modeled as NOT accepted here (the rhel8 libselinux
    /// 2.9 behavior, with no post-`=` whitespace skip - se-W02, the only
    /// consumer, is rhel8-only per G4's version-divergence note), so the
    /// leading space becomes PART of the stored value, same as the real 2.9
    /// parser would corrupt the policy root.
    pub selinuxtype: Option<ConfigValue>,
}

/// Parse `text` (the contents of `/etc/selinux/config`) into the two
/// directives this reader cares about.
///
/// Tolerant: malformed / unrecognized lines are silently skipped, mirroring
/// libselinux's own non-fatal behavior for a malformed or unreadable config
/// (G4 Q5) - there is no fatal/error code path for this reader.
#[must_use]
pub fn parse_selinux_config(text: &str) -> SelinuxConfig {
    let lines = lines_with_spans(text);
    SelinuxConfig {
        selinux: find_selinux(&lines),
        selinuxtype: find_selinuxtype(&lines),
    }
}

/// One raw line of `text`: its 1-based line number, its byte span (excluding
/// the trailing `\n`, but INCLUDING a trailing `\r` for a CRLF file - a raw
/// `fgets`-style slice, not `str::lines()`, which would silently strip it),
/// and the line's text.
type RawLine<'a> = (usize, std::ops::Range<usize>, &'a str);

/// Split `text` into 1-based-numbered, byte-spanned raw lines. A trailing
/// `\n` produces one final empty "line" (harmless: it matches nothing).
fn lines_with_spans(text: &str) -> Vec<RawLine<'_>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut line_no = 0usize;
    for raw in text.split('\n') {
        line_no += 1;
        let start = offset;
        let end = start + raw.len();
        out.push((line_no, start..end, raw));
        offset = end + 1;
    }
    out
}

/// The three `SELINUX=` values `selinux_getenforcemode()` recognizes (G4 Q7),
/// each matched as a case-insensitive PREFIX of the line's value.
const SELINUX_VALUE_WORDS: [&str; 3] = ["enforcing", "permissive", "disabled"];

/// True when `value` starts with (case-insensitively) one of
/// [`SELINUX_VALUE_WORDS`] - `strncasecmp(tag, word, word.len())` (G4 Q7). A
/// value shorter than every word's length is never a match.
fn is_recognized_selinux_value(value: &str) -> bool {
    SELINUX_VALUE_WORDS.iter().any(|word| {
        value
            .get(..word.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(word))
    })
}

/// `SELINUX=` per `selinux_getenforcemode()` (G4): key match at column 0,
/// case-SENSITIVE (`strncmp`); FIRST line whose value is a recognized prefix
/// wins (an unrecognized value does not stop the scan). The stored value is
/// the tag with only LEADING whitespace skipped (models the rhel9/10 3.6+
/// whitespace-skip-after-`=` behavior, per this module's own doc comment) -
/// verbatim otherwise, case-preserved, comment text included.
fn find_selinux(lines: &[RawLine<'_>]) -> Option<ConfigValue> {
    for (line, span, raw) in lines {
        let Some(tag) = raw.strip_prefix("SELINUX=") else {
            continue;
        };
        let after_ws = tag.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if is_recognized_selinux_value(after_ws) {
            return Some(ConfigValue {
                value: after_ws.to_string(),
                line: *line,
                span: span.clone(),
            });
        }
    }
    None
}

/// The `SELINUXTYPE=` tag, matched case-insensitively (G4 Q3).
const SELINUXTYPE_TAG: &str = "SELINUXTYPE=";

/// Strip trailing `isspace`/`iscntrl` bytes (G4 Q2/Q14) - the right-trim loop
/// `init_selinux_config()` applies to the extracted value (removes CRLF's
/// `\r` along with ordinary trailing whitespace).
fn right_trim_selinuxtype_value(value: &str) -> &str {
    value.trim_end_matches(|c: char| c.is_ascii_whitespace() || c.is_ascii_control())
}

/// `SELINUXTYPE=` per `init_selinux_config()` (G4): leading whitespace before
/// the key IS skipped; a line that is (after that skip) empty or starts with
/// `#` is a whole-line comment and never matched; the key match is
/// case-INSENSITIVE; the value is the literal remainder after the tag (NO
/// post-`=` whitespace skip - models the rhel8 2.9 behavior, per this
/// module's own doc comment), right-trimmed. The LAST matching line wins (the
/// loop runs to EOF with no break - opposite of `find_selinux`).
fn find_selinuxtype(lines: &[RawLine<'_>]) -> Option<ConfigValue> {
    let mut winner: Option<ConfigValue> = None;
    for (line, span, raw) in lines {
        let trimmed = raw.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(tag_region) = trimmed.get(..SELINUXTYPE_TAG.len()) else {
            continue;
        };
        if !tag_region.eq_ignore_ascii_case(SELINUXTYPE_TAG) {
            continue;
        }
        let raw_value = &trimmed[SELINUXTYPE_TAG.len()..];
        winner = Some(ConfigValue {
            value: right_trim_selinuxtype_value(raw_value).to_string(),
            line: *line,
            span: span.clone(),
        });
    }
    winner
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selinux_value(cfg: &SelinuxConfig) -> Option<&str> {
        cfg.selinux.as_ref().map(|v| v.value.as_str())
    }

    fn selinuxtype_value(cfg: &SelinuxConfig) -> Option<&str> {
        cfg.selinuxtype.as_ref().map(|v| v.value.as_str())
    }

    // --- G4 item 1: SELINUX= duplicate keys, FIRST recognized wins ---------

    #[test]
    fn g4_1_selinux_first_recognized_value_wins() {
        let cfg = parse_selinux_config("SELINUX=enforcing\nSELINUX=permissive\n");
        assert_eq!(
            selinux_value(&cfg),
            Some("enforcing"),
            "the FIRST recognized SELINUX= line wins (G4 Q1); a last-wins impl \
             would report permissive here"
        );
    }

    #[test]
    fn g4_1_selinux_first_recognized_value_wins_reverse_order() {
        let cfg = parse_selinux_config("SELINUX=permissive\nSELINUX=enforcing\n");
        assert_eq!(
            selinux_value(&cfg),
            Some("permissive"),
            "order matters: the FIRST recognized line wins regardless of which \
             value it is"
        );
    }

    // --- G4 item 2: an unrecognized SELINUX= value does not stop the scan --

    #[test]
    fn g4_2_unrecognized_selinux_value_does_not_stop_the_scan() {
        let cfg = parse_selinux_config("SELINUX=bogus\nSELINUX=permissive\n");
        assert_eq!(
            selinux_value(&cfg),
            Some("permissive"),
            "an unrecognized value is silently skipped, not a scan-stopping \
             match; the LATER recognized line must still win"
        );
    }

    // --- G4 item 3: SELINUXTYPE= duplicate keys, LAST wins (OPPOSITE of
    // SELINUX=) -------------------------------------------------------------

    #[test]
    fn g4_3_selinuxtype_last_value_wins() {
        let cfg = parse_selinux_config("SELINUXTYPE=targeted\nSELINUXTYPE=mls\n");
        assert_eq!(
            selinuxtype_value(&cfg),
            Some("mls"),
            "SELINUXTYPE= has the OPPOSITE duplicate-winner rule from SELINUX=: \
             the LAST matching line wins (G4 Q1); do not share one duplicate \
             policy between the two keys"
        );
    }

    // --- G4 item 4: leading whitespace before the key ----------------------

    #[test]
    fn g4_4_leading_whitespace_hides_selinux_but_not_selinuxtype() {
        let cfg = parse_selinux_config("  SELINUX=enforcing\n  SELINUXTYPE=mls\n");
        assert_eq!(
            selinux_value(&cfg),
            None,
            "a `SELINUX=` line is matched at column 0 with `strncmp` - leading \
             whitespace makes it invisible to the reader (G4 Q2)"
        );
        assert_eq!(
            selinuxtype_value(&cfg),
            Some("mls"),
            "SELINUXTYPE= skips leading whitespace before the key match \
             (G4 Q2) - leading whitespace is allowed for THIS key only"
        );
    }

    // --- G4 item 5: space BEFORE `=` is never accepted for either key ------

    #[test]
    fn g4_5_space_before_equals_is_ignored_for_both_keys() {
        let cfg = parse_selinux_config("SELINUX = enforcing\nSELINUXTYPE = mls\n");
        assert_eq!(
            selinux_value(&cfg),
            None,
            "`SELINUX ` (space before `=`) mismatches the `SELINUX=` tag at \
             the `=` byte on every libselinux version (G4 Q2)"
        );
        assert_eq!(
            selinuxtype_value(&cfg),
            None,
            "same tag-mismatch rule applies to `SELINUXTYPE=` (G4 Q2)"
        );
    }

    // --- G4 item 6: space AFTER `=` is version-divergent; this lane models
    // the rhel9/10 behavior for SELINUX= (se-W01 is rhel9/10-only) and the
    // rhel8 behavior for SELINUXTYPE= (se-W02 is rhel8-only) -----------------

    #[test]
    fn g4_6_selinux_space_after_equals_is_modeled_as_accepted() {
        // Modeled on libselinux 3.6+ (rhel9/10): the post-`=` whitespace IS
        // skipped, so the value is recognized and stored without the
        // leading space.
        let cfg = parse_selinux_config("SELINUX= enforcing\n");
        assert_eq!(
            selinux_value(&cfg),
            Some("enforcing"),
            "se-W01 only ever runs at rhel9/rhel10, so this reader models the \
             3.6+ (rhel9/10) whitespace-skip-after-`=` behavior for SELINUX= \
             (G4 Q2/6); a rhel8-faithful (2.9) impl would report None here"
        );
    }

    #[test]
    fn g4_6_selinuxtype_space_after_equals_is_modeled_as_not_accepted() {
        // Modeled on libselinux 2.9 (rhel8): there is NO post-`=` whitespace
        // skip, so the leading space becomes PART of the stored value
        // (mirroring the real corrupted-policy-root behavior on rhel8).
        let cfg = parse_selinux_config("SELINUXTYPE= targeted\n");
        assert_eq!(
            selinuxtype_value(&cfg),
            Some(" targeted"),
            "se-W02 only ever runs at rhel8, so this reader models the 2.9 \
             (rhel8) no-whitespace-skip behavior for SELINUXTYPE= (G4 Q2/6): \
             the leading space is preserved in the stored value, which will \
             mismatch the exact string `targeted` at the lint layer - a \
             rhel9/10-faithful impl would report Some(\"targeted\") here"
        );
    }

    // --- G4 item 7: case sensitivity is asymmetric per key ------------------

    #[test]
    fn g4_7_selinux_key_is_case_sensitive() {
        let cfg = parse_selinux_config("selinux=enforcing\n");
        assert_eq!(
            selinux_value(&cfg),
            None,
            "the SELINUX= key match is case-SENSITIVE (`strncmp`, G4 Q3)"
        );
    }

    #[test]
    fn g4_7_selinuxtype_key_is_case_insensitive() {
        let cfg = parse_selinux_config("selinuxtype=mls\n");
        assert_eq!(
            selinuxtype_value(&cfg),
            Some("mls"),
            "the SELINUXTYPE= key match is case-INSENSITIVE (`strncasecmp`, \
             G4 Q3) - a case-sensitive-key impl would miss this line entirely"
        );
    }

    #[test]
    fn g4_7_selinux_value_is_case_insensitive() {
        let cfg = parse_selinux_config("SELINUX=Enforcing\n");
        assert_eq!(
            selinux_value(&cfg),
            Some("Enforcing"),
            "the SELINUX= VALUE match is case-insensitive (G4 Q3), so a mixed \
             case value IS recognized (winning the line); the STORED value is \
             verbatim, case-PRESERVED text, not normalized"
        );
    }

    // --- G4 item 8: quotes are not stripped for either key -----------------

    #[test]
    fn g4_8_selinux_quoted_value_is_unrecognized() {
        let cfg = parse_selinux_config("SELINUX=\"enforcing\"\n");
        assert_eq!(
            selinux_value(&cfg),
            None,
            "quotes are ordinary bytes to selinux_getenforcemode's prefix \
             match; `\"enforcing\"` does not start with `enforcing` (G4 Q6)"
        );
    }

    #[test]
    fn g4_8_selinuxtype_quoted_value_is_literal_with_quotes() {
        let cfg = parse_selinux_config("SELINUXTYPE=\"targeted\"\n");
        assert_eq!(
            selinuxtype_value(&cfg),
            Some("\"targeted\""),
            "SELINUXTYPE= takes the remainder LITERALLY, quotes included \
             (G4 Q6) - stripping quotes here would be a real behavior change \
             from libselinux (it would corrupt the policy root differently)"
        );
    }

    // --- G4 item 9: SELINUX= value match is a PREFIX, not exact ------------

    #[test]
    fn g4_9_selinux_prefix_match_accepts_a_longer_value() {
        let cfg = parse_selinux_config("SELINUX=enforcingXYZ\n");
        assert_eq!(
            selinux_value(&cfg),
            Some("enforcingXYZ"),
            "`strncasecmp(tag, \"enforcing\", 9)` only compares the first 9 \
             bytes (G4 Q7); `enforcingXYZ` is ACCEPTED as a recognized value \
             even though it is not an exact match - a stylistic nit, not a \
             parse rejection"
        );
    }

    #[test]
    fn g4_9_selinux_short_value_is_not_a_prefix_match() {
        let cfg = parse_selinux_config("SELINUX=enf\nSELINUX=permissive\n");
        assert_eq!(
            selinux_value(&cfg),
            Some("permissive"),
            "`enf` is too short to satisfy the 9-byte `enforcing` prefix \
             compare and is therefore unrecognized; the scan continues to \
             the next recognized line (G4 Q7)"
        );
    }

    // --- G4 item 10: inline `# comment` handling differs per key -----------

    #[test]
    fn g4_10_selinux_inline_comment_is_accidentally_accepted_via_prefix_match() {
        let cfg = parse_selinux_config("SELINUX=enforcing # comment\n");
        assert_eq!(
            selinux_value(&cfg),
            Some("enforcing # comment"),
            "SELINUX= has NO comment-handling code at all; it is accepted \
             only because the value comparison is a 9-byte prefix match \
             (G4 Q4/Q10) - the stored value includes the trailing text \
             verbatim"
        );
    }

    #[test]
    fn g4_10_selinuxtype_inline_comment_becomes_part_of_the_value() {
        let cfg = parse_selinux_config("SELINUXTYPE=targeted # comment\n");
        assert_eq!(
            selinuxtype_value(&cfg),
            Some("targeted # comment"),
            "init_selinux_config has NO inline-comment handling: everything \
             after the tag (whitespace-skipped, right-trimmed) is the value, \
             so the `#` text becomes part of it (G4 Q4/Q10) - a real \
             misconfiguration worth a lint, not a comment to strip here"
        );
    }

    // --- G4 item 11: whole-line comments have no effect on either key ------

    #[test]
    fn g4_11_whole_line_and_indented_comments_have_no_effect() {
        let cfg = parse_selinux_config(
            "#SELINUX=disabled\n# comment\n   # indented comment\n#SELINUXTYPE=mls\n",
        );
        assert_eq!(
            selinux_value(&cfg),
            None,
            "`#SELINUX=disabled` fails the column-0 tag match (the `#` is at \
             column 0, not `S`) - never recognized (G4 Q11)"
        );
        assert_eq!(
            selinuxtype_value(&cfg),
            None,
            "`#SELINUXTYPE=mls` is a whole-line comment (leading-whitespace \
             skip then `*buf_p == '#'`) - never recognized (G4 Q4/Q11)"
        );
    }

    // --- G4 item 12 & 13: missing lines are None (no defaulting applied) ---

    #[test]
    fn g4_12_missing_selinuxtype_line_is_none() {
        // The reader reports what WAS in the file; it does NOT apply
        // libselinux's runtime "targeted" default (G4 item 12) - that
        // defaulting is a libselinux/getenforce-time behavior, and se-W02
        // explicitly treats an absent key as a STIG finding regardless
        // (grounding F5 / SV-230282 check-content).
        let cfg = parse_selinux_config("SELINUX=enforcing\n");
        assert_eq!(selinuxtype_value(&cfg), None);
    }

    #[test]
    fn g4_13_missing_selinux_line_is_none() {
        // No recognized SELINUX= line means selinux_getenforcemode returns an
        // error state (-1), NOT a default of any mode (G4 item 13); the
        // reader reports None, not a fabricated "enforcing"/"disabled".
        let cfg = parse_selinux_config("SELINUXTYPE=targeted\n");
        assert_eq!(selinux_value(&cfg), None);
    }

    #[test]
    fn empty_file_yields_both_fields_none() {
        let cfg = parse_selinux_config("");
        assert_eq!(selinux_value(&cfg), None);
        assert_eq!(selinuxtype_value(&cfg), None);
    }

    // --- G4 item 14: CRLF line endings --------------------------------------

    #[test]
    fn g4_14_selinux_crlf_is_still_recognized_via_prefix_match() {
        let cfg = parse_selinux_config("SELINUX=enforcing\r\n");
        let value = selinux_value(&cfg);
        assert!(
            value.is_some_and(|v| v.starts_with("enforcing")),
            "the trailing \\r is ignored by the 9-byte prefix match (G4 Q14); \
             got {value:?}"
        );
    }

    #[test]
    fn g4_14_selinuxtype_crlf_is_right_trimmed_including_control_bytes() {
        let cfg = parse_selinux_config("SELINUXTYPE=targeted\r\n");
        assert_eq!(
            selinuxtype_value(&cfg),
            Some("targeted"),
            "the right-trim loop strips trailing `isspace` OR `iscntrl` \
             bytes, so the \\r is removed (G4 Q2/14); a naive trim that only \
             strips whitespace (not control bytes) would leave a trailing \
             \\r here"
        );
    }

    // --- malformed / junk lines are silently skipped, never fatal ----------

    #[test]
    fn malformed_lines_are_silently_skipped_not_fatal() {
        let cfg = parse_selinux_config(
            "this is not a config line at all\n=SELINUX=enforcing\nSELINUX=enforcing\n",
        );
        assert_eq!(
            selinux_value(&cfg),
            Some("enforcing"),
            "junk lines before the real assignment must not abort the scan \
             or produce a fatal (G4 Q5): the reader is tolerant, never fatal"
        );
    }

    // --- anchoring metadata: line/span for a winning assignment ------------

    #[test]
    fn winning_selinux_line_carries_its_source_line_and_span() {
        let text = "# header\nSELINUX=enforcing\n";
        let cfg = parse_selinux_config(text);
        let cv = cfg.selinux.expect("SELINUX= line recognized");
        assert_eq!(cv.line, 2, "the SELINUX= line is the 2nd line of the file");
        assert_eq!(
            &text[cv.span.clone()],
            "SELINUX=enforcing",
            "span must point exactly at the winning line's bytes"
        );
    }

    #[test]
    fn winning_selinuxtype_line_carries_its_source_line_and_span() {
        let text = "SELINUXTYPE=targeted\nSELINUXTYPE=mls\n";
        let cfg = parse_selinux_config(text);
        let cv = cfg.selinuxtype.expect("SELINUXTYPE= line recognized");
        assert_eq!(
            cv.line, 2,
            "the LAST-wins SELINUXTYPE= line is the 2nd line, not the 1st"
        );
        assert_eq!(&text[cv.span.clone()], "SELINUXTYPE=mls");
    }

    // --- adequacy-bar guard: a uniform KEY=VALUE map cannot pass both duplicate
    // rules at once ----------------------------------------------------------

    #[test]
    fn selinux_and_selinuxtype_duplicate_rules_are_opposite_kill_a_uniform_map() {
        // A single combined fixture where SELINUX= (first-wins) and
        // SELINUXTYPE= (last-wins) each have two lines. A uniform
        // last-wins-for-everything map would report "permissive" for
        // SELINUX= (wrong: must be "enforcing"); a uniform first-wins map
        // would report "targeted" for SELINUXTYPE= (wrong: must be "mls").
        let text = "SELINUX=enforcing\nSELINUXTYPE=targeted\nSELINUX=permissive\nSELINUXTYPE=mls\n";
        let cfg = parse_selinux_config(text);
        assert_eq!(selinux_value(&cfg), Some("enforcing"));
        assert_eq!(selinuxtype_value(&cfg), Some("mls"));
    }
}
