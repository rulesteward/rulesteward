//! The offline derivation core: parse an official DISA XCCDF benchmark into the
//! normalized [`DerivedControl`] table for the sshd W01/W02 STIG baseline.
//!
//! This is the testable heart of the tool - it takes raw XCCDF text and returns the
//! derived controls, with NO network or filesystem. The live fetch that hands it the
//! XCCDF bytes lives behind the seam in [`crate::source`].
//!
//! # How a Rule is selected + classified (grounded in the real DISA XCCDF)
//!
//! A `<Group>`/`<Rule>` is an sshd_config W01/W02 directive control IFF its
//! `<check-content>` contains DISA's canonical check idiom `grep -iH '^\s*<kw>'`
//! AND the Rule references `sshd_config`. The keyword is the grepped (lowercase)
//! word; the V-number is `<Group id>`. The required VALUE is the fixtext's canonical
//! `<Keyword> <args>` config line; the comparison SEMANTIC is inferred from robust
//! token-shape signals (never fragile sentence parsing):
//!
//! - value is a path (`/...`)                -> `PresenceOnly` (Banner)
//! - two tokens (`1G 1h`)                    -> `TwoTokenExact`
//! - all-digit token + "or less" in check    -> `NumericCeiling`, else `NumericExact`
//! - fixtext `set the value to "X" or "Y"`   -> `AnyOf`
//! - otherwise                               -> `ExactLower`
//!
//! Anything the parser cannot confidently classify (a selected Rule with no fixtext
//! config line, or a duplicate keyword) is a hard error - it fails CLOSED so a future
//! DISA reformat surfaces loudly instead of silently deriving a wrong baseline.

use regex::Regex;

use crate::derive::{DerivedControl, OwnedValueRule};

/// Parse a full DISA XCCDF benchmark into the normalized sshd STIG control table,
/// sorted by keyword. Returns an error on any Rule the parser cannot confidently
/// classify (fail-closed).
pub fn parse_controls(xccdf: &str) -> Result<Vec<DerivedControl>, String> {
    // Fixed regexes, compiled once. `unwrap` on a literal pattern is an invariant.
    let group_re = Regex::new(r"(?s)<Group id=\x22(V-\d+)\x22.*?</Group>").unwrap();
    let check_re = Regex::new(r"(?s)<check-content[^>]*>(.*?)</check-content>").unwrap();
    let fixtext_re = Regex::new(r"(?s)<fixtext[^>]*>(.*?)</fixtext>").unwrap();
    // DISA canonical check idiom: `... | xargs sudo grep -iH '^\s*<keyword>'`.
    let grep_re = Regex::new(r"grep\s+-i[A-Za-z]*\s+'\^\\s\*([a-z][a-z0-9]+)'").unwrap();
    // fixtext "set the value to \"X\" or \"Y\"" (the AnyOf signal).
    let anyof_re = Regex::new(r#"(?i)set the value to\s+"([^"]+)"\s+or\s+"([^"]+)""#).unwrap();

    let mut out: Vec<DerivedControl> = Vec::new();
    for caps in group_re.captures_iter(xccdf) {
        let block = caps.get(0).map_or("", |m| m.as_str());
        let v_number = caps.get(1).map_or("", |m| m.as_str());

        // Extract the two fields the parser reads, then decode entities in their
        // CONTENT (extracting first, on the still-encoded block, keeps the real tags
        // unambiguous - a decoded `&lt;/check-content&gt;` cannot spoof a tag).
        let check = check_re
            .captures(block)
            .map_or_else(String::new, |c| decode_entities(&c[1]));
        let fixtext = fixtext_re
            .captures(block)
            .map_or_else(String::new, |c| decode_entities(&c[1]));

        // Selector: the canonical grep idiom + an sshd_config reference.
        let Some(gm) = grep_re.captures(&check) else {
            continue;
        };
        if !check.contains("sshd_config") && !fixtext.contains("sshd_config") {
            continue;
        }
        let keyword = gm[1].to_string();

        let value_rule = classify(&keyword, &fixtext, &check, &anyof_re)
            .map_err(|e| format!("{v_number} ({keyword}): {e}"))?;

        out.push(DerivedControl {
            keyword,
            v_number: v_number.to_string(),
            value_rule,
        });
    }

    out.sort_by(|a, b| a.keyword.cmp(&b.keyword));
    // A duplicate keyword means the selector over-matched (two Rules for one
    // directive); fail closed rather than emit an ambiguous table.
    for pair in out.windows(2) {
        if pair[0].keyword == pair[1].keyword {
            return Err(format!(
                "duplicate directive {:?} ({} and {}); selector over-matched",
                pair[0].keyword, pair[0].v_number, pair[1].v_number
            ));
        }
    }
    Ok(out)
}

/// Classify one selected Rule's value assertion from its fixtext + check-content.
///
/// Fail-closed: a selected Rule with no canonical `<Keyword> <args>` fixtext config
/// line is an error (the parser will not guess).
fn classify(
    keyword: &str,
    fixtext: &str,
    check: &str,
    anyof_re: &Regex,
) -> Result<OwnedValueRule, String> {
    let Some(tokens) = config_line_value(keyword, fixtext) else {
        return Err("no canonical config line in fixtext".to_string());
    };
    let first = &tokens[0];

    // Banner: a site-specific path value -> presence-only (W01), no value assertion.
    if first.starts_with('/') {
        return Ok(OwnedValueRule::PresenceOnly);
    }
    // RekeyLimit: two-token amount + time.
    if tokens.len() >= 2 {
        return Ok(OwnedValueRule::TwoTokenExact(
            tokens[0].to_ascii_lowercase(),
            tokens[1].to_ascii_lowercase(),
        ));
    }
    // Numeric: ceiling if the check says "or less", else exact.
    if !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit()) {
        let n: u64 = first
            .parse()
            .map_err(|_| format!("numeric value {first:?} does not fit u64"))?;
        return Ok(if check.to_ascii_lowercase().contains("or less") {
            OwnedValueRule::NumericCeiling(n)
        } else {
            OwnedValueRule::NumericExact(n)
        });
    }
    // Compression: fixtext offers two alternatives.
    if let Some(a) = anyof_re.captures(fixtext) {
        let mut alts = vec![a[1].to_ascii_lowercase(), a[2].to_ascii_lowercase()];
        alts.sort();
        return Ok(OwnedValueRule::AnyOf(alts));
    }
    // Otherwise an exact case-insensitive literal (no/yes/verbose).
    Ok(OwnedValueRule::ExactLower(first.to_ascii_lowercase()))
}

/// The value tokens from the fixtext's canonical `<Keyword> <args>` config line
/// (first matching line; case-insensitive keyword). `None` when no such line exists.
fn config_line_value(keyword: &str, fixtext: &str) -> Option<Vec<String>> {
    // Match a line that STARTS with the keyword (after optional leading blanks); the
    // separator is horizontal whitespace only, so the value stays on that one line.
    let pat = format!(
        r"(?im)^[ \t]*{}[ \t]+(\S.*?)[ \t]*$",
        regex::escape(keyword)
    );
    let re = Regex::new(&pat).ok()?;
    let caps = re.captures(fixtext)?;
    let tokens: Vec<String> = caps[1].split_whitespace().map(str::to_string).collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens)
    }
}

/// Decode the handful of XML entities that appear in DISA XCCDF text. `&amp;` is
/// decoded LAST so `&amp;lt;` becomes `&lt;`, not `<`.
fn decode_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::code_table;
    use rulesteward_sshd::TargetVersion;

    const RHEL8_FIXTURE: &str = include_str!("../tests/fixtures/rhel8_sshd_controls.xml");
    const RHEL9_FIXTURE: &str = include_str!("../tests/fixtures/rhel9_sshd_controls.xml");
    const RHEL10_FIXTURE: &str = include_str!("../tests/fixtures/rhel10_sshd_controls.xml");

    fn find<'a>(t: &'a [DerivedControl], kw: &str) -> &'a DerivedControl {
        t.iter().find(|c| c.keyword == kw).expect("keyword present")
    }

    /// The golden test: deriving from the real DISA XCCDF fixture must reproduce the
    /// shipped projection (`code_table`) EXACTLY - same directives, V-numbers, and
    /// value rules, zero drift. This ties the parser to the shipped tables.
    #[test]
    fn rhel9_fixture_reproduces_code_table_exactly() {
        let derived = parse_controls(RHEL9_FIXTURE).expect("parses");
        let code = code_table(TargetVersion::Rhel9);
        let diff = crate::derive::diff_controls(&derived, &code);
        assert!(
            diff.is_empty(),
            "RHEL9 fixture must reproduce the shipped table: {diff:?}"
        );
        assert_eq!(derived, code, "derived table must equal the code table");
    }

    #[test]
    fn rhel8_fixture_reproduces_code_table_exactly() {
        let derived = parse_controls(RHEL8_FIXTURE).expect("parses");
        let code = code_table(TargetVersion::Rhel8);
        assert!(
            crate::derive::diff_controls(&derived, &code).is_empty(),
            "RHEL8 fixture must reproduce the shipped table"
        );
        assert_eq!(derived, code);
    }

    #[test]
    fn rhel10_fixture_reproduces_code_table_exactly() {
        let derived = parse_controls(RHEL10_FIXTURE).expect("parses");
        let code = code_table(TargetVersion::Rhel10);
        assert!(
            crate::derive::diff_controls(&derived, &code).is_empty(),
            "RHEL10 fixture must reproduce the shipped table"
        );
        assert_eq!(derived, code);
    }

    /// Every value-rule KIND must be exercised by the RHEL9 fixture and classified
    /// correctly (anti-tautology: hard-coded expectations from the DISA grounding).
    #[test]
    fn rhel9_all_semantics_classified() {
        let d = parse_controls(RHEL9_FIXTURE).expect("parses");
        assert_eq!(find(&d, "banner").value_rule, OwnedValueRule::PresenceOnly);
        assert_eq!(
            find(&d, "permitrootlogin").value_rule,
            OwnedValueRule::ExactLower("no".into())
        );
        assert_eq!(
            find(&d, "loglevel").value_rule,
            OwnedValueRule::ExactLower("verbose".into())
        );
        assert_eq!(
            find(&d, "clientaliveinterval").value_rule,
            OwnedValueRule::NumericCeiling(600)
        );
        assert_eq!(
            find(&d, "clientalivecountmax").value_rule,
            OwnedValueRule::NumericExact(1)
        );
        assert_eq!(
            find(&d, "rekeylimit").value_rule,
            OwnedValueRule::TwoTokenExact("1g".into(), "1h".into())
        );
        assert_eq!(
            find(&d, "compression").value_rule,
            OwnedValueRule::AnyOf(vec!["delayed".into(), "no".into()])
        );
    }

    /// The fixtures carry decoy non-directive Groups (crypto-policies + file-perms);
    /// the selector must EXCLUDE them (exact expected counts, no decoy keywords).
    #[test]
    fn decoys_excluded_exact_counts() {
        assert_eq!(parse_controls(RHEL8_FIXTURE).unwrap().len(), 14);
        assert_eq!(parse_controls(RHEL9_FIXTURE).unwrap().len(), 20);
        assert_eq!(parse_controls(RHEL10_FIXTURE).unwrap().len(), 19);
    }

    #[test]
    fn non_sshd_document_yields_empty() {
        let doc = r#"<Benchmark><Group id="V-1"><Rule><version>X</version>
            <check><check-content>Verify permissions with: stat /etc/passwd
            If it is not 0644, this is a finding.</check-content></check>
            <fixtext>Run chmod 0644 /etc/passwd</fixtext></Rule></Group></Benchmark>"#;
        assert!(parse_controls(doc).unwrap().is_empty());
    }

    #[test]
    fn selected_rule_without_config_line_fails_closed() {
        // Has the grep idiom + sshd_config (so it is SELECTED), but the fixtext has
        // no `<Keyword> <value>` config line -> the parser must error, not guess.
        let doc = "<Benchmark><Group id=\"V-42\"><Rule><version>RHEL-09-999999</version>\
            <check><check-content>xargs sudo grep -iH '^\\s*permitrootlogin' \
            /etc/ssh/sshd_config\nIf missing, this is a finding.</check-content></check>\
            <fixtext>Configure the daemon appropriately. See sshd_config.</fixtext></Rule></Group></Benchmark>";
        let err = parse_controls(doc).expect_err("must fail closed");
        assert!(err.contains("V-42"), "{err}");
        assert!(err.contains("no canonical config line"), "{err}");
    }

    #[test]
    fn duplicate_keyword_is_error() {
        let one = |v: &str| {
            format!(
                "<Group id=\"{v}\"><Rule><version>X</version>\
                 <check><check-content>xargs sudo grep -iH '^\\s*permitrootlogin' \
                 /etc/ssh/sshd_config</check-content></check>\
                 <fixtext>PermitRootLogin no</fixtext></Rule></Group>"
            )
        };
        let doc = format!("<Benchmark>{}{}</Benchmark>", one("V-1"), one("V-2"));
        let err = parse_controls(&doc).expect_err("duplicate keyword must error");
        assert!(err.contains("duplicate directive"), "{err}");
    }

    #[test]
    fn entity_encoded_check_content_still_classifies() {
        // A Rule whose check-content carries encoded `&gt;`/`&amp;` (as real DISA does
        // in `2>&1`) must still be selected + classified.
        let doc = "<Benchmark><Group id=\"V-7\"><Rule><version>RHEL-09-255045</version>\
            <check><check-content>$ sudo /usr/sbin/sshd -dd 2&gt;&amp;1 | \
            xargs sudo grep -iH '^\\s*permitrootlogin' /etc/ssh/sshd_config\n\
            If set to any value other than &quot;no&quot;, this is a finding.\
            </check-content></check><fixtext>PermitRootLogin no</fixtext></Rule></Group></Benchmark>";
        let d = parse_controls(doc).expect("parses");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].keyword, "permitrootlogin");
        assert_eq!(d[0].v_number, "V-7");
        assert_eq!(d[0].value_rule, OwnedValueRule::ExactLower("no".into()));
    }
}
