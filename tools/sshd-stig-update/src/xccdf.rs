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
//! `<Keyword> <args>` config line (matched at line start); the comparison SEMANTIC is
//! inferred from robust token-shape signals (never fragile sentence parsing):
//!
//! - value is a path (`/...`)                    -> `PresenceOnly` (Banner)
//! - two tokens (`1G 1h`)                        -> `TwoTokenExact`
//! - all-digit token + "<value> or less" tied to
//!   THIS value                                  -> `NumericCeiling`, else `NumericExact`
//! - fixtext `set the value to "X", "Y"[, or "Z"]` -> `AnyOf` (ALL alternatives)
//! - otherwise                                   -> `ExactLower`
//!
//! Anything the parser cannot confidently classify is a hard error - it fails CLOSED
//! so a future DISA reformat surfaces loudly instead of silently deriving a wrong
//! baseline. The fail-closed cases: a selected Rule with no fixtext config line; TWO
//! keyword lines in one fixtext that DISAGREE on the value (DISA sometimes shows an
//! illustrative/old value before the canonical one - the parser refuses to guess);
//! and a duplicate keyword across Rules.
//!
//! # Known limitation: runtime-only checks (tracked for v0.6)
//!
//! The selector keys on the FILE-grep idiom. DISA is trending toward additional
//! runtime checks (`sshd -T | grep -i <kw>`); today every controlled directive across
//! RHEL 8/9/10 ALSO carries the file grep, so all are captured. A hypothetical FUTURE
//! control that used ONLY a runtime check (no file grep) would be skipped. An existing
//! control going runtime-only still surfaces as `- <dir>` drift (a human reviews it);
//! only a brand-new runtime-only control would go unseen. Not guarded here (no current
//! benchmark exercises it; per no-speculative-abstraction) - tracked as issue #468.

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
    // The Rule id (STIG Rule id, e.g. `RHEL-09-255045`), carried in the FIRST
    // `<version>` element inside the Rule (#507). Applied to the still-encoded
    // block (not the decoded check/fixtext), so the search is scoped to the raw
    // XCCDF tag rather than any prose that happens to mention "version".
    let version_re = Regex::new(r"<version>([^<]+)</version>").unwrap();

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

        // Fail closed: a selected Rule with no `<version>` has no STIG Rule id to
        // derive, and a default/empty value would silently defeat the #507 drift
        // guard rather than surface the reformat loudly.
        let rule_id = version_re
            .captures(block)
            .map(|c| c[1].trim().to_string())
            .ok_or_else(|| format!("{v_number} ({keyword}): no <version> (STIG Rule id) found"))?;

        let value_rule = classify(&keyword, &fixtext, &check)
            .map_err(|e| format!("{v_number} ({keyword}): {e}"))?;

        out.push(DerivedControl {
            keyword,
            v_number: v_number.to_string(),
            rule_id,
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

/// Surface directive controls that carry a runtime check (`sshd -T | grep -i <kw>`)
/// but NO file-grep idiom (`grep -iH '^\s*<kw>'`) for that SAME keyword within the
/// SAME `<Group>` `<check-content>` block (issue #468).
///
/// [`parse_controls`] keys on the file-grep idiom, so a control checked ONLY at
/// runtime is silently SKIPPED today. This guard returns those skipped directives so
/// the caller can fail loud instead of dropping a required control. The keywords are
/// the lowercase word grepped after `sshd -T | grep -i`, sorted ascending. An empty
/// result means every runtime check is duplicated by a file grep for the same
/// keyword in the same Group - the current state across the pinned RHEL 8/9/10
/// benchmarks (0 / 1 / 16 runtime checks, all duplicated), so the guard must not fire
/// on any of them.
pub fn runtime_only_directives(_xccdf: &str) -> Vec<String> {
    // Signature freeze (test-author, lane-2c): the RED tests below pin this contract;
    // the implementer replaces this body. A `todo!()` (not an empty `Vec`) so EVERY
    // authored test - the positive AND the negative ones - fails until the guard is
    // genuinely implemented, per the RED-barrier discipline.
    todo!("#468: runtime-only directive guard - implemented by lane-2c")
}

/// Classify one selected Rule's value assertion from its fixtext + check-content.
///
/// Fail-closed: a selected Rule with no canonical `<Keyword> <args>` fixtext config
/// line - or with two config lines that DISAGREE on the value - is an error (the
/// parser will not guess which value is canonical).
fn classify(keyword: &str, fixtext: &str, check: &str) -> Result<OwnedValueRule, String> {
    let Some(tokens) = config_line_value(keyword, fixtext)? else {
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
    // Numeric: a ceiling ONLY when "or less" is tied to THIS directive's own value
    // (`<value>["']? or less`). A bare "or less" elsewhere in the check-content - e.g.
    // a cross-reference to a DIFFERENT directive ("apply with ClientAliveInterval 600
    // or less") - must NOT demote an exact-value control (ClientAliveCountMax = 1).
    if first.bytes().all(|b| b.is_ascii_digit()) {
        let n: u64 = first
            .parse()
            .map_err(|_| format!("numeric value {first:?} does not fit u64"))?;
        let ceiling_re = Regex::new(&format!(
            r#"(?i)\b{}["']?\s+or\s+less"#,
            regex::escape(first)
        ))
        .expect("escaped numeric value always compiles");
        return Ok(if ceiling_re.is_match(check) {
            OwnedValueRule::NumericCeiling(n)
        } else {
            OwnedValueRule::NumericExact(n)
        });
    }
    // AnyOf: the fixtext enumerates the acceptable values ("set the value to X, Y, or
    // Z"). Capture EVERY quoted alternative in that clause (2+ -> AnyOf), so a
    // three-alternative control is not silently narrowed to a single ExactLower.
    if let Some(alts) = anyof_alternatives(fixtext) {
        return Ok(OwnedValueRule::AnyOf(alts));
    }
    // Otherwise an exact case-insensitive literal (no/yes/verbose).
    Ok(OwnedValueRule::ExactLower(first.to_ascii_lowercase()))
}

/// The value tokens from the fixtext's canonical `<Keyword> <args>` config line
/// (case-insensitive keyword, matched at line start).
///
/// Returns `Ok(None)` when there is no such line, `Ok(Some(tokens))` when there is
/// exactly one distinct value, and `Err` when TWO OR MORE keyword lines disagree on
/// the value (fail-closed: DISA sometimes shows an illustrative/old value before the
/// canonical one, and the parser must not silently pick the wrong one).
fn config_line_value(keyword: &str, fixtext: &str) -> Result<Option<Vec<String>>, String> {
    // Match every line that STARTS with the keyword (after optional leading blanks);
    // the separator is horizontal whitespace only, so the value stays on that line.
    let pat = format!(
        r"(?im)^[ \t]*{}[ \t]+(\S.*?)[ \t]*$",
        regex::escape(keyword)
    );
    let re = Regex::new(&pat).expect("escaped keyword always compiles");
    let mut candidates: Vec<Vec<String>> = Vec::new();
    for caps in re.captures_iter(fixtext) {
        let tokens: Vec<String> = caps[1].split_whitespace().map(str::to_string).collect();
        if !tokens.is_empty() && !candidates.contains(&tokens) {
            candidates.push(tokens);
        }
    }
    if candidates.len() > 1 {
        return Err(format!(
            "ambiguous fixtext: multiple differing {keyword:?} config lines {candidates:?}; \
             cannot pick the canonical value - re-ground by hand"
        ));
    }
    Ok(candidates.into_iter().next())
}

/// The acceptable values a fixtext enumerates in a "set the value to X, Y, or Z"
/// clause, lowercased + sorted + deduped. `None` when the clause is absent or lists
/// fewer than two values (a single "set the value to X" is an exact literal, not a
/// choice). Captures ALL alternatives, so a three-value enumeration is not truncated.
fn anyof_alternatives(fixtext: &str) -> Option<Vec<String>> {
    let setval = Regex::new(r"(?i)set the value to\s+([^:.\n]+)").expect("literal regex compiles");
    let quoted = Regex::new(r#""([^"]+)""#).expect("literal regex compiles");
    let clause = setval.captures(fixtext)?;
    let mut alts: Vec<String> = quoted
        .captures_iter(&clause[1])
        .map(|c| c[1].to_ascii_lowercase())
        .collect();
    alts.sort();
    alts.dedup();
    (alts.len() >= 2).then_some(alts)
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

    // --- adversarial miss-cases (impl-aware review, 2026-07-07) ---------------

    /// MISS A: a fixtext that shows an illustrative/old value line before the
    /// canonical one must NOT silently derive the first value. Two DIFFERING config
    /// lines are ambiguous -> fail closed (error), so drift can never be masked.
    #[test]
    fn ambiguous_config_lines_fail_closed() {
        let doc = "<Benchmark><Group id=\"V-9\"><Rule><version>RHEL-09-255045</version>\
            <check><check-content>xargs sudo grep -iH '^\\s*permitrootlogin' /etc/ssh/sshd_config\
            </check-content></check><fixtext>The previous insecure setting was:\n\n\
            PermitRootLogin no\n\nChange it to:\n\nPermitRootLogin prohibit-password\
            </fixtext></Rule></Group></Benchmark>";
        let err = parse_controls(doc).expect_err("two differing config lines must fail closed");
        assert!(err.contains("V-9"), "{err}");
        assert!(err.contains("ambiguous"), "{err}");
    }

    /// A duplicated but IDENTICAL config line (an example shown twice) is NOT
    /// ambiguous - it derives the single agreed value.
    #[test]
    fn duplicate_identical_config_lines_are_ok() {
        let doc = "<Benchmark><Group id=\"V-10\"><Rule><version>RHEL-09-255045</version>\
            <check><check-content>xargs sudo grep -iH '^\\s*permitrootlogin' /etc/ssh/sshd_config\
            </check-content></check><fixtext>Add the line:\n\nPermitRootLogin no\n\n\
            or confirm it already reads:\n\nPermitRootLogin no\
            </fixtext></Rule></Group></Benchmark>";
        let d = parse_controls(doc).expect("identical duplicate lines are unambiguous");
        assert_eq!(d[0].value_rule, OwnedValueRule::ExactLower("no".into()));
    }

    /// MISS B: an "or less" clause that belongs to a DIFFERENT directive (a
    /// cross-reference in the check-content) must not demote an exact-value control.
    /// ClientAliveCountMax stays NumericExact(1) even when its check mentions
    /// "ClientAliveInterval ... 600 or less".
    #[test]
    fn cross_reference_or_less_does_not_demote_numeric_exact() {
        let doc = "<Benchmark><Group id=\"V-11\"><Rule><version>RHEL-09-255095</version>\
            <check><check-content>Note: apply in conjunction with ClientAliveInterval set to \
            600 or less.\nxargs sudo grep -iH '^\\s*clientalivecountmax' /etc/ssh/sshd_config\n\
            If not set to a value of \"1\", this is a finding.</check-content></check>\
            <fixtext>ClientAliveCountMax 1</fixtext></Rule></Group></Benchmark>";
        let d = parse_controls(doc).expect("parses");
        assert_eq!(
            d[0].value_rule,
            OwnedValueRule::NumericExact(1),
            "a cross-reference 'or less' for another directive must not make this a ceiling"
        );
    }

    /// A real ceiling ("value of 600 or less" tied to THIS directive) still derives
    /// NumericCeiling.
    #[test]
    fn own_value_or_less_is_a_ceiling() {
        let doc = "<Benchmark><Group id=\"V-12\"><Rule><version>RHEL-09-255100</version>\
            <check><check-content>xargs sudo grep -iH '^\\s*clientaliveinterval' /etc/ssh/sshd_config\n\
            Verify the value is \"600\" or less. If not, this is a finding.</check-content></check>\
            <fixtext>ClientAliveInterval 600</fixtext></Rule></Group></Benchmark>";
        let d = parse_controls(doc).expect("parses");
        assert_eq!(d[0].value_rule, OwnedValueRule::NumericCeiling(600));
    }

    /// MISS C: a three-alternative AnyOf ("set the value to X, Y, or Z") must capture
    /// ALL alternatives, not collapse to a single over-strict ExactLower that would
    /// reject a compliant value.
    #[test]
    fn three_alternative_anyof_captures_all() {
        let doc = "<Benchmark><Group id=\"V-13\"><Rule><version>RHEL-09-255130</version>\
            <check><check-content>xargs sudo grep -iH '^\\s*compression' /etc/ssh/sshd_config\n\
            If set to \"yes\", this is a finding.</check-content></check>\
            <fixtext>Uncomment the \"Compression\" keyword and set the value to \"delayed\", \"no\", \
            or \"zlib\":\n\nCompression no</fixtext></Rule></Group></Benchmark>";
        let d = parse_controls(doc).expect("parses");
        assert_eq!(
            d[0].value_rule,
            OwnedValueRule::AnyOf(vec!["delayed".into(), "no".into(), "zlib".into()])
        );
    }

    // --- #507 STIG Rule id (`<version>`) capture ------------------------------
    // 8b hand-authored the RHEL{8,9,10}_RULE_ID maps in stig.rs from the DISA
    // XCCDF but this parser never read `<Rule><version>`, so those maps had zero
    // drift protection. The Rule id is the canonical `ControlRef::id`; the
    // Group id (already captured as `v_number`) is the DISA V-number alias.

    #[test]
    fn parse_controls_captures_rule_id() {
        let doc = "<Benchmark><Group id=\"V-999999\"><Rule><version>RHEL-09-255045</version>\
            <check><check-content>xargs sudo grep -iH '^\\s*permitrootlogin' /etc/ssh/sshd_config\
            </check-content></check><fixtext>PermitRootLogin no</fixtext></Rule></Group></Benchmark>";
        let d = parse_controls(doc).expect("parses");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].keyword, "permitrootlogin");
        assert_eq!(d[0].v_number, "V-999999");
        assert_eq!(d[0].rule_id, "RHEL-09-255045");
    }

    /// A selected Rule (grep idiom + sshd_config, valid fixtext config line) but
    /// with NO `<version>` element must fail closed, not silently derive an empty
    /// or default Rule id (the whole point of #507 is that the Rule id must be
    /// genuinely load-bearing, not a decorative default).
    #[test]
    fn selected_rule_without_version_fails_closed() {
        let doc = "<Benchmark><Group id=\"V-98\"><Rule>\
            <check><check-content>xargs sudo grep -iH '^\\s*permitrootlogin' /etc/ssh/sshd_config\
            </check-content></check><fixtext>PermitRootLogin no</fixtext></Rule></Group></Benchmark>";
        let err = parse_controls(doc).expect_err("missing <version> must fail closed");
        assert!(err.contains("V-98"), "{err}");
        assert!(err.contains("version"), "{err}");
    }

    // --- #468 runtime-only directive guard ------------------------------------
    // `parse_controls` selects on the FILE-grep idiom (`grep -iH '^\s*<kw>'`). DISA
    // is adding RUNTIME checks (`sshd -T | grep -i <kw>`); today every controlled
    // directive ALSO carries the file grep, so all are captured. A directive checked
    // ONLY at runtime would be silently dropped. `runtime_only_directives` surfaces
    // those so the caller can fail loud (issue #468). Every assertion below is
    // grounded in the real `sshd -T | grep -i <kw>` idiom used verbatim across the
    // pinned RHEL 9 (V-257996) and RHEL 10 (V-281254..V-281296) benchmarks.

    /// A Group whose check-content carries ONLY the runtime idiom
    /// (`sshd -T | grep -i x11forwarding`) and NO file grep for that keyword is a
    /// runtime-only directive: it must be surfaced (else it is silently skipped).
    #[test]
    fn runtime_only_single_directive_is_surfaced() {
        let doc = "<Benchmark><Group id=\"V-800001\"><Rule><version>RHEL-09-800001</version>\
            <check><check-content>Verify the runtime configuration with the following command:\n\
            $ sudo sshd -T | grep -i x11forwarding\nx11forwarding no\n\
            If \"X11Forwarding\" is not set to \"no\", this is a finding.</check-content></check>\
            <fixtext>Add the following line to sshd_config:\nX11Forwarding no</fixtext>\
            </Rule></Group></Benchmark>";
        assert_eq!(
            runtime_only_directives(doc),
            vec!["x11forwarding".to_string()],
            "a directive checked only via `sshd -T | grep` must be surfaced"
        );
    }

    /// A Group carrying BOTH the file grep AND the runtime check for the same
    /// keyword (the real "duplicated" shape - e.g. RHEL 10 V-281265 permitrootlogin)
    /// is fully captured by `parse_controls`, so the guard must NOT surface it.
    #[test]
    fn duplicated_runtime_and_file_grep_same_group_not_surfaced() {
        let doc = "<Benchmark><Group id=\"V-800002\"><Rule><version>RHEL-09-800002</version>\
            <check><check-content>$ sudo /usr/sbin/sshd -dd 2&gt;&amp;1 | \
            xargs sudo grep -iH '^\\s*permitrootlogin' /etc/ssh/sshd_config\n\
            permitrootlogin no\nVerify the runtime setting with the following command:\n\
            $ sudo sshd -T | grep -i permitrootlogin\npermitrootlogin no\n\
            If not set to \"no\", this is a finding.</check-content></check>\
            <fixtext>PermitRootLogin no</fixtext></Rule></Group></Benchmark>";
        assert!(
            runtime_only_directives(doc).is_empty(),
            "a runtime check duplicated by a same-group file grep is NOT runtime-only"
        );
    }

    /// The exact #468 acceptance requirement: the three pinned DISA benchmarks carry
    /// 0 / 1 / 16 runtime checks respectively, and (verified mechanically against the
    /// fixtures) EVERY one is duplicated by a same-Group file grep. The guard must
    /// return empty for all three - zero false positives on shipping data.
    #[test]
    fn real_pinned_benchmarks_have_zero_runtime_only_directives() {
        assert!(
            runtime_only_directives(RHEL8_FIXTURE).is_empty(),
            "RHEL 8 (0 runtime checks) must not trip the guard"
        );
        assert!(
            runtime_only_directives(RHEL9_FIXTURE).is_empty(),
            "RHEL 9 (1 runtime check, duplicated) must not trip the guard"
        );
        assert!(
            runtime_only_directives(RHEL10_FIXTURE).is_empty(),
            "RHEL 10 (16 runtime checks, all duplicated) must not trip the guard"
        );
    }

    /// The guard is scoped PER check-content block: a runtime-only directive in one
    /// Group must be surfaced even when a DIFFERENT Group in the same document carries
    /// a file grep. A document-wide "is there any file grep at all" check would wrongly
    /// treat this as clean; the per-Group scoping forbids that.
    #[test]
    fn runtime_only_scoped_per_group_not_document() {
        let doc = "<Benchmark>\
            <Group id=\"V-800003\"><Rule><version>RHEL-09-800003</version>\
            <check><check-content>$ sudo sshd -T | grep -i maxauthtries\nmaxauthtries 3\n\
            If not \"3\" or less, this is a finding.</check-content></check>\
            <fixtext>MaxAuthTries 3</fixtext></Rule></Group>\
            <Group id=\"V-800004\"><Rule><version>RHEL-09-800004</version>\
            <check><check-content>xargs sudo grep -iH '^\\s*permitrootlogin' /etc/ssh/sshd_config\
            </check-content></check><fixtext>PermitRootLogin no</fixtext></Rule></Group>\
            </Benchmark>";
        assert_eq!(
            runtime_only_directives(doc),
            vec!["maxauthtries".to_string()],
            "a runtime-only Group is surfaced regardless of a file grep in another Group"
        );
    }

    /// The guard keys specifically on the `sshd -T | grep` runtime idiom, NOT on a
    /// bare `grep -i <kw>`. A rule that greps a file WITHOUT the anchored file-grep
    /// idiom and WITHOUT `sshd -T` is not a runtime directive check and must not be
    /// surfaced (guards against an over-broad "any grep" selector).
    #[test]
    fn bare_grep_without_sshd_dash_t_is_not_surfaced() {
        let doc = "<Benchmark><Group id=\"V-800005\"><Rule><version>RHEL-09-800005</version>\
            <check><check-content>Run the following command:\n\
            $ sudo grep -i maxsessions /etc/ssh/sshd_config\nmaxsessions 10\n\
            If not set, this is a finding.</check-content></check>\
            <fixtext>MaxSessions 10</fixtext></Rule></Group></Benchmark>";
        assert!(
            runtime_only_directives(doc).is_empty(),
            "a bare `grep -i <kw>` without `sshd -T` is not a runtime directive check"
        );
    }

    /// Two distinct runtime-only directives are BOTH surfaced, sorted ascending. The
    /// Groups are authored in reverse-sorted order (pubkey before hostbased) so a
    /// non-sorting or first-only implementation fails this test.
    #[test]
    fn multiple_runtime_only_directives_all_surfaced_sorted() {
        let doc = "<Benchmark>\
            <Group id=\"V-800006\"><Rule><version>RHEL-09-800006</version>\
            <check><check-content>$ sudo sshd -T | grep -i pubkeyauthentication\n\
            pubkeyauthentication yes\nIf not \"yes\", this is a finding.</check-content></check>\
            <fixtext>PubkeyAuthentication yes</fixtext></Rule></Group>\
            <Group id=\"V-800007\"><Rule><version>RHEL-09-800007</version>\
            <check><check-content>$ sudo sshd -T | grep -i hostbasedauthentication\n\
            hostbasedauthentication no\nIf not \"no\", this is a finding.</check-content></check>\
            <fixtext>HostbasedAuthentication no</fixtext></Rule></Group>\
            </Benchmark>";
        assert_eq!(
            runtime_only_directives(doc),
            vec![
                "hostbasedauthentication".to_string(),
                "pubkeyauthentication".to_string()
            ],
            "all runtime-only directives are surfaced, sorted ascending"
        );
    }
}
