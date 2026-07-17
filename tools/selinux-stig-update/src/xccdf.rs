//! Parse a DISA XCCDF benchmark into the normalized, family-classified
//! `rulesteward-selinux` STIG control table.
//!
//! # How a Group is selected + classified
//!
//! Every `<Group>`/`<Rule>` in a RHEL STIG benchmark is walked; its
//! `check-content` text is classified into (at most) one of the 5 control
//! families this crate maps, by a small set of check-content markers unique
//! to each family (verified against the real, pinned RHEL 8/9/10 XCCDF text
//! in `tests/fixtures/`, see that directory's `README.md`):
//!
//! - `PolicycoreutilsPython` - check-content mentions the literal package
//!   name `policycoreutils-python-utils`. Checked FIRST because that string
//!   is itself a superstring of the plain `Policycoreutils` marker below.
//! - `Policycoreutils` - check-content mentions `policycoreutils` (and, by
//!   the ordering above, does NOT mention the `-python-utils` variant).
//! - `FaillockDirContext` - check-content mentions the `faillog_t` context
//!   type (the `ls -Zd` expected output for the STIG-compliant tally dir).
//! - `Enforcing` - check-content mentions `getenforce` (the boot-enforcing
//!   check invokes this binary; the targeted-policy check below never does).
//! - `PolicyType` - check-content mentions `loaded policy name` (the
//!   `sestatus`/`sestatus | grep "policy name"` check's output line).
//! - none of the above -> not a selinux STIG control this crate maps
//!   (excludes DoD-notice-banner and other unrelated Groups); silently
//!   skipped, not an error.
//!
//! A selected (classified) Group whose enclosing `<Group>` has no `id`
//! attribute, or whose `<Rule>` has no `<version>`, is a hard parse error -
//! fail CLOSED, never a row with an empty/synthesized id (mirrors
//! `tools/auditd-stig-update`'s `xccdf.rs` doc-comment discipline).

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::derive::{DerivedControl, Family};

/// Classify `check_content` into a control family, per this module's doc
/// comment. Case-insensitive: a future DISA rewording that changes casing
/// (but not wording) should not silently drop a control.
fn classify(check_content: &str) -> Option<Family> {
    let lower = check_content.to_ascii_lowercase();
    if lower.contains("policycoreutils-python-utils") {
        Some(Family::PolicycoreutilsPython)
    } else if lower.contains("policycoreutils") {
        Some(Family::Policycoreutils)
    } else if lower.contains("faillog_t") {
        Some(Family::FaillockDirContext)
    } else if lower.contains("getenforce") {
        Some(Family::Enforcing)
    } else if lower.contains("loaded policy name") {
        Some(Family::PolicyType)
    } else {
        None
    }
}

/// Parse a full DISA XCCDF benchmark into the normalized, family-classified
/// control table, in document order. Returns an error on any classified
/// Group the parser cannot confidently extract an id/stig_id from
/// (fail-closed; see the module doc).
///
/// # Errors
/// See the module doc's "fail closed" discipline: a classified-but-unidentified
/// Group is an `Err`, never a silently-empty or partially-guessed row.
pub fn parse_controls(xccdf: &str) -> Result<Vec<DerivedControl>, String> {
    let mut reader = Reader::from_str(xccdf);

    let mut out = Vec::new();

    // State for the Group/Rule pair currently being walked. Groups never nest
    // and each wraps exactly one Rule, so flat "current" slots (reset on
    // </Group>) suffice - no stack needed (mirrors auditd-stig-update's
    // xccdf.rs).
    let mut cur_group_id: Option<String> = None;
    let mut cur_stig_id: Option<String> = None;
    let mut cur_check_content: Option<String> = None;

    #[derive(PartialEq)]
    enum Capture {
        None,
        Version,
        CheckContent,
    }
    let mut capture = Capture::None;
    let mut text_buf = String::new();

    loop {
        let event = reader
            .read_event()
            .map_err(|e| format!("xccdf xml parse error: {e}"))?;
        match event {
            Event::Eof => break,

            Event::Start(e) => match e.name().as_ref() {
                b"Group" => {
                    cur_group_id = xml_attr(&e, b"id");
                    cur_stig_id = None;
                    cur_check_content = None;
                }
                // Only the FIRST <version> in a Rule is the STIG id.
                b"version" if cur_stig_id.is_none() => {
                    capture = Capture::Version;
                    text_buf.clear();
                }
                b"check-content" => {
                    capture = Capture::CheckContent;
                    text_buf.clear();
                }
                _ => {}
            },

            Event::Text(t) => {
                if capture != Capture::None {
                    let decoded = t
                        .decode()
                        .map_err(|e| format!("xccdf xml text decode error: {e}"))?;
                    text_buf.push_str(&decoded);
                }
            }

            // An entity/character reference (e.g. `&gt;` in `2&gt;&amp;1`) is
            // tokenized as its own event by quick-xml 0.41, separate from the
            // surrounding Text events. Resolve numeric char refs first, then
            // the five predefined XML entities.
            Event::GeneralRef(r) => {
                if capture != Capture::None {
                    let resolved = match r
                        .resolve_char_ref()
                        .map_err(|e| format!("xccdf xml char-ref resolve error: {e}"))?
                    {
                        Some(c) => c.to_string(),
                        None => {
                            let name = r
                                .decode()
                                .map_err(|e| format!("xccdf xml entity decode error: {e}"))?;
                            quick_xml::escape::resolve_xml_entity(&name)
                                .map(str::to_string)
                                .ok_or_else(|| {
                                    format!("xccdf xml: unresolvable entity '&{name};'")
                                })?
                        }
                    };
                    text_buf.push_str(&resolved);
                }
            }

            Event::End(e) => match e.name().as_ref() {
                b"version" if capture == Capture::Version => {
                    cur_stig_id = Some(text_buf.trim().to_string());
                    capture = Capture::None;
                }
                b"check-content" if capture == Capture::CheckContent => {
                    cur_check_content = Some(std::mem::take(&mut text_buf));
                    capture = Capture::None;
                }
                b"Group" => {
                    if let Some(content) = cur_check_content.take()
                        && let Some(family) = classify(&content)
                    {
                        let stig_id = cur_stig_id.take().unwrap_or_default();
                        let v_number = cur_group_id.take().ok_or_else(|| {
                            format!(
                                "selected Rule {stig_id} has no enclosing Group id (fail-closed)"
                            )
                        })?;
                        if stig_id.is_empty() {
                            return Err(format!("Group {v_number} has no <version> (fail-closed)"));
                        }
                        out.push(DerivedControl {
                            family,
                            v_number,
                            stig_id,
                        });
                    }
                }
                _ => {}
            },

            Event::Empty(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::Decl(_)
            | Event::PI(_)
            | Event::DocType(_) => {}
        }
    }

    Ok(out)
}

/// Read an attribute's value as plain UTF-8 (no entity unescaping): the
/// attribute this parser reads (`Group/@id`) is a simple token (`V-NNNNNN`)
/// that never contains XML entities in the real DISA corpus.
fn xml_attr(start: &quick_xml::events::BytesStart, key: &[u8]) -> Option<String> {
    start
        .attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .map(|a| String::from_utf8_lossy(a.value.as_ref()).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulesteward_selinux::TargetVersion;

    const RHEL8_FIXTURE: &str = include_str!("../tests/fixtures/rhel8_selinux_controls.xml");
    const RHEL9_FIXTURE: &str = include_str!("../tests/fixtures/rhel9_selinux_controls.xml");
    const RHEL10_FIXTURE: &str = include_str!("../tests/fixtures/rhel10_selinux_controls.xml");

    // --- the drift-gate golden test: derived-from-real-XCCDF must equal the
    // shipped table exactly, for all three products ------------------------

    #[test]
    fn rhel9_fixture_reproduces_code_table_exactly() {
        let derived = parse_controls(RHEL9_FIXTURE).expect("parses");
        let code = crate::derive::code_table(TargetVersion::Rhel9);
        let diff = crate::derive::diff_controls(&derived, &code);
        assert!(
            diff.is_empty(),
            "RHEL9 fixture must reproduce the shipped table: {diff:?}"
        );
    }

    #[test]
    fn rhel8_fixture_reproduces_code_table_exactly() {
        let derived = parse_controls(RHEL8_FIXTURE).expect("parses");
        let code = crate::derive::code_table(TargetVersion::Rhel8);
        let diff = crate::derive::diff_controls(&derived, &code);
        assert!(
            diff.is_empty(),
            "RHEL8 fixture must reproduce the shipped table: {diff:?}"
        );
    }

    #[test]
    fn rhel10_fixture_reproduces_code_table_exactly() {
        let derived = parse_controls(RHEL10_FIXTURE).expect("parses");
        let code = crate::derive::code_table(TargetVersion::Rhel10);
        let diff = crate::derive::diff_controls(&derived, &code);
        assert!(
            diff.is_empty(),
            "RHEL10 fixture must reproduce the shipped table: {diff:?}"
        );
    }

    // --- known-answer counts: 5 selected + 2 decoys excluded per fixture ---

    #[test]
    fn rhel9_known_answer_count_excludes_the_two_decoys() {
        let derived = parse_controls(RHEL9_FIXTURE).expect("parses");
        assert_eq!(derived.len(), 5, "{derived:?}");
    }

    #[test]
    fn rhel8_known_answer_count_excludes_the_two_decoys() {
        let derived = parse_controls(RHEL8_FIXTURE).expect("parses");
        assert_eq!(derived.len(), 5, "{derived:?}");
    }

    #[test]
    fn rhel10_known_answer_count_excludes_the_two_decoys() {
        let derived = parse_controls(RHEL10_FIXTURE).expect("parses");
        assert_eq!(derived.len(), 5, "{derived:?}");
    }

    // --- classification precedence: PolicycoreutilsPython before
    // Policycoreutils, since the former's marker is a superstring of the
    // latter's -------------------------------------------------------------

    #[test]
    fn policycoreutils_python_utils_marker_wins_over_plain_policycoreutils() {
        assert_eq!(
            classify("dnf list --installed policycoreutils-python-utils"),
            Some(Family::PolicycoreutilsPython)
        );
        assert_eq!(
            classify("dnf list --installed policycoreutils"),
            Some(Family::Policycoreutils)
        );
    }

    #[test]
    fn classifier_is_case_insensitive() {
        assert_eq!(classify("$ GETENFORCE\nEnforcing"), Some(Family::Enforcing));
        assert_eq!(
            classify("LOADED POLICY NAME:             targeted"),
            Some(Family::PolicyType)
        );
    }

    #[test]
    fn unclassified_content_is_none() {
        assert_eq!(
            classify("Check that a banner is displayed at the command line login screen"),
            None
        );
    }

    // --- selector exclusion (decoys) ----------------------------------------

    #[test]
    fn non_selinux_document_yields_empty() {
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-1"><Rule severity="medium"><version>X</version>
            <check><check-content>Verify the banner text matches exactly.
            If the banner text does not match, this is a finding.</check-content></check>
            </Rule></Group></Benchmark>"#;
        assert_eq!(parse_controls(doc).unwrap(), vec![]);
    }

    #[test]
    fn selected_group_missing_id_fails_closed() {
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group><Rule severity="medium"><version>RHEL-09-999999</version>
            <check><check-content>$ getenforce
            Enforcing</check-content></check>
            </Rule></Group></Benchmark>"#;
        let err = parse_controls(doc).expect_err("a Group with no id must fail closed");
        assert!(
            err.contains("RHEL-09-999999") || err.to_lowercase().contains("group id"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_version_element_within_one_rule_keeps_the_first() {
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-42"><Rule severity="medium"><version>RHEL-09-999999</version>
            <version>RHEL-09-000000</version>
            <check><check-content>$ getenforce
            Enforcing</check-content></check>
            </Rule></Group></Benchmark>"#;
        let derived = parse_controls(doc).expect("parses");
        assert_eq!(derived.len(), 1, "{derived:?}");
        assert_eq!(
            derived[0].stig_id, "RHEL-09-999999",
            "the FIRST <version> must win, not a later one: {derived:?}"
        );
    }

    #[test]
    fn entity_reference_in_check_content_decodes() {
        // `2&gt;&amp;1` in a shell-invocation preamble line the classifier
        // never keys on, but the decode path must not error out on it.
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-99"><Rule severity="medium"><version>RHEL-09-888888</version>
            <check><check-content>$ sudo cmd 2&gt;&amp;1
            $ getenforce
            Enforcing</check-content></check>
            </Rule></Group></Benchmark>"#;
        let derived = parse_controls(doc).expect("parses");
        assert_eq!(derived.len(), 1, "{derived:?}");
        assert_eq!(derived[0].family, Family::Enforcing);
    }
}
