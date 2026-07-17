//! The offline derivation core: parse an official DISA XCCDF benchmark into
//! the normalized [`DerivedControl`] table for fapolicyd's #519 STIG control
//! table (Installed/Enabled/DenyAll).
//!
//! # Selector + classification
//!
//! Grounded in the pinned rhel8/9/10 XCCDF (see
//! `/mnt/side-projects/9d-v0_8-wave2b/grounding/g7-g8-xccdf-vnumbers.md` and
//! `tests/fixtures/README.md`): a `<Group>`/`<Rule>` is SELECTED iff its
//! `check-content` mentions `fapolicyd` at all - every real fapolicyd control
//! across all three pinned benchmarks names the daemon literally in its
//! check-content, and the two decoy SELinux Groups per fixture never do. A
//! selected Group is then CLASSIFIED into one of the three families by the
//! shape of its check command:
//!   - Installed: `... list --installed fapolicyd` (dnf) or
//!     `... list installed fapolicyd` (yum)
//!   - Enabled: `systemctl is-active fapolicyd` or `systemctl status fapolicyd`
//!   - DenyAll: `tail /etc/fapolicyd/compiled.rules` (or the pre-8.5 legacy
//!     `tail /etc/fapolicyd/fapolicyd.rules`), or
//!     `grep permissive /etc/fapolicyd/fapolicyd.conf`
//!
//! A selected Group whose check-content matches none of the three shapes, or
//! whose enclosing Group has no `id` attribute, is a hard parse error - fail
//! CLOSED (mirrors `tools/auditd-stig-update`'s xccdf.rs discipline), never a
//! row with a guessed/empty family or v_number.
//!
//! Real, namespace-aware XML parser (`quick-xml`), matching
//! `tools/auditd-stig-update`'s deliberate deviation from
//! `tools/sshd-stig-update`'s homegrown regex+entity-decode approach.

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::derive::DerivedControl;
use rulesteward_fapolicyd::lints::stig::ControlFamily;

/// Parse a full DISA XCCDF benchmark into the normalized fapolicyd STIG
/// control table, in document order.
///
/// # Errors
/// A selected-but-unclassifiable Group, or a selected Group with no
/// enclosing `id`, is an `Err` (fail-closed; see the module doc).
pub fn parse_controls(xccdf: &str) -> Result<Vec<DerivedControl>, String> {
    let mut reader = Reader::from_str(xccdf);
    let mut out = Vec::new();

    // State for the Group/Rule pair currently being walked. Groups never nest
    // and each wraps exactly one Rule, so a flat set of "current" slots
    // (reset on `<Group>` Start) is sufficient - no stack needed.
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

            // quick-xml tokenizes an entity/character reference as its OWN
            // event, separate from the surrounding Text events. Resolve
            // numeric char refs first, then the five predefined XML entities
            // (lt/gt/amp/apos/quot). An unresolvable entity is a hard parse
            // error (fail-closed, per the module doc).
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
                        && content.contains("fapolicyd")
                    {
                        // `stig_id` is taken first so the fail-closed error
                        // message can name it without a clone.
                        let stig_id = cur_stig_id.take().unwrap_or_default();
                        let v_number = cur_group_id.take().ok_or_else(|| {
                            format!(
                                "selected Group {stig_id} has no enclosing Group id (fail-closed)"
                            )
                        })?;
                        let family = classify(&content).ok_or_else(|| {
                            format!(
                                "Group {v_number} ({stig_id}) mentions fapolicyd but its \
                                 check-content matched no known family \
                                 (Installed/Enabled/DenyAll) - fail-closed"
                            )
                        })?;
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

/// Classify a selected (fapolicyd-mentioning) Group's check-content into one
/// of the three #519 control families, or `None` if it matches no known
/// shape (fail-closed at the call site).
fn classify(content: &str) -> Option<ControlFamily> {
    if content.contains("list --installed fapolicyd")
        || content.contains("list installed fapolicyd")
    {
        Some(ControlFamily::Installed)
    } else if content.contains("systemctl is-active fapolicyd")
        || content.contains("systemctl status fapolicyd")
    {
        Some(ControlFamily::Enabled)
    } else if content.contains("tail /etc/fapolicyd/compiled.rules")
        || content.contains("tail /etc/fapolicyd/fapolicyd.rules")
        || content.contains("grep permissive /etc/fapolicyd/fapolicyd.conf")
    {
        Some(ControlFamily::DenyAll)
    } else {
        None
    }
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

    const RHEL8_FIXTURE: &str = include_str!("../tests/fixtures/rhel8_fapolicyd_controls.xml");
    const RHEL9_FIXTURE: &str = include_str!("../tests/fixtures/rhel9_fapolicyd_controls.xml");
    const RHEL10_FIXTURE: &str = include_str!("../tests/fixtures/rhel10_fapolicyd_controls.xml");

    #[test]
    fn rhel9_fixture_selects_exactly_3_and_classifies_correctly() {
        let derived = parse_controls(RHEL9_FIXTURE).expect("parses");
        assert_eq!(derived.len(), 3, "{derived:?}");

        let installed = derived
            .iter()
            .find(|d| d.family == ControlFamily::Installed)
            .expect("Installed present");
        assert_eq!(installed.v_number, "V-258089");
        assert_eq!(installed.stig_id, "RHEL-09-433010");

        let enabled = derived
            .iter()
            .find(|d| d.family == ControlFamily::Enabled)
            .expect("Enabled present");
        assert_eq!(enabled.v_number, "V-258090");
        assert_eq!(enabled.stig_id, "RHEL-09-433015");

        let deny_all = derived
            .iter()
            .find(|d| d.family == ControlFamily::DenyAll)
            .expect("DenyAll present");
        assert_eq!(deny_all.v_number, "V-270180");
        assert_eq!(deny_all.stig_id, "RHEL-09-433016");
    }

    #[test]
    fn rhel8_fixture_selects_exactly_3_and_classifies_correctly() {
        let derived = parse_controls(RHEL8_FIXTURE).expect("parses");
        assert_eq!(derived.len(), 3, "{derived:?}");
        assert!(
            derived
                .iter()
                .any(|d| d.family == ControlFamily::Installed && d.stig_id == "RHEL-08-040135")
        );
        assert!(
            derived
                .iter()
                .any(|d| d.family == ControlFamily::Enabled && d.stig_id == "RHEL-08-040136")
        );
        assert!(
            derived
                .iter()
                .any(|d| d.family == ControlFamily::DenyAll && d.stig_id == "RHEL-08-040137")
        );
    }

    #[test]
    fn rhel10_fixture_selects_exactly_3_and_classifies_correctly() {
        let derived = parse_controls(RHEL10_FIXTURE).expect("parses");
        assert_eq!(derived.len(), 3, "{derived:?}");
        assert!(
            derived
                .iter()
                .any(|d| d.family == ControlFamily::Installed && d.stig_id == "RHEL-10-200600")
        );
        assert!(
            derived
                .iter()
                .any(|d| d.family == ControlFamily::Enabled && d.stig_id == "RHEL-10-200601")
        );
        assert!(
            derived
                .iter()
                .any(|d| d.family == ControlFamily::DenyAll && d.stig_id == "RHEL-10-200602")
        );
    }

    #[test]
    fn decoy_selinux_groups_are_excluded() {
        for fixture in [RHEL8_FIXTURE, RHEL9_FIXTURE, RHEL10_FIXTURE] {
            let derived = parse_controls(fixture).expect("parses");
            assert_eq!(
                derived.len(),
                3,
                "the 2 decoy SELinux Groups must be excluded, not counted: {derived:?}"
            );
        }
    }

    #[test]
    fn non_fapolicyd_document_yields_empty() {
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-1"><Rule severity="medium"><version>X</version>
            <check><check-content>Verify SELinux is enforcing: getenforce</check-content></check>
            </Rule></Group></Benchmark>"#;
        assert_eq!(parse_controls(doc).unwrap(), vec![]);
    }

    #[test]
    fn selected_group_missing_id_fails_closed() {
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group><Rule severity="medium"><version>RHEL-09-999999</version>
            <check><check-content>$ dnf list --installed fapolicyd</check-content></check>
            </Rule></Group></Benchmark>"#;
        let err = parse_controls(doc).expect_err("a Group with no id must fail closed");
        assert!(
            err.contains("RHEL-09-999999") || err.to_lowercase().contains("group id"),
            "{err}"
        );
    }

    #[test]
    fn selected_group_unclassifiable_check_content_fails_closed() {
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-1"><Rule severity="medium"><version>RHEL-09-999999</version>
            <check><check-content>fapolicyd is mentioned here but the command shape is unknown</check-content></check>
            </Rule></Group></Benchmark>"#;
        let err =
            parse_controls(doc).expect_err("an unclassifiable fapolicyd mention must fail closed");
        assert!(err.to_lowercase().contains("no known family"), "{err}");
    }

    #[test]
    fn duplicate_version_element_within_one_rule_keeps_the_first() {
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-42"><Rule severity="medium"><version>RHEL-09-999999</version>
            <version>RHEL-09-000000</version>
            <check><check-content>$ systemctl is-active fapolicyd</check-content></check>
            </Rule></Group></Benchmark>"#;
        let derived = parse_controls(doc).expect("parses");
        assert_eq!(derived.len(), 1, "{derived:?}");
        assert_eq!(
            derived[0].stig_id, "RHEL-09-999999",
            "the FIRST <version> must win, not a later one: {derived:?}"
        );
    }
}
