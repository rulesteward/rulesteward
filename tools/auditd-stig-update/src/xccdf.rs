//! The offline derivation core: parse an official DISA XCCDF benchmark into the
//! normalized [`DerivedRule`] required-rules table for the auditd au-W06 STIG
//! baseline.
//!
//! This is the testable heart of the tool - it takes raw XCCDF text and returns
//! the derived rules, with NO network or filesystem. The live fetch that hands
//! it the XCCDF bytes lives behind the seam in [`crate::source`].
//!
//! # Deliberate deviation from the `sshd-stig-update` precedent: extraction source
//!
//! `tools/sshd-stig-update`'s `xccdf.rs` extracts its canonical VALUE from
//! `fixtext` ("the required VALUE is the fixtext's canonical `<Keyword> <args>`
//! config line"). THIS extractor uses `check-content` instead. This is a
//! grounded, deliberate choice, not an oversight: the P2 grounding doc (session
//! 7c-v0_6-wave3, Part B.4) mechanically diffs fixtext-extracted lines against
//! check-content-extracted lines for all 146 audit-rule requirements across
//! rhel8/9/10 and finds they DISAGREE for 41/51 (rhel9) and 35/50 (rhel10)
//! requirements: fixtext systematically omits `-S all`, spells the `auid`
//! sentinel `unset` instead of `-1`, and spells the key `-k` instead of
//! `-F key=`, for the exact same rule family, in a way that is NOT cosmetic --
//! a real `rules.d` line that literally followed fixtext's advice (omitting
//! `-S all`) would produce a syscall rule with an all-zero mask that never
//! fires (grounded in `audit-userspace` source, `auditctl-listing.c`
//! `print_syscall`/`audit_rule_syscallbyname_data`, commit `3bfa048`). Since
//! check-content IS the literal audit procedure the "is a finding" verdict is
//! based on, it is the authoritative source for this baseline.
//!
//! # How a Rule is selected + classified (grounded in the real DISA XCCDF)
//!
//! A `<Group>`/`<Rule>` is an audit-rule requirement IFF its `check-content`
//! contains at least one line (after trimming whitespace) matching
//! `^(-A|-a|-w|-e|-f)\s+\S` -- a literal `auditctl`-syntax rule line
//! (widened #523 to also select a bare Control-rule requirement like "-e 2"/
//! "-f 2"; see [`RULE_LINE_RE`]'s doc comment). This is a CHECK-CONTENT GATE,
//! not a keyword/domain pre-check (grounding Part B.2): in practice every Rule
//! carrying such a line is already an audit-domain check, and the explicit
//! EXCLUDE classes (auditd.conf `key = value` checks, service/package checks,
//! rules-file permission checks, narrative-only checks) never contain a
//! literal `-a`/`-A`/`-w`/`-e`/`-f` line, so they are naturally excluded by
//! the line gate alone with no additional domain check needed.
//!
//! Extraction, per selected Rule (grounding Part B.3):
//! 1. Parse with a real, namespace-aware XML parser (NOT a regex/homegrown
//!    decoder like the sshd tool's `xccdf.rs` -- the auditd Group/Rule shape has
//!    no need for it and a real parser is simpler and correct-by-construction for
//!    entity decoding). `quick-xml` is the crates.io-idiomatic minimal choice if a
//!    dependency is added; confirm the exact API shape via docsrs before writing
//!    the parse loop (project convention: prefer docsrs/context7 over
//!    training-recall for a new dependency's API).
//! 2. Read `<Group id>` (the V-number), `Rule/version` (`RHEL-XX-NNNNNN`), and the
//!    full `.//check-content` text.
//! 3. Split check-content on `\n`, trim each line, keep lines matching
//!    [`RULE_LINE_RE`] in document order, deduped (a line repeated verbatim
//!    collapses to one -- mirrors the sshd tool's fixtext dedup discipline;
//!    grounding Part B.3.3 -- not observed in the corpus but defended for a
//!    future DISA reformat, same "fail closed for the unknown future case"
//!    spirit as the sshd tool's known-limitation doc comment).
//! 4. Emit ONE [`DerivedRule`] row PER EXTRACTED LINE (not one row per Group): a
//!    multi-line requirement (an arch=b32/b64 pair, a 2x2 Cartesian product, or
//!    multiple watched paths) produces multiple rows sharing the same
//!    `v_number`/`stig_id` (grounding Part B.5, C.5; see [`crate::derive`]'s
//!    module doc for why this shape is required, not a simplification).
//! 5. A selected Rule whose enclosing `<Group>` has no `id` attribute (so no
//!    DISA V-number can be assigned) is a hard parse error - fail CLOSED, never
//!    a row with an empty/synthesized `v_number`. (A selected Rule from which NO
//!    rule line can be extracted at all should be IMPOSSIBLE by construction,
//!    since selection and extraction both key off the same line-match; unlike
//!    the sshd tool's fixtext-vs-check-content split field this extractor has no
//!    such gap.) Mirrors the sshd tool's `xccdf.rs` doc-comment discipline
//!    (module doc there, "Anything the parser cannot confidently classify is a
//!    hard error").
//!
//! # Known non-goals (documented, not silently ignored)
//!
//! * No alternation ("either X or Y") handling: grounding Part B.7.4 confirms
//!   zero occurrences of alternation language attached to a rule line across all
//!   146 requirements in the three pinned benchmarks - every extracted line
//!   within one requirement is a REQUIRED, ADDITIONAL line (a conjunction), never
//!   an "or" choice. A future DISA revision that introduces alternation is
//!   expected to surface as an extraction the implementer must re-ground, not
//!   something this parser silently guesses at.
//! * Watch-path trailing-slash: check-content and fixtext disagree on a trailing
//!   `/` for the one multi-watch requirement that has any slash at all (grounding
//!   Part B.7.2); this extractor takes check-content's spelling (no trailing
//!   slash) as authoritative per the check-content-is-source-of-truth decision
//!   above. Whether the au-W06 MATCHER should ignore `is_dir`/normalize the
//!   trailing slash is that matcher's own documented design call, not this
//!   extractor's.

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::derive::DerivedRule;

/// The check-content line selector (grounding Part B.2/B.3): a literal
/// `auditctl`-syntax rule line, never the shell-invocation preamble (which
/// starts with `$` or `auditctl`/`cat`/`grep`, never with the rule flag as the
/// first token).
///
/// Widened (#523, session 9b-v0_8-wave2 lane 2e): `-e`/`-f` also select a bare
/// Control-rule requirement ("-e 2" immutable-audit-config, "-f 2"
/// panic-on-critical-failure) - real DISA requirements whose ENTIRE
/// requirement is a bare control line, never a `-a`/`-A`/`-w` line at all.
/// Verified live 2026-07-15: widening to also recognize `-e`/`-f` against the
/// real pinned rhel8/9/10 XCCDF benchmarks selects EXACTLY the five new
/// Groups this deepening adds (V-230402, V-258227, V-258229, V-281103,
/// V-281365) and introduces zero false positives elsewhere in any of the
/// three benchmarks.
static RULE_LINE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^(-A|-a|-w|-e|-f)\s+\S").expect("valid regex")
});

/// Parse a full DISA XCCDF benchmark into the normalized au-W06 required-rules
/// table, in document order. Returns an error on any selected Rule the parser
/// cannot confidently extract a line from (fail-closed; see the module doc).
///
/// # Errors
/// See the module doc's "fail closed" discipline: a selected-but-unextractable
/// Rule is an `Err`, never a silently-empty or partially-guessed row.
pub fn parse_requirements(xccdf: &str) -> Result<Vec<DerivedRule>, String> {
    let mut reader = Reader::from_str(xccdf);

    let mut out = Vec::new();

    // State for the Group/Rule pair currently being walked. B.1 confirms Groups
    // never nest and each wraps exactly one Rule, so a flat set of "current"
    // slots (reset on </Group>) is sufficient - no stack needed.
    let mut cur_group_id: Option<String> = None;
    let mut cur_stig_id: Option<String> = None;
    let mut cur_check_content: Option<String> = None;

    // Which element (if any) text events should accumulate into right now.
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
                // Only the FIRST <version> in a Rule is the STIG id; a second
                // <version> (not observed, but defended per the module doc's
                // "fail closed for a future DISA reformat" posture) is ignored.
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

            // quick-xml 0.41 tokenizes an entity/character reference (e.g. the
            // `&gt;` in `-F auid&gt;=1000`) as its OWN event, separate from the
            // surrounding Text events (NOT folded into Event::Text as older
            // quick-xml versions did) - confirmed empirically against this
            // version. Resolve numeric char refs first, then the five
            // predefined XML entities (lt/gt/amp/apos/quot; the only ones the
            // real DISA corpus uses - grounding Part B.3.1). An unresolvable
            // entity is a hard parse error (fail-closed, per the module doc),
            // never silently dropped or passed through as literal `&name;`.
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
                    if let Some(content) = cur_check_content.take() {
                        let lines = extract_rule_lines(&content);
                        if !lines.is_empty() {
                            // `take()` moves each field out AND resets it to None in
                            // one step. The trailing per-field `= None` resets the
                            // old code carried are redundant: the only reader of these
                            // fields is this handler, and the next `<Group>` start
                            // resets all three before any new content accumulates.
                            // stig_id is taken first so the fail-closed error message
                            // can name it without a clone.
                            let stig_id = cur_stig_id.take().unwrap_or_default();
                            let v_number = cur_group_id.take().ok_or_else(|| {
                                format!(
                                    "selected Rule {stig_id} has no enclosing Group id (fail-closed)"
                                )
                            })?;
                            for line in lines {
                                out.push(DerivedRule {
                                    v_number: v_number.clone(),
                                    stig_id: stig_id.clone(),
                                    line,
                                });
                            }
                        }
                    }
                }
                _ => {}
            },

            // Empty elements (`<version/>`) carry no text: nothing to capture,
            // and Group id is already captured on Start above (a self-closed
            // `<Group/>` never occurs in a real XCCDF, but handling id capture
            // only on Start is deliberate - a self-closed Group can never wrap
            // a Rule, so it is never "selected" and needs no id).
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
/// attributes this parser reads (`Group/@id`) are simple tokens (`V-NNNNNN`)
/// that never contain XML entities in the real DISA corpus.
fn xml_attr(start: &quick_xml::events::BytesStart, key: &[u8]) -> Option<String> {
    start
        .attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .map(|a| String::from_utf8_lossy(a.value.as_ref()).into_owned())
}

/// Extract the required rule lines from one Rule's check-content text
/// (grounding Part B.3): split on `\n`, trim each line, keep lines matching
/// the [`RULE_LINE_RE`] selector, in document order, deduped (a line repeated
/// verbatim within one Rule collapses to one row).
fn extract_rule_lines(content: &str) -> Vec<String> {
    // `seen` borrows the trimmed slices of `content` (which outlives this loop),
    // so the dedup set costs no allocation; a kept line is allocated exactly once
    // (in `out.push`), not twice.
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for raw_line in content.split('\n') {
        let line = raw_line.trim();
        if RULE_LINE_RE.is_match(line) && seen.insert(line) {
            out.push(line.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::code_table;
    use rulesteward_auditd::TargetVersion;

    const RHEL8_FIXTURE: &str = include_str!("../tests/fixtures/rhel8_auditd_controls.xml");
    const RHEL9_FIXTURE: &str = include_str!("../tests/fixtures/rhel9_auditd_controls.xml");
    const RHEL10_FIXTURE: &str = include_str!("../tests/fixtures/rhel10_auditd_controls.xml");

    /// Every requirement's V-number, from the appendix oracle (session
    /// 7c-v0_6-wave3 P2 grounding doc, Part B.6 / appendix.txt), for uniqueness
    /// counting: `parse_requirements` emits one row PER LINE, so the requirement
    /// count is the number of DISTINCT v_numbers, not `derived.len()`.
    fn distinct_v_numbers(derived: &[DerivedRule]) -> usize {
        let mut vs: Vec<&str> = derived.iter().map(|d| d.v_number.as_str()).collect();
        vs.sort_unstable();
        vs.dedup();
        vs.len()
    }

    // --- the drift-gate golden test: derived-from-real-XCCDF must equal the
    // shipped table exactly, once both are filled in (currently RED for TWO
    // independent reasons: parse_requirements is todo!(), AND the shipped
    // RHEL*_REQUIRED tables are empty placeholders per the P2 dispatch's
    // explicit "the implementer + tool derive fill real content" instruction).
    // This is the same "fixture reproduces code_table exactly" shape as
    // tools/sshd-stig-update's xccdf.rs tests -- it is the test that proves the
    // `auditd-stig-check` CI gate (and `just auditd-stig-check-offline`) will
    // report 0 drift once the implementer pastes `derive`'s output in. -------

    #[test]
    fn rhel9_fixture_reproduces_code_table_exactly() {
        let derived = parse_requirements(RHEL9_FIXTURE).expect("parses");
        let code = code_table(TargetVersion::Rhel9);
        let diff = crate::derive::diff_rules(&derived, &code);
        assert!(
            diff.is_empty(),
            "RHEL9 fixture must reproduce the shipped table: {diff:?}"
        );
    }

    // Barrier BLOCKER 1: the rhel9 pin above was the ONLY per-product golden
    // test before this addition. Without a pin for EVERY product, an
    // implementation that populates only RHEL9_REQUIRED (leaving
    // RHEL8_REQUIRED/RHEL10_REQUIRED as empty placeholders, or mis-wiring
    // stig_required::baseline_for's match arms) passes every pre-existing
    // test in this file while `--target rhel8`/`--target rhel10` silently
    // emit zero au-W06 findings on a real host. RED now for the same two
    // reasons as the rhel9 pin: parse_requirements is todo!(), AND the
    // shipped RHEL8_REQUIRED/RHEL10_REQUIRED tables are empty placeholders
    // (see stig_required.rs's module doc) -- GREEN only once the implementer
    // populates ALL THREE shipped tables from `auditd-stig-update derive`'s
    // per-product output.

    #[test]
    fn rhel8_fixture_reproduces_code_table_exactly() {
        let derived = parse_requirements(RHEL8_FIXTURE).expect("parses");
        let code = code_table(TargetVersion::Rhel8);
        let diff = crate::derive::diff_rules(&derived, &code);
        assert!(
            diff.is_empty(),
            "RHEL8 fixture must reproduce the shipped table: {diff:?}"
        );
    }

    #[test]
    fn rhel10_fixture_reproduces_code_table_exactly() {
        let derived = parse_requirements(RHEL10_FIXTURE).expect("parses");
        let code = code_table(TargetVersion::Rhel10);
        let diff = crate::derive::diff_rules(&derived, &code);
        assert!(
            diff.is_empty(),
            "RHEL10 fixture must reproduce the shipped table: {diff:?}"
        );
    }

    // --- known-answer counts (grounding doc Part B.2, re-verified against the
    // cached XCCDFs via an independent ElementTree-based script; re-confirmed by
    // this test-author's own fixture-generation script producing the SAME
    // 45/61, 51/67, 50/75 counts before this file was written) ---------------

    // UPDATED (#523, session 9b-v0_8-wave2 lane 2e): each fixture gained new
    // real Groups whose ENTIRE requirement is a bare Control-rule line
    // ("-e 2" / "-f 2") -- fetched live 2026-07-15 against the pinned DISA
    // zips. `RULE_LINE_RE` (this module) does not recognize "-e"/"-f" leading
    // tokens today, so these Groups are currently DROPPED by the selector
    // (zero extracted lines each): the three tests below are RED until the
    // implementer widens `RULE_LINE_RE` to also select them (see
    // `control_rule_check_content_e_flag_is_selected_as_a_required_line` /
    // `..._f_flag_...` below, which pin the mechanism directly).

    #[test]
    fn rhel8_known_answer_counts() {
        let derived = parse_requirements(RHEL8_FIXTURE).expect("fixture must parse");
        assert_eq!(distinct_v_numbers(&derived), 46, "rhel8 requirement count");
        assert_eq!(derived.len(), 62, "rhel8 total extracted line count");
    }

    #[test]
    fn rhel9_known_answer_counts() {
        let derived = parse_requirements(RHEL9_FIXTURE).expect("fixture must parse");
        assert_eq!(distinct_v_numbers(&derived), 53, "rhel9 requirement count");
        assert_eq!(derived.len(), 69, "rhel9 total extracted line count");
    }

    #[test]
    fn rhel10_known_answer_counts() {
        let derived = parse_requirements(RHEL10_FIXTURE).expect("fixture must parse");
        assert_eq!(distinct_v_numbers(&derived), 52, "rhel10 requirement count");
        assert_eq!(derived.len(), 77, "rhel10 total extracted line count");
    }

    // --- deepening (#523): the selector-widening mechanism, pinned directly
    // against minimal synthetic fixtures (independent of the real-fixture
    // known-answer counts above) ------------------------------------------

    #[test]
    fn control_rule_check_content_e_flag_is_selected_as_a_required_line() {
        // SV-230402r1017208_rule (RHEL-08-030121): a real DISA requirement
        // whose ENTIRE requirement is a bare Control-rule line ("-e 2", the
        // immutable-audit-config flag) -- never a "-a"/"-A"/"-w" line at all.
        // `RULE_LINE_RE` today only recognizes "-A"/"-a"/"-w" leading tokens,
        // so this Group is currently DROPPED entirely (zero extracted lines),
        // even though "-e 2" is a real, parser-recognized
        // `AuditRule::Control(ControlRule::Enable(2))` line
        // (`crates/rulesteward-auditd/src/parser.rs`'s "-e" arm). Verified
        // live 2026-07-15: widening the selector to also recognize "-e"/"-f"
        // leading tokens against the REAL pinned rhel8/9/10 XCCDF benchmarks
        // selects EXACTLY the five new Groups this deepening adds
        // (V-230402, V-258227, V-258229, V-281103, V-281365) and introduces
        // ZERO false positives elsewhere in any of the three benchmarks
        // (mechanically re-verified against the live XCCDF text, not merely
        // asserted).
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-230402"><Rule severity="medium"><version>RHEL-08-030121</version>
            <check><check-content>Verify the audit system prevents unauthorized changes with the following command:

$ sudo grep "^\s*[^#]" /etc/audit/audit.rules | tail -1

-e 2

If the audit system is not set to be immutable by adding the "-e 2" option to the "/etc/audit/audit.rules", this is a finding.</check-content></check>
            </Rule></Group></Benchmark>"#;
        let derived = parse_requirements(doc).expect("parses");
        assert_eq!(
            derived.len(),
            1,
            "the bare \"-e 2\" Control-rule line must be selected as a required line: {derived:?}"
        );
        assert_eq!(derived[0].v_number, "V-230402");
        assert_eq!(derived[0].stig_id, "RHEL-08-030121");
        assert_eq!(derived[0].line, "-e 2");
    }

    #[test]
    fn control_rule_check_content_f_flag_is_selected_as_a_required_line() {
        // SV-258227r1014992_rule (RHEL-09-654265): companion to the "-e" test
        // above -- a bare "-f 2" Control-rule line (panic-on-critical-failure).
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-258227"><Rule severity="medium"><version>RHEL-09-654265</version>
            <check><check-content>Verify the audit service is configured to panic on a critical error with the following command:

$ sudo grep "\-f" /etc/audit/audit.rules

-f 2

If the value for "-f" is not "2", and availability is not documented as an overriding concern, this is a finding.</check-content></check>
            </Rule></Group></Benchmark>"#;
        let derived = parse_requirements(doc).expect("parses");
        assert_eq!(derived.len(), 1, "{derived:?}");
        assert_eq!(derived[0].v_number, "V-258227");
        assert_eq!(derived[0].stig_id, "RHEL-09-654265");
        assert_eq!(derived[0].line, "-f 2");
    }

    // --- pinned spot-checks (cite appendix.txt ids; each line copied verbatim
    // from the appendix oracle, itself re-derivable from the cached XCCDFs) ----

    #[test]
    fn rhel9_execve_c_pair_four_line_cartesian_product() {
        // SV-258176r1155595_rule (RHEL-09-654010): a genuine 2-axis Cartesian
        // product (arch b32/b64 x uid!=euid/gid!=egid), grounding Part B.5.5.
        let derived = parse_requirements(RHEL9_FIXTURE).expect("fixture must parse");
        let rows: Vec<&DerivedRule> = derived
            .iter()
            .filter(|d| d.v_number == "V-258176")
            .collect();
        assert_eq!(
            rows.len(),
            4,
            "the execve C-pair rule has 4 lines: {rows:?}"
        );
        assert!(rows.iter().all(|r| r.stig_id == "RHEL-09-654010"));
        for line in [
            "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv",
            "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
            "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv",
            "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv",
        ] {
            assert!(
                rows.iter().any(|r| r.line == line),
                "missing line {line:?} in {rows:?}"
            );
        }
    }

    #[test]
    fn rhel9_multi_path_watch_cronjobs_two_lines_one_v_number() {
        // SV-279936r1156361_rule (RHEL-09-654097): TWO distinct watched paths
        // required simultaneously under one V-number (grounding Part B.5.7),
        // distinct from an arch b32/b64 pair.
        let derived = parse_requirements(RHEL9_FIXTURE).expect("fixture must parse");
        let rows: Vec<&DerivedRule> = derived
            .iter()
            .filter(|d| d.v_number == "V-279936")
            .collect();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(
            rows.iter()
                .any(|r| r.line == "-w /etc/cron.d -p wa -k cronjobs")
        );
        assert!(
            rows.iter()
                .any(|r| r.line == "-w /var/spool/cron -p wa -k cronjobs")
        );
    }

    #[test]
    fn rhel9_cat_rules_d_idiom_shutdown_extracts_the_same_as_auditctl_l_idiom() {
        // SV-258214r1045427_rule (RHEL-09-654200): the `cat /etc/audit/rules.d/*`
        // idiom variant (grounding Part B.3.4) must extract identically to the
        // `auditctl -l | grep` idiom used everywhere else - the idiom preamble
        // never changes the extraction, only the shell-command prose does.
        let derived = parse_requirements(RHEL9_FIXTURE).expect("fixture must parse");
        let rows: Vec<&DerivedRule> = derived
            .iter()
            .filter(|d| d.v_number == "V-258214")
            .collect();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(
            rows[0].line,
            "-a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 \
             -F auid!=-1 -F key=privileged-shutdown"
        );
    }

    #[test]
    fn rhel9_privileged_command_s_all_plus_f_key_spelling() {
        // SV-258180r1045325_rule (RHEL-09-654030): the "-S all" + "-F key=" +
        // "auid!=-1" privileged-command family (grounding Part B.5.3/B.5.4).
        let derived = parse_requirements(RHEL9_FIXTURE).expect("fixture must parse");
        let rows: Vec<&DerivedRule> = derived
            .iter()
            .filter(|d| d.v_number == "V-258180")
            .collect();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(
            rows[0].line,
            "-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 \
             -F auid!=-1 -F key=privileged-mount"
        );
    }

    #[test]
    fn rhel9_watch_single_path_identity_key_shared_across_distinct_v_numbers() {
        // SV-258217r1045436_rule (RHEL-09-654215): a plain single-path watch. The
        // `identity` key is shared by SEVEN separate V-numbers in rhel9
        // (grounding Part B.5.8) - the table must NOT dedupe/merge them by key.
        let derived = parse_requirements(RHEL9_FIXTURE).expect("fixture must parse");
        let sudoers_watch = derived
            .iter()
            .find(|d| d.v_number == "V-258217")
            .expect("V-258217 present");
        assert_eq!(sudoers_watch.line, "-w /etc/sudoers -p wa -k identity");
        let identity_v_numbers: std::collections::HashSet<&str> = derived
            .iter()
            .filter(|d| d.line.ends_with("-k identity"))
            .map(|d| d.v_number.as_str())
            .collect();
        assert_eq!(
            identity_v_numbers.len(),
            7,
            "identity key must remain attached to 7 distinct V-numbers, not merged: \
             {identity_v_numbers:?}"
        );
    }

    // --- selector exclusion (the fixtures carry 2 decoy Groups each; see
    // tests/fixtures/README.md) ------------------------------------------------

    #[test]
    fn decoys_excluded_exact_v_number_count() {
        // Each fixture carries exactly 2 decoy Groups (an auditd.conf key=value
        // check and a service/package check) that must be excluded by the
        // selector, on top of the real audit-rule requirement count.
        let derived = parse_requirements(RHEL9_FIXTURE).expect("fixture must parse");
        assert_eq!(
            distinct_v_numbers(&derived),
            53,
            "the 2 decoy Groups in the fixture must be excluded, not counted"
        );
    }

    #[test]
    fn non_audit_document_yields_empty() {
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-1"><Rule severity="medium"><version>X</version>
            <check><check-content>Verify permissions with: stat /etc/audit/rules.d/
            If not 0640, this is a finding.</check-content></check>
            </Rule></Group></Benchmark>"#;
        assert_eq!(parse_requirements(doc).unwrap(), vec![]);
    }

    #[test]
    fn selected_group_missing_id_fails_closed() {
        // A selected Rule (its check-content matches the line selector) whose
        // enclosing Group has NO `id` attribute has no DISA V-number to carry --
        // rather than silently emitting a row with an empty/synthesized
        // v_number, the extractor must fail closed (the module doc's "fail
        // closed" discipline, mirroring the sshd tool's own posture for a
        // Rule it cannot confidently classify).
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group><Rule severity="medium"><version>RHEL-09-999999</version>
            <check><check-content>-w /etc/passwd -p wa -k identity</check-content></check>
            </Rule></Group></Benchmark>"#;
        let err = parse_requirements(doc).expect_err("a Group with no id must fail closed");
        assert!(
            err.contains("RHEL-09-999999") || err.to_lowercase().contains("group id"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_version_element_within_one_rule_keeps_the_first() {
        // Grounding: the module doc's Start-event guard, `b"version" if
        // cur_stig_id.is_none()`, states "Only the FIRST <version> in a Rule
        // is the STIG id; a second <version> (not observed, but defended per
        // the module doc's 'fail closed for a future DISA reformat' posture)
        // is ignored." (mutation gate, session 7c pipeline P2: the
        // `cur_stig_id.is_none() -> true` mutant survived because no test
        // pinned this contract). Pin: the FIRST <version> wins, not the
        // last.
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-42"><Rule severity="medium"><version>RHEL-09-999999</version>
            <version>RHEL-09-000000</version>
            <check><check-content>-w /etc/passwd -p wa -k identity</check-content></check>
            </Rule></Group></Benchmark>"#;
        let derived = parse_requirements(doc).expect("parses");
        assert_eq!(derived.len(), 1, "{derived:?}");
        assert_eq!(
            derived[0].stig_id, "RHEL-09-999999",
            "the FIRST <version> must win, not a later one: {derived:?}"
        );
    }

    #[test]
    fn duplicate_verbatim_line_within_one_rule_dedupes_to_one_row() {
        // Grounding Part B.3.3: a line repeated verbatim within one Rule's
        // check-content collapses to one row (not observed in the real corpus,
        // defended for a future DISA reformat).
        let doc = r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">
            <Group id="V-42"><Rule severity="medium"><version>RHEL-09-999999</version>
            <check><check-content>-w /etc/passwd -p wa -k identity
            -w /etc/passwd -p wa -k identity</check-content></check>
            </Rule></Group></Benchmark>"#;
        let derived = parse_requirements(doc).expect("parses");
        assert_eq!(derived.len(), 1, "{derived:?}");
    }
}
