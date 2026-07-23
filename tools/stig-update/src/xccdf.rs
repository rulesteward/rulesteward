//! The offline derivation core: parse an official DISA XCCDF benchmark into the
//! normalized [`DerivedKey`] table for the sysctld-W02 STIG kernel-hardening
//! baseline (#512, session 9h-v0_8-wave4 Lane B - port from ComplianceAsCode to
//! DISA XCCDF, mirroring `tools/sshd-stig-update`/`tools/auditd-stig-update`).
//!
//! This is the testable heart of the tool - it takes raw XCCDF text and returns the
//! derived baseline, with NO network or filesystem. The live fetch that hands it the
//! XCCDF bytes lives behind the seam in [`crate::source`] (implementer's job; the
//! existing `source.rs` is CaC-github-api-specific and needs a curl+unzip DISA-zip
//! fetch added, mirroring `tools/sshd-stig-update/src/source.rs` /
//! `tools/auditd-stig-update/src/source.rs`).
//!
//! # How a Rule is selected + classified (grounded in the real DISA XCCDF)
//!
//! Full inventory + every V-number/value cited below:
//! `/mnt/side-projects/9h-v0_8-wave4/lane-b-grounding.md` (this lane's grounding
//! doc; not part of the repo - the load-bearing facts are restated here so this
//! module doc stands on its own once that scratch file is gone).
//!
//! A `<Group>`/`<Rule>` is a settable-sysctl-key requirement IFF its `check-content`
//! contains BOTH:
//! 1. a `sysctl <dotted.key>` command invocation (`$ sudo sysctl <key>` OR the bare
//!    `$ sysctl <key>` with no `sudo` - both forms occur in the real corpus, e.g.
//!    V-257810/V-257811/V-281335/V-281316/V-257972/V-281355 all omit `sudo`); AND
//! 2. a same-content echo line `<dotted.key>[ ]=[ ]<value>` for that SAME key
//!    (whitespace around `=` varies: most are `key = value`, but
//!    `net.ipv4.conf.default.send_redirects=0` (V-257969, V-281352) has none - both
//!    must be accepted). The command line itself sometimes carries a trailing space
//!    before the newline (`$ sudo sysctl kernel.kptr_restrict ` - V-230547/
//!    V-257800/V-281308), which must not break the key extraction.
//!
//! The V-number (`<Group id>`) is NOT carried into [`DerivedKey`] (it has no
//! `v_number` field - see the survival-constraint note below); the STIG id is the
//! Rule's first `<version>` element (`RHEL-XX-NNNNNN`), exactly as the sshd/auditd
//! tools derive their own `rule_id`/`stig_id` fields.
//!
//! **Selector-negative (excluded) case**: the FIPS-mode check
//! (`crypto.fips_enabled`, V-258230 rhel9 / V-281009 rhel10; rhel8's own STIG has
//! no `/proc/sys`-based FIPS check at all - it checks via
//! `update-crypto-policies --show` instead) reads `/proc/sys/crypto/fips_enabled`
//! via `cat`, never via a `sysctl <key>` command - so it is NATURALLY excluded by
//! requirement 1 above, with no explicit exclude-list needed. This replaces the old
//! CaC-era `stig-refs.toml` `exclude_rules = ["sysctl_crypto_fips_enabled",
//! "sysctl_kernel_exec_shield"]` entirely: `kernel.exec-shield` is ALSO naturally
//! absent (zero DISA Group mentions "exec-shield"/"exec_shield" in any of the three
//! pinned rhel8/9/10 benchmarks at all - it is a 32-bit-only kernel feature DISA
//! does not check on RHEL 8+). The new `config.rs` shape carries no
//! exclude-list field.
//!
//! **Value typing**: every value across the real corpus (96 keys across all three
//! products, plus 3 new rhel8 keys DISA V2R8 added - see the grounding doc's diff
//! table) is one of `0`, `1`, `2` (numeric) or the one string-typed
//! `kernel.core_pattern` (`|/bin/false`, on all three products). `numeric` is simply
//! "every byte of the extracted value is an ASCII digit" (non-empty).
//!
//! **No value SETS in DISA text**: unlike `tools/sshd-stig-update`'s fixtext (which
//! has real `set the value to "X", "Y", or "Z"` clauses), NOT ONE of the 96 real
//! sysctl `check-content`s offers more than one acceptable literal value - every
//! DISA check is `If ... is not set to "<X>" ... this is a finding` for exactly one
//! `X`. [`DerivedKey::accepted`] is therefore always a single-element `Vec` when
//! built from a DISA XCCDF (the CaC-era `derive_table`'s set-valued outputs, e.g.
//! `kernel.kptr_restrict` accepting `{1, 2}` on rhel9/rhel10 via a CaC jinja
//! branch, trace to ComplianceAsCode's OWN broader-than-DISA compliant range, not
//! to DISA's literal text - reconciling to DISA-authoritative narrows those rows to
//! `["1"]`; grounding doc section 4a/5).
//!
//! Anything the parser cannot confidently classify is a hard error - it fails
//! CLOSED so a future DISA reformat surfaces loudly instead of silently deriving a
//! wrong baseline (mirrors the sshd/auditd tools' own discipline): a Group whose
//! `check-content` invokes `sysctl <key>` but has NO matching `<key> = <value>`
//! echo line; a Group whose Rule has no `<version>`; and two DIFFERENT Groups that
//! derive the SAME key with DIFFERING values (a duplicated key with an IDENTICAL
//! value is not ambiguous and dedupes to one row, mirroring the sshd tool's
//! `duplicate_identical_config_lines_are_ok`).
//!
//! # Survival constraint (#512)
//!
//! [`DerivedKey`] and [`normalize_set`] (both in [`crate::derive`]) keep their
//! EXACT existing field/signature shape - `tools/cis-update` constructs
//! `DerivedKey` struct literals directly (`report.rs`) and calls
//! `derive::normalize_set` (`values.rs`) for its OWN, still-CaC-sourced CIS-value
//! derivation (a genuinely different, still-jinja-conditional standard/data
//! source). This module does NOT add a field to `DerivedKey` (e.g. no `v_number`),
//! since the shipped `rulesteward_sysctld::StigEntry` public view (which
//! `derive::code_table` projects into this comparison shape) carries no V-number
//! either, so there is no gap.

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::sync::LazyLock;

use crate::derive::DerivedKey;

/// The check-content `sysctl <key>` command selector (module doc, grounding section
/// 2): a literal `sysctl` command invocation naming the dotted key that a same-content
/// echo line later reports the value of. Matches both `$ sudo sysctl <key>` and the
/// bare `$ sysctl <key>` form (both occur in the real corpus).
static SYSCTL_CMD_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"sysctl\s+([a-z][a-z0-9_.]+)").expect("valid regex"));

/// Parse a full DISA XCCDF benchmark into the normalized sysctld-W02 baseline
/// table, sorted by dotted sysctl key. Returns an error on any Rule the parser
/// selects (via the `sysctl <key>` command idiom) but cannot confidently extract a
/// value from, or on two differently-valued Rules that select the same key
/// (fail-closed; see the module doc).
///
/// # Errors
/// See the module doc's "fails CLOSED" paragraph.
pub fn parse_baseline(xccdf: &str) -> Result<Vec<DerivedKey>, String> {
    let mut reader = Reader::from_str(xccdf);

    let mut out: Vec<DerivedKey> = Vec::new();

    // State for the Group/Rule pair currently being walked. Groups never nest and
    // each wraps exactly one Rule (same shape as the auditd tool's xccdf.rs), so a
    // flat set of "current" slots (reset on the next `<Group>` Start) is sufficient.
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

            // quick-xml 0.41 tokenizes an entity/character reference as its OWN
            // event, separate from the surrounding Text events (see the auditd
            // tool's xccdf.rs for the same handling + rationale). Resolve numeric
            // char refs first, then the five predefined XML entities. An
            // unresolvable entity is a hard parse error (fail-closed).
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
                        select_and_push(
                            &mut out,
                            cur_group_id.take(),
                            cur_stig_id.take(),
                            &content,
                        )?;
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

    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

/// Apply the selector + extraction to one Group's check-content (module doc): select
/// via the `sysctl <key>` command idiom, then extract the required value from a
/// matching `<key>[ ]=[ ]<value>` echo line. A non-selected Group (no `sysctl <key>`
/// command at all) is silently skipped - this is the FIPS-decoy exclusion mechanism
/// (see the module doc's "Selector-negative" paragraph), not an error.
fn select_and_push(
    out: &mut Vec<DerivedKey>,
    group_id: Option<String>,
    stig_id: Option<String>,
    content: &str,
) -> Result<(), String> {
    let Some(caps) = SYSCTL_CMD_RE.captures(content) else {
        return Ok(());
    };
    let key = caps[1].to_string();
    let group_id = group_id.unwrap_or_default();

    let stig_id = stig_id.ok_or_else(|| {
        format!("{group_id}: selected sysctl key {key:?} but the Rule has no <version> element (fail-closed)")
    })?;
    let value = extract_echo_value(content, &key).ok_or_else(|| {
        format!(
            "{group_id}: sysctl {key} selected but no matching '{key} = <value>' echo line \
             found in check-content (fail-closed)"
        )
    })?;
    let numeric = value.chars().all(|c| c.is_ascii_digit());

    if let Some(existing) = out.iter().find(|d| d.key == key) {
        if existing.accepted != [value.clone()] {
            return Err(format!(
                "{group_id}: sysctl {key} = {value:?} conflicts with an earlier Group's value \
                 {:?} for the same key (fail-closed, ambiguous duplicate)",
                existing.accepted
            ));
        }
        // Identical duplicate value: unambiguous, dedupe (drop this row).
        return Ok(());
    }

    out.push(DerivedKey {
        key,
        accepted: vec![value],
        stig_id,
        numeric,
    });
    Ok(())
}

/// Find the `<key>[ ]=[ ]<value>` echo line for `key` within `content` (module doc:
/// tolerates both `key = value` and `key=value` spacing, and a trailing space after
/// the value before the newline). Returns the first match; not observed to occur more
/// than once per real Group in the corpus.
fn extract_echo_value(content: &str, key: &str) -> Option<String> {
    let pattern = format!(r"(?m)^\s*{}\s*=\s*(\S+)\s*$", regex::escape(key));
    let re = regex::Regex::new(&pattern).ok()?;
    re.captures(content).map(|c| c[1].to_string())
}

/// Read an attribute's value as plain UTF-8 (no entity unescaping): the attribute
/// this parser reads (`Group/@id`) is a simple token (`V-NNNNNN`) that never carries
/// XML entities in the real DISA corpus.
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
    use crate::derive::{code_table, diff_tables};
    use rulesteward_sysctld::TargetVersion;

    const RHEL8_FIXTURE: &str = include_str!("../tests/fixtures/rhel8_sysctld_controls.xml");
    const RHEL9_FIXTURE: &str = include_str!("../tests/fixtures/rhel9_sysctld_controls.xml");
    const RHEL10_FIXTURE: &str = include_str!("../tests/fixtures/rhel10_sysctld_controls.xml");

    fn dk(key: &str, accepted: &[&str], stig_id: &str, numeric: bool) -> DerivedKey {
        DerivedKey {
            key: key.to_string(),
            accepted: accepted.iter().map(|s| (*s).to_string()).collect(),
            stig_id: stig_id.to_string(),
            numeric,
        }
    }

    fn set_accepted(t: &mut [DerivedKey], key: &str, accepted: &[&str]) {
        let e = t
            .iter_mut()
            .find(|d| d.key == key)
            .unwrap_or_else(|| panic!("{key} must be present in the shipped table"));
        e.accepted = accepted.iter().map(|s| (*s).to_string()).collect();
    }

    /// Insert `key` with the grounded fields if `t` does not already have it, or
    /// overwrite it IN PLACE (to the same grounded fields) if it does - idempotent
    /// either way, unlike a bare `push`. Needed (not just `set_accepted`) for a row
    /// that is ABSENT pre-reconciliation and PRESENT post-reconciliation: a plain
    /// `push` would duplicate the row once the implementer's `RHEL8_BASELINE`
    /// already carries it (#512 adversarial-review BLOCKER 1, session
    /// 9h-v0_8-wave4 Lane B, 2026-07-23 - `reconciled_rhel8`'s three `push`es were
    /// non-idempotent: correct while `code_table(Rhel8)` was still the
    /// un-reconciled 28-key table, but duplicating once the implementer lands the
    /// reconciled 31-key table, since all three keys would then already be present).
    fn upsert(t: &mut Vec<DerivedKey>, key: &str, accepted: &[&str], stig_id: &str, numeric: bool) {
        if let Some(e) = t.iter_mut().find(|d| d.key == key) {
            e.accepted = accepted.iter().map(|s| (*s).to_string()).collect();
            e.stig_id = stig_id.to_string();
            e.numeric = numeric;
        } else {
            t.push(dk(key, accepted, stig_id, numeric));
        }
    }

    // --- the golden tests: fixture-derived must equal the RECONCILED table -----
    // Built FROM the shipped `code_table` with the DISA-grounded reconciliation
    // patch applied (lane-b-grounding.md section 5), so these stay correct whether
    // `baseline.rs` has already been updated to the reconciled values by the time
    // this runs (patch is then a no-op) or not yet (patch supplies the delta) -
    // RED today for BOTH reasons at once (parse_baseline is todo!(), AND
    // baseline.rs has not yet been updated), the same "RED for TWO independent
    // reasons" shape tools/auditd-stig-update's own xccdf.rs had at its barrier.
    // The "no-op once baseline.rs is updated" claim REQUIRES every patch operation
    // to be idempotent: `set_accepted` (narrow-in-place) always was; the rhel8
    // helper's `push`es were not until they were rewritten to `upsert` above (see
    // its doc comment) - both forms are now idempotent, so the claim holds for all
    // three products.

    /// RHEL8: `net.ipv4.conf.all.rp_filter` narrows from `{1,2}` to `{1}`
    /// (V-230549/RHEL-08-040285), plus 3 new DISA V2R8 keys the shipped table
    /// does not have yet: `net.ipv4.conf.default.rp_filter` (V-284947/
    /// RHEL-08-040287), `net.ipv4.conf.all.log_martians` (V-284948/
    /// RHEL-08-040221), `net.ipv4.conf.default.log_martians` (V-284949/
    /// RHEL-08-040222) - all three `ENABLE`-only (`["1"]`), numeric. Uses `upsert`
    /// (not a bare `push`) for the 3 new keys so this stays correct both before AND
    /// after the implementer adds them to `RHEL8_BASELINE` (converges to the same
    /// 31-row table either way, never duplicating).
    fn reconciled_rhel8() -> Vec<DerivedKey> {
        let mut t = code_table(TargetVersion::Rhel8);
        set_accepted(&mut t, "net.ipv4.conf.all.rp_filter", &["1"]);
        upsert(
            &mut t,
            "net.ipv4.conf.default.rp_filter",
            &["1"],
            "RHEL-08-040287",
            true,
        );
        upsert(
            &mut t,
            "net.ipv4.conf.all.log_martians",
            &["1"],
            "RHEL-08-040221",
            true,
        );
        upsert(
            &mut t,
            "net.ipv4.conf.default.log_martians",
            &["1"],
            "RHEL-08-040222",
            true,
        );
        t.sort_by(|a, b| a.key.cmp(&b.key));
        t
    }

    /// RHEL9: only `kernel.kptr_restrict` narrows from `{1,2}` to `{1}`
    /// (V-257800/RHEL-09-213025). Zero key-set drift (33 keys before and after).
    fn reconciled_rhel9() -> Vec<DerivedKey> {
        let mut t = code_table(TargetVersion::Rhel9);
        set_accepted(&mut t, "kernel.kptr_restrict", &["1"]);
        t.sort_by(|a, b| a.key.cmp(&b.key));
        t
    }

    /// RHEL10: `kernel.kptr_restrict` (V-281308/RHEL-10-701060) AND
    /// `net.ipv4.conf.all.rp_filter` (V-281345/RHEL-10-800130) both narrow from
    /// `{1,2}` to `{1}`. Zero key-set drift (32 keys before and after).
    fn reconciled_rhel10() -> Vec<DerivedKey> {
        let mut t = code_table(TargetVersion::Rhel10);
        set_accepted(&mut t, "kernel.kptr_restrict", &["1"]);
        set_accepted(&mut t, "net.ipv4.conf.all.rp_filter", &["1"]);
        t.sort_by(|a, b| a.key.cmp(&b.key));
        t
    }

    #[test]
    fn rhel8_fixture_reproduces_the_reconciled_baseline_exactly() {
        let derived = parse_baseline(RHEL8_FIXTURE).expect("parses");
        let expected = reconciled_rhel8();
        assert_eq!(
            diff_tables(&derived, &expected),
            Vec::<String>::new(),
            "RHEL8 fixture must reproduce the DISA-reconciled table"
        );
        assert_eq!(derived, expected);
    }

    #[test]
    fn rhel9_fixture_reproduces_the_reconciled_baseline_exactly() {
        let derived = parse_baseline(RHEL9_FIXTURE).expect("parses");
        let expected = reconciled_rhel9();
        assert_eq!(
            diff_tables(&derived, &expected),
            Vec::<String>::new(),
            "RHEL9 fixture must reproduce the DISA-reconciled table"
        );
        assert_eq!(derived, expected);
    }

    #[test]
    fn rhel10_fixture_reproduces_the_reconciled_baseline_exactly() {
        let derived = parse_baseline(RHEL10_FIXTURE).expect("parses");
        let expected = reconciled_rhel10();
        assert_eq!(
            diff_tables(&derived, &expected),
            Vec::<String>::new(),
            "RHEL10 fixture must reproduce the DISA-reconciled table"
        );
        assert_eq!(derived, expected);
    }

    // --- decoy exclusion + negative selector ------------------------------------

    /// The fixtures carry 2 decoy Groups each (a near-miss + a wholly unrelated
    /// check; see `tests/fixtures/README.md`); the selector must EXCLUDE them, so
    /// each fixture's derived count is EXACTLY the real/selected count, never
    /// inflated by a decoy.
    #[test]
    fn decoys_excluded_exact_counts() {
        assert_eq!(
            parse_baseline(RHEL8_FIXTURE).unwrap().len(),
            31,
            "rhel8: 28 shipped + 3 new DISA V2R8 keys"
        );
        assert_eq!(parse_baseline(RHEL9_FIXTURE).unwrap().len(), 33);
        assert_eq!(parse_baseline(RHEL10_FIXTURE).unwrap().len(), 32);
    }

    /// The real FIPS-mode near-miss decoy (rhel9/rhel10: `cat
    /// /proc/sys/crypto/fips_enabled`, no `sysctl <key>` command) must never
    /// contribute a row - proven directly (not just implied by the exact counts
    /// above), since a selector bug that keyed on a bare `/proc/sys` substring
    /// instead of the `sysctl <key>` command would wrongly select it.
    #[test]
    fn fips_near_miss_decoy_never_selected() {
        for fixture in [RHEL9_FIXTURE, RHEL10_FIXTURE] {
            let derived = parse_baseline(fixture).expect("parses");
            assert!(
                !derived.iter().any(|d| d.key.contains("fips")),
                "the FIPS near-miss (cat /proc/sys/..., no sysctl <key> command) \
                 must never be selected: {derived:?}"
            );
        }
    }

    // --- semantic spot-checks (hard-coded, independent of baseline.rs's state) --

    #[test]
    fn rhel9_kptr_restrict_is_reconciled_to_enable_only() {
        let d = parse_baseline(RHEL9_FIXTURE).expect("parses");
        let kptr = d
            .iter()
            .find(|e| e.key == "kernel.kptr_restrict")
            .expect("kernel.kptr_restrict present");
        assert_eq!(
            kptr.accepted,
            ["1"],
            "DISA V-257800/RHEL-09-213025 requires exactly 1, not {{1,2}}"
        );
        assert_eq!(kptr.stig_id, "RHEL-09-213025");
        assert!(kptr.numeric);
    }

    #[test]
    fn rhel10_rp_filter_all_is_reconciled_to_enable_only() {
        let d = parse_baseline(RHEL10_FIXTURE).expect("parses");
        let rpf = d
            .iter()
            .find(|e| e.key == "net.ipv4.conf.all.rp_filter")
            .expect("net.ipv4.conf.all.rp_filter present");
        assert_eq!(
            rpf.accepted,
            ["1"],
            "DISA V-281345/RHEL-10-800130 requires exactly 1"
        );
        assert_eq!(rpf.stig_id, "RHEL-10-800130");
    }

    #[test]
    fn rhel8_gains_three_new_v2r8_keys() {
        let d = parse_baseline(RHEL8_FIXTURE).expect("parses");
        for (key, stig_id) in [
            ("net.ipv4.conf.default.rp_filter", "RHEL-08-040287"),
            ("net.ipv4.conf.all.log_martians", "RHEL-08-040221"),
            ("net.ipv4.conf.default.log_martians", "RHEL-08-040222"),
        ] {
            let e = d
                .iter()
                .find(|e| e.key == key)
                .unwrap_or_else(|| panic!("{key} must be present (new in DISA V2R8): {d:?}"));
            assert_eq!(e.accepted, ["1"]);
            assert_eq!(e.stig_id, stig_id);
            assert!(e.numeric);
        }
    }

    #[test]
    fn core_pattern_is_string_typed_not_numeric_on_every_target() {
        for (fixture, stig_id) in [
            (RHEL8_FIXTURE, "RHEL-08-010671"),
            (RHEL9_FIXTURE, "RHEL-09-213040"),
            (RHEL10_FIXTURE, "RHEL-10-701090"),
        ] {
            let d = parse_baseline(fixture).expect("parses");
            let cp = d
                .iter()
                .find(|e| e.key == "kernel.core_pattern")
                .expect("kernel.core_pattern present");
            assert_eq!(cp.accepted, ["|/bin/false"]);
            assert_eq!(cp.stig_id, stig_id);
            assert!(!cp.numeric, "core_pattern's value is not all-ASCII-digit");
        }
    }

    #[test]
    fn derived_table_is_sorted_by_key() {
        for fixture in [RHEL8_FIXTURE, RHEL9_FIXTURE, RHEL10_FIXTURE] {
            let d = parse_baseline(fixture).expect("parses");
            let mut sorted = d.clone();
            sorted.sort_by(|a, b| a.key.cmp(&b.key));
            assert_eq!(d, sorted, "parse_baseline must return rows sorted by key");
        }
    }

    // --- synthetic robustness tests (small documents, grounded in real DISA
    // formatting quirks observed across the corpus; see the module doc) ---------

    #[test]
    fn bare_sysctl_command_without_sudo_is_selected() {
        // Mirrors V-257810 (kernel.unprivileged_bpf_disabled, rhel9): `$ sysctl
        // <key>` with NO leading `sudo`.
        let doc = r#"<Benchmark><Group id="V-1"><Rule><version>RHEL-09-999001</version>
            <check><check-content>Check the status with the following command:

$ sysctl kernel.unprivileged_bpf_disabled
kernel.unprivileged_bpf_disabled = 1

If not set to "1", this is a finding.</check-content></check></Rule></Group></Benchmark>"#;
        let d = parse_baseline(doc).expect("parses");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].key, "kernel.unprivileged_bpf_disabled");
        assert_eq!(d[0].accepted, ["1"]);
        assert_eq!(d[0].stig_id, "RHEL-09-999001");
    }

    #[test]
    fn no_space_around_equals_echo_line_is_selected() {
        // Mirrors V-257969/V-281352 (net.ipv4.conf.default.send_redirects):
        // `key=value` with no surrounding whitespace at all.
        let doc = r#"<Benchmark><Group id="V-2"><Rule><version>RHEL-09-999002</version>
            <check><check-content>$ sudo sysctl net.ipv4.conf.default.send_redirects
net.ipv4.conf.default.send_redirects=0

If not "0", this is a finding.</check-content></check></Rule></Group></Benchmark>"#;
        let d = parse_baseline(doc).expect("parses");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].key, "net.ipv4.conf.default.send_redirects");
        assert_eq!(d[0].accepted, ["0"]);
    }

    #[test]
    fn trailing_space_after_key_in_command_line_is_tolerated() {
        // Mirrors V-230547/V-257800/V-281308 (kernel.kptr_restrict): the command
        // line itself carries a trailing space before the newline
        // (`$ sudo sysctl kernel.kptr_restrict `).
        let doc = "<Benchmark><Group id=\"V-3\"><Rule><version>RHEL-09-999003</version>\
            <check><check-content>$ sudo sysctl kernel.kptr_restrict \nkernel.kptr_restrict = 1\n\
            If not \"1\", this is a finding.</check-content></check></Rule></Group></Benchmark>";
        let d = parse_baseline(doc).expect("parses");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].key, "kernel.kptr_restrict");
        assert_eq!(d[0].accepted, ["1"]);
    }

    #[test]
    fn cat_proc_sys_without_a_sysctl_command_is_not_selected() {
        // The synthetic shape of the real FIPS decoy (section above uses the real
        // fixture; this pins the MECHANISM directly on a minimal synthetic doc): a
        // Group that reads /proc/sys via `cat`, never invoking `sysctl <key>`, must
        // not be selected - proves the selector requires the COMMAND, not a bare
        // "/proc/sys" substring.
        let doc = r#"<Benchmark><Group id="V-4"><Rule><version>RHEL-09-999004</version>
            <check><check-content>$ cat /proc/sys/crypto/fips_enabled
1

If the command does not return "1", this is a finding.</check-content></check></Rule></Group></Benchmark>"#;
        let d = parse_baseline(doc).expect("parses");
        assert!(
            d.is_empty(),
            "a bare `cat /proc/sys/...` must not be selected: {d:?}"
        );
    }

    #[test]
    fn non_sysctl_document_yields_empty() {
        let doc = r#"<Benchmark><Group id="V-5"><Rule><version>RHEL-09-999005</version>
            <check><check-content>Verify permissions with: stat /etc/passwd
If not 0644, this is a finding.</check-content></check></Rule></Group></Benchmark>"#;
        assert!(parse_baseline(doc).unwrap().is_empty());
    }

    #[test]
    fn selected_command_without_matching_echo_line_fails_closed() {
        // A `sysctl <key>` command with NO `<key> = <value>` echo anywhere in the
        // check-content: selected (the command is there) but unextractable -> a
        // hard error, never a silently-dropped or default-valued row.
        let doc = r#"<Benchmark><Group id="V-6"><Rule><version>RHEL-09-999006</version>
            <check><check-content>Check the status of the "kernel.dmesg_restrict" kernel
parameter with the following command:

$ sudo sysctl kernel.dmesg_restrict

Compare the output against the site's documented policy.</check-content></check></Rule></Group></Benchmark>"#;
        let err = parse_baseline(doc).expect_err("must fail closed");
        assert!(
            err.contains("V-6") || err.contains("kernel.dmesg_restrict"),
            "{err}"
        );
    }

    #[test]
    fn selected_rule_without_version_fails_closed() {
        let doc = r#"<Benchmark><Group id="V-7"><Rule>
            <check><check-content>$ sudo sysctl kernel.dmesg_restrict
kernel.dmesg_restrict = 1
If not "1", this is a finding.</check-content></check></Rule></Group></Benchmark>"#;
        let err = parse_baseline(doc).expect_err("missing <version> must fail closed");
        assert!(err.contains("V-7"), "{err}");
    }

    #[test]
    fn duplicate_key_with_differing_values_fails_closed() {
        // Two DIFFERENT Groups both deriving kernel.dmesg_restrict, but with
        // DISAGREEING required values - ambiguous, must fail closed (not observed
        // in the real corpus; defended for a future DISA reformat, same
        // "fail-closed for the unknown future case" spirit the sshd/auditd tools'
        // own duplicate-key guards document).
        let one = |v: &str, val: &str| {
            format!(
                "<Group id=\"{v}\"><Rule><version>RHEL-09-{v}</version>\
                 <check><check-content>$ sudo sysctl kernel.dmesg_restrict\n\
                 kernel.dmesg_restrict = {val}\nIf not \"{val}\", this is a finding.\
                 </check-content></check></Rule></Group>"
            )
        };
        let doc = format!(
            "<Benchmark>{}{}</Benchmark>",
            one("V-8A", "1"),
            one("V-8B", "0")
        );
        let err = parse_baseline(&doc).expect_err("differing duplicate values must fail closed");
        assert!(err.contains("kernel.dmesg_restrict"), "{err}");
    }

    #[test]
    fn duplicate_key_with_identical_values_dedupes_to_one_row() {
        // The mirror case: two Groups deriving the SAME key with the SAME value are
        // not ambiguous - dedupe to one row (mirrors the sshd tool's
        // `duplicate_identical_config_lines_are_ok`).
        let one = |v: &str| {
            format!(
                "<Group id=\"{v}\"><Rule><version>RHEL-09-{v}</version>\
                 <check><check-content>$ sudo sysctl kernel.dmesg_restrict\n\
                 kernel.dmesg_restrict = 1\nIf not \"1\", this is a finding.\
                 </check-content></check></Rule></Group>"
            )
        };
        let doc = format!("<Benchmark>{}{}</Benchmark>", one("V-9A"), one("V-9B"));
        let d = parse_baseline(&doc).expect("identical duplicate values are unambiguous");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].accepted, ["1"]);
    }

    #[test]
    fn stig_id_comes_from_rule_version_not_group_id() {
        // The Group id (V-NNNNNN) and the Rule's <version> (RHEL-XX-NNNNNN) are
        // DIFFERENT identifiers; DerivedKey.stig_id must be the latter (the
        // `<version>` text), never the former - an easy mix-up since both are
        // "the id" in casual reading of the XCCDF.
        let doc = r#"<Benchmark><Group id="V-999999"><Rule><version>RHEL-09-213010</version>
            <check><check-content>$ sudo sysctl kernel.dmesg_restrict
kernel.dmesg_restrict = 1
If not "1", this is a finding.</check-content></check></Rule></Group></Benchmark>"#;
        let d = parse_baseline(doc).expect("parses");
        assert_eq!(d.len(), 1);
        assert_eq!(
            d[0].stig_id, "RHEL-09-213010",
            "stig_id must be the Rule's <version> text, not the Group's V-number id"
        );
    }

    // --- mutation-strengthening tests (post-GREEN Adversarial Testing Loop,
    // impl commit 03960a3, session 9h-v0_8-wave4 Lane B, 2026-07-23) - the
    // impl-aware review found no miss-case, but the coverage-blind mutation gate
    // on this file surfaced 4 survivors. Each test below pins the specific state
    // guard whose survivor is listed. None of these shapes are observed in the
    // real DISA corpus (every real Rule has exactly one <version> and one
    // check-content); they defend against a hypothetical future XCCDF reformat,
    // the same "fail-closed / behave-correctly for the unobserved case" posture
    // `duplicate_key_with_differing_values_fails_closed` and its siblings above
    // already establish for this module.

    #[test]
    fn only_the_first_version_element_sets_the_stig_id() {
        // Kills TWO survivors at once, both guarding the SAME "first <version>
        // wins" contract from opposite ends:
        //   - line 147 `b"version" if cur_stig_id.is_none()` (Start): mutated to
        //     `true` would re-arm capture for a SECOND <version>, so the LATER
        //     value would overwrite the first.
        //   - line 195 `b"version" if capture == Capture::Version` (End): mutated
        //     to `true` would fire on ANY `</version>` close, even one reached
        //     while `capture` is `None` (as it legitimately is here, once the
        //     intervening check-content's End resets it) - corrupting
        //     `cur_stig_id` with `text_buf.trim()` of whatever is CURRENTLY in the
        //     buffer (here: the empty string the check-content's End left behind
        //     via `mem::take`), not the second <version>'s own text.
        // A check-content is deliberately sandwiched between the two <version>
        // elements so the buffer-tampering half of the guard-195 mutant is
        // exercised (without it, `text_buf` would coincidentally still hold the
        // first version's text and the mutant would go undetected - see the
        // adversarial-review-round test-report notes for the full trace).
        let doc = r#"<Benchmark><Group id="V-10"><Rule><version>RHEL-09-999010</version>
            <check><check-content>$ sudo sysctl kernel.dmesg_restrict
kernel.dmesg_restrict = 1
If not "1", this is a finding.</check-content></check>
            <version>RHEL-09-999999</version>
            </Rule></Group></Benchmark>"#;
        let d = parse_baseline(doc).expect("parses");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(
            d[0].stig_id, "RHEL-09-999010",
            "the FIRST <version> must win over a later stray one, and no later \
             </version> close may leak in and overwrite it: {d:?}"
        );
    }

    #[test]
    fn numeric_character_reference_inside_check_content_resolves_into_the_value() {
        // Kills the `Event::GeneralRef(r) => { if capture != Capture::None { ... }
        // }` survivor (line 173, `!=` mutated to `==`): quick-xml 0.41 tokenizes a
        // character/entity reference as its OWN event, separate from the
        // surrounding Text events (module doc). A numeric character reference for
        // the digit '1' (`&#49;`) sits INSIDE the echo line's value, while we ARE
        // in a capture state (`Capture::CheckContent`) - the correct guard
        // (`capture != None`) accumulates it; the mutant guard (`capture ==
        // None`) would DROP it instead (we are never NOT capturing here), leaving
        // the echo line's value empty and the whole check-content unextractable
        // (fails closed) instead of resolving to "1".
        let doc = r#"<Benchmark><Group id="V-11"><Rule><version>RHEL-09-999011</version>
            <check><check-content>$ sudo sysctl kernel.dmesg_restrict
kernel.dmesg_restrict = &#49;
If not "1", this is a finding.</check-content></check></Rule></Group></Benchmark>"#;
        let d = parse_baseline(doc)
            .expect("parses: the numeric character reference &#49; must resolve to '1'");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].key, "kernel.dmesg_restrict");
        assert_eq!(
            d[0].accepted,
            ["1"],
            "&#49; must resolve to the digit '1' inside the captured check-content"
        );
    }

    #[test]
    fn a_premature_check_content_close_does_not_clobber_an_already_extracted_value() {
        // Kills the `b"check-content" if capture == Capture::CheckContent`
        // survivor (line 199, End): mutated to `true` would fire on ANY
        // `</check-content>` close, even one reached while `capture` is `None`.
        // A (deliberately malformed / not real-DISA-shaped) NESTED check-content
        // forces exactly that: the INNER close legitimately captures the real
        // check text and resets `capture` to `None`; under the real guard the
        // OUTER close is then correctly a no-op (capture isn't `CheckContent`
        // anymore) and `cur_check_content` keeps the inner value. Under the
        // mutant, the outer close fires anyway and overwrites `cur_check_content`
        // with `text_buf.trim()` of the (now-empty, already-taken) buffer,
        // silently dropping the Group (the empty content matches no `sysctl
        // <key>` command) instead of keeping the correctly-extracted row.
        let doc = r#"<Benchmark><Group id="V-12"><Rule><version>RHEL-09-999012</version>
            <check><check-content>PREFIX <check-content>$ sudo sysctl kernel.dmesg_restrict
kernel.dmesg_restrict = 1
If not "1", this is a finding.</check-content></check-content></check></Rule></Group></Benchmark>"#;
        let d = parse_baseline(doc).expect("parses");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].key, "kernel.dmesg_restrict");
        assert_eq!(d[0].accepted, ["1"]);
        assert_eq!(d[0].stig_id, "RHEL-09-999012");
    }
}
