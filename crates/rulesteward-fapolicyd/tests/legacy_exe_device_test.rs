//! RED barrier tests for the legacy-grammar `exe_device=` false-fapd-F01
//! reject on rhel8, and its rhel9/rhel10 version-divergence follow-up
//! (issue #570, lane-6, sequenced after #568).
//!
//! Ground truth (fresh `WebFetch` of upstream `src/library/subject-attr.c` at
//! the pinned `v1.3.2` / `v1.4.5` tags, 2026-07-23 - matches the issue's cited
//! evidence exactly):
//!   * v1.3.2 table1 (LEGACY/ORIG-format subject table): all, auid, uid,
//!     sessionid, pid, pattern, comm, exe, `exe_dir`, `exe_type`, `exe_device` -
//!     `exe_device` IS present.
//!   * v1.4.5 table1: all, auid, uid, sessionid, pid, pattern, comm, exe,
//!     `exe_dir`, `exe_type` - `exe_device` is ABSENT (dropped between 1.3.2 and
//!     1.4.5).
//!   * Neither version's table2 (MODERN/colon format) lists `exe_device` at
//!     all (table2 uses `device` instead) - the modern dialect is completely
//!     unaffected by this issue; `allow exe_device=/dev/sda : all` stays
//!     rejected by `attrs::is_known` on every target, exactly as today.
//!
//! Live differential cited in #570: legacy `allow exe_device=/dev/sda
//! path=/usr/bin/sh` loads clean on fapolicyd 1.3.2 (fapolicyd8) but is
//! rejected "Field type (`exe_device`) is unknown" on 1.4.5 (fapolicyd9).
//!
//! Unlike `exe_dir`/`exe_type` (legacy subject-only, but version-INVARIANT -
//! valid on BOTH 1.3.2 and 1.4.5, fixed in 9e-wave2c/#546 via
//! `LEGACY_ONLY_SUBJECT_ATTRS` alone), `exe_device` is version-DIVERGENT
//! (1.3.2-only), so it needs BOTH the parser-level legacy-subject-anchor fix
//! (mirroring `exe_dir`/`exe_type`) AND a new fapd-E06 version-divergence arm
//! mirroring `version_target.rs::check_subject_device` (valid on rhel8,
//! flagged on rhel9/rhel10).
//!
//! `--target` None-convention: `exe_device`'s rhel8-only validity is
//! genuinely version-DIVERGENT (unlike #568's subject-side `filehash=`,
//! which is version-INVARIANT once it exists at all) - so it follows the
//! established fapd-E06 None-closed default (mirroring
//! `check_subject_device`'s own `check2_none_accepts_subject_side_device_clean`
//! pin in `version_target.rs`), staying CLEAN under no `--target`.
//!
//! Today: `parser::grammar::legacy_classify("exe_device")` returns `None`
//! (not in `LEGACY_ONLY_SUBJECT_ATTRS`), so the legacy parse (via
//! `positional_split`, #546) fails too. `parser::mod::parse_line` tries
//! `modern_rule()` first; on a DUAL failure (both modern and legacy fail) it
//! surfaces MODERN's diagnostic, not legacy's "unknown or legacy-illegal
//! attribute" message from `positional_split` - so the observed fapd-F01 is
//! the MODERN "malformed rule syntax: found end of input expected any, ' ',
//! '\t', or colon separator" message (see `parser::mod::parse_line`'s "Both
//! failed - return modern's diagnostics" branch), a false positive under
//! EVERY target (including rhel8, where the real daemon accepts it). Every
//! test below that expects a successful parse is RED today (panics in the
//! `unwrap_or_else` parse step itself).

use std::path::Path;

use rulesteward_fapolicyd::{
    Attr, Entry, LintContext, SyntaxFlavor, TargetVersion, lint, lint_with_context,
    parse_rules_file,
};

const LEGACY_EXE_DEVICE_SRC: &str = "allow exe_device=/dev/sda path=/usr/bin/sh\n";

/// (a) Parse-level pin, mirroring `legacy_exe_dir_parses_with_exe_dir_on_subject_side`
/// in `test_legacy_exe_dir_type.rs`: a legacy `exe_device=` rule must parse
/// successfully, with the attribute correctly classified subject-side and the
/// rule tagged `SyntaxFlavor::Legacy`.
#[test]
fn legacy_exe_device_parses_with_exe_device_on_subject_side() {
    let file = Path::new("legacy-exe-device.rules");
    let entries = parse_rules_file(LEGACY_EXE_DEVICE_SRC, file).unwrap_or_else(|d| {
        panic!(
            "daemon-1.3.2-valid legacy rule `{LEGACY_EXE_DEVICE_SRC}` must parse \
             (live-verified in #570: loads clean on fapolicyd 1.3.2); got \
             diagnostics: {d:?}"
        )
    });
    assert_eq!(entries.len(), 1, "expected exactly one entry");
    let Entry::Rule(r) = &entries[0] else {
        panic!("expected an Entry::Rule, got {:?}", entries[0]);
    };
    assert_eq!(r.syntax, SyntaxFlavor::Legacy);
    assert_eq!(
        r.subject.len(),
        1,
        "exe_device must land in the subject list; got {:?}",
        r.subject
    );
    assert!(
        matches!(&r.subject[0], Attr::Kv { key, .. } if key == "exe_device"),
        "subject[0] must be exe_device; got {:?}",
        r.subject[0]
    );
    assert_eq!(r.object.len(), 1);
    assert!(matches!(&r.object[0], Attr::Kv { key, .. } if key == "path"));
}

/// (b) Full default-context lint (no `--target`, `lint()`) must emit neither
/// fapd-F01 (the parse-level false-Fatal) nor fapd-E01 (`attrs::is_known`
/// doesn't know `exe_device` at all - only `LEGACY_ONLY_SUBJECT_ATTRS` +
/// `Rule.syntax == Legacy` makes `walker::e01` skip it), nor fapd-E06 (no
/// `--target` follows the established E06 None-closed convention - see the
/// module doc). RED for two independent reasons today: the parse itself
/// fails (fapd-F01 pre-empts everything), and even a parser-only fix would
/// still need `walker::e01` to consult the (not-yet-updated)
/// `LEGACY_ONLY_SUBJECT_ATTRS`.
#[test]
fn legacy_exe_device_full_lint_clean_under_no_target() {
    let file = Path::new("legacy-exe-device.rules");
    let entries = parse_rules_file(LEGACY_EXE_DEVICE_SRC, file)
        .unwrap_or_else(|d| panic!("must parse cleanly (see the parse-level test above): {d:?}"));
    let diags = lint(&entries, LEGACY_EXE_DEVICE_SRC, file);
    assert!(
        diags.is_empty(),
        "a daemon-1.3.2-valid legacy exe_device= rule must be fully CLEAN under \
         no --target (fapd-E06's established None-closed convention, matching \
         check_subject_device's own None pin); got {diags:?}"
    );
}

/// (c) rhel8: `exe_device=` is valid on 1.3.2 (the version rhel8 targets) ->
/// CLEAN (no fapd-F01, fapd-E01, or fapd-E06). This is the direct fix for
/// #570's false-F01-reject on rhel8.
#[test]
fn legacy_exe_device_rhel8_clean_via_full_lint() {
    let file = Path::new("legacy-exe-device.rules");
    let entries = parse_rules_file(LEGACY_EXE_DEVICE_SRC, file)
        .unwrap_or_else(|d| panic!("must parse cleanly (see the parse-level test above): {d:?}"));
    let ctx = LintContext {
        target: Some(TargetVersion::Rhel8),
        ..Default::default()
    };
    let diags = lint_with_context(&entries, LEGACY_EXE_DEVICE_SRC, file, &ctx);
    assert!(
        diags.is_empty(),
        "exe_device= is valid on 1.3.2 (rhel8): the legacy rule must be fully \
         CLEAN under --target rhel8 (live-verified in #570: 'Loaded' clean on \
         fapolicyd8); got {diags:?}"
    );
}

/// (d) rhel9/rhel10: `exe_device=` was dropped from the legacy subject table
/// in 1.4.5, so it must fire fapd-E06 there, mirroring
/// `check_subject_device`'s rhel9/rhel10 arm. No fapd-F01/fapd-E01 alongside
/// it (the rule still parses and is a legal LEGACY-subject placement; only
/// its VERSION validity is what's wrong, which is fapd-E06's exclusive
/// territory).
#[test]
fn legacy_exe_device_rhel9_and_rhel10_fire_e06() {
    let file = Path::new("legacy-exe-device.rules");
    let entries = parse_rules_file(LEGACY_EXE_DEVICE_SRC, file)
        .unwrap_or_else(|d| panic!("must parse cleanly (see the parse-level test above): {d:?}"));
    for (t, ver) in [
        (TargetVersion::Rhel9, "1.4.5"),
        (TargetVersion::Rhel10, "1.4.5"),
    ] {
        let ctx = LintContext {
            target: Some(t),
            ..Default::default()
        };
        let diags = lint_with_context(&entries, LEGACY_EXE_DEVICE_SRC, file, &ctx);
        assert!(
            !diags.iter().any(|d| d.code.as_ref() == "fapd-F01"),
            "exe_device= must not be Fatal-rejected under --target {t} (it is a \
             legal LEGACY subject-side token, just version-divergent); got {diags:?}"
        );
        assert!(
            !diags.iter().any(|d| d.code.as_ref() == "fapd-E01"),
            "exe_device= is a recognized LEGACY subject attr (via \
             LEGACY_ONLY_SUBJECT_ATTRS) and must not be flagged unknown by \
             fapd-E01 under --target {t}; got {diags:?}"
        );
        let e06 = diags
            .iter()
            .find(|d| d.code.as_ref() == "fapd-E06")
            .unwrap_or_else(|| {
                panic!(
                    "exe_device= was dropped from the legacy subject table in 1.4.5, \
                     so it must fire fapd-E06 under --target {t} (mirroring \
                     check_subject_device); got {diags:?}"
                )
            });
        assert!(
            e06.message.contains("exe_device"),
            "fapd-E06 message must name the offending construct `exe_device`: {}",
            e06.message,
        );
        assert!(
            e06.message.contains(ver),
            "fapd-E06 message must name the fapolicyd version ({ver}): {}",
            e06.message,
        );
        assert!(
            e06.message.contains(&t.to_string()),
            "fapd-E06 message must name the rhel target ({t}): {}",
            e06.message,
        );
    }
}

/// (e) Negative control: the legacy leniency for `exe_device` extends ONLY to
/// that name - a genuinely unknown attribute (not in the modern table, the
/// legacy table, or `LEGACY_ONLY_SUBJECT_ATTRS`) must still be rejected as a
/// legacy-illegal token, exactly as today. Must PASS both before and after
/// the fix (pins the fix isn't a blanket "anything goes" fallback).
#[test]
fn legacy_rule_with_genuinely_unknown_attr_still_errors_exe_device_lane() {
    let file = Path::new("legacy-bogus.rules");
    let src = "allow bogus_exe_thing=1 trust=1\n";
    let result = parse_rules_file(src, file);
    assert!(
        result.is_err(),
        "`bogus_exe_thing` is unknown to every attribute table (modern, legacy, \
         and LEGACY_ONLY_SUBJECT_ATTRS) and must still be rejected; got {result:?}"
    );
}

/// (f) Negative control: the MODERN (colon) grammar is unaffected - neither
/// version's table2 lists `exe_device`, so `allow exe_device=/dev/sda : all`
/// stays rejected by `attrs::is_known` on every target, exactly as today.
#[test]
fn modern_exe_device_stays_unknown_on_every_target() {
    let file = Path::new("modern-exe-device.rules");
    let src = "allow perm=any exe_device=/dev/sda : all\n";
    let entries =
        parse_rules_file(src, file).unwrap_or_else(|d| panic!("must parse cleanly: {d:?}"));
    for target in [
        None,
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
    ] {
        let ctx = LintContext {
            target,
            ..Default::default()
        };
        let diags = lint_with_context(&entries, src, file, &ctx);
        assert!(
            diags.iter().any(|d| d.code.as_ref() == "fapd-E01"),
            "modern exe_device= is unknown to BOTH versions' table2 and must \
             stay fapd-E01 'unknown attribute' under --target {target:?}; \
             got {diags:?}"
        );
        assert!(
            !diags.iter().any(|d| d.code.as_ref() == "fapd-E06"),
            "modern exe_device= is uniformly unknown across all fapolicyd \
             versions (RULE_FMT_COLON table2 lacks it on both 1.3.2 and \
             1.4.5, confirmed via WebFetch of upstream subject-attr.c at \
             both tags) - it is fapd-E01's territory, not a version \
             divergence, so fapd-E06 must NOT also fire under --target \
             {target:?}; got {diags:?}"
        );
    }
}
