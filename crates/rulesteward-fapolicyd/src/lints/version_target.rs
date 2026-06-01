//! Version-aware lint pass: fapolicyd checks whose verdict diverges by target
//! release (fapd-W07 hash-keyword advice, `device=` subject-side validity,
//! `pattern=` value set, hash-value length).
//!
//! Phase-0 stub: the version-target impl pipeline fills the per-check logic. The
//! signature is frozen here so the fan-out edits only this file's body, not the
//! shared `lints/mod.rs` dispatcher.

use std::path::Path;

use rulesteward_core::Diagnostic;

use crate::ast::Entry;
use crate::version::TargetVersion;

/// Run the version-divergent checks for `target`. Returns no diagnostics when
/// `target` is `None` (the implicit 1.4.x dialect, i.e. no `--target`) so a
/// default lint reproduces today's behavior exactly.
#[must_use]
pub(crate) fn walk(
    _entries: &[Entry],
    _file: &Path,
    _target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    //! Version-target RED barrier tests.
    //!
    //! Every divergent check is driven through the public `lint_with_context`
    //! seam (NOT the private `walk`), because the activation decision ("fire
    //! only when `ctx.target.is_some()`") is a property of the whole pipeline:
    //! the implementer may suppress W07 inside `deprecation::walk` and emit the
    //! E06s inside `version_target::walk`, and these tests must hold regardless
    //! of where the logic lands. Mirrors
    //! `earlier_macros_context_suppresses_e03_vs_default` in `lints/mod.rs`.
    //!
    //! Grounding (all empirically verified on the img8/img9/img10 containers,
    //! A3 wave-2 matrix):
    //!   * `filehash=` REJECTED on 1.3.2 (rhel8), accepted 1.4.x (rhel9/10).
    //!   * `sha256hash=` accepted on all; deprecation NOTICE only on 1.4.x.
    //!   * `device=` valid on the SUBJECT side on 1.3.2, REJECTED on 1.4.x.
    //!   * `pattern=` value set: rhel8 = {`ld_so`, `ld_preload`, `static`};
    //!     rhel9/10 = {`normal`, `ld_so`, `ld_preload`, `static`}.
    //!     `pattern=ld_preload` LOADS on 1.3.2 (re-confirmed in this session
    //!     via `docker run fapolicyd8 ... fagenrules --load`: "Loaded 15 rules",
    //!     the rule appears in the loaded set), so it stays in the rhel8 set.
    //!
    //! RED expectation: the current `walk` returns `Vec::new()` unconditionally
    //! and `deprecation::w07` is version-agnostic, so every "E06 fires" test and
    //! the "Rhel8 suppresses W07" test FAIL; the None-context and clean-value
    //! tests pass (current behavior).

    use std::path::Path;

    use rulesteward_core::{Diagnostic, Severity};

    use crate::ast::{Attr, AttrValue, Decision, Perm};
    use crate::lints::LintContext;
    use crate::lints::testkit::modern_rule;
    use crate::version::TargetVersion;

    /// 64-char canonical lowercase hex (a syntactically valid SHA256 digest), so
    /// the only variable under test is the hash ATTRIBUTE NAME, not its value
    /// shape (fapd-E02's concern). Using a valid digest keeps fapd-E02/W11 silent
    /// so the only diagnostics observed are the version-divergent ones.
    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Build a `LintContext` whose only non-default field is the version target.
    fn ctx_for(target: Option<TargetVersion>) -> LintContext<'static> {
        LintContext {
            target,
            ..Default::default()
        }
    }

    /// Lint a single rule through the public context seam against `target`.
    /// `line` flows into the rule so the line-correctness assertions are real
    /// (a hardcoded `line = 1` impl is caught by the non-1-line cases).
    fn run(
        line: usize,
        subj: Vec<Attr>,
        obj: Vec<Attr>,
        target: Option<TargetVersion>,
    ) -> Vec<Diagnostic> {
        let entries = vec![modern_rule(
            line,
            Decision::Allow,
            Some(Perm::Any),
            subj,
            obj,
        )];
        // `source`/`file` are immaterial to the version checks; supply a minimal
        // non-empty source so column backfill (`fill_columns`) does not panic.
        let path = Path::new("rules.d/50-vt.rules");
        let source = "allow perm=any : all\n";
        crate::lints::lint_with_context(&entries, source, path, &ctx_for(target))
    }

    /// `key=value` string attribute (local clone of the testkit helper so this
    /// module needs only `modern_rule` from testkit).
    fn kv(key: &str, value: &str) -> Attr {
        Attr::Kv {
            key: key.to_string(),
            value: AttrValue::Str(value.to_string()),
            span: 0..0,
        }
    }

    fn codes(diags: &[Diagnostic]) -> Vec<&str> {
        diags.iter().map(|d| d.code.as_ref()).collect()
    }

    fn count(diags: &[Diagnostic], code: &str) -> usize {
        diags.iter().filter(|d| d.code.as_ref() == code).count()
    }

    // ===================================================================
    // CHECK 1 - hash attribute version-divergence (sha256hash / filehash)
    // ===================================================================

    #[test]
    fn check1_rhel8_suppresses_w07_on_sha256hash() {
        // On fapolicyd 1.3.2 (rhel8) `sha256hash=` is the correct,
        // NON-deprecated spelling (filehash= does not exist there), so fapd-W07
        // must NOT fire. RED: deprecation::w07 is version-agnostic and still
        // fires under any target.
        let diags = run(
            3,
            vec![],
            vec![kv("sha256hash", HEX64)],
            Some(TargetVersion::Rhel8),
        );
        assert!(
            !diags.iter().any(|d| d.code.as_ref() == "fapd-W07"),
            "under --target rhel8, sha256hash= is canonical: fapd-W07 must be suppressed, \
             got codes={:?} diags={diags:?}",
            codes(&diags),
        );
    }

    #[test]
    fn check1_rhel9_and_rhel10_still_fire_w07_on_sha256hash() {
        // Regression guard (GREEN now): under rhel9/rhel10 the 1.4.x deprecation
        // NOTICE applies, so fapd-W07 still fires on sha256hash=, exactly as
        // under None. This proves the rhel8 suppression is a NARROW gate, not a
        // blanket "any target suppresses W07".
        for t in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            let diags = run(2, vec![], vec![kv("sha256hash", HEX64)], Some(t));
            assert!(
                diags.iter().any(|d| d.code.as_ref() == "fapd-W07"),
                "under --target {t}, sha256hash= is still deprecated (1.4.x): fapd-W07 \
                 must fire, got codes={:?}",
                codes(&diags),
            );
        }
    }

    #[test]
    fn check1_none_still_fires_w07_on_sha256hash() {
        // Regression guard (GREEN now): with no --target the behavior is exactly
        // today's - sha256hash= -> fapd-W07. Same assertion the existing W07
        // tests make (they call plain lint(), i.e. None context).
        let diags = run(1, vec![], vec![kv("sha256hash", HEX64)], None);
        assert!(
            diags.iter().any(|d| d.code.as_ref() == "fapd-W07"),
            "with no target, sha256hash= must still fire fapd-W07 (unchanged), got codes={:?}",
            codes(&diags),
        );
    }

    #[test]
    fn check1_rhel8_rejects_filehash_with_e06() {
        // On 1.3.2 (rhel8) `filehash=` does not exist -> fapd-E06 Error. The
        // message must name the offending construct (`filehash`), the fapolicyd
        // version (1.3.2), and the rhel target (rhel8). Line is 4 (not 1) so a
        // hardcoded-line impl is caught.
        let diags = run(
            4,
            vec![],
            vec![kv("filehash", HEX64)],
            Some(TargetVersion::Rhel8),
        );
        let e06 = diags
            .iter()
            .find(|d| d.code.as_ref() == "fapd-E06")
            .unwrap_or_else(|| {
                panic!(
                    "under --target rhel8, filehash= must fire fapd-E06; got codes={:?} diags={diags:?}",
                    codes(&diags),
                )
            });
        assert_eq!(
            e06.severity,
            Severity::Error,
            "fapd-E06 must be Severity::Error, got {:?}",
            e06.severity,
        );
        assert_eq!(
            e06.line, 4,
            "fapd-E06 must carry the offending rule's line (4), not a hardcoded 1; got {}",
            e06.line,
        );
        assert!(
            e06.message.contains("filehash"),
            "fapd-E06 message must name the offending construct `filehash`: {}",
            e06.message,
        );
        assert!(
            e06.message.contains("1.3.2"),
            "fapd-E06 message must name the fapolicyd version (1.3.2): {}",
            e06.message,
        );
        assert!(
            e06.message.contains("rhel8"),
            "fapd-E06 message must name the rhel target (rhel8): {}",
            e06.message,
        );
    }

    #[test]
    fn check1_rhel9_rhel10_none_accept_filehash_clean() {
        // Non-vacuity / cross-target: the SAME filehash= input that fires E06
        // under rhel8 is CLEAN under rhel9/rhel10/None (filehash= is the modern
        // canonical spelling there - no E06, and no W07 since filehash is not
        // deprecated). Proves the rhel8 E06 gate is real, not "returns empty".
        for t in [
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
            None,
        ] {
            let diags = run(1, vec![], vec![kv("filehash", HEX64)], t);
            assert!(
                diags.is_empty(),
                "filehash=<64hex> must be CLEAN under target {t:?} (no E06, no W07); got {diags:?}",
            );
        }
    }

    // ===================================================================
    // CHECK 2 - device= subject-side version-divergence
    // ===================================================================

    #[test]
    fn check2_rhel9_rhel10_reject_subject_side_device_with_e06() {
        // `device=` on the SUBJECT side is object-only on 1.4.x (rhel9/rhel10)
        // -> fapd-E06. Message names `device`, the version, and the target.
        for (t, ver) in [
            (TargetVersion::Rhel9, "1.4.3"),
            (TargetVersion::Rhel10, "1.4.5"),
        ] {
            let diags = run(6, vec![kv("device", "/dev/sda")], vec![Attr::All], Some(t));
            let e06 = diags
                .iter()
                .find(|d| d.code.as_ref() == "fapd-E06")
                .unwrap_or_else(|| {
                    panic!(
                        "under --target {t}, subject-side device= must fire fapd-E06; \
                         got codes={:?} diags={diags:?}",
                        codes(&diags),
                    )
                });
            assert_eq!(e06.severity, Severity::Error);
            assert_eq!(
                e06.line, 6,
                "fapd-E06 must carry the rule line (6), not a hardcoded 1; got {}",
                e06.line,
            );
            assert!(
                e06.message.contains("device"),
                "fapd-E06 message must name `device`: {}",
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

    #[test]
    fn check2_rhel8_accepts_subject_side_device_clean() {
        // `device=` on the subject side is VALID on 1.3.2 (rhel8) -> CLEAN.
        // Cross-target non-vacuity for the rhel9/rhel10 E06 above.
        let diags = run(
            1,
            vec![kv("device", "/dev/sda")],
            vec![Attr::All],
            Some(TargetVersion::Rhel8),
        );
        assert!(
            diags.is_empty(),
            "subject-side device= is valid on rhel8 (1.3.2): must be CLEAN; got {diags:?}",
        );
    }

    #[test]
    fn check2_none_accepts_subject_side_device_clean() {
        // No --target: unchanged behavior. There is NO subject-side device check
        // today (verified), so this is CLEAN and stays CLEAN. Regression guard.
        let diags = run(1, vec![kv("device", "/dev/sda")], vec![Attr::All], None);
        assert!(
            diags.is_empty(),
            "with no target, subject-side device= must be CLEAN (no such check today); got {diags:?}",
        );
    }

    #[test]
    fn check2_object_side_device_clean_on_all_targets() {
        // `device=` on the OBJECT side is normal usage on every version -> CLEAN
        // on rhel8/rhel9/rhel10/None. This is the critical non-vacuity case: a
        // wrong impl that fires E06 on ANY device= (ignoring the side) dies here.
        for t in [
            Some(TargetVersion::Rhel8),
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
            None,
        ] {
            let diags = run(1, vec![], vec![kv("device", "/dev/sda")], t);
            assert!(
                diags.is_empty(),
                "object-side device= is normal usage on target {t:?}: must be CLEAN; got {diags:?}",
            );
        }
    }

    // ===================================================================
    // CHECK 3 - pattern= value, FULL 4-value enum
    //   rhel8       = {ld_so, ld_preload, static}
    //   rhel9/rhel10 = {normal, ld_so, ld_preload, static}
    // pattern is a SUBJECT attr: `allow perm=any pattern=X : all`.
    // ===================================================================

    #[test]
    fn check3_pattern_normal_e06_on_rhel8_clean_on_rhel9_rhel10() {
        // `pattern=normal` is NOT accepted on 1.3.2 (rhel8) -> fapd-E06, but IS
        // accepted on 1.4.x (rhel9/rhel10) -> CLEAN. The same input diverging by
        // target is the cross-target non-vacuity proof for this value.
        let diags8 = run(
            7,
            vec![kv("pattern", "normal")],
            vec![Attr::All],
            Some(TargetVersion::Rhel8),
        );
        let e06 = diags8
            .iter()
            .find(|d| d.code.as_ref() == "fapd-E06")
            .unwrap_or_else(|| {
                panic!(
                    "pattern=normal must fire fapd-E06 on rhel8 (not in {{ld_so,ld_preload,static}}); \
                     got codes={:?} diags={diags8:?}",
                    codes(&diags8),
                )
            });
        assert_eq!(e06.severity, Severity::Error);
        assert_eq!(
            e06.line, 7,
            "fapd-E06 must carry the rule line (7), not a hardcoded 1; got {}",
            e06.line,
        );
        assert!(
            e06.message.contains("normal"),
            "fapd-E06 message must name the offending pattern value `normal`: {}",
            e06.message,
        );
        assert!(
            e06.message.contains("1.3.2") && e06.message.contains("rhel8"),
            "fapd-E06 message must name the fapolicyd version + rhel target: {}",
            e06.message,
        );

        for t in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            let diags = run(1, vec![kv("pattern", "normal")], vec![Attr::All], Some(t));
            assert!(
                diags.is_empty(),
                "pattern=normal is accepted on {t} (1.4.x): must be CLEAN; got {diags:?}",
            );
        }
    }

    #[test]
    fn check3_pattern_bogus_e06_on_all_targets() {
        // `pattern=bogusxyz` is in NO accepted set -> fapd-E06 on rhel8, rhel9,
        // AND rhel10. Exactly one E06 per target (per-attribute, one offender).
        for t in [
            TargetVersion::Rhel8,
            TargetVersion::Rhel9,
            TargetVersion::Rhel10,
        ] {
            let diags = run(5, vec![kv("pattern", "bogusxyz")], vec![Attr::All], Some(t));
            assert_eq!(
                count(&diags, "fapd-E06"),
                1,
                "pattern=bogusxyz must fire exactly one fapd-E06 on {t}; got codes={:?}",
                codes(&diags),
            );
            let e06 = diags
                .iter()
                .find(|d| d.code.as_ref() == "fapd-E06")
                .expect("checked count above");
            assert_eq!(e06.severity, Severity::Error);
            assert!(
                e06.message.contains("bogusxyz"),
                "fapd-E06 message must name the offending value `bogusxyz`: {}",
                e06.message,
            );
        }
    }

    #[test]
    fn check3_accepted_pattern_values_clean_on_all_targets() {
        // The three values in EVERY accepted set - ld_so, ld_preload, static -
        // are CLEAN on rhel8, rhel9, rhel10. (ld_preload-on-1.3.2 was empirically
        // re-confirmed this session: "Loaded 15 rules".) Non-vacuity guard: a
        // wrong impl that rejects everything dies here.
        for value in ["ld_so", "ld_preload", "static"] {
            for t in [
                TargetVersion::Rhel8,
                TargetVersion::Rhel9,
                TargetVersion::Rhel10,
            ] {
                let diags = run(1, vec![kv("pattern", value)], vec![Attr::All], Some(t));
                assert!(
                    diags.is_empty(),
                    "pattern={value} is in the accepted set for {t}: must be CLEAN; got {diags:?}",
                );
            }
        }
    }

    #[test]
    fn check3_none_does_no_pattern_validation() {
        // With no --target there is NO pattern validation (unchanged). Both an
        // accepted value AND a bogus value are CLEAN under None - a regression
        // guard proving the pattern gate is target-driven, not always-on.
        for value in ["normal", "bogusxyz"] {
            let diags = run(1, vec![kv("pattern", value)], vec![Attr::All], None);
            assert!(
                diags.is_empty(),
                "with no target, pattern={value} must be CLEAN (no validation today); got {diags:?}",
            );
        }
    }

    // ===================================================================
    // Activation invariant - the None context produces ZERO new diagnostics
    // ===================================================================

    #[test]
    fn none_context_emits_no_version_target_diagnostics() {
        // Belt-and-suspenders activation guard: a rule that would trip CHECK 1
        // (filehash), CHECK 2 (subject device), AND CHECK 3 (bogus pattern) all
        // at once must emit NO fapd-E06 under None (target gate closed). It still
        // emits whatever the version-agnostic passes emit (here: none, since
        // filehash/device/pattern are individually clean under None), so we
        // assert specifically on the absence of fapd-E06.
        let diags = run(
            1,
            vec![kv("device", "/dev/sda"), kv("pattern", "bogusxyz")],
            vec![kv("filehash", HEX64)],
            None,
        );
        assert_eq!(
            count(&diags, "fapd-E06"),
            0,
            "None context must emit zero fapd-E06 (version gate is closed); got codes={:?}",
            codes(&diags),
        );
    }

    #[test]
    fn rhel8_context_fires_multiple_e06_for_multiple_offenders() {
        // Under rhel8, a single rule carrying filehash= (CHECK 1 reject) AND
        // pattern=normal (CHECK 3 reject) fires TWO fapd-E06 - one per offending
        // construct - and ZERO fapd-W07 (sha256hash is not present; filehash is
        // the E06 case). Kills a mutant that emits at most one E06 per rule.
        let diags = run(
            9,
            vec![kv("pattern", "normal")],
            vec![kv("filehash", HEX64)],
            Some(TargetVersion::Rhel8),
        );
        assert_eq!(
            count(&diags, "fapd-E06"),
            2,
            "rhel8 rule with filehash= + pattern=normal must fire two fapd-E06 \
             (one per offender); got codes={:?} diags={diags:?}",
            codes(&diags),
        );
        assert!(
            diags.iter().all(|d| d.line == 9),
            "both fapd-E06 must carry the rule line (9); got {diags:?}",
        );
    }
}
