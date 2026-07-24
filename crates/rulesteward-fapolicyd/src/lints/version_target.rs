//! Version-aware lint pass: fapolicyd checks whose verdict diverges by target
//! release (fapd-W07 hash-keyword advice, `device=` subject-side validity,
//! `filehash=` subject-side validity, `exe_device=` legacy-subject validity,
//! `pattern=` value set, hash-value length).
//!
//! Runs only when a `--target` release is supplied (see `LintContext.target`);
//! each per-check helper emits fapd-E06 when the rule uses a construct invalid
//! for that release.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use super::anchored;
use crate::ast::{Attr, AttrValue, Entry, Rule, SyntaxFlavor};
use crate::version::TargetVersion;

/// `pattern=` values accepted by fapolicyd on the rhel8 dialect (1.3.2). The
/// `normal` value was introduced later, so it is absent here. Empirically
/// confirmed on the img8 container (A3 wave-2 matrix).
const RHEL8_PATTERN_VALUES: &[&str] = &["ld_so", "ld_preload", "static"];

/// `pattern=` values accepted by fapolicyd on the rhel9/rhel10 dialect (1.4.x).
/// The 1.4.x line adds `normal` to the rhel8 set.
const RHEL9_PLUS_PATTERN_VALUES: &[&str] = &["normal", "ld_so", "ld_preload", "static"];

/// The accepted `pattern=` value set for `target`.
///
/// `pub` (module `pub` since #478) so `tools/fapolicyd-probe-update` can diff a live
/// daemon probe against this shipped table without duplicating it - the same
/// consumer-driven visibility rulesteward-sshd already uses for
/// `lints::registry::known_keywords` / `lints::deprecation::deprecated_keywords`.
/// Pure visibility change; the values and logic are unchanged.
#[must_use]
pub fn accepted_pattern_values(target: TargetVersion) -> &'static [&'static str] {
    match target {
        TargetVersion::Rhel8 => RHEL8_PATTERN_VALUES,
        TargetVersion::Rhel9 | TargetVersion::Rhel10 => RHEL9_PLUS_PATTERN_VALUES,
    }
}

/// Run the version-divergent checks for `target`. Returns no diagnostics when
/// `target` is `None` (the implicit 1.4.x dialect, i.e. no `--target`) so a
/// default lint reproduces today's behavior exactly.
#[must_use]
pub(crate) fn walk(
    entries: &[Entry],
    file: &Path,
    target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    // The whole pass is gated on an explicit `--target`; the implicit 1.4.x
    // dialect (`None`) emits nothing, preserving today's behavior byte-for-byte.
    let Some(target) = target else {
        return Vec::new();
    };
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::Rule(rule) = entry else { continue };
        check_filehash(rule, file, target, &mut diags);
        check_subject_device(rule, file, target, &mut diags);
        check_subject_exe_device(rule, file, target, &mut diags);
        check_pattern(rule, file, target, &mut diags);
    }
    diags
}

/// Emit a fapd-E06 anchored to `rule`, naming the offending construct, the
/// concrete fapolicyd version, and the rhel target so the operator can see all
/// three facts in one line.
fn e06(rule: &Rule, file: &Path, target: TargetVersion, what: &str) -> Diagnostic {
    let message = format!(
        "{what} is not valid on the selected --target {target} (fapolicyd {})",
        target.fapolicyd_version(),
    );
    anchored(
        Severity::Error,
        "fapd-E06",
        rule.span.clone(),
        message,
        file,
        rule.line,
    )
}

/// CHECK 1 / CHECK 1B - `filehash=` validity by target and side.
///
/// CHECK 1 (rhel8/1.3.2): the whole attribute does not exist on 1.3.2 (the
/// canonical 1.3.2 spelling is `sha256hash=`), so it is rejected on EITHER
/// side there.
///
/// CHECK 1B (rhel9/rhel10, issue #568): on 1.4.x `filehash=` exists but is
/// object-only, mirroring `device=`'s CHECK 2 object/subject split - a
/// subject-side `filehash=` is rejected, object-side stays canonical/clean.
/// Per the barrier-rework ruling this check is None-closed (like CHECK 2):
/// `walk` never calls this for `target == None`, so there is nothing further
/// to gate here.
fn check_filehash(rule: &Rule, file: &Path, target: TargetVersion, diags: &mut Vec<Diagnostic>) {
    match target {
        TargetVersion::Rhel8 => {
            // Name the offending side so the operator can locate it in a
            // multi-attribute rule (`filehash` is normally an object attr,
            // but is rejected on either side on 1.3.2, since it does not
            // exist there at all).
            for (side, attrs) in [
                ("subject-side", &rule.subject),
                ("object-side", &rule.object),
            ] {
                for attr in attrs {
                    if let Attr::Kv { key, .. } = attr
                        && key == "filehash"
                    {
                        diags.push(e06(
                            rule,
                            file,
                            target,
                            &format!("{side} attribute `filehash=` (use `sha256hash=` instead)"),
                        ));
                    }
                }
            }
        }
        TargetVersion::Rhel9 | TargetVersion::Rhel10 => {
            // filehash= exists and is canonical on the object side on 1.4.x;
            // only the subject side is invalid there (#568).
            for attr in &rule.subject {
                if let Attr::Kv { key, .. } = attr
                    && key == "filehash"
                {
                    diags.push(e06(
                        rule,
                        file,
                        target,
                        "subject-side attribute `filehash=` (object-only)",
                    ));
                }
            }
        }
    }
}

/// CHECK 2 - `device=` is object-only on fapolicyd 1.4.x (rhel9/rhel10); a
/// subject-side `device=` is rejected there. It is valid on the subject side on
/// 1.3.2 (rhel8), so this fires ONLY under rhel9/rhel10. Object-side `device=` is
/// normal usage everywhere and is left untouched.
fn check_subject_device(
    rule: &Rule,
    file: &Path,
    target: TargetVersion,
    diags: &mut Vec<Diagnostic>,
) {
    if target < TargetVersion::Rhel9 {
        return;
    }
    for attr in &rule.subject {
        if let Attr::Kv { key, .. } = attr
            && key == "device"
        {
            diags.push(e06(
                rule,
                file,
                target,
                "subject-side attribute `device=` (object-only)",
            ));
        }
    }
}

/// CHECK 4 - `exe_device=` (legacy-grammar subject attr; issue #570) exists
/// in upstream's LEGACY subject table (`subject-attr.c` table1) on 1.3.2
/// (rhel8) but was dropped from that table by 1.4.5 (rhel9/rhel10), so a
/// subject-side `exe_device=` is rejected there. Target-gated (fires only on
/// rhel9/rhel10) and None-closed (no `--target` means no version to evaluate
/// the divergence against, matching `walk`'s overall None gate) - same shape
/// as `check_subject_device`.
///
/// UNLIKE `device` (known to BOTH grammars' attribute tables, just
/// version-divergent on the subject side - so `check_subject_device` fires
/// regardless of `Rule.syntax`), `exe_device` does not exist in EITHER
/// version's MODERN table (table2) at all; a modern-grammar rule using it
/// (`allow exe_device=... : all`) is uniformly unknown on every target and
/// is fapd-E01's territory, not a version divergence. So this check is
/// ADDITIONALLY gated on `rule.syntax == SyntaxFlavor::Legacy`: `exe_device`
/// can land in `rule.subject` purely by COLON POSITION in a modern-syntax
/// rule (the modern grammar splits subject/object positionally, not by
/// attribute-name classification - see `parser::grammar::modern_rule`), so
/// without this gate a modern-position `exe_device=` would spuriously
/// double-report alongside fapd-E01 on rhel9/rhel10. See
/// `attrs::LEGACY_ONLY_SUBJECT_ATTRS` / `parser::grammar::legacy_classify`
/// for where the legacy-only legality itself is established.
fn check_subject_exe_device(
    rule: &Rule,
    file: &Path,
    target: TargetVersion,
    diags: &mut Vec<Diagnostic>,
) {
    if rule.syntax != SyntaxFlavor::Legacy {
        return;
    }
    if target < TargetVersion::Rhel9 {
        return;
    }
    for attr in &rule.subject {
        if let Attr::Kv { key, .. } = attr
            && key == "exe_device"
        {
            diags.push(e06(
                rule,
                file,
                target,
                "subject-side attribute `exe_device=` (legacy-only, removed in 1.4.x)",
            ));
        }
    }
}

/// CHECK 3 - `pattern=` (a subject attr) whose value is not in the target
/// version's accepted set. `normal` is rejected only on rhel8; a wholly unknown
/// value (`bogusxyz`) is rejected on every target.
fn check_pattern(rule: &Rule, file: &Path, target: TargetVersion, diags: &mut Vec<Diagnostic>) {
    let accepted = accepted_pattern_values(target);
    for attr in &rule.subject {
        if let Attr::Kv {
            key,
            value: AttrValue::Str(value),
            ..
        } = attr
            && key == "pattern"
            && !accepted.contains(&value.as_str())
        {
            diags.push(e06(rule, file, target, &format!("pattern value `{value}`")));
        }
    }
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

    #[test]
    fn check1_filehash_e06_message_names_the_offending_side() {
        // Task-2 (senior-review nit): the fapd-E06 message for a rejected
        // `filehash=` must name WHICH side carried it so the operator can locate
        // it in a multi-attribute rule. subject-side and object-side messages
        // must each say their side and must differ from each other. RED: today's
        // message is the side-agnostic "attribute `filehash=` ..." for both.
        let subj = run(
            1,
            vec![kv("filehash", HEX64)],
            vec![Attr::All],
            Some(TargetVersion::Rhel8),
        );
        let subj_e06 = subj
            .iter()
            .find(|d| d.code.as_ref() == "fapd-E06")
            .expect("subject-side filehash= must fire fapd-E06 on rhel8");
        let obj = run(
            1,
            vec![],
            vec![kv("filehash", HEX64)],
            Some(TargetVersion::Rhel8),
        );
        let obj_e06 = obj
            .iter()
            .find(|d| d.code.as_ref() == "fapd-E06")
            .expect("object-side filehash= must fire fapd-E06 on rhel8");
        assert!(
            subj_e06.message.contains("subject-side"),
            "subject-side filehash= E06 must say 'subject-side', got: {}",
            subj_e06.message,
        );
        assert!(
            obj_e06.message.contains("object-side"),
            "object-side filehash= E06 must say 'object-side', got: {}",
            obj_e06.message,
        );
        assert_ne!(
            subj_e06.message, obj_e06.message,
            "subject- vs object-side filehash= E06 messages must be distinguishable",
        );
        // Both must still name the offending construct.
        assert!(subj_e06.message.contains("filehash") && obj_e06.message.contains("filehash"));
    }

    // ===================================================================
    // CHECK 2 - device= subject-side version-divergence
    // ===================================================================

    #[test]
    fn check2_rhel9_rhel10_reject_subject_side_device_with_e06() {
        // `device=` on the SUBJECT side is object-only on 1.4.x (rhel9/rhel10)
        // -> fapd-E06. Message names `device`, the version, and the target.
        for (t, ver) in [
            // RHEL 9.8 rebased fapolicyd 1.4.3 -> 1.4.5 (re-grounded 2026-06-07),
            // so rhel9 and rhel10 now both report 1.4.5.
            (TargetVersion::Rhel9, "1.4.5"),
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

    // ===================================================================
    // CHECK 1B - subject-side filehash= wrong-side gap (issue #568, lane-6)
    //
    // USER RULING (barrier rework round, 2026-07-23): option (a) NONE-CLOSED.
    // Subject-side filehash= gets EXACTLY the same shape as `device=` (CHECK
    // 2): fires fapd-E06 under an explicit --target rhel9/rhel10 (closing
    // the "uncaught on rhel9/rhel10" half of #568's gap), but stays CLEAN
    // under `None` - matching the established E06 None-convention (see
    // `check2_none_accepts_subject_side_device_clean` above: with no
    // --target, a version-conditional subject-side check does not fire,
    // because there is no version to evaluate the condition against). This
    // supersedes an earlier draft of this section that argued (via the
    // fapd-E07 `type_compat.rs`/`ALL_TARGETS` outcome-invariance precedent)
    // that filehash should fire under `None` too since it is invalid on
    // EVERY version; the user overruled that reading in favor of the
    // simpler, established device-shaped convention. The "uncaught under
    // None" half of #568 is therefore an ACCEPTED, documented residual gap
    // (consistent with how `device=`'s own None case already behaves), not
    // something this fix closes.
    //
    // Grounding for filehash's existence/side, re-derived via a fresh
    // `WebFetch` of upstream `src/library/subject-attr.c` at the pinned
    // `v1.3.2`/`v1.4.5` tags (2026-07-23): the string "filehash" does NOT
    // appear in EITHER version's subject attribute tables (table1/legacy or
    // table2/modern) - filehash is never a recognized SUBJECT attribute on
    // any supported version. This matches issue #568's own cited live
    // differential ("`allow perm=any filehash=<hex> : all` is rejected by
    // BOTH fapolicyd 1.3.2 and 1.4.5" - "Field type (filehash) is unknown" +
    // "Subject is missing", confirmed 2026-07-17) and confirms CHECK 1's
    // existing rhel8 behavior (E06 fires there today) is CORRECT, current
    // behavior - not something the #568 fix changes. rhel8 is therefore a
    // green pin (CHECK 1 already covers it for both sides), same as before.
    //
    // Contrast with `device`'s subject side (CHECK 2): `device` DOES appear
    // in v1.3.2's subject-attr.c table2 (valid on the subject side on
    // 1.3.2/rhel8) but is ABSENT from v1.4.5's subject-attr.c entirely
    // (invalid on rhel9/rhel10) - genuinely version-DIVERGENT, which is why
    // `check_subject_device` is target-gated and None-closed already.
    // filehash is version-INVARIANT (never valid on the subject side on any
    // version) but, per the ruling above, still gets the None-closed
    // treatment rather than the E07-style None-fires treatment.
    //
    // RED expectation: today CHECK 1 (`check_filehash`) only fires under
    // `target == Rhel8`, so a subject-side filehash= under an explicit
    // --target rhel9/rhel10 is uncaught by ANYTHING (E01 defers it - see
    // `SIDE_CHECK_EXCLUDED` in `walker.rs` - and CHECK 1 is rhel8-only). The
    // rhel9/rhel10 "must fire" assertions below FAIL today; the rhel8 green
    // pin, the None-clean pin (matches TODAY's silent behavior exactly - it
    // is the ACCEPTED final behavior per the ruling, not a bug), and the
    // object-side negative controls already pass and must keep passing.
    // ===================================================================

    #[test]
    fn filehash_subject_side_fires_e06_on_rhel9() {
        let diags = run(
            11,
            vec![kv("filehash", HEX64)],
            vec![Attr::All],
            Some(TargetVersion::Rhel9),
        );
        let e06 = diags
            .iter()
            .find(|d| d.code.as_ref() == "fapd-E06")
            .unwrap_or_else(|| {
                panic!(
                    "subject-side filehash= must fire fapd-E06 under --target rhel9 \
                     (filehash exists on 1.4.5 but is object-only there, per #568's \
                     live differential); got codes={:?} diags={diags:?}",
                    codes(&diags),
                )
            });
        assert_eq!(e06.severity, Severity::Error);
        assert_eq!(
            e06.line, 11,
            "fapd-E06 must carry the rule line (11), not a hardcoded 1; got {}",
            e06.line,
        );
        assert!(
            e06.message.contains("filehash"),
            "fapd-E06 message must name the offending construct `filehash`: {}",
            e06.message,
        );
    }

    #[test]
    fn filehash_subject_side_fires_e06_on_rhel10() {
        let diags = run(
            12,
            vec![kv("filehash", HEX64)],
            vec![Attr::All],
            Some(TargetVersion::Rhel10),
        );
        assert!(
            diags
                .iter()
                .any(|d| d.code.as_ref() == "fapd-E06" && d.line == 12),
            "subject-side filehash= must fire fapd-E06 (line 12) under --target \
             rhel10, mirroring the rhel9 case (rhel9/rhel10 share fapolicyd 1.4.5); \
             got {diags:?}",
        );
    }

    #[test]
    fn filehash_subject_side_stays_clean_under_none() {
        // USER RULING (barrier rework round, 2026-07-23): NONE-CLOSED.
        // Mirrors `check2_none_accepts_subject_side_device_clean` above -
        // with no `--target`, there is no version to evaluate a
        // version-conditional subject-side check against, so nothing fires.
        // This matches TODAY's actual (buggy, per #568) silent behavior
        // exactly; the ruling accepts it as the final, intended None
        // behavior rather than closing it via the fapd-E07 outcome-
        // invariance route an earlier draft of this test used. Non-vacuity:
        // this is a genuine green/negative-control pin (protect-against-
        // over-widening), not a not-yet-implemented RED case - it must stay
        // GREEN before and after the rhel9/rhel10 arms of the #568 fix land.
        let diags = run(13, vec![kv("filehash", HEX64)], vec![Attr::All], None);
        assert!(
            diags.is_empty(),
            "with no --target, subject-side filehash= must stay CLEAN \
             (None-closed, matching device's established None convention - \
             #568's 'uncaught under None' is an accepted residual, not \
             closed by this fix); got {diags:?}",
        );
    }

    #[test]
    fn filehash_subject_side_rhel8_unaffected_green_pin() {
        // Regression guard: rhel8 is NOT part of #568's gap (CHECK 1 already
        // flags filehash= on either side there, since the whole attribute
        // does not exist on 1.3.2). This must stay GREEN before and after
        // the #568 fix - included here so the CHECK-1B group is a
        // self-contained set spanning every target.
        //
        // Re-derived per the barrier rework ruling (2026-07-23): does 1.3.2
        // accept subject-side filehash=? NO - a fresh `WebFetch` of upstream
        // `src/library/subject-attr.c` at the `v1.3.2` tag confirms the
        // string "filehash" does not appear in EITHER of that file's
        // attribute tables (table1/legacy or table2/modern) - it is not a
        // recognized subject attribute on 1.3.2 at all. Since 1.3.2 does
        // NOT accept it, this pin correctly stays E06 (current behavior),
        // not clean.
        let diags = run(
            14,
            vec![kv("filehash", HEX64)],
            vec![Attr::All],
            Some(TargetVersion::Rhel8),
        );
        assert!(
            diags.iter().any(|d| d.code.as_ref() == "fapd-E06"),
            "subject-side filehash= must still fire fapd-E06 on rhel8 (CHECK 1, \
             unaffected by the #568 fix); got {diags:?}",
        );
    }

    #[test]
    fn filehash_object_side_stays_clean_on_rhel9_rhel10_none() {
        // Negative control / protect-against-over-widening (brief's "green
        // pins... protect against over-widening"): filehash's CORRECT,
        // canonical placement is the object side on 1.4.x. The #568 fix must
        // not turn into a blanket "filehash always fires" - object-side
        // filehash= stays completely clean on rhel9/rhel10/None. Duplicates
        // (deliberately, as an explicit CHECK-1B-scoped pin)
        // `check1_rhel9_rhel10_none_accept_filehash_clean`'s assertion.
        for t in [
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
            None,
        ] {
            let diags = run(1, vec![], vec![kv("filehash", HEX64)], t);
            assert!(
                diags.is_empty(),
                "object-side filehash= is canonical usage on target {t:?} and must \
                 stay CLEAN after the #568 fix; got {diags:?}",
            );
        }
    }

    #[test]
    fn filehash_subject_side_fix_does_not_disturb_subject_side_device() {
        // Protect-against-over-widening (brief): a rule combining subject-
        // side `device=` (CHECK 2, version-divergent, valid on rhel8, E06 on
        // rhel9+) with subject-side `filehash=` (CHECK 1B, version-invariant,
        // E06 everywhere) must fire exactly the RIGHT E06 per target, proving
        // the two checks compose independently rather than one implementation
        // accidentally coupling them (e.g. a fix that makes `check_filehash`
        // ALSO start gating on `target >= Rhel9` the way `check_subject_device`
        // does, silently reintroducing the rhel8/None gap this section closes).
        let subj = vec![kv("device", "/dev/sda"), kv("filehash", HEX64)];

        // rhel8: device (subject) is valid -> no E06 from CHECK 2; filehash
        // (subject) is invalid (doesn't exist at all on 1.3.2) -> exactly one
        // E06 from CHECK 1.
        let diags8 = run(
            15,
            subj.clone(),
            vec![Attr::All],
            Some(TargetVersion::Rhel8),
        );
        assert_eq!(
            count(&diags8, "fapd-E06"),
            1,
            "rhel8: only filehash= should fire fapd-E06 (device= is valid there); \
             got codes={:?} diags={diags8:?}",
            codes(&diags8),
        );

        // rhel9: BOTH device (subject, CHECK 2) and filehash (subject, CHECK
        // 1B) are invalid there -> exactly two E06.
        let diags9 = run(
            16,
            subj.clone(),
            vec![Attr::All],
            Some(TargetVersion::Rhel9),
        );
        assert_eq!(
            count(&diags9, "fapd-E06"),
            2,
            "rhel9: both device= and filehash= on the subject side must fire \
             fapd-E06 (one each); got codes={:?} diags={diags9:?}",
            codes(&diags9),
        );

        // None: per the barrier rework ruling (2026-07-23), filehash's
        // subject-side check is None-closed just like device's (CHECK 2) -
        // with no --target there is no version to evaluate either
        // version-conditional check against, so NEITHER fires -> zero E06.
        let diags_none = run(17, subj, vec![Attr::All], None);
        assert_eq!(
            count(&diags_none, "fapd-E06"),
            0,
            "None: neither device= nor filehash= subject-side checks fire \
             without an explicit --target (both None-closed); got codes={:?} \
             diags={diags_none:?}",
            codes(&diags_none),
        );
    }
}
