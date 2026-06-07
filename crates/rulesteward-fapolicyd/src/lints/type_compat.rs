//! fapd-E07 - set / attribute type-compatibility.
//!
//! Predicts fapolicyd's load-time rejection of a `%set` assigned to an attribute
//! whose value type the set is incompatible with (e.g. a STRING-typed set on
//! `uid=`). Grounded in cited `fapolicyd --debug --permissive` runtime output
//! from three pinned images (1.3.2-el8 / 1.4.5-el9_8 / 1.4.5-el10; re-grounded
//! 2026-06-07, #163); see `.private-docs/fapd-e07-grounding.md`.
//!
//! Model (full bidirectional, EXACT - matches fapolicyd across versions):
//!   * Each attribute has a type category
//!     ([`crate::attrs::AttrTypeCategory`]): `Unsigned` / `Signed` / `Str` /
//!     `Permissive` / `NoSet`. Most are version-invariant, but `pid`/`ppid` and
//!     `gid` DIVERGE across the 1.3.2 -> 1.4.x boundary (resolved per-version by
//!     [`crate::attrs::type_category_for`]): pid/ppid are `Unsigned` on rhel8
//!     (accept a numeric set) but `Signed` on rhel9+ (reject every set); `gid`
//!     is `Permissive` on rhel8 but `Unsigned` on rhel9+ (reject string/mixed).
//!   * A `%set`'s type is inferred version-DIVERGENTLY: rhel8 (1.3.2) by the
//!     first element, rhel9/rhel10 (1.4.x) STRING-if-any-non-numeric.
//!   * Firing gates on OUTCOME-invariance: under an explicit `--target`, fire
//!     iff the mismatch holds for that version; under `None`, fire iff it holds
//!     on ALL supported versions (so universal mismatches fire without
//!     `--target`, version-divergent ones only under it). Because the category
//!     itself can diverge, a numeric set on `pid=` (accepted on rhel8, rejected
//!     on rhel9+) fires only under `--target rhel9`/`rhel10`, not under `None`.
//!   * `pattern`/`trust` (`NoSet`) are owned by fapd-E04, so E07 defers there
//!     rather than double-reporting.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use super::anchored;
use super::macros::looks_int;
use super::subsume::build_macro_map;
use crate::ast::{Attr, AttrValue, Entry};
use crate::attrs::{self, AttrTypeCategory};
use crate::version::TargetVersion;

/// Every supported target, used to evaluate the implicit (`None`) dialect: a
/// mismatch fires under `None` only when it holds on ALL of these.
const ALL_TARGETS: [TargetVersion; 3] = [
    TargetVersion::Rhel8,
    TargetVersion::Rhel9,
    TargetVersion::Rhel10,
];

/// fapd-E07 pass. Unlike `version_target::walk`, this does NOT early-return on
/// `target == None`: E07 has UNIVERSAL mismatches (wrong on every supported
/// version) that fire without `--target`, plus VERSION-DIVERGENT mismatches that
/// fire only under an explicit `--target`. See the module doc for the model.
#[must_use]
pub(crate) fn walk(
    entries: &[Entry],
    file: &Path,
    target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    let macro_map = build_macro_map(entries);
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::Rule(rule) = entry else { continue };
        // Both sides participate: the check is bidirectional and `path=`/`dir=`
        // etc. live on the object side.
        for attr in rule.subject.iter().chain(rule.object.iter()) {
            let Attr::Kv {
                key,
                value: AttrValue::SetRef(name),
                span,
            } = attr
            else {
                // Literals (Str/Int) are fapd-E02's concern; `Attr::All` has no value.
                continue;
            };
            let Some(base) = attrs::type_category(key) else {
                // Unknown attribute - fapd-E01's concern, not E07's.
                continue;
            };
            // `pattern`/`trust` (NoSet, version-invariant) are already flagged by
            // fapd-E04, so E07 defers to avoid double-reporting. (Permissive is NOT
            // skipped up front: `gid` is Permissive only on rhel8 - on rhel9+ it is
            // Unsigned and CAN mismatch, so the per-version gate below decides.)
            if matches!(base, AttrTypeCategory::NoSet) {
                continue;
            }
            let Some(values) = macro_map.get(name) else {
                // Undefined set - fapd-E03's concern; nothing to type-check.
                continue;
            };
            if values.is_empty() {
                // An empty set cannot be typed.
                continue;
            }
            // Outcome-invariance gate: under an explicit target, fire iff the
            // mismatch holds for that version; under `None`, fire iff it holds on
            // every supported version (universal mismatches only). The attribute's
            // CATEGORY is resolved per-version (pid/ppid/gid diverge), so a finding
            // that is version-divergent (e.g. a numeric set on `pid=`, accepted on
            // rhel8 but rejected on rhel9+) only fires under an explicit target.
            let fires = match target {
                Some(v) => fires_for(values, key, v),
                None => ALL_TARGETS.iter().all(|&v| fires_for(values, key, v)),
            };
            if fires {
                // The message names the expected type at the relevant version: the
                // explicit target, or the newest supported version under `None`.
                let msg_version = target.unwrap_or(TargetVersion::Rhel10);
                let category = attrs::type_category_for(key, msg_version).unwrap_or(base);
                diags.push(anchored(
                    Severity::Error,
                    "fapd-E07",
                    span.clone(),
                    message(name, key, category, target),
                    file,
                    rule.line,
                ));
            }
        }
    }
    diags
}

/// Whether assigning the set `values` to attribute `key` is a type mismatch under
/// `version` (i.e. fapolicyd would reject it at load time). The category is
/// resolved per-version (`pid`/`ppid`/`gid` diverge); `Permissive`/`NoSet`
/// attributes never mismatch under any version.
fn fires_for(values: &[String], key: &str, version: TargetVersion) -> bool {
    let Some(category) = attrs::type_category_for(key, version) else {
        return false;
    };
    match category {
        AttrTypeCategory::Permissive | AttrTypeCategory::NoSet => false,
        _ => compat_mismatch(infer_numeric(values, version), category),
    }
}

/// Whether a set inferred as `numeric` (vs string) is type-incompatible with an
/// attribute of `category`. `Permissive`/`NoSet` never reach here (filtered in
/// `walk`); they return `false` to keep the match total.
fn compat_mismatch(numeric: bool, category: AttrTypeCategory) -> bool {
    match category {
        // Unsigned accepts a numeric set; a string set is rejected.
        AttrTypeCategory::Unsigned => !numeric,
        // Signed rejects ANY set: a numeric set types unsigned on the subject
        // side (mismatch), and a string set is not signed either.
        AttrTypeCategory::Signed => true,
        // String accepts a string set; a numeric set is rejected.
        AttrTypeCategory::Str => numeric,
        AttrTypeCategory::Permissive | AttrTypeCategory::NoSet => false,
    }
}

/// fapolicyd's version-divergent set-type inference: rhel8 (1.3.2) types a set by
/// its FIRST element; rhel9/rhel10 (1.4.x) type it STRING if ANY element is
/// non-numeric. Returns `true` when the set is numeric-typed under `version`.
/// `values` is never empty (the caller skips empty sets).
fn infer_numeric(values: &[String], version: TargetVersion) -> bool {
    match version {
        TargetVersion::Rhel8 => values.first().is_some_and(|v| looks_int(v)),
        TargetVersion::Rhel9 | TargetVersion::Rhel10 => values.iter().all(|v| looks_int(v)),
    }
}

/// The fapd-E07 diagnostic message. Under an explicit `--target` it names the
/// target + concrete fapolicyd version (the finding may be version-divergent);
/// under `None` it states the mismatch holds on every supported version.
fn message(
    name: &str,
    key: &str,
    category: AttrTypeCategory,
    target: Option<TargetVersion>,
) -> String {
    let expects = match category {
        AttrTypeCategory::Unsigned => "an unsigned integer",
        AttrTypeCategory::Signed => "a signed integer",
        AttrTypeCategory::Str => "a string",
        // Filtered in `walk`; never formatted.
        AttrTypeCategory::Permissive | AttrTypeCategory::NoSet => "a compatible value",
    };
    match target {
        Some(t) => format!(
            "set `%{name}` is type-incompatible with `{key}=` (expects {expects}) on \
             --target {t} (fapolicyd {})",
            t.fapolicyd_version(),
        ),
        None => format!(
            "set `%{name}` is type-incompatible with `{key}=` (expects {expects}) on \
             every supported fapolicyd version",
        ),
    }
}

#[cfg(test)]
mod tests {
    //! fapd-E07 RED barrier tests, driven through the public `lint_with_context`
    //! seam (NOT the private `walk`) so the activation/firing decision is tested
    //! as a whole-pipeline property regardless of where the logic lands.
    //!
    //! Every assertion is grounded in `.private-docs/fapd-e07-grounding.md`'s
    //! cited runtime output. Key facts:
    //!   * Attribute type categories: UNSIGNED `uid`/`auid`/`sessionid`;
    //!     STRING `comm`/`exe`/`dir`/`ftype`/`path`/`device`/`filehash`/
    //!     `sha256hash`; NO-SET `pattern`/`trust`. VERSION-DIVERGENT (#163):
    //!     `pid`/`ppid` are UNSIGNED on rhel8 (accept a numeric set) but SIGNED
    //!     on rhel9+ (reject every set); `gid` is PERMISSIVE on rhel8 (never
    //!     flagged) but UNSIGNED on rhel9+ (a string/mixed set is flagged).
    //!   * Set-type inference is VERSION-DIVERGENT: rhel8 (1.3.2) types by the
    //!     FIRST element; rhel9/rhel10 (1.4.x) type STRING if ANY element is
    //!     non-numeric.
    //!   * Firing gates on OUTCOME-invariance: under `--target Some(v)`, fire iff
    //!     the mismatch holds for v; under `None`, fire iff it holds for ALL of
    //!     rhel8/rhel9/rhel10 (so universal mismatches fire without `--target`,
    //!     version-divergent ones only under it).
    //!   * NO-SET (`pattern`/`trust`): a `%set` there is already flagged by
    //!     fapd-E04 (macro in trust=/pattern=). E07 DEFERS to E04 - it must NOT
    //!     double-report. Locked by `pattern_setref_is_e04_not_e07` below.
    //!
    //! RED expectation: `walk` returns `Vec::new()` unconditionally, so every
    //! "E07 fires" test FAILS; the "clean"/"E04-not-E07" regression guards pass.

    use rulesteward_core::{Diagnostic, Severity};

    use crate::lints::LintContext;
    use crate::version::TargetVersion;

    /// All four lint contexts E07 must be correct under.
    const ALL_CONTEXTS: [Option<TargetVersion>; 4] = [
        None,
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
    ];

    /// Parse `src` and lint it under `target`. Panics if the fixture does not
    /// parse cleanly (a malformed fixture is an authoring bug, not a lint case).
    fn lint_src(src: &str, target: Option<TargetVersion>) -> Vec<Diagnostic> {
        let path = std::path::Path::new("rules.d/50-e07.rules");
        let entries = crate::parser::parse_rules_file(src, path)
            .unwrap_or_else(|d| panic!("E07 fixture must parse cleanly: {d:?}"));
        let ctx = LintContext {
            target,
            ..Default::default()
        };
        crate::lints::lint_with_context(&entries, src, path, &ctx)
    }

    fn e07_count(diags: &[Diagnostic]) -> usize {
        diags
            .iter()
            .filter(|d| d.code.as_ref() == "fapd-E07")
            .count()
    }

    fn first_e07(diags: &[Diagnostic]) -> Option<&Diagnostic> {
        diags.iter().find(|d| d.code.as_ref() == "fapd-E07")
    }

    fn codes(diags: &[Diagnostic]) -> Vec<&str> {
        diags.iter().map(|d| d.code.as_ref()).collect()
    }

    #[test]
    fn numeric_set_on_mode_fires_e07_on_every_context() {
        // `mode` is STRING-typed; a numeric `%set` is SIGNED-typed and rejected on
        // 1.3.2/1.4.3/1.4.5 (daemon: "cannot assign SIGNED set nums to the STRING
        // attribute", differential 2026-06-01). So E07 fires under None and each
        // target. RED before `mode` is a known STRING attribute (E07 skips it).
        let src = "# header\n%nums=0755,0644\nallow perm=any all : mode=%nums\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                1,
                "numeric set on mode= must fire exactly one fapd-E07 under {ctx:?}; \
                 got codes={:?}",
                codes(&diags),
            );
        }
    }

    #[test]
    fn string_set_on_mode_does_not_fire_e07() {
        // A string `%set` on the STRING attribute `mode` loads on all three versions
        // (differential set-str-on-mode VALID), so E07 must NOT fire.
        let src = "# header\n%strs=foo,bar\nallow perm=any all : mode=%strs\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "string set on mode= must NOT fire fapd-E07 under {ctx:?}; got codes={:?}",
                codes(&diags),
            );
        }
    }

    // -----------------------------------------------------------------
    // UNIVERSAL: string-typed set on a numeric attribute (the headline
    // security case). Wrong on every version -> fires under None AND each
    // target. `uid=` is UNSIGNED.
    // -----------------------------------------------------------------

    #[test]
    fn string_set_on_uid_fires_e07_on_every_context() {
        // %t=abc,def is a homogeneous STRING set; `uid=` is UNSIGNED. Rejected on
        // 1.3.2/1.4.3/1.4.5 alike (grounding: "homogeneous all-string set on uid=
        // rejected on ALL three versions"), so E07 fires under None and each target.
        let src = "# header\n%t=abc,def\nallow uid=%t : all\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                1,
                "string set on uid= must fire exactly one fapd-E07 under {ctx:?}; \
                 got codes={:?}",
                codes(&diags),
            );
            let e07 = first_e07(&diags).expect("checked count");
            assert_eq!(
                e07.severity,
                Severity::Error,
                "fapd-E07 must be Severity::Error under {ctx:?}",
            );
            assert_eq!(
                e07.line, 3,
                "fapd-E07 must carry the rule's line (3), not a hardcoded 1, under {ctx:?}; got {}",
                e07.line,
            );
            assert!(
                e07.message.contains("uid") && e07.message.contains("%t"),
                "fapd-E07 message must name the attribute `uid=` and the set `%t`: {}",
                e07.message,
            );
        }
    }

    #[test]
    fn string_set_on_uid_caret_points_at_the_attribute_not_the_rule() {
        // The caret must anchor at the offending `uid=%t` attribute (span/column),
        // not the rule's first column. On line `allow uid=%t : all`, `uid` starts
        // at column 7. A mutant that emits at the rule span lands at column 1 and
        // dies here.
        let src = "# header\n%t=abc,def\nallow uid=%t : all\n";
        let diags = lint_src(src, Some(TargetVersion::Rhel9));
        let e07 = first_e07(&diags).expect("string set on uid= must fire fapd-E07 on rhel9");
        assert!(
            e07.column > 1,
            "fapd-E07 caret must point at the `uid=` attribute (column > 1), not the rule \
             start (column 1); got column={} span={:?}",
            e07.column,
            e07.span,
        );
    }

    #[test]
    fn auid_and_sessionid_are_unsigned_like_uid() {
        // auid and sessionid are UNSIGNED too: a string set is rejected on every
        // version. Guards against an impl that special-cases only `uid`.
        for attr in ["auid", "sessionid"] {
            let src = format!("%t=abc,def\nallow {attr}=%t : all\n");
            for ctx in ALL_CONTEXTS {
                let diags = lint_src(&src, ctx);
                assert_eq!(
                    e07_count(&diags),
                    1,
                    "string set on {attr}= (UNSIGNED) must fire fapd-E07 under {ctx:?}; \
                     got codes={:?}",
                    codes(&diags),
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // CLEAN: numeric set on a numeric attribute.
    // -----------------------------------------------------------------

    #[test]
    fn int_set_on_uid_is_clean_on_every_context() {
        // %t=1,2,3 is a homogeneous numeric set; `uid=` is UNSIGNED -> ACCEPT on
        // every version (grounding: numeric set assigned to uid loads). No E07.
        let src = "%t=1,2,3\nallow uid=%t : all\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "numeric set on uid= must be CLEAN of fapd-E07 under {ctx:?}; got codes={:?}",
                codes(&diags),
            );
        }
    }

    // -----------------------------------------------------------------
    // UNIVERSAL (bidirectional): numeric set on a STRING attribute. Wrong on
    // every version -> fires under None and each target.
    // -----------------------------------------------------------------

    #[test]
    fn int_set_on_exe_fires_e07_on_every_context() {
        // `exe=` is STRING. A numeric set on a STRING attribute is rejected on all
        // versions (grounding bidirectional row: numeric set on a STRING attr ->
        // "cannot assign ... set to the STRING attribute"). The opposite direction
        // of string-set-on-uid; proves the check is bidirectional, not one-way.
        let src = "%t=1,2,3\nallow exe=%t : all\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                1,
                "numeric set on exe= (STRING) must fire fapd-E07 under {ctx:?}; got codes={:?}",
                codes(&diags),
            );
            assert!(
                first_e07(&diags).unwrap().message.contains("exe"),
                "fapd-E07 message must name `exe=`",
            );
        }
    }

    #[test]
    fn int_set_on_object_side_path_fires_e07_on_every_context() {
        // OBJECT-side STRING attr: `path=` is object-only and STRING-typed. A
        // numeric set on it is rejected on every version (grounding bidirectional
        // row + the object-side path types a positive-int set SIGNED, lines 62/78-82).
        // Kills a mutant that only checks the SUBJECT side and skips object attrs.
        let src = "%t=1,2,3\nallow all : path=%t\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                1,
                "numeric set on object-side path= (STRING) must fire fapd-E07 under {ctx:?}; \
                 got codes={:?}",
                codes(&diags),
            );
            assert!(
                first_e07(&diags).unwrap().message.contains("path"),
                "fapd-E07 message must name `path=`",
            );
        }
    }

    #[test]
    fn string_set_on_object_side_path_is_clean_on_every_context() {
        // Non-vacuity for the object-side path: a STRING set on the STRING attr
        // `path=` is the normal valid case -> never fires.
        let src = "%t=/usr/bin,/usr/sbin\nallow all : path=%t\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "string set on object-side path= (STRING) is valid: must be CLEAN under {ctx:?}; \
                 got codes={:?}",
                codes(&diags),
            );
        }
    }

    #[test]
    fn string_set_on_exe_is_clean_on_every_context() {
        // A STRING set on the STRING attribute `exe=` is the normal, valid case
        // (e.g. `%languages` on exe=) -> never fires. Critical non-vacuity guard:
        // an impl that fires on ANY set-on-exe dies here.
        let src = "%t=abc,def\nallow exe=%t : all\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "string set on exe= (STRING) is valid: must be CLEAN of fapd-E07 under {ctx:?}; \
                 got codes={:?}",
                codes(&diags),
            );
        }
    }

    // -----------------------------------------------------------------
    // VERSION-DIVERGENT: heterogeneous set (first element numeric, a later
    // element non-numeric). rhel8 types by first element (numeric); rhel9/10
    // type STRING (any non-numeric). Fires only under the targets where it is
    // wrong; suppressed under None.
    // -----------------------------------------------------------------

    #[test]
    fn het_set_on_uid_diverges_clean_rhel8_fires_rhel9_rhel10() {
        // %s=1,abc on uid= (UNSIGNED): rhel8 types it INT-by-first-element ->
        // ACCEPT (clean); rhel9/rhel10 type it STRING-by-any-non-numeric ->
        // REJECT. Suppressed under None (version-divergent). Grounding RED seed.
        let src = "%s=1,abc\nallow uid=%s : all\n";

        for clean_ctx in [None, Some(TargetVersion::Rhel8)] {
            let diags = lint_src(src, clean_ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "heterogeneous set on uid= must be CLEAN under {clean_ctx:?} \
                 (rhel8 types by first element; None suppresses divergent); got codes={:?}",
                codes(&diags),
            );
        }

        for t in [TargetVersion::Rhel9, TargetVersion::Rhel10] {
            let diags = lint_src(src, Some(t));
            assert_eq!(
                e07_count(&diags),
                1,
                "heterogeneous set on uid= must FIRE fapd-E07 under --target {t} \
                 (1.4.x types STRING if any element is non-numeric); got codes={:?}",
                codes(&diags),
            );
            let e07 = first_e07(&diags).unwrap();
            assert_eq!(e07.line, 2, "fapd-E07 must carry the rule line (2)");
            assert!(
                e07.message.contains(&t.to_string()),
                "version-divergent fapd-E07 must name the --target {t}: {}",
                e07.message,
            );
        }
    }

    #[test]
    fn het_set_on_exe_diverges_opposite_fires_rhel8_clean_rhel9_rhel10() {
        // %s=1,abc on exe= (STRING) - the OPPOSITE divergence: rhel8 types it
        // numeric (first element) -> numeric on STRING attr -> REJECT; rhel9/10
        // type it STRING -> STRING on STRING attr -> ACCEPT. Suppressed under None.
        let src = "%s=1,abc\nallow exe=%s : all\n";

        let diags8 = lint_src(src, Some(TargetVersion::Rhel8));
        assert_eq!(
            e07_count(&diags8),
            1,
            "heterogeneous set on exe= must FIRE under --target rhel8 (numeric by first \
             element, on a STRING attr); got codes={:?}",
            codes(&diags8),
        );
        assert!(
            first_e07(&diags8).unwrap().message.contains("rhel8"),
            "version-divergent fapd-E07 must name --target rhel8",
        );

        for clean_ctx in [
            None,
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ] {
            let diags = lint_src(src, clean_ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "heterogeneous set on exe= must be CLEAN under {clean_ctx:?} \
                 (1.4.x types STRING -> valid on STRING attr; None suppresses divergent); \
                 got codes={:?}",
                codes(&diags),
            );
        }
    }

    // -----------------------------------------------------------------
    // pid/ppid are VERSION-DIVERGENT (#163, re-grounded 2026-06-07 via
    // `rpm -q fapolicyd` on fapolicyd8=1.3.2-el8 and fapolicyd9=1.4.5-el9_8):
    //   * rhel8 (1.3.2): pid/ppid are INT/UNSIGNED - a positive-int set LOADS,
    //     a string set is rejected ("STRING type to INT").
    //   * rhel9/rhel10 (1.4.5): pid/ppid are SIGNED - a positive-int set types
    //     UNSIGNED != SIGNED, so EVERY set is rejected.
    // The old all-version SIGNED model emitted a FALSE POSITIVE on rhel8.
    // -----------------------------------------------------------------

    #[test]
    fn int_set_on_pid_ppid_fires_only_under_rhel9_plus() {
        // A positive-int set `%t=1,2,3` on pid=/ppid= LOADS on 1.3.2 (rhel8) but is
        // REJECTED on 1.4.5 (rhel9/rhel10). Version-divergent: it must NOT fire
        // under rhel8 or None (rhel8 accepts it -> not a universal mismatch), and
        // MUST fire under an explicit rhel9/rhel10 target. This is the #163 fix:
        // the old model fired on every context (a false positive on el8).
        for attr in ["pid", "ppid"] {
            let src = format!("%t=1,2,3\nallow {attr}=%t : all\n");
            for ctx in [None, Some(TargetVersion::Rhel8)] {
                let diags = lint_src(&src, ctx);
                assert_eq!(
                    e07_count(&diags),
                    0,
                    "positive-int set on {attr}= must NOT fire fapd-E07 under {ctx:?} \
                     (fapolicyd 1.3.2 LOADS it; not a universal mismatch); got codes={:?}",
                    codes(&diags),
                );
            }
            for ctx in [Some(TargetVersion::Rhel9), Some(TargetVersion::Rhel10)] {
                let diags = lint_src(&src, ctx);
                assert_eq!(
                    e07_count(&diags),
                    1,
                    "positive-int set on {attr}= must fire fapd-E07 under {ctx:?} \
                     (fapolicyd 1.4.5 rejects: SIGNED expected); got codes={:?}",
                    codes(&diags),
                );
            }
        }
    }

    #[test]
    fn string_set_on_pid_ppid_fires_on_every_context() {
        // A STRING set on pid=/ppid= is rejected on EVERY version: rhel8 (1.3.2)
        // types pid INT and rejects a string set ("STRING type to INT"); rhel9/10
        // (1.4.5) type pid SIGNED and reject any set. Universal mismatch -> fires
        // under None too. Guards that the rhel8 INT handling rejects strings.
        for attr in ["pid", "ppid"] {
            let src = format!("%t=abc,def\nallow {attr}=%t : all\n");
            for ctx in ALL_CONTEXTS {
                let diags = lint_src(&src, ctx);
                assert_eq!(
                    e07_count(&diags),
                    1,
                    "string set on {attr}= must fire fapd-E07 under {ctx:?}; got codes={:?}",
                    codes(&diags),
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // gid is VERSION-DIVERGENT (#163, re-grounded 2026-06-07):
    //   * rhel8 (1.3.2): gid is PERMISSIVE (accepts group NAMES) - string,
    //     numeric, AND mixed sets all LOAD.
    //   * rhel9/rhel10 (1.4.5): gid is UNSIGNED - a numeric set LOADS, but a
    //     STRING or MIXED set types STRING != UNSIGNED and is REJECTED.
    // The old all-version PERMISSIVE model emitted a FALSE NEGATIVE on 1.4.5.
    // -----------------------------------------------------------------

    #[test]
    fn numeric_set_on_gid_never_fires_e07() {
        // A numeric set on gid= LOADS on every version (rhel8 PERMISSIVE accepts
        // it; rhel9/10 UNSIGNED accepts a numeric set). Never fires.
        let src = "%t=1,2,3\nallow gid=%t : all\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "numeric set on gid= must NEVER fire fapd-E07 under {ctx:?}; got codes={:?}",
                codes(&diags),
            );
        }
    }

    #[test]
    fn string_or_mixed_set_on_gid_fires_only_under_rhel9_plus() {
        // A STRING (`abc,def`) or MIXED (`1,abc`) set on gid= LOADS on 1.3.2
        // (rhel8: gid PERMISSIVE) but is REJECTED on 1.4.5 (rhel9/10: gid UNSIGNED,
        // a non-all-numeric set types STRING). Version-divergent: no fire under
        // rhel8/None, fire under rhel9/rhel10. This is the #163 false-negative fix.
        for values in ["abc,def", "1,abc"] {
            let src = format!("%t={values}\nallow gid=%t : all\n");
            for ctx in [None, Some(TargetVersion::Rhel8)] {
                let diags = lint_src(&src, ctx);
                assert_eq!(
                    e07_count(&diags),
                    0,
                    "gid=%t ({values}) must NOT fire fapd-E07 under {ctx:?} \
                     (fapolicyd 1.3.2 LOADS it); got codes={:?}",
                    codes(&diags),
                );
            }
            for ctx in [Some(TargetVersion::Rhel9), Some(TargetVersion::Rhel10)] {
                let diags = lint_src(&src, ctx);
                assert_eq!(
                    e07_count(&diags),
                    1,
                    "gid=%t ({values}) must fire fapd-E07 under {ctx:?} \
                     (fapolicyd 1.4.5 rejects: UNSIGNED expected); got codes={:?}",
                    codes(&diags),
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // NO-SET boundary: pattern=/trust= sets are owned by fapd-E04. E07 must
    // defer (no double-report).
    // -----------------------------------------------------------------

    #[test]
    fn pattern_setref_is_e04_not_e07() {
        // A `%set` in pattern= is already an Error via fapd-E04 (macro in
        // pattern=). E07 must NOT also fire - double-reporting the same defect is
        // a quality regression. Asserts E04 present, E07 absent, on every context.
        let src = "%t=abc,def\nallow pattern=%t : all\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert!(
                diags.iter().any(|d| d.code.as_ref() == "fapd-E04"),
                "macro in pattern= must fire fapd-E04 under {ctx:?}; got codes={:?}",
                codes(&diags),
            );
            assert_eq!(
                e07_count(&diags),
                0,
                "E07 must DEFER to fapd-E04 for pattern= (no double-report) under {ctx:?}; \
                 got codes={:?}",
                codes(&diags),
            );
        }
    }

    #[test]
    fn trust_setref_is_e04_not_e07() {
        // Same boundary for trust= (a both-sides attr). E04 owns it; E07 defers.
        let src = "%t=0,1\nallow uid=0 : trust=%t\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert!(
                diags.iter().any(|d| d.code.as_ref() == "fapd-E04"),
                "macro in trust= must fire fapd-E04 under {ctx:?}; got codes={:?}",
                codes(&diags),
            );
            assert_eq!(
                e07_count(&diags),
                0,
                "E07 must DEFER to fapd-E04 for trust= under {ctx:?}; got codes={:?}",
                codes(&diags),
            );
        }
    }

    // -----------------------------------------------------------------
    // Non-SetRef values and literals are not E07's concern.
    // -----------------------------------------------------------------

    #[test]
    fn literal_string_on_uid_is_not_e07() {
        // A literal `uid=abc` (not a %set) is fapd-E02's concern (invalid value),
        // not E07's (E07 is about SET type-compatibility). E07 must not fire.
        let src = "allow uid=abc : all\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "literal uid=abc is fapd-E02's concern, not E07's, under {ctx:?}; got codes={:?}",
                codes(&diags),
            );
        }
    }

    #[test]
    fn message_names_target_under_explicit_target_only() {
        // Message contract: under an explicit --target, the universal-case message
        // names that target; under None it does not name a specific rhelN (it is
        // wrong on every supported version). Locks the two message shapes.
        let src = "%t=abc,def\nallow uid=%t : all\n";

        let diags9 = lint_src(src, Some(TargetVersion::Rhel9));
        assert!(
            first_e07(&diags9).unwrap().message.contains("rhel9"),
            "under --target rhel9 the fapd-E07 message must name rhel9: {}",
            first_e07(&diags9).unwrap().message,
        );

        let diags_none = lint_src(src, None);
        let msg = &first_e07(&diags_none).unwrap().message;
        assert!(
            !msg.contains("rhel8") && !msg.contains("rhel9") && !msg.contains("rhel10"),
            "under None the fapd-E07 message must NOT name a specific rhel target: {msg}",
        );
    }
}
