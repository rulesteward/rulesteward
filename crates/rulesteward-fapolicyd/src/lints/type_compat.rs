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
//!     (accept a positive-int set) but `Signed` on rhel9+ (accept ONLY a SIGNED
//!     set - all ints with a negative member - rejecting positive-int and string
//!     sets); `gid` is `Permissive` on rhel8 but `Unsigned` on rhel9+ (reject
//!     string/mixed).
//!   * A `%set`'s type is inferred version-DIVERGENTLY into UNSIGNED / SIGNED /
//!     STRING ([`SetType`]): rhel8 (1.3.2) by the first element (no SIGNED type);
//!     rhel9/rhel10 (1.4.x) STRING if any member is non-integer, else SIGNED if
//!     any is negative, else UNSIGNED.
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
use super::macros::is_fap_int;
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
    // `compat_mismatch` already returns `false` for `Permissive`/`NoSet`, so no
    // early-out is needed here (and `NoSet` is skipped before `walk` calls us).
    compat_mismatch(infer_set_type(values, version), category)
}

/// fapolicyd's three-way set value type. A `%set` assigned to a numeric attribute
/// is accepted iff its inferred type EXACTLY matches the attribute's expected
/// type (UNSIGNED `uid`/rhel8-`pid`/rhel9-`gid`; SIGNED rhel9-`pid`; STRING `exe`
/// etc.). Grounded 2026-06-07 against the daemon (#163): a SIGNED set (a negative
/// member) loads on a SIGNED `pid=` but an UNSIGNED set does not, and vice versa.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SetType {
    /// Every member is a non-negative integer (e.g. `1,2,3`).
    Unsigned,
    /// Every member is an integer and at least one is negative (e.g. `-1`, `1,-2`).
    Signed,
    /// At least one member is not an integer (e.g. `abc`, `1,abc`).
    Str,
}

/// Whether a set of `set_type` is type-incompatible with an attribute of
/// `category` (fapolicyd rejects it at load time). The numeric categories require
/// an EXACT type match; `Permissive` accepts any set and `NoSet` is owned by
/// fapd-E04, so both return `false` (never a mismatch here).
fn compat_mismatch(set_type: SetType, category: AttrTypeCategory) -> bool {
    match category {
        AttrTypeCategory::Unsigned => set_type != SetType::Unsigned,
        AttrTypeCategory::Signed => set_type != SetType::Signed,
        AttrTypeCategory::Str => set_type != SetType::Str,
        AttrTypeCategory::Permissive | AttrTypeCategory::NoSet => false,
    }
}

/// fapolicyd's version-divergent set-type inference (grounded 2026-06-07):
/// rhel8 (1.3.2) types a set by its FIRST element only and has no SIGNED type (a
/// leading `-` makes the first element a non-INT -> STRING); rhel9/rhel10 (1.4.x)
/// type by ALL elements: STRING if any is non-integer, else SIGNED if any is
/// negative, else UNSIGNED. `values` is never empty (the caller skips empty sets).
fn infer_set_type(values: &[String], version: TargetVersion) -> SetType {
    match version {
        TargetVersion::Rhel8 => {
            // 1.3.2 types a set by its FIRST element and types that element INT iff
            // its first CHARACTER is an ASCII digit (isdigit-style): `1abc`/`12`
            // -> INT (load); `-1`/`+1`/`abc` -> STRING. It has no SIGNED type.
            let first_is_intish = values
                .first()
                .and_then(|v| v.bytes().next())
                .is_some_and(|b| b.is_ascii_digit());
            if first_is_intish {
                SetType::Unsigned
            } else {
                SetType::Str
            }
        }
        TargetVersion::Rhel9 | TargetVersion::Rhel10 => {
            if !values.iter().all(|v| looks_signed_int(v)) {
                SetType::Str
            } else if values.iter().any(|v| v.starts_with('-')) {
                SetType::Signed
            } else {
                SetType::Unsigned
            }
        }
    }
}

/// Whether `v` is an integer fapolicyd 1.4.x would accept as a SIGNED or UNSIGNED
/// set member: an optional leading sign (`-` or `+`, strtol-style) followed by
/// digits that fit `i64` ([`is_fap_int`], NOT just "looks like digits" -
/// `looks_int`). #477: an all-digit member that overflows `i64` must NOT count
/// as numeric membership on rhel9/rhel10 - the real 1.4.5 daemon types such a
/// set STRING ("cannot assign %s which has STRING type to uid (UNSIGNED
/// expected)", grounded session-7b corpus cases 03-07), not
/// UNSIGNED/SIGNED. Only a leading `-` makes the member negative (the SIGNED
/// determination in [`infer_set_type`] keys on `-`, so `+1` stays UNSIGNED).
fn looks_signed_int(v: &str) -> bool {
    is_fap_int(v.strip_prefix(['-', '+']).unwrap_or(v))
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
    //!     `pid`/`ppid` are UNSIGNED on rhel8 (accept a positive-int set) but
    //!     SIGNED on rhel9+ (accept ONLY a signed-int set, reject positive-int and
    //!     string sets); `gid` is PERMISSIVE on rhel8 (never flagged) but UNSIGNED
    //!     on rhel9+ (a string/mixed set is flagged).
    //!   * Set-type inference is VERSION-DIVERGENT + three-way (UNSIGNED / SIGNED
    //!     / STRING): rhel8 (1.3.2) types by the FIRST element (no SIGNED type);
    //!     rhel9/rhel10 (1.4.x) STRING if any member is non-integer, else SIGNED
    //!     if any is negative, else UNSIGNED.
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

    #[test]
    fn negative_int_set_on_pid_ppid_matches_daemon_signedness() {
        // GROUNDED 2026-06-07 (docker, fapolicyd 1.3.2-el8 vs 1.4.5-el9_8/el10;
        // found by the #163 impl-aware adversarial review): fapolicyd's set-type
        // inference is three-way (UNSIGNED / SIGNED / STRING). pid/ppid are SIGNED
        // on 1.4.5, so they ACCEPT a SIGNED set (all ints, >=1 negative) and reject
        // an UNSIGNED set (all positive). A `%t=-1,-2` set types SIGNED on 1.4.5
        // (LOADS -> no fire) but STRING-by-first-element on 1.3.2 (rejected "to
        // INT" -> fires). The old `Signed => reject-every-set` shortcut fired on
        // EVERY context here, a false positive on rhel9/rhel10.
        for attr in ["pid", "ppid"] {
            let src = format!("%t=-1,-2\nallow {attr}=%t : all\n");
            let r8 = lint_src(&src, Some(TargetVersion::Rhel8));
            assert_eq!(
                e07_count(&r8),
                1,
                "negative-int set on {attr}= must fire under rhel8 (1.3.2 types it \
                 STRING by first element); got codes={:?}",
                codes(&r8),
            );
            for ctx in [
                None,
                Some(TargetVersion::Rhel9),
                Some(TargetVersion::Rhel10),
            ] {
                let diags = lint_src(&src, ctx);
                assert_eq!(
                    e07_count(&diags),
                    0,
                    "negative-int set on {attr}= must NOT fire under {ctx:?} \
                     (fapolicyd 1.4.5 types it SIGNED, which pid/ppid accept; not a \
                     universal mismatch so suppressed under None); got codes={:?}",
                    codes(&diags),
                );
            }
        }
    }

    #[test]
    fn mixed_sign_int_set_on_pid_ppid_never_fires() {
        // `%t=1,-2` LOADS on every version: 1.3.2 types by the first element (`1`
        // is INT); 1.4.5 types the whole set SIGNED (a negative member), which
        // pid/ppid accept. So it never fires under any context.
        for attr in ["pid", "ppid"] {
            let src = format!("%t=1,-2\nallow {attr}=%t : all\n");
            for ctx in ALL_CONTEXTS {
                let diags = lint_src(&src, ctx);
                assert_eq!(
                    e07_count(&diags),
                    0,
                    "mixed-sign set on {attr}= must NEVER fire under {ctx:?} \
                     (loads on all versions); got codes={:?}",
                    codes(&diags),
                );
            }
        }
    }

    #[test]
    fn leading_plus_int_set_types_numeric_like_the_daemon() {
        // GROUNDED 2026-06-07 (docker, found by the #163 impl-aware adversarial
        // review): fapolicyd 1.4.x accepts a leading `+` as an integer
        // (strtol-style), so `+1` types UNSIGNED on rhel9/rhel10 (a `+` does NOT
        // make a set SIGNED; only a `-` does). The set-type inference must treat
        // `+1` as a number, not a string.
        // `+1` on uid (UNSIGNED): LOADS on rhel9/10 -> no fire.
        let uid = "%t=+1\nallow uid=%t : all\n";
        for ctx in [Some(TargetVersion::Rhel9), Some(TargetVersion::Rhel10)] {
            assert_eq!(
                e07_count(&lint_src(uid, ctx)),
                0,
                "`+1` on uid= (UNSIGNED) must LOAD on {ctx:?}; got codes={:?}",
                codes(&lint_src(uid, ctx)),
            );
        }
        // `+1` on exe (STRING): an UNSIGNED set on a STRING attr is REJECTED on
        // rhel9/10 -> fire (a false negative under the old `+`-as-STRING bug).
        let exe = "%t=+1\nallow exe=%t : all\n";
        for ctx in [Some(TargetVersion::Rhel9), Some(TargetVersion::Rhel10)] {
            assert_eq!(
                e07_count(&lint_src(exe, ctx)),
                1,
                "`+1` on exe= (STRING) must fire fapd-E07 on {ctx:?}; got codes={:?}",
                codes(&lint_src(exe, ctx)),
            );
        }
        // `+1,-2` on pid/ppid (SIGNED on rhel9/10): a negative member makes it a
        // SIGNED set, which pid/ppid accept -> LOADS -> no fire.
        for attr in ["pid", "ppid"] {
            let src = format!("%t=+1,-2\nallow {attr}=%t : all\n");
            for ctx in [Some(TargetVersion::Rhel9), Some(TargetVersion::Rhel10)] {
                assert_eq!(
                    e07_count(&lint_src(&src, ctx)),
                    0,
                    "`+1,-2` on {attr}= (SIGNED) must LOAD on {ctx:?}; got codes={:?}",
                    codes(&lint_src(&src, ctx)),
                );
            }
        }
    }

    #[test]
    fn partial_int_first_member_types_intish_on_rhel8() {
        // GROUNDED 2026-06-07 (found by the #163 adversarial review, round 3):
        // fapolicyd 1.3.2 types a set's FIRST element INT iff its first CHARACTER
        // is a digit (isdigit-style), so a partial-int like `1abc` types INT on
        // rhel8 (LOADS on an integer attr) but STRING on rhel9/rhel10 (all-element
        // typing). The old all-digits `looks_int` rhel8 check fired a false
        // positive on rhel8/None.
        // Integer attrs: `1abc` loads on rhel8 (no fire) but is rejected on
        // rhel9/10 (fire); divergent -> suppressed under None.
        for attr in ["pid", "uid", "sessionid"] {
            let src = format!("%t=1abc\nallow {attr}=%t : all\n");
            for ctx in [None, Some(TargetVersion::Rhel8)] {
                assert_eq!(
                    e07_count(&lint_src(&src, ctx)),
                    0,
                    "`1abc` on {attr}= must LOAD on rhel8 (first char is a digit) -> \
                     no fire under {ctx:?}; got codes={:?}",
                    codes(&lint_src(&src, ctx)),
                );
            }
            for ctx in [Some(TargetVersion::Rhel9), Some(TargetVersion::Rhel10)] {
                assert_eq!(
                    e07_count(&lint_src(&src, ctx)),
                    1,
                    "`1abc` on {attr}= must fire on {ctx:?} (1.4.5 types it STRING); \
                     got codes={:?}",
                    codes(&lint_src(&src, ctx)),
                );
            }
        }
        // STRING attr `exe`: an INT-by-first-element set is rejected on rhel8
        // (fire) but loads on rhel9/10 as a STRING set (no fire).
        let exe = "%t=1abc\nallow exe=%t : all\n";
        assert_eq!(
            e07_count(&lint_src(exe, Some(TargetVersion::Rhel8))),
            1,
            "`1abc` on exe= must fire under rhel8 (INT-by-first-element on a STRING \
             attr); got codes={:?}",
            codes(&lint_src(exe, Some(TargetVersion::Rhel8))),
        );
        for ctx in [
            None,
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ] {
            assert_eq!(
                e07_count(&lint_src(exe, ctx)),
                0,
                "`1abc` on exe= must NOT fire under {ctx:?} (STRING set on STRING \
                 attr on 1.4.5); got codes={:?}",
                codes(&lint_src(exe, ctx)),
            );
        }
    }

    // -----------------------------------------------------------------
    // #477 (fapd-E07 overflow-membership fix) - an all-digit member that
    // EXCEEDS i64::MAX must NOT type a set UNSIGNED at rhel9/rhel10. Fixes a
    // genuine pre-existing bug found by the #477 grounding pass (the #477
    // issue itself is about fapd-E05; this fix rides along because the same
    // corpus fixture surfaced it): `infer_set_type`'s rhel9/rhel10 arm uses
    // `looks_int` (all-ASCII-digit only, via `looks_signed_int`) for its
    // numeric-membership test instead of `is_fap_int` (all-ASCII-digit AND
    // fits i64, already defined in `macros.rs` for exactly this purpose), so
    // an overflowing value was wrongly treated as numeric, mistyping the set
    // UNSIGNED instead of STRING.
    //
    // Grounded 2026-07-10 via `fapolicyd --debug --permissive` (corpus case
    // 17, /var/tmp/7b-grounding/p1/corpus/17-overflow-used-as-ftype,
    // rules.d/10-case.rules):
    //   %s=99999999999999999999
    //   allow perm=open all : ftype=%s
    // transcripts 17-overflow-used-as-ftype__fapd9.txt /
    // __fapd10.txt: "Loaded 1 rules" (VALID) - the real 1.4.5 daemon types
    // the overflowing member STRING, and `ftype=` is a STRING attribute, so
    // the assignment is compatible and loads cleanly.
    //
    // RED today: running this fixture through the CLI currently emits
    // `[fapd-E07] set `%s` is type-incompatible with `ftype=` ...` at
    // rhel9/rhel10 (and under None) - a false positive, because
    // `looks_int("99999999999999999999")` is `true`.
    // -----------------------------------------------------------------

    #[test]
    fn overflow_member_referenced_by_string_attr_does_not_fire_e07_at_rhel9_plus() {
        let src = "%s=99999999999999999999\nallow perm=open all : ftype=%s\n";
        for ctx in [
            None,
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ] {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "an overflowing all-digit member must NOT type the set UNSIGNED \
                 at {ctx:?} (fapolicyd 1.4.5 types it STRING, compatible with the \
                 STRING attribute ftype=); corpus case 17 loads cleanly; got \
                 codes={:?}",
                codes(&diags),
            );
        }
    }

    #[test]
    fn overflow_member_referenced_by_string_attr_still_fires_e07_at_rhel8() {
        // Regression guard, NOT a new #477 requirement (contract note E: "do
        // not demand an E07 change [at rhel8] beyond what the matrix
        // supports"). The fix touches only the rhel9/rhel10 arm of
        // `infer_set_type` (`looks_int` -> `is_fap_int` via `looks_signed_int`);
        // rhel8 types a set by its FIRST element via `first_is_intish` (a
        // totally separate code path, unaffected by the fix) and is
        // unrelated to this bug. fapolicyd 1.3.2 itself also rejects this
        // fixture, but via a parse-time abort (fapd-E05's category, not a
        // type-compatibility mismatch) - see corpus case 17's fapd8
        // transcript. This test only pins that the fix does not accidentally
        // change rhel8's E07 firing behavior for this fixture.
        let src = "%s=99999999999999999999\nallow perm=open all : ftype=%s\n";
        let diags = lint_src(src, Some(TargetVersion::Rhel8));
        assert_eq!(
            e07_count(&diags),
            1,
            "rhel8 E07 firing for this fixture must be UNCHANGED by the #477 \
             overflow fix (the fix only touches the rhel9/rhel10 arm of \
             infer_set_type); got codes={:?}",
            codes(&diags),
        );
    }

    #[test]
    fn overflow_set_on_uid_fires_e07_at_rhel9_plus() {
        // The OTHER side of the #477 overflow-membership fix: an overflow set
        // referenced by `uid=` (UNSIGNED) at rhel9/rhel10 MUST fire fapd-E07
        // post-fix, because 1.4.5 types the set STRING and a STRING set on an
        // UNSIGNED attribute is a genuine load-time mismatch.
        //
        // Grounded 2026-07-10: corpus case 05 (int-overflow-single),
        // rules.d/10-case.rules:
        //   %s=99999999999999999999
        //   allow uid=%s : all
        // transcripts 05-int-overflow-single__fapd9.txt / __fapd10.txt:
        // "ERROR: rules: line:3: assign_subject: cannot assign %s which has
        // STRING type to uid (UNSIGNED expected)" (case 03 gives the same
        // message on fapd9/fapd10 for i64::MAX+1).
        //
        // RED today at rhel9/rhel10: pre-fix, `looks_int` treats the overflow
        // member as numeric, the set types UNSIGNED, uid= expects UNSIGNED,
        // no mismatch, no E07. Kills the "just drop the overflow member from
        // typing" wrong implementation: a drop-impl leaves this single-member
        // set with no members contributing STRING-ness and produces no E07
        // here either.
        //
        // rhel8: NO E07 (GREEN pin) - 1.3.2 types the set UNSIGNED by its
        // first CHARACTER (a digit), which uid= accepts; the real 1.3.2
        // rejection of this file is the definition-time "Error converting
        // val" abort (case 05 fapd8 transcript), which is fapd-E05's
        // category, not a type mismatch. None: NO E07 (GREEN pin) - the
        // mismatch does not hold on rhel8, so it is version-divergent, and
        // divergent findings are suppressed under the portable default.
        let src = "%s=99999999999999999999\nallow uid=%s : all\n";

        for ctx in [Some(TargetVersion::Rhel9), Some(TargetVersion::Rhel10)] {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                1,
                "an overflow set on uid= must fire fapd-E07 under {ctx:?} \
                 (fapolicyd 1.4.5 types it STRING: \"cannot assign %s which has \
                 STRING type to uid (UNSIGNED expected)\", corpus case 05); got \
                 codes={:?}",
                codes(&diags),
            );
            let e07 = first_e07(&diags).expect("checked count");
            assert!(
                e07.message.contains("uid") && e07.message.contains("%s"),
                "fapd-E07 message must name the attribute `uid=` and the set `%s`: {}",
                e07.message,
            );
        }
        for ctx in [None, Some(TargetVersion::Rhel8)] {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "an overflow set on uid= must NOT fire fapd-E07 under {ctx:?} \
                 (1.3.2 types it UNSIGNED by first character - the daemon's \
                 rejection there is the definition-time abort, fapd-E05's \
                 category; divergent findings are suppressed under None); got \
                 codes={:?}",
                codes(&diags),
            );
        }
    }

    #[test]
    fn mixed_int_and_overflow_set_on_ftype_does_not_fire_e07_at_rhel9_plus() {
        // DERIVED (no corpus case pairs exactly `1,<overflow>` with ftype=;
        // the derivation composes three grounded rules): (a) case 17 fapd9/10
        // grounds that an overflowing all-digit member types STRING on 1.4.5;
        // (b) cases 08/09 ground that 1.4.5 scans EVERY member and types the
        // whole set STRING if ANY member is non-numeric ("STRING type to uid"
        // on `1,2,foo,3` / `1,abc`); (c) case 13 (`abc,99999999999999999999`
        // referenced by ftype=) grounds that a STRING-typed set containing an
        // overflow member loads cleanly against ftype= on every version
        // ("Loaded 1 rules"). Composing (a)+(b): `%s=1,99999999999999999999`
        // types STRING on 1.4.5; with (c): STRING on the STRING attribute
        // ftype= is compatible -> no fapd-E07 at rhel9/rhel10, and (mismatch
        // not universal) none under None either.
        //
        // RED today at all three contexts: pre-fix both members satisfy
        // `looks_int`, so the set types UNSIGNED on rhel9/rhel10 (and
        // INT-by-first-element on rhel8), the mismatch wrongly holds on
        // EVERY version, and E07 fires even under None.
        let src = "%s=1,99999999999999999999\nallow perm=open all : ftype=%s\n";
        for ctx in [
            None,
            Some(TargetVersion::Rhel9),
            Some(TargetVersion::Rhel10),
        ] {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "a mixed in-range+overflow set on ftype= must NOT fire fapd-E07 \
                 under {ctx:?} (1.4.5 types it STRING - any member not fitting \
                 i64 makes the set STRING - and STRING is compatible with \
                 ftype=); got codes={:?}",
                codes(&diags),
            );
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
    // Unknown attribute: fapd-E01's concern, not E07's (`attrs::type_category`
    // returns `None`).
    // -----------------------------------------------------------------

    #[test]
    fn unknown_attribute_setref_is_not_e07() {
        // `frobnicate` is not a real fapolicyd attribute (absent from every
        // table in `attrs::type_category`). A `%set` assigned to it is fapd-E01's
        // concern (unknown attribute name), not E07's (set/attribute TYPE
        // compatibility) - E07 must skip it silently under every context.
        let src = "%t=abc,def\nallow frobnicate=%t : all\n";
        for ctx in ALL_CONTEXTS {
            let diags = lint_src(src, ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "unknown attribute frobnicate= is not fapd-E07's concern under {ctx:?}; \
                 got codes={:?}",
                codes(&diags),
            );
        }
    }

    // -----------------------------------------------------------------
    // Empty set: cannot be typed, so `walk` skips it before calling
    // `fires_for`/`infer_set_type` (which assumes a non-empty slice).
    //
    // The real chumsky grammar requires `set_value.separated_by(',').at_least(1)`
    // (`parser/grammar.rs::set_definition`), so an empty set can never be parsed
    // from a rules-file string. Built directly via the shared `testkit` AST
    // helpers instead (the same hand-built-entries technique
    // `version_target.rs`'s test module uses), matching the shape `macro_map`
    // would hold for a zero-value `SetDefinition`.
    // -----------------------------------------------------------------

    #[test]
    fn empty_set_values_cannot_be_typed_so_e07_does_not_fire() {
        use crate::ast::{Attr, Decision};
        use crate::lints::testkit::{kv_ref, modern_rule, set_def};

        let entries = vec![
            set_def(1, "empty", &[]),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_ref("uid", "empty")],
                vec![Attr::All],
            ),
        ];
        let path = std::path::Path::new("rules.d/50-e07-empty.rules");
        let source = "%empty=\nallow uid=%empty : all\n";
        for ctx in ALL_CONTEXTS {
            let lint_ctx = LintContext {
                target: ctx,
                ..Default::default()
            };
            let diags = crate::lints::lint_with_context(&entries, source, path, &lint_ctx);
            assert_eq!(
                e07_count(&diags),
                0,
                "an empty %set has no element to infer a type from; fapd-E07 must not fire \
                 under {ctx:?}; got codes={:?}",
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

    /// `codes()` names every diagnostic firing on this fixture, not just the
    /// count of fapd-E07-coded ones (`e07_count` alone cannot tell "exactly one
    /// diagnostic total, and it is fapd-E07" apart from "fapd-E07 fires once
    /// alongside some other unrelated diagnostic"). A minimal, unambiguous
    /// string-set-on-uid fixture must fire fapd-E07 and NOTHING else.
    #[test]
    fn string_set_on_uid_is_the_only_diagnostic() {
        let src = "%t=abc,def\nallow uid=%t : all\n";
        let diags = lint_src(src, Some(TargetVersion::Rhel9));
        assert_eq!(
            codes(&diags),
            vec!["fapd-E07"],
            "a minimal string-set-on-uid= fixture must fire fapd-E07 and no other \
             diagnostic under --target rhel9"
        );
    }
}
