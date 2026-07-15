//! Deprecation lint passes: fapd-W07 (`sha256hash=` is deprecated; use
//! `filehash=` instead) and fapd-W12 (`dir=untrusted` is deprecated upstream;
//! currently DORMANT, see [`deprecates_untrusted_dir`]). Future deprecation
//! warnings land here.
//!
//! Every lint here gates ITSELF inside its own helper; see [`walk`].

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};

use super::anchored;
use crate::ast::{Attr, Entry};
use crate::version::TargetVersion;

/// Run every deprecation lint pass over `entries` and return the merged
/// diagnostics.
///
/// `target` makes fapd-W07 version-aware: on `--target rhel8` (fapolicyd 1.3.2)
/// `sha256hash=` is the canonical, NON-deprecated spelling (`filehash=` does not
/// exist there), so W07 is suppressed. Under `None` (implicit 1.4.x) and
/// rhel9/rhel10, the 1.4.2+ deprecation NOTICE applies and W07 still fires.
pub(crate) fn walk(
    entries: &[Entry],
    file: &Path,
    target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    // Each lint gates ITSELF, never here. The rhel8 suppression is W07-SPECIFIC
    // (sha256hash= is canonical there) and the >= 1.6 gate is W12-SPECIFIC, so a
    // lint added to this dispatcher is never silently suppressed by a SIBLING
    // lint's gate. Do not hoist a `target` check into this function.
    let mut diags = w07(entries, file, target);
    diags.extend(w12(entries, file, target));
    diags
}

/// fapd-W07 - deprecated `sha256hash=` attribute name. fapolicyd 1.4.2
/// introduced `filehash=` as the canonical name for the same SHA-256 hex
/// digest; `sha256hash=` is accepted as a `FILE_HASH` alias and still loads
/// (it is NOT rejected). The daemon emits the deprecation notice only ONCE PER
/// START (`object-attr.c:47-59`, guarded by a `static bool warned`), so it
/// cannot point at each offending rule. We deliberately diverge and fire
/// per-attribute instead, so every occurrence is surfaced: emit one fapd-W07
/// (`Severity::Warning`, not Error) for each `Attr::Kv` whose key is literally
/// `sha256hash`. A rule with two such attrs emits two fapd-W07s. The value is
/// NOT inspected here - value-shape validation (64 hex chars) is fapd-E02's
/// concern and runs independently.
fn w07(entries: &[Entry], file: &Path, target: Option<TargetVersion>) -> Vec<Diagnostic> {
    // sha256hash= is canonical (not deprecated) on fapolicyd 1.3.2, and filehash=
    // does not exist there, so W07 must not fire under --target rhel8.
    if target == Some(TargetVersion::Rhel8) {
        return Vec::new();
    }
    let mut diags = Vec::new();
    for entry in entries {
        let Entry::Rule(r) = entry else { continue };
        for attr in r.subject.iter().chain(r.object.iter()) {
            let Attr::Kv { key, .. } = attr else {
                continue;
            };
            // Case-sensitive: only the lowercase form fires fapd-W07.
            // Uppercase variants like `Sha256Hash=` or `SHA256HASH=` are
            // reported by fapd-E01 (unknown attribute) since fapolicyd's
            // parser is case-sensitive on attribute names. Confirmed via
            // fapd-E01__sha256hash-uppercase trap.
            if key == "sha256hash" {
                diags.push(anchored(
                    Severity::Warning,
                    "fapd-W07",
                    r.span.clone(),
                    "deprecated attribute name `sha256hash=`; use `filehash=` instead (fapolicyd 1.4.2+)",
                    file,
                    r.line,
                ));
            }
        }
    }
    diags
}

/// fapd-W12 - `dir=untrusted` is deprecated upstream. VERSION-GATED, and
/// currently DORMANT for every target: see [`deprecates_untrusted_dir`].
///
/// Grounded in the TAGGED upstream v1.6 tree (`refs/tags/v1.6` = a303c4a,
/// deref `v1.6^{}` = 2edb7ae). Every claim below was read from that tree:
///
/// * `src/library/rules.c:86-95` - `warn_deprecated_untrusted_dir` fires iff
///   `(type == EXE_DIR || type == ODIR) && attr_set_check_str(set, "untrusted")`.
///   It keys off the `dir=` attribute TYPE, not the raw value text: a non-`dir`
///   attribute whose value happens to be `untrusted` does NOT warn.
/// * BOTH sides warn: called at `rules.c:597` with side `"subject"`
///   (`EXE_DIR`) and `rules.c:748` with side `"object"` (`ODIR`), each at the shared
///   `finalize:` label that every value-assignment path falls through.
/// * `%set` MEMBERSHIP counts, exactly like a literal: the set-reference
///   branches (`rules.c:394-395` subject, `rules.c:666-667` object) assign the
///   named set (`n->s[i].set = set`) then `goto finalize`, and
///   `attr_set_check_str` (`src/library/attr-sets.c:412-422`) searches THE
///   SET'S tree for a member equal to `"untrusted"`. So `dir=%s` where `%s`
///   lists `untrusted` warns.
/// * Matching SEMANTICS are unchanged: the helper is a `static void` whose only
///   effect is `msg(LOG_WARNING, ...)`. It never touches `n->s[i].set` /
///   `n->o[i].set`, so the shipped `dir=untrusted` parity (#136) and the pinned
///   absent-path behavior (#142) remain correct.
/// * `doc/fapolicyd.rules.5:83-92` - `untrusted` is "deprecated in favor of
///   using object trust with execute permission when writing rules"; rules that
///   use `dir=untrusted` "emit a deprecation warning when parsed, and this
///   compatibility option will be removed in a future release".
///
/// The gate lives INSIDE this helper, never in [`walk`], per the dispatcher
/// contract documented there.
fn w12(entries: &[Entry], file: &Path, target: Option<TargetVersion>) -> Vec<Diagnostic> {
    if !deprecates_untrusted_dir(target) {
        return Vec::new();
    }
    w12_detect(entries, file)
}

/// Whether the targeted fapolicyd deprecates `dir=untrusted` (upstream >= 1.6).
///
/// DORMANT BY CONSTRUCTION - this is `false` for EVERY input today, so fapd-W12
/// never fires. [`TargetVersion`] is RHEL-keyed and its newest variant
/// (`Rhel10`) maps to fapolicyd 1.4.5 (`version.rs::fapolicyd_version`), so no
/// target reaches 1.6; `None` is the implicit 1.4.x dialect and is older still.
/// fapd-W12 is therefore correct-but-inert until a 1.6-capable target variant
/// lands. Adding that variant now is deliberately OUT OF SCOPE (no speculative
/// future variants); when it lands, this predicate is the single place to
/// change, and the frozen `w12_is_dormant_*` tests are the thing to revisit.
fn deprecates_untrusted_dir(_target: Option<TargetVersion>) -> bool {
    false
}

/// Detection seam for fapd-W12, deliberately SEPARATE from [`w12`]'s version
/// gate so the detection logic is directly testable while the lint is dormant.
/// Routing detection through the gate would make every fapd-W12 test vacuous
/// (a "no finding" assertion passes against an empty implementation), so the
/// frozen tests drive this function directly.
///
/// Contract (mirrors upstream's scope exactly; see [`w12`] for citations):
/// emit one `Severity::Warning` fapd-W12 per offending `dir=` ATTRIBUTE, on
/// either side, anchored at the rule.
///
/// A `dir=` attribute is offending iff `untrusted` is an EXACT member of the
/// value's MEMBER SET. Upstream is set-backed on BOTH paths, so there are three
/// surface forms and all three reduce to the same membership test:
///
/// 1. the literal `dir=untrusted` (a one-member set);
/// 2. an inline comma list, `dir=/usr/bin/,untrusted` -- upstream treats `dir=`
///    (`EXE_DIR` at rules.c:565, `ODIR` at rules.c:711) as "regular strings ->
///    multiple value" (rules.c:562) and splits the raw value with
///    `strtok_r(tmp, ",", &saved)` (rules.c:572-578 subject / 721-727 object),
///    appending each comma token to a STRING set. This crate's parser does NOT
///    split on `,` (grammar.rs:86-95 filters only whitespace and `:`), so
///    `/usr/bin/,untrusted` arrives as ONE [`AttrValue::Str`] and this function
///    owns the split. Matching the whole VALUE instead of each member is a
///    FALSE NEGATIVE against upstream;
/// 3. a `%set` reference whose definition contains `untrusted` as a member.
///
/// Membership is EXACT, case-sensitive, whole-member: upstream's
/// `attr_set_check_str(set, "untrusted")` (rules.c:90) is an `avl_search`
/// (attr-sets.c:412-422) over a tree ordered by `strcmp_cb` = plain `strcmp`
/// (attr-sets.c:71-74). So `dir=/opt/untrusted/` (substring) and `dir=UNTRUSTED`
/// (case) do NOT warn. The set's NAME is never consulted -- only its members --
/// so `dir=%untrusted` does not warn unless the set DEFINES an `untrusted`
/// member. The attribute KEY is case-sensitive too (`subj_name_to_val` is a
/// `strcmp` table scan, subject-attr.c:75/81), so `Dir=` is not `EXE_DIR`;
/// fapd-E01 owns unknown attribute names (same division as fapd-W07 above).
///
/// An undefined `%set` emits nothing (fapd-E03 owns undefined-macro reporting).
fn w12_detect(_entries: &[Entry], _file: &Path) -> Vec<Diagnostic> {
    // NOT IMPLEMENTED. The frozen fapd-W12 detection tests are RED against this
    // stub; the implementer replaces this body. `dir_slash::walk` is the
    // structural template: iterate subject+object, match `AttrValue::Str` for
    // the literal/comma-list and `AttrValue::SetRef` expanded through
    // `subsume::build_macro_map`. Note the deprecation module does not expand
    // sets today, so set expansion is NEW behavior here.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{AttrValue, Decision};
    use crate::lints::testkit::{kv, kv_int, kv_ref, legacy_rule, modern_rule, p, set_def};

    // -----------------------------------------------------------------
    // fapd-W07 helper-level unit tests. Pin the per-attribute walker so
    // each branch (sha256hash hit, filehash silent, multi-fire in one rule,
    // key-only check ignoring value shape, severity is Warning not Error,
    // SetDefinition skipped) is exercised independently of the snapshot +
    // proptest suites. A mutant that flips the key comparison, drops the
    // Severity, broadens the key match (e.g. matching any *hash* key),
    // or fires on Entry::SetDefinition dies here.
    // -----------------------------------------------------------------

    /// 64-char canonical hex for use in fapd-W07 unit tests. fapd-W07 ignores
    /// the value but using realistic content keeps the tests readable.
    const HEX64: &str = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

    #[test]
    fn w07_emits_on_sha256hash_attr() {
        // `sha256hash=<64hex>` -> 1 fapd-W07 with Severity::Warning.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
                span: 0..0,
            }],
            vec![Attr::Kv {
                key: "exe".into(),
                value: AttrValue::Str("/foo".into()),
                span: 0..0,
            }],
        )];
        let diags = w07(&entries, &p(), None);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code.as_ref(), "fapd-W07");
        assert!(
            diags[0].message.contains("sha256hash"),
            "message must name the deprecated attribute: {}",
            diags[0].message,
        );
        assert!(
            diags[0].message.contains("filehash"),
            "message must recommend the replacement attribute: {}",
            diags[0].message,
        );
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn w07_silent_on_filehash_attr() {
        // `filehash=<64hex>` is the modern canonical spelling; no fapd-W07.
        // Kills a mutation that broadens the key match to "any *hash key"
        // or inverts the key comparison.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "filehash".into(),
                value: AttrValue::Str(HEX64.into()),
                span: 0..0,
            }],
            vec![Attr::Kv {
                key: "exe".into(),
                value: AttrValue::Str("/foo".into()),
                span: 0..0,
            }],
        )];
        let diags = w07(&entries, &p(), None);
        assert!(
            diags.is_empty(),
            "filehash= is the modern spelling; fapd-W07 must not fire: {diags:?}",
        );
    }

    #[test]
    fn w07_diagnostics_identical_for_legacy_and_modern_flavor() {
        // #295: fapd-W07 keys off the attribute NAME, never `Rule.syntax` (the
        // rhel8 suppression is by `--target`, not flavor), so a legacy-parsed
        // `sha256hash=` rule must produce the same fapd-W07 output as the modern
        // form. The W07 output tests previously exercised only `modern_rule`.
        let subj = || {
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
                span: 0..0,
            }]
        };
        let obj = || {
            vec![Attr::Kv {
                key: "exe".into(),
                value: AttrValue::Str("/foo".into()),
                span: 0..0,
            }]
        };
        let modern = w07(
            &[modern_rule(1, Decision::Allow, None, subj(), obj())],
            &p(),
            None,
        );
        let legacy = w07(
            &[legacy_rule(1, Decision::Allow, None, subj(), obj())],
            &p(),
            None,
        );
        // Absolute behavior on the legacy-flavored rule.
        assert_eq!(legacy.len(), 1, "legacy sha256hash= must fire one fapd-W07");
        assert_eq!(legacy[0].code.as_ref(), "fapd-W07");
        assert_eq!(legacy[0].severity, Severity::Warning);
        // Flavor-invariance: identical to the modern form.
        assert_eq!(
            modern, legacy,
            "fapd-W07 diagnostics must not depend on SyntaxFlavor",
        );
    }

    #[test]
    fn w07_walker_emits_one_per_offending_attr() {
        // A rule with TWO `sha256hash=` attrs (one subject, one object) ->
        // 2 fapd-W07 diagnostics. Kills a mutation that deduplicates by rule
        // or short-circuits after the first hit per rule.
        let entries = vec![modern_rule(
            5,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
                span: 0..0,
            }],
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
                span: 0..0,
            }],
        )];
        let diags = w07(&entries, &p(), None);
        assert_eq!(
            diags.len(),
            2,
            "expected one fapd-W07 per offending attr in the rule: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-W07"));
        assert!(
            diags
                .iter()
                .all(|d| d.source_id == Some("/tmp/test.rules".to_string()))
        );
    }

    #[test]
    fn w07_ignores_value_only_matches_key() {
        // fapd-W07 fires on the attribute NAME regardless of value shape; even
        // a clearly-invalid hash (a 3-char string, an Int, a SetRef) fires
        // fapd-W07. Value-shape validation is fapd-E02's concern, not
        // fapd-W07's. Kills a mutation that adds value validation to fapd-W07.
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "sha256hash".into(),
                    value: AttrValue::Str("abc".into()), // bogus 3-char value
                    span: 0..0,
                }],
                vec![Attr::All],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "sha256hash".into(),
                    value: AttrValue::Int(12_345), // numeric value
                    span: 0..0,
                }],
                vec![Attr::All],
            ),
            modern_rule(
                3,
                Decision::Allow,
                None,
                vec![Attr::Kv {
                    key: "sha256hash".into(),
                    value: AttrValue::SetRef("my_hashes".into()), // macro ref
                    span: 0..0,
                }],
                vec![Attr::All],
            ),
        ];
        let diags = w07(&entries, &p(), None);
        assert_eq!(
            diags.len(),
            3,
            "fapd-W07 fires on the key regardless of value shape (Str/Int/SetRef): {diags:?}",
        );
    }

    #[test]
    fn w07_severity_is_warning() {
        // Pin severity = Warning (not Error). Kills a mutation that
        // upgrades fapd-W07 to Error or downgrades to a non-Warning variant.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
                span: 0..0,
            }],
            vec![Attr::All],
        )];
        let diags = w07(&entries, &p(), None);
        assert_eq!(diags.len(), 1);
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "fapd-W07 must be Severity::Warning (not Error/Fatal/Info/Hint)",
        );
    }

    #[test]
    fn w07_walker_silent_on_setdefinition() {
        // SetDefinition entries (`%mymacro=...`) are never inspected by
        // fapd-W07; the walker only looks at Entry::Rule. Kills a mutation
        // that fires fapd-W07 on any Entry containing the string "sha256hash"
        // (e.g. a SetDefinition with that literal name).
        let entries = vec![Entry::SetDefinition {
            name: "sha256hash".to_string(),
            values: vec!["1".to_string(), "2".to_string()],
            line: 1,
            span: rulesteward_core::span(0, 0),
        }];
        let diags = w07(&entries, &p(), None);
        assert!(
            diags.is_empty(),
            "SetDefinition entries are never fapd-W07's concern: {diags:?}",
        );
    }

    // ===================================================================
    // fapd-W12 - `dir=untrusted` deprecation (upstream v1.6 = 2edb7ae).
    //
    // The lint is DORMANT: no TargetVersion maps to fapolicyd >= 1.6, so it
    // fires for no target today. That makes any "no finding" assertion through
    // the public path VACUOUS on its own (it holds against an empty impl), so
    // these tests pin DETECTION and the GATE separately:
    //
    //   * `w12_detect_*` drive the detection seam DIRECTLY, bypassing the gate.
    //     These carry the RED: they fail against the `w12_detect` stub.
    //   * `w12_is_dormant_*` assert detection FIRES and the gate then suppresses
    //     it, so dormancy is proven to be the gate's doing rather than a missing
    //     detector. These are RED pre-impl too (the precondition fails).
    //   * `walk_gates_each_lint_independently` pins the dispatcher contract.
    //
    // Upstream scope being mirrored (see `w12_detect` for full file:line
    // citations): fires on `dir=` (EXE_DIR/ODIR) on EITHER side iff `untrusted`
    // is an EXACT member of the value's member set. Upstream is set-backed on
    // BOTH paths -- a raw `dir=` value is comma-split by `strtok_r` into a
    // STRING set (rules.c:562/572-578/721-727) and then searched with
    // `attr_set_check_str` -> `avl_search` over plain `strcmp` (rules.c:90,
    // attr-sets.c:412-422, attr-sets.c:71-74). Three consequences the negative
    // fixtures below pin, because each one is a plausible wrong impl that the
    // positive fixtures alone do NOT exclude:
    //
    //   * `contains("untrusted")` is WRONG   -> `dir=/opt/untrusted/` must NOT fire
    //   * case-insensitive matching is WRONG -> `dir=UNTRUSTED` must NOT fire
    //   * whole-VALUE matching is WRONG      -> `dir=/usr/bin/,untrusted` MUST fire
    //   * keying off the set NAME is WRONG   -> `dir=%untrusted` (members exclude
    //                                            `untrusted`) must NOT fire
    // ===================================================================

    /// Every `--target` the CLI can produce today, plus the implicit `None`
    /// dialect. fapd-W12 must be dormant under EVERY one. Mirrors
    /// `snapshot_test::version_target_matrix`.
    ///
    /// This is hand-written, so it cannot itself notice a NEW `TargetVersion`
    /// variant -- a future `Rhel11` would simply be skipped by every dormancy
    /// sweep below, silently. `all_targets_is_exhaustive` closes that: it is an
    /// exhaustive `match`, so adding a variant is a COMPILE error here rather
    /// than a quietly-narrowed test matrix.
    const ALL_TARGETS: [Option<TargetVersion>; 4] = [
        None,
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
    ];

    #[test]
    fn all_targets_is_exhaustive() {
        // The `match` is the assertion: it does not compile if a `TargetVersion`
        // variant exists that `ALL_TARGETS` omits. When a 1.6-capable variant
        // lands, this fails to build and forces both `ALL_TARGETS` and the
        // `deprecates_untrusted_dir` gate to be revisited together -- which is
        // exactly the moment fapd-W12 stops being dormant.
        for target in ALL_TARGETS {
            let Some(t) = target else { continue };
            let listed = match t {
                TargetVersion::Rhel8 | TargetVersion::Rhel9 | TargetVersion::Rhel10 => true,
            };
            assert!(listed, "unreachable while the match above is exhaustive");
        }
        assert_eq!(
            ALL_TARGETS.iter().filter(|t| t.is_some()).count(),
            3,
            "ALL_TARGETS must list every TargetVersion variant; if a new variant \
             landed, add it here AND revisit fapd-W12's dormancy gate",
        );
    }

    /// A rule whose SUBJECT carries `dir=untrusted` (upstream `EXE_DIR`).
    fn subject_dir_untrusted() -> Vec<Entry> {
        vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![kv("dir", "untrusted")],
            vec![Attr::All],
        )]
    }

    /// A rule whose OBJECT carries `dir=untrusted` (upstream `ODIR`).
    fn object_dir_untrusted() -> Vec<Entry> {
        vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![kv_int("uid", 0)],
            vec![kv("dir", "untrusted")],
        )]
    }

    fn w12_codes(diags: &[Diagnostic]) -> Vec<&str> {
        diags.iter().map(|d| d.code.as_ref()).collect()
    }

    #[test]
    fn w12_detect_fires_on_subject_dir_untrusted() {
        // upstream rules.c:597 calls the warner with side="subject" (EXE_DIR).
        let entries = subject_dir_untrusted();
        let diags = w12_detect(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "subject `dir=untrusted` must produce exactly one fapd-W12: {diags:?}",
        );
        assert_eq!(diags[0].code.as_ref(), "fapd-W12");
        assert_eq!(
            diags[0].severity,
            Severity::Warning,
            "fapd-W12 must be Severity::Warning (not Error/Fatal/Info/Hint)",
        );
        assert_eq!(diags[0].line, 1, "fapd-W12 must anchor at the rule's line");
        assert_eq!(diags[0].source_id, Some("/tmp/test.rules".to_string()));
    }

    #[test]
    fn w12_detect_fires_on_object_dir_untrusted() {
        // upstream rules.c:748 calls the warner with side="object" (ODIR). A
        // subject-only implementation dies here.
        let entries = object_dir_untrusted();
        let diags = w12_detect(&entries, &p());
        assert_eq!(
            diags.len(),
            1,
            "object `dir=untrusted` must produce exactly one fapd-W12: {diags:?}",
        );
        assert_eq!(diags[0].code.as_ref(), "fapd-W12");
        assert_eq!(diags[0].severity, Severity::Warning);
    }

    #[test]
    fn w12_detect_message_names_the_construct_and_the_replacement() {
        // Mirrors the fapd-W07 message contract (names the deprecated thing and
        // its replacement). Upstream's own LOG_WARNING text (rules.c:91-94) is
        // "dir=untrusted is deprecated and will be removed in a future release"
        // - it does NOT name an alternative; fapolicyd.rules(5):85-86 does:
        // `untrusted` is "deprecated in favor of using object trust with
        // execute permission". Assertions are on substrings, not the whole
        // sentence, so the implementer keeps wording latitude.
        let diags = w12_detect(&subject_dir_untrusted(), &p());
        assert_eq!(diags.len(), 1, "precondition: detection must fire");
        let msg = &diags[0].message;
        assert!(
            msg.contains("untrusted"),
            "message must name the deprecated construct: {msg}",
        );
        assert!(
            msg.contains("deprecated"),
            "message must say the construct is deprecated: {msg}",
        );
        assert!(
            msg.contains("remov"),
            "message must mirror upstream's scheduled-for-removal framing \
             (rules.c:93 'will be removed in a future release'): {msg}",
        );
        // NOTE: a bare `msg.contains("trust")` would be VACUOUS - the word
        // "untrusted", asserted above, already contains "trust". Strip every
        // occurrence of the deprecated keyword first, so this can only pass if
        // the replacement is named INDEPENDENTLY of the construct's own name.
        assert!(
            msg.replace("untrusted", "").contains("trust"),
            "message must point at the object `trust` replacement, in words \
             other than `untrusted` itself: {msg}",
        );
    }

    #[test]
    fn w12_detect_fires_via_set_membership() {
        // upstream checks the SET's tree for a member "untrusted"
        // (attr-sets.c:412-422), reached from the set-reference branches at
        // rules.c:394-395 / 666-667. So `dir=%dirs` where %dirs lists
        // `untrusted` warns exactly like the literal. An implementation that
        // only matches AttrValue::Str dies here.
        for values in [
            // Last position (2 members).
            vec!["/usr/bin/", "untrusted"],
            // Middle position (>=3 members, `untrusted` neither first nor
            // last). This fixture closes the POSITIONAL axis of the
            // not-whole-member defect family on the set path too: it kills
            // every positional shortcut - first-only, last-only,
            // first-or-last-only - forcing "check every member" like
            // upstream's `avl_search` (attr-sets.c:412-422). It does NOT by
            // itself exclude a per-member COMPARISON shortcut (e.g. a
            // per-member `starts_with("untrusted")` still checks every
            // member and so still passes this positive fixture); that axis
            // is pinned separately by the CONTAINS / SUFFIX / PREFIX
            // negative fixtures ("set member", "set member, no trailing
            // slash", "set member, prefix (not suffix)") in
            // `w12_detect_silent_on_untrusted_as_a_path_substring`.
            vec!["/a/", "untrusted", "/b/"],
        ] {
            let entries = vec![
                set_def(1, "dirs", &values),
                modern_rule(
                    2,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv_ref("dir", "dirs")],
                ),
            ];
            let diags = w12_detect(&entries, &p());
            assert_eq!(
                diags.len(),
                1,
                "a `dir=%set` whose members include `untrusted` must fire one fapd-W12: {diags:?}",
            );
            assert_eq!(diags[0].code.as_ref(), "fapd-W12");
            assert_eq!(
                diags[0].line, 2,
                "fapd-W12 must anchor at the referencing RULE, not the set definition",
            );
        }
    }

    #[test]
    fn w12_detect_fires_on_inline_comma_list_member() {
        // Upstream comma-splits a raw `dir=` value into a STRING set before the
        // membership test: `dir=` is EXE_DIR (rules.c:565) / ODIR (rules.c:711),
        // both in the "regular strings -> multiple value" case (rules.c:562)
        // whose body is `strtok_r(tmp, ",", &saved)` appending each token
        // (rules.c:572-578 subject, 721-727 object). `attr_set_check_str` then
        // finds the `untrusted` MEMBER, so upstream WARNS on this line.
        //
        // RuleSteward's parser does not split on `,` (grammar.rs:86-95 filters
        // only whitespace and `:`), so this arrives as ONE AttrValue::Str
        // "/usr/bin/,untrusted". An impl that compares the whole VALUE to
        // "untrusted" is therefore a FALSE NEGATIVE and dies here.
        for entries in [
            vec![modern_rule(
                3,
                Decision::Allow,
                None,
                vec![kv("dir", "/usr/bin/,untrusted")],
                vec![Attr::All],
            )],
            vec![modern_rule(
                3,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("dir", "/usr/bin/,untrusted")],
            )],
            // Non-final position: `untrusted` is the FIRST member, not the
            // last. Kills any impl that only inspects the final comma
            // segment (e.g. `split(',').next_back()`) or the whole-value
            // tail (`ends_with("untrusted")`) instead of splitting on `,`
            // and checking members.
            vec![modern_rule(
                3,
                Decision::Allow,
                None,
                vec![kv("dir", "untrusted,/usr/bin/")],
                vec![Attr::All],
            )],
            // Middle position (>=3 members, `untrusted` neither first nor
            // last). This fixture closes the POSITIONAL axis of the
            // not-whole-member defect family: it kills every positional
            // shortcut - whole-value ends_with, whole-value starts_with,
            // next_back-only, first-or-last-only - forcing "split on `,`
            // and check every member" (rules.c:572-578 strtok_r). (Whole-
            // value `contains` also happens to fire correctly here since
            // the substring IS present in "/a/,untrusted,/b/"; that
            // shortcut is killed instead by
            // `w12_detect_silent_on_comma_list_without_an_untrusted_member`
            // and `w12_detect_silent_on_untrusted_as_a_path_substring`.) It
            // does NOT by itself exclude a per-member COMPARISON shortcut
            // (e.g. per-member `starts_with("untrusted")` also checks every
            // member and so also passes this positive fixture); that axis
            // is pinned separately by the negative prefix fixture in
            // `w12_detect_silent_on_untrusted_as_a_path_substring`.
            vec![modern_rule(
                3,
                Decision::Allow,
                None,
                vec![kv("dir", "/a/,untrusted,/b/")],
                vec![Attr::All],
            )],
        ] {
            let diags = w12_detect(&entries, &p());
            assert_eq!(
                diags.len(),
                1,
                "`untrusted` as an inline comma-list MEMBER must fire one \
                 fapd-W12, as upstream does after strtok_r: {diags:?}",
            );
            assert_eq!(diags[0].code.as_ref(), "fapd-W12");
            assert_eq!(diags[0].line, 3);
        }
    }

    #[test]
    fn w12_detect_silent_on_comma_list_without_an_untrusted_member() {
        // The comma split must not degrade into a substring search. Every member
        // here is a path; none is an exact `untrusted`, so no token matches and
        // upstream stays silent -- even though the raw value contains the
        // substring twice.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![kv("dir", "/opt/untrusted/,/srv/untrusted-cache/")],
            vec![Attr::All],
        )];
        let diags = w12_detect(&entries, &p());
        assert!(
            diags.is_empty(),
            "no comma-list member is an exact `untrusted`, so fapd-W12 must \
             stay silent: {diags:?}",
        );
    }

    #[test]
    fn w12_detect_silent_on_untrusted_as_a_path_substring() {
        // THE anti-substring pin, covering THREE comparison-shortcut
        // directions against a member that merely EMBEDS the word
        // "untrusted" rather than EQUALLING it:
        //   - CONTAINS: the word sits in the middle of a longer member,
        //     neither a prefix nor a suffix, e.g. `/opt/untrusted/` (kills
        //     `value.contains("untrusted")`);
        //   - SUFFIX: a member ENDING in "untrusted" with no trailing
        //     slash, e.g. `/opt/untrusted` (kills
        //     `value.ends_with("untrusted")`) -- `/opt/untrusted/` above is
        //     NOT a suffix example, since it ends in `/`, not `untrusted`;
        //     an earlier round mislabeled that fixture as covering the
        //     SUFFIX direction on the `%set` path too, which left the set
        //     path's suffix direction untested until the "set member, no
        //     trailing slash" case below was added;
        //   - PREFIX: a member STARTING WITH "untrusted", e.g. `untrusted/`
        //     (kills `value.starts_with("untrusted")`).
        // All of these are real directory paths that happen to embed, end
        // with, or start with the word. Upstream's membership test is an
        // avl_search over plain `strcmp` (rules.c:90 -> attr-sets.c:412-422
        // -> attr-sets.c:71-74), which is exact whole-member equality --
        // upstream even ships a SEPARATE `attr_set_check_pstr` ("check if
        // any set entry PREFIXES a string", attr-sets.c:424) that the
        // warner deliberately does NOT call -- so any of the three
        // shortcuts above fires a false fapd-W12 on one of these fixtures.
        // Each direction is pinned on BOTH the literal path and the `%set`
        // path: CONTAINS via "subject literal" + "object literal" + "set
        // member"; SUFFIX via "subject literal, no trailing slash" + "set
        // member, no trailing slash"; PREFIX via "subject literal, prefix
        // (not suffix)" + "set member, prefix (not suffix)".
        let cases: [(&str, Vec<Entry>); 7] = [
            (
                "subject literal",
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv("dir", "/opt/untrusted/")],
                    vec![Attr::All],
                )],
            ),
            (
                // No trailing slash: the path's LAST path-segment is exactly
                // "untrusted", so a `value.ends_with("untrusted")` impl fires
                // a false fapd-W12 here even though it correctly avoided the
                // simpler `contains` mistake. Same defect family, one notch
                // narrower. Upstream's strcmp still sees the whole member
                // "/opt/untrusted" != "untrusted", so it stays silent.
                "subject literal, no trailing slash",
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv("dir", "/opt/untrusted")],
                    vec![Attr::All],
                )],
            ),
            (
                // Set-path mirror of "subject literal, no trailing slash"
                // above (SUFFIX direction), added round 7. Before this
                // fixture, the set path's only suffix-ish member was
                // `/opt/untrusted/` (the CONTAINS case, below), which does
                // NOT exercise `ends_with("untrusted")` since it ends in
                // `/`. This member's LAST path-segment is exactly
                // "untrusted" with no trailing slash, so a `SetRef` impl
                // computing `member.ends_with("untrusted")` fires a false
                // fapd-W12 here. Upstream's strcmp still sees the whole
                // member "/opt/untrusted" != "untrusted", so it stays
                // silent.
                "set member, no trailing slash",
                vec![
                    set_def(1, "dirs", &["/opt/untrusted", "/usr/bin/"]),
                    modern_rule(
                        2,
                        Decision::Allow,
                        None,
                        vec![kv_int("uid", 0)],
                        vec![kv_ref("dir", "dirs")],
                    ),
                ],
            ),
            (
                "object literal",
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv("dir", "/opt/untrusted/")],
                )],
            ),
            (
                "set member",
                vec![
                    set_def(1, "dirs", &["/opt/untrusted/", "/usr/bin/"]),
                    modern_rule(
                        2,
                        Decision::Allow,
                        None,
                        vec![kv_int("uid", 0)],
                        vec![kv_ref("dir", "dirs")],
                    ),
                ],
            ),
            (
                // PREFIX direction: `untrusted/` is a member that STARTS WITH
                // `untrusted` without EQUALLING it - `dir=untrusted` plus the
                // trailing slash this very tool's fapd-W08 advice pushes
                // everywhere else. A `value.starts_with("untrusted")` impl
                // fires a false fapd-W12 here even though it correctly
                // avoided the `ends_with`/`contains` mistakes above. rules.c
                // has no `dir=` path validation (a grep of rules.c for
                // `must start` / `absolute` / `[0] != '/'` returns nothing),
                // so this is a realistic operator value, not an unreachable
                // one. Upstream's strcmp still sees the whole member
                // "untrusted/" != "untrusted", so it stays silent.
                "subject literal, prefix (not suffix)",
                vec![modern_rule(
                    1,
                    Decision::Allow,
                    None,
                    vec![kv("dir", "untrusted/")],
                    vec![Attr::All],
                )],
            ),
            (
                // Same PREFIX direction as above, through a `%set` member
                // instead of a literal. Kills a `SetRef` impl that compares
                // each member with `starts_with("untrusted")` instead of the
                // upstream-exact `attr_set_check_str` equality.
                "set member, prefix (not suffix)",
                vec![
                    set_def(1, "dirs", &["untrusted/", "/usr/bin/"]),
                    modern_rule(
                        2,
                        Decision::Allow,
                        None,
                        vec![kv_int("uid", 0)],
                        vec![kv_ref("dir", "dirs")],
                    ),
                ],
            ),
        ];
        for (label, entries) in cases {
            let diags = w12_detect(&entries, &p());
            assert!(
                diags.is_empty(),
                "a member that only embeds, ends with, or starts with the \
                 word \"untrusted\" is not an EXACT member; upstream \
                 matches whole members via strcmp, so fapd-W12 must not \
                 fire ({label}): {diags:?}",
            );
        }
    }

    #[test]
    fn w12_detect_is_case_sensitive_on_the_value() {
        // Upstream orders the set's tree with `strcmp_cb` = plain `strcmp`
        // (attr-sets.c:71-74), so the search is case-SENSITIVE: only the exact
        // lowercase `untrusted` is deprecated. An impl that lowercases the value
        // before comparing fires false positives here. Same defect class as #262
        // (auditd arch-coverage), where a case-insensitivity miss was caught.
        for value in ["UNTRUSTED", "Untrusted", "unTrusted"] {
            let entries = vec![modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv("dir", value)],
                vec![Attr::All],
            )];
            let diags = w12_detect(&entries, &p());
            assert!(
                diags.is_empty(),
                "fapolicyd matches `untrusted` with strcmp, so `dir={value}` is \
                 NOT the deprecated construct: {diags:?}",
            );
        }
    }

    #[test]
    fn w12_detect_is_case_sensitive_on_the_value_via_set_membership() {
        // Set-path mirror of `w12_detect_is_case_sensitive_on_the_value`
        // above, added round 7. Upstream's per-member search
        // (`attr_set_check_str` -> `avl_search` over `strcmp_cb` = plain
        // `strcmp`, attr-sets.c:71-74/412-422) is the SAME case-sensitive
        // comparison regardless of whether the member came from a literal
        // `dir=` value or a `%set` definition, so a set member spelled
        // `UNTRUSTED` / `Untrusted` / `unTrusted` must stay silent exactly
        // like the literal. Before this fixture, the set path's case
        // handling was entirely unpinned: a `SetRef` impl comparing
        // members with `eq_ignore_ascii_case("untrusted")` passed the
        // whole suite up to this point.
        for value in ["UNTRUSTED", "Untrusted", "unTrusted"] {
            let entries = vec![
                set_def(1, "dirs", &[value]),
                modern_rule(
                    2,
                    Decision::Allow,
                    None,
                    vec![kv_int("uid", 0)],
                    vec![kv_ref("dir", "dirs")],
                ),
            ];
            let diags = w12_detect(&entries, &p());
            assert!(
                diags.is_empty(),
                "fapolicyd matches `untrusted` with strcmp, so a set member \
                 `{value}` is NOT the deprecated construct: {diags:?}",
            );
        }
    }

    #[test]
    fn w12_detect_is_case_sensitive_on_the_attribute_key() {
        // The attribute NAME is resolved by a `strcmp` table scan
        // (`subj_name_to_val`, subject-attr.c:75/81), so `Dir=` never resolves
        // to EXE_DIR and cannot be the deprecated construct. fapd-E01 owns
        // unknown attribute names -- the same division fapd-W07 documents for
        // `Sha256Hash=` above.
        for key in ["Dir", "DIR"] {
            let entries = vec![modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv(key, "untrusted")],
                vec![Attr::All],
            )];
            let diags = w12_detect(&entries, &p());
            assert!(
                diags.is_empty(),
                "`{key}=` is not fapolicyd's case-sensitive `dir=` keyword, so \
                 fapd-W12 must not fire (fapd-E01 owns unknown attrs): {diags:?}",
            );
        }
    }

    #[test]
    fn w12_detect_silent_on_set_named_untrusted_whose_members_exclude_it() {
        // Upstream keys PURELY on set MEMBERSHIP: `attr_set_check_str` searches
        // the set's tree (rules.c:90 -> attr-sets.c:412-422). The set's NAME is
        // never consulted. So a set merely CALLED `untrusted`, whose members are
        // ordinary paths, is not the deprecated construct. Kills an impl that
        // matches `SetRef(name) => name == "untrusted" || members.contains(..)`.
        let entries = vec![
            set_def(1, "untrusted", &["/usr/bin/"]),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv_ref("dir", "untrusted")],
            ),
        ];
        let diags = w12_detect(&entries, &p());
        assert!(
            diags.is_empty(),
            "fapd-W12 keys on set MEMBERSHIP, never the set's name; `%untrusted` \
             expands to `/usr/bin/` and must not fire: {diags:?}",
        );
    }

    #[test]
    fn w12_detect_fires_once_per_offending_attr_on_the_same_side() {
        // Sibling of `w12_detect_fires_once_per_offending_attr`, which puts one
        // offending attr on EACH side and so cannot distinguish per-ATTRIBUTE
        // from per-SIDE: an impl doing `.any()` per side and pushing once passes
        // it with 2 diagnostics. Upstream calls the warner from each side's
        // `finalize:` label (rules.c:597 subject / rules.c:748 object), i.e.
        // once per assign_subject/assign_object CALL = once per ATTRIBUTE. Two
        // offending attrs on ONE side must therefore yield 2 diagnostics.
        let entries = vec![modern_rule(
            5,
            Decision::Allow,
            None,
            vec![kv("dir", "untrusted"), kv("dir", "untrusted")],
            vec![Attr::All],
        )];
        let diags = w12_detect(&entries, &p());
        assert_eq!(
            diags.len(),
            2,
            "upstream warns once per offending `dir=` ATTRIBUTE, not once per \
             side: two on the subject must give two fapd-W12: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-W12"));
        assert!(diags.iter().all(|d| d.line == 5));
    }

    #[test]
    fn w12_detect_fires_once_per_offending_attr() {
        // Both sides offending in ONE rule -> 2 diagnostics: upstream warns
        // once per assigned attribute (the warner sits at each side's
        // `finalize:` label), not once per rule. Kills a mutation that
        // deduplicates by rule or short-circuits after the first hit.
        let entries = vec![modern_rule(
            7,
            Decision::Allow,
            None,
            vec![kv("dir", "untrusted")],
            vec![kv("dir", "untrusted")],
        )];
        let diags = w12_detect(&entries, &p());
        assert_eq!(
            diags.len(),
            2,
            "expected one fapd-W12 per offending `dir=` attr in the rule: {diags:?}",
        );
        assert!(diags.iter().all(|d| d.code.as_ref() == "fapd-W12"));
        assert!(diags.iter().all(|d| d.line == 7));
    }

    #[test]
    fn w12_detect_silent_on_plain_dir_path() {
        // The overwhelmingly common case. Kills an always-fire implementation.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![kv_int("uid", 0)],
            vec![kv("dir", "/usr/bin/")],
        )];
        let diags = w12_detect(&entries, &p());
        assert!(
            diags.is_empty(),
            "a plain `dir=` path is not deprecated: {diags:?}",
        );
    }

    #[test]
    fn w12_detect_silent_on_other_dir_keywords() {
        // fapolicyd.rules(5) documents THREE dir= keywords; upstream deprecates
        // ONLY `untrusted` (rules.c:90 compares against the literal). Kills an
        // implementation that fires on any non-path dir= keyword (e.g. one that
        // reuses dir_slash's DIR_KEYWORDS list as the trigger).
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("dir", "execdirs")],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv("dir", "systemdirs")],
                vec![Attr::All],
            ),
        ];
        let diags = w12_detect(&entries, &p());
        assert!(
            diags.is_empty(),
            "only `untrusted` is deprecated; execdirs/systemdirs are not: {diags:?}",
        );
    }

    #[test]
    fn w12_detect_silent_on_non_dir_attr_with_untrusted_value() {
        // upstream gates on the attribute TYPE (`type == EXE_DIR || type ==
        // ODIR`, rules.c:89) BEFORE inspecting the value, so `untrusted` as the
        // value of some OTHER attribute is not deprecated. Kills an
        // implementation that greps any attribute value for "untrusted".
        //
        // `dirfoo=untrusted` (rule 3) additionally kills a key-PREFIX match
        // (`key.starts_with("dir")` substituted for `key == "dir"`): `dirfoo`
        // is absent from subject-attr.c's table2 (v1.6:53-65) and from
        // object-attr.c (v1.6:35-41), so it never resolves to EXE_DIR/ODIR and
        // rules.c:89's `type ==` guard cannot fire. The rule IS parseable and
        // fapd-E01 owns the unknown attribute (same division the
        // case-sensitivity test above documents for `Dir=`/`DIR=`).
        let entries = vec![
            modern_rule(
                1,
                Decision::Allow,
                None,
                vec![kv("exe", "untrusted")],
                vec![Attr::All],
            ),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("ftype", "untrusted")],
            ),
            modern_rule(
                3,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv("dirfoo", "untrusted")],
            ),
        ];
        let diags = w12_detect(&entries, &p());
        assert!(
            diags.is_empty(),
            "fapd-W12 keys off the exact `dir=` attribute, not a value-text \
             grep or a key PREFIX match: {diags:?}",
        );
    }

    #[test]
    fn w12_detect_silent_on_set_without_untrusted() {
        // Kills an implementation that fires on ANY `dir=%set` reference
        // without inspecting the members.
        let entries = vec![
            set_def(1, "dirs", &["/usr/bin/", "/usr/sbin/"]),
            modern_rule(
                2,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv_ref("dir", "dirs")],
            ),
        ];
        let diags = w12_detect(&entries, &p());
        assert!(
            diags.is_empty(),
            "a dir set with no `untrusted` member must not fire fapd-W12: {diags:?}",
        );
    }

    #[test]
    fn w12_detect_silent_on_undefined_set() {
        // Mirrors dir_slash: an undefined macro emits nothing here; fapd-E03
        // owns undefined-macro reporting. Also pins that the lookup does not
        // panic on a missing key.
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![kv_int("uid", 0)],
            vec![kv_ref("dir", "nosuchset")],
        )];
        let diags = w12_detect(&entries, &p());
        assert!(
            diags.is_empty(),
            "an undefined `dir=%set` is fapd-E03's concern, not fapd-W12's: {diags:?}",
        );
    }

    #[test]
    fn w12_detect_silent_on_int_dir_value_and_setdefinition() {
        // An `AttrValue::Int` dir value is not the `untrusted` keyword, and a
        // SetDefinition entry is never a rule: neither fires. Kills an
        // implementation that fires on any Entry mentioning `untrusted` (here a
        // set literally NAMED `untrusted`, and one whose member is `untrusted`
        // but which no rule references from a `dir=`).
        let entries = vec![
            set_def(1, "untrusted", &["/usr/bin/"]),
            set_def(2, "other", &["untrusted"]),
            modern_rule(
                3,
                Decision::Allow,
                None,
                vec![kv_int("uid", 0)],
                vec![kv_int("dir", 5)],
            ),
        ];
        let diags = w12_detect(&entries, &p());
        assert!(
            diags.is_empty(),
            "fapd-W12 only inspects `dir=` attrs on rules: {diags:?}",
        );
    }

    #[test]
    fn w12_detect_identical_for_legacy_and_modern_flavor() {
        // fapd-W12 keys off attributes, never `Rule.syntax` (mirrors the #295
        // fapd-W07 flavor-invariance pin). The legacy grammar predates the
        // deprecation, but the LINT is gated by `--target`, not by flavor.
        let subj = || vec![kv("dir", "untrusted")];
        let obj = || vec![Attr::All];
        let modern = w12_detect(
            &[modern_rule(1, Decision::Allow, None, subj(), obj())],
            &p(),
        );
        let legacy = w12_detect(
            &[legacy_rule(1, Decision::Allow, None, subj(), obj())],
            &p(),
        );
        assert_eq!(
            legacy.len(),
            1,
            "legacy dir=untrusted must fire one fapd-W12"
        );
        assert_eq!(legacy[0].code.as_ref(), "fapd-W12");
        assert_eq!(
            modern, legacy,
            "fapd-W12 diagnostics must not depend on SyntaxFlavor",
        );
    }

    #[test]
    fn deprecates_untrusted_dir_is_false_for_every_current_target() {
        // The dormancy gate itself. No TargetVersion maps to fapolicyd >= 1.6
        // (version.rs: Rhel8 -> 1.3.2, Rhel9/Rhel10 -> 1.4.5), and `None` is the
        // implicit 1.4.x dialect, so the predicate is false everywhere. When a
        // 1.6-capable variant lands this test is the thing to revisit.
        for target in ALL_TARGETS {
            assert!(
                !deprecates_untrusted_dir(target),
                "no current target reaches fapolicyd 1.6, so fapd-W12's gate \
                 must be closed for {target:?}",
            );
        }
    }

    #[test]
    fn w12_is_dormant_for_every_current_target() {
        // THE dormancy pin. The precondition below is what keeps it honest: it
        // asserts detection ACTUALLY fires on the fixture, so the emptiness
        // assertions prove the GATE suppressed a real finding rather than the
        // detector simply not existing.
        for entries in [subject_dir_untrusted(), object_dir_untrusted()] {
            assert_eq!(
                w12_detect(&entries, &p()).len(),
                1,
                "precondition: fapd-W12 detection must fire on this fixture, \
                 otherwise the dormancy assertion below is vacuous",
            );
            for target in ALL_TARGETS {
                let diags = w12(&entries, &p(), target);
                assert!(
                    diags.is_empty(),
                    "fapd-W12 is dormant until a fapolicyd >= 1.6 target exists; \
                     it must not fire under {target:?}: {diags:?}",
                );
            }
        }
    }

    #[test]
    fn walk_gates_each_lint_independently() {
        // The dispatcher contract: `walk` applies NO gate of its own; each lint
        // gates itself. One rule trips both W07 (`sha256hash=`) and W12
        // (`dir=untrusted`). This test enforces two things: (1) fapd-W12 must
        // never leak into `walk`'s output under ANY target -- a wrong impl
        // that hoists W12's always-closed gate OUT of the per-lint dispatch
        // and INTO `walk` in a way that stops it being applied is KILLED here
        // (verified empirically); and (2) adding fapd-W12 to the dispatcher
        // must not disturb fapd-W07's existing per-target (rhel8) gate on the
        // SAME rule.
        //
        // NOT enforced here: whether fapd-W07's rhel8 check lives inside
        // `w07()` or is hoisted into `walk` instead. That refactor is
        // behaviourally a no-op against this fixture (both land on the same
        // per-target codes set), so this test does not distinguish the two
        // (verified empirically -- the hoisted-W07 variant still passes).
        let entries = vec![modern_rule(
            1,
            Decision::Allow,
            None,
            vec![Attr::Kv {
                key: "sha256hash".into(),
                value: AttrValue::Str(HEX64.into()),
                span: 0..0,
            }],
            vec![kv("dir", "untrusted")],
        )];
        for target in ALL_TARGETS {
            let diags = walk(&entries, &p(), target);
            let codes = w12_codes(&diags);
            assert!(
                !codes.contains(&"fapd-W12"),
                "fapd-W12 is dormant and must never reach `walk`'s output \
                 under {target:?}: {codes:?}",
            );
            let want_w07 = target != Some(TargetVersion::Rhel8);
            assert_eq!(
                codes.contains(&"fapd-W07"),
                want_w07,
                "adding fapd-W12 must not disturb fapd-W07's own rhel8 gate \
                 under {target:?}: {codes:?}",
            );
        }
    }

    #[test]
    fn w12_detect_span_slices_back_to_the_offending_rule() {
        // Spans must be BYTE offsets into the source. Nothing else in this file
        // pins fapd-W12's span, and a byte-vs-char span bug is INVISIBLE to
        // tests built from `testkit` (its builders hard-code `span: 0..0`) and
        // to any all-ASCII fixture (where the two offsets coincide). #340
        // (sysctld) shipped exactly that bug for this reason.
        //
        // The header comment below carries multi-byte UTF-8 (written as ASCII
        // `\u{..}` escapes), so byte offsets run AHEAD of char offsets by the
        // time the rule starts. A char-indexed span slices short and lands
        // mid-rule; a byte span slices the rule exactly.
        const SOURCE: &str = concat!(
            "# caf\u{00e9} na\u{00ef}ve header: multi-byte chars shift byte offsets\n",
            "allow uid=0 dir=untrusted : all\n",
        );
        const RULE: &str = "allow uid=0 dir=untrusted : all";
        // Precondition: the header really does desynchronize the two offsets,
        // otherwise this test cannot distinguish byte from char indexing.
        assert_ne!(
            SOURCE.len(),
            SOURCE.chars().count(),
            "fixture must contain multi-byte UTF-8 for the span check to bite",
        );

        let file = p();
        let entries = crate::parser::parse_rules_file(SOURCE, &file).expect("source must parse");
        let diags = w12_detect(&entries, &file);
        assert_eq!(
            diags.len(),
            1,
            "precondition: the offending rule must be detected: {diags:?}",
        );
        let span = &diags[0].span;
        assert_eq!(
            SOURCE.get(span.start..span.end),
            Some(RULE),
            "fapd-W12's span must be BYTE offsets slicing the offending rule \
             exactly; got {:?} which slices {:?}",
            span,
            SOURCE.get(span.start..span.end),
        );
    }

    #[test]
    fn lint_with_context_never_emits_w12_for_any_target() {
        // The PUBLIC lint path, end to end from real source through the parser.
        // Covers all three offending shapes (subject literal, object literal,
        // set membership) under every target. The precondition keeps it
        // non-vacuous for the same reason as `w12_is_dormant_for_every_current_target`.
        const SOURCE: &str = concat!(
            "%dirs=/usr/bin/,untrusted\n",
            "allow uid=0 dir=untrusted : all\n",
            "allow uid=1 : dir=untrusted\n",
            "allow uid=2 : dir=%dirs\n",
        );
        let file = p();
        let entries = crate::parser::parse_rules_file(SOURCE, &file).expect("source must parse");
        assert_eq!(
            w12_detect(&entries, &file).len(),
            3,
            "precondition: all three offending shapes must be detected, \
             otherwise the dormancy assertion below is vacuous",
        );
        for target in ALL_TARGETS {
            let ctx = crate::lints::LintContext {
                target,
                ..Default::default()
            };
            let diags = crate::lints::lint_with_context(&entries, SOURCE, &file, &ctx);
            let codes = w12_codes(&diags);
            assert!(
                !codes.contains(&"fapd-W12"),
                "fapd-W12 must be dormant through the public lint path \
                 under {target:?}: {codes:?}",
            );
        }
    }
}
