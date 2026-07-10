//! Extract fapd-E01 attribute NAMES + SIDE classification from upstream fapolicyd
//! `subject-attr.c` / `object-attr.c` sources, scoped to the NEW-FORMAT tables only
//! (`subject-attr.c`'s `table2`, `object-attr.c`'s `table`) - matching the shipped
//! `crates/rulesteward-fapolicyd/src/attrs.rs`'s own documented "flavor-agnostic,
//! most-permissive" scope. The legacy `table1` in `subject-attr.c` (old-format
//! names, e.g. `exe_dir` / `exe_type` / `exe_device`) is deliberately out of
//! scope, mirroring attrs.rs's own `exe_dir`/`exe_type` exclusion precedent (see
//! attrs.rs lines 24-31: both were removed as false-negative-causing because
//! neither is a real new-format attribute name).
//!
//! Source citations: upstream `linux-application-whitelisting/fapolicyd`,
//! `src/library/{subject,object}-attr.c` at tags `v1.3.2` and `v1.4.5` - see
//! `../attr-refs.toml` for the pinned commit SHAs + sha256 of the fetched sources
//! `tests/fixtures/<version>/*.c` were copied and verified from (2026-07-10
//! grounding recon for #479).

use std::collections::BTreeSet;

/// Which side(s) of a fapolicyd rule an attribute name is valid on, as derived
/// DIRECTLY from which upstream C table(s) contain the name - NOT the shipped
/// `rulesteward_fapolicyd::attrs::AttrSide` classification (which [`crate::registry`]
/// exists to drift-check this against).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Side {
    Subject,
    Object,
    Both,
}

/// One derived attribute: its name and which upstream table(s) it was found in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DerivedAttr {
    pub name: String,
    pub side: Side,
}

/// The distinct attribute NAMES in `attrs` (side-agnostic) - the input to the
/// name-level (union-across-versions) half of the drift contract in
/// [`crate::registry::name_drift`].
#[must_use]
pub fn names(attrs: &[DerivedAttr]) -> BTreeSet<String> {
    attrs.iter().map(|a| a.name.clone()).collect()
}

/// A documented deprecated-name alias that fapolicyd accepts via a hardcoded
/// string comparison in `obj_name_to_val` rather than as a literal row in the
/// object `table[]` array. `alias` is accepted at runtime whenever `canonical` is
/// a real table row; the alias itself is NEVER a table entry there, so a
/// literal-table-only parse would silently miss it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasException {
    pub alias: &'static str,
    pub canonical: &'static str,
}

/// The `sha256hash` -> `filehash` rename (fapolicyd >=1.4.2). `object-attr.c`'s
/// `obj_name_to_val` (v1.4.5 source, lines 47-60) hardcodes:
/// ```c
/// if (strcmp(name, "sha256hash") == 0)
///     return FILE_HASH;
/// ```
/// immediately before the literal-table linear scan, preceded by a one-time
/// deprecation log ("SHA256HASH object name is deprecated; use FILE_HASH
/// instead", lines 52-56). `sha256hash` is therefore a valid, accepted
/// OBJECT-side name whenever `filehash` (`FILE_HASH`) is a real table row, even
/// though the literal `"sha256hash"` string never appears as a table row at that
/// tag. On fapolicyd 1.3.2, `sha256hash` IS already a literal table row
/// (`SHA256HASH`, pre-rename) and `filehash` does not exist there at all - the
/// `canonical` guard below must therefore be a no-op on a 1.3.2 source (asserted
/// by `apply_object_alias_exceptions_is_noop_when_alias_already_a_literal_row_1_3_2_shape`).
pub const OBJECT_ALIAS_EXCEPTIONS: &[AliasException] = &[AliasException {
    alias: "sha256hash",
    canonical: "filehash",
}];

/// Extract the double-quoted attribute-name literals declared in the
/// `static const nv_t <table_name>[] = { ... };` array in `src`. Scoped to an
/// EXACT identifier match on `table_name` (a word-boundary check on both sides,
/// so a search for `"table"` in `object-attr.c` cannot match a `table1`/`table2`
/// identifier, and a search for `"table2"` cannot match a hypothetical
/// `"table20"`).
///
/// Fails CLOSED (`Err`) - never returns an empty or partial list silently - when:
/// * the `table_name` declaration cannot be found at all;
/// * the array's opening or matching closing brace cannot be located (a
///   truncated / hand-mangled source, e.g. cut off mid-table);
/// * the declaration is found but contains zero quoted-string literals (an
///   empty table is not a real fapolicyd source file).
///
/// A caller that silently accepted a truncated result (`Ok(vec![])` or a
/// partial row list) would make the `check` subcommand's drift gate report a
/// false "no drift" - a real `attrs.rs` regression would go undetected. This is
/// the PARSE-path fail-closed guard (mirrors `tools/stig-update/src/source.rs`'s
/// `reject_if_truncated`, which is the analogous FETCH-path guard - see
/// [`crate::source`]).
pub fn extract_table_names(src: &str, table_name: &str) -> Result<Vec<String>, String> {
    let _ = (src, table_name);
    todo!(
        "locate `static const nv_t <table_name>[] = {{ ... }};`, extract the quoted name literals, fail closed on a missing declaration / unbalanced braces / empty table"
    )
}

/// [`extract_table_names`] scoped to `subject-attr.c`'s NEW-FORMAT table
/// (`table2`). The legacy `table1` is deliberately out of scope - see the module
/// doc comment.
pub fn parse_subject_table2(src: &str) -> Result<Vec<String>, String> {
    extract_table_names(src, "table2")
}

/// [`extract_table_names`] scoped to `object-attr.c`'s single table (`table`).
/// Returns the LITERAL table rows only - does NOT apply
/// [`OBJECT_ALIAS_EXCEPTIONS`]; callers combine the literal rows with the
/// exceptions via [`apply_object_alias_exceptions`].
pub fn parse_object_table(src: &str) -> Result<Vec<String>, String> {
    extract_table_names(src, "table")
}

/// Add any [`OBJECT_ALIAS_EXCEPTIONS`] whose `canonical` name is present in
/// `object_names` and whose `alias` is not ALREADY a literal row (on fapolicyd
/// 1.3.2, `sha256hash` is already literal and `filehash` does not exist, so the
/// exception must be a no-op there).
pub fn apply_object_alias_exceptions(object_names: Vec<String>) -> Vec<String> {
    let _ = object_names;
    todo!(
        "for each OBJECT_ALIAS_EXCEPTIONS entry, add `alias` when `canonical` is present and `alias` is not already a row"
    )
}

/// Classify the union of `subject_names` (already scoped to `table2`) and
/// `object_names` (already scoped to `table`, exceptions already applied via
/// [`apply_object_alias_exceptions`]) into one [`DerivedAttr`] per distinct name:
/// [`Side::Subject`] (subject-list only), [`Side::Object`] (object-list only), or
/// [`Side::Both`] (present in both lists).
pub fn classify(subject_names: &[String], object_names: &[String]) -> Vec<DerivedAttr> {
    let _ = (subject_names, object_names);
    todo!("union subject_names + object_names, classify each name's Side")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBJECT_1_3_2: &str = include_str!("../tests/fixtures/1.3.2/subject-attr.c");
    const OBJECT_1_3_2: &str = include_str!("../tests/fixtures/1.3.2/object-attr.c");
    const SUBJECT_1_4_5: &str = include_str!("../tests/fixtures/1.4.5/subject-attr.c");
    const OBJECT_1_4_5: &str = include_str!("../tests/fixtures/1.4.5/object-attr.c");

    /// Parse one pinned version's fixture pair into the final classified registry
    /// (the exact pipeline `derive`/`check` will run per version).
    fn derive(subject_src: &str, object_src: &str) -> Vec<DerivedAttr> {
        let subject = parse_subject_table2(subject_src).expect("subject parses");
        let object_literal = parse_object_table(object_src).expect("object parses");
        let object = apply_object_alias_exceptions(object_literal);
        classify(&subject, &object)
    }

    fn side_of<'a>(attrs: &'a [DerivedAttr], name: &str) -> &'a Side {
        &attrs
            .iter()
            .find(|a| a.name == name)
            .unwrap_or_else(|| panic!("{name} missing from derived set: {attrs:?}"))
            .side
    }

    /// KNOWN-ANSWER, fapolicyd 1.3.2 (rhel8): 17 names total. `sha256hash` is a
    /// literal object-table row here (no rename yet) so `filehash` must be ABSENT.
    /// `device` is present in BOTH `subject-attr.c` `table2` (via the `EXE_DEVICE`
    /// alias, `{EXE_DEVICE, "device"}`) and `object-attr.c` `table` (`{DEVICE,
    /// "device"}`), so it classifies `Side::Both` here - a real, version-specific
    /// fact about 1.3.2, NOT the shipped `OBJECT_ONLY` classification (see
    /// `crate::registry`'s module doc for why the side-drift check deliberately
    /// does not run this version).
    ///
    /// Adversarial property: this asserts the FULL 17-name set, not spot names. A
    /// wrong implementation that just echoes `rulesteward_fapolicyd::attrs`'s
    /// shipped consts (18 names, includes `filehash`, classifies `device` as
    /// `Object`-only) must FAIL this test: 17 != 18, and `device`'s side would
    /// disagree.
    #[test]
    fn parse_1_3_2_table2_and_table_yield_correct_names_and_sides() {
        let derived = derive(SUBJECT_1_3_2, OBJECT_1_3_2);
        assert_eq!(
            derived.len(),
            17,
            "fapolicyd 1.3.2's derived registry must have exactly 17 names: {derived:?}"
        );

        let mut got: Vec<&str> = derived.iter().map(|a| a.name.as_str()).collect();
        got.sort_unstable();
        let want = [
            "all",
            "auid",
            "comm",
            "device",
            "dir",
            "exe",
            "ftype",
            "gid",
            "mode",
            "path",
            "pattern",
            "pid",
            "ppid",
            "sessionid",
            "sha256hash",
            "trust",
            "uid",
        ];
        assert_eq!(got, want, "1.3.2 derived name set mismatch");

        assert!(
            !got.contains(&"filehash"),
            "filehash must NOT exist on 1.3.2 (the rename happened at fapolicyd 1.4.2+): {got:?}"
        );

        for name in [
            "auid",
            "uid",
            "sessionid",
            "pid",
            "ppid",
            "gid",
            "comm",
            "exe",
            "pattern",
        ] {
            assert_eq!(
                *side_of(&derived, name),
                Side::Subject,
                "{name} must be Subject-only on 1.3.2"
            );
        }
        for name in ["path", "sha256hash", "mode"] {
            assert_eq!(
                *side_of(&derived, name),
                Side::Object,
                "{name} must be Object-only on 1.3.2"
            );
        }
        for name in ["all", "dir", "ftype", "trust", "device"] {
            assert_eq!(
                *side_of(&derived, name),
                Side::Both,
                "{name} must be Both-sides on 1.3.2"
            );
        }
    }

    /// KNOWN-ANSWER, fapolicyd 1.4.5 (rhel9/rhel10): 18 names total, matching the
    /// shipped registry EXACTLY (name-for-name and side-for-side - see
    /// `crate::registry`'s side-drift GREEN-case test, which asserts this same
    /// pipeline's output against the real shipped consts). `sha256hash` is
    /// reached ONLY via [`OBJECT_ALIAS_EXCEPTIONS`] here (it is not a literal
    /// `object-attr.c` `table` row at this tag - `filehash` is). `device` is
    /// Object-only here (the `EXE_DEVICE` row was dropped from `subject-attr.c`
    /// `table2` between 1.3.2 and 1.4.5 - contrast with the 1.3.2 test above).
    #[test]
    fn parse_1_4_5_table2_and_table_yield_correct_names_and_sides() {
        let derived = derive(SUBJECT_1_4_5, OBJECT_1_4_5);
        assert_eq!(
            derived.len(),
            18,
            "fapolicyd 1.4.5's derived registry must have exactly 18 names: {derived:?}"
        );

        let mut got: Vec<&str> = derived.iter().map(|a| a.name.as_str()).collect();
        got.sort_unstable();
        let want = [
            "all",
            "auid",
            "comm",
            "device",
            "dir",
            "exe",
            "filehash",
            "ftype",
            "gid",
            "mode",
            "path",
            "pattern",
            "pid",
            "ppid",
            "sessionid",
            "sha256hash",
            "trust",
            "uid",
        ];
        assert_eq!(got, want, "1.4.5 derived name set mismatch");

        for name in [
            "auid",
            "uid",
            "sessionid",
            "pid",
            "ppid",
            "gid",
            "comm",
            "exe",
            "pattern",
        ] {
            assert_eq!(
                *side_of(&derived, name),
                Side::Subject,
                "{name} must be Subject-only on 1.4.5"
            );
        }
        for name in ["path", "device", "filehash", "sha256hash", "mode"] {
            assert_eq!(
                *side_of(&derived, name),
                Side::Object,
                "{name} must be Object-only on 1.4.5"
            );
        }
        for name in ["all", "dir", "ftype", "trust"] {
            assert_eq!(
                *side_of(&derived, name),
                Side::Both,
                "{name} must be Both-sides on 1.4.5"
            );
        }
    }

    /// Defensive: `subject-attr.c` declares BOTH `table1` (legacy old-format) and
    /// `table2` (new format) in the SAME file. `parse_subject_table2` must scope
    /// to `table2` only - the legacy-only names `exe_dir` / `exe_type` (both
    /// versions) and `exe_device` (1.3.2 only) must never leak into the result. A
    /// wrong implementation that greedily extracts every quoted string in the
    /// whole file (both tables) would fail this test.
    #[test]
    fn parse_subject_table2_excludes_legacy_table1_only_names() {
        let names = parse_subject_table2(SUBJECT_1_3_2).expect("subject parses");
        for legacy_only in ["exe_dir", "exe_type", "exe_device"] {
            assert!(
                !names.contains(&legacy_only.to_string()),
                "table1-only name {legacy_only:?} must not appear in the table2 extraction: {names:?}"
            );
        }
        // table2's OWN new-format renames of those same concepts must be present.
        for renamed in ["dir", "ftype", "device"] {
            assert!(
                names.contains(&renamed.to_string()),
                "table2's new-format name {renamed:?} must be present: {names:?}"
            );
        }
    }

    /// On a 1.4.5-shaped object table (`filehash` present, `sha256hash` absent as
    /// a literal row), the exception must ADD `sha256hash`.
    #[test]
    fn apply_object_alias_exceptions_adds_sha256hash_when_filehash_present_1_4_5_shape() {
        let literal = vec![
            "path".to_string(),
            "filehash".to_string(),
            "mode".to_string(),
        ];
        let with_exceptions = apply_object_alias_exceptions(literal);
        assert!(
            with_exceptions.contains(&"sha256hash".to_string()),
            "sha256hash must be added when filehash is present: {with_exceptions:?}"
        );
        assert!(with_exceptions.contains(&"filehash".to_string()));
    }

    /// On a 1.3.2-shaped object table (`sha256hash` already a literal row,
    /// `filehash` absent entirely), the exception's `canonical` guard (`filehash`)
    /// does not fire, so the list is unchanged (no duplicate `sha256hash`, no
    /// spurious `filehash`).
    #[test]
    fn apply_object_alias_exceptions_is_noop_when_alias_already_a_literal_row_1_3_2_shape() {
        let literal = vec![
            "path".to_string(),
            "sha256hash".to_string(),
            "mode".to_string(),
        ];
        let out = apply_object_alias_exceptions(literal.clone());
        assert_eq!(
            out, literal,
            "no filehash row present -> the exception must not fire: {out:?}"
        );
    }

    /// A truncated source (cut off mid-`table2` declaration, no closing `};`)
    /// must fail CLOSED, not return a partial or empty list.
    #[test]
    fn extract_table_names_fails_closed_on_truncated_source() {
        let truncated = "\
static const nv_t table2[] = {
{	ALL_SUBJ,   \"all\"	},
{	AUID,       \"auid\"	},
";
        let err = extract_table_names(truncated, "table2")
            .expect_err("a truncated table declaration (no closing brace) must be rejected");
        assert!(!err.is_empty(), "error message must not be empty");
    }

    /// A source with no `table2` declaration at all (e.g. only `table1` present)
    /// must fail CLOSED, not silently return an empty list.
    #[test]
    fn extract_table_names_fails_closed_on_missing_table_declaration() {
        let no_table2 = "\
static const nv_t table1[] = {
{	ALL_SUBJ,   \"all\"	},
};
";
        let err = extract_table_names(no_table2, "table2")
            .expect_err("a source with no table2 declaration must be rejected, not silently empty");
        assert!(!err.is_empty(), "error message must not be empty");
    }

    /// A `table2` declaration whose body is present but carries zero quoted
    /// string literals (a hand-mangled / stripped fixture) must also fail closed
    /// rather than reporting a vacuous empty registry.
    #[test]
    fn extract_table_names_fails_closed_on_empty_table_body() {
        let empty_body = "static const nv_t table2[] = {\n};\n";
        let err = extract_table_names(empty_body, "table2").expect_err(
            "an empty table body must be rejected, not treated as a valid 0-name table",
        );
        assert!(!err.is_empty(), "error message must not be empty");
    }
}
