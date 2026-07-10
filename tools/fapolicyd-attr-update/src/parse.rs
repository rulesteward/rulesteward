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
    let decl = find_declaration(src, table_name).ok_or_else(|| {
        format!("no `{table_name}[]` declaration found in source (expected `static const nv_t {table_name}[] = {{ ... }};`)")
    })?;

    let open_rel = src[decl..]
        .find('{')
        .ok_or_else(|| format!("no opening brace found for `{table_name}[]`"))?;
    let open = decl + open_rel;
    let close = find_matching_close(src, open).ok_or_else(|| {
        format!(
            "unbalanced/truncated `{table_name}[]` declaration: no matching closing brace found"
        )
    })?;

    let names = extract_quoted_strings(&src[open + 1..close]);
    if names.is_empty() {
        return Err(format!(
            "`{table_name}[]` declaration has zero quoted name literals (empty table)"
        ));
    }
    Ok(names)
}

/// Locate the byte offset of the literal `<table_name>[]` in `src`, requiring a
/// word-boundary on the LEFT side (the char immediately preceding the match, if
/// any, must not be an identifier char) so a search for `"table"` cannot match a
/// `"table1"`/`"table2"` identifier. The RIGHT-side boundary falls out of the
/// literal match itself: searching for the exact bytes `<table_name>[]` cannot
/// match inside a longer identifier like `table20[]` (its bytes are `t able 2 0
/// [ ]`, not `t a b l e 2 [ ]`), and cannot match array-index usages like
/// `table[i]` or `table2[0]` (neither is followed immediately by `[]`).
fn find_declaration(src: &str, table_name: &str) -> Option<usize> {
    let needle = format!("{table_name}[]");
    let bytes = src.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = src[search_from..].find(needle.as_str()) {
        let idx = search_from + rel;
        let left_ok = idx == 0 || !is_ident_byte(bytes[idx - 1]);
        if left_ok {
            return Some(idx);
        }
        search_from = idx + 1;
    }
    None
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Find the `}` matching the `{` at `open` via simple brace-depth counting.
/// Attribute-table sources never carry braces inside their quoted string
/// literals (the names are plain lowercase words), so no quote-awareness is
/// needed here.
fn find_matching_close(src: &str, open: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract every double-quoted literal's contents from `body`, in source order.
/// No escape handling: the attribute-name literals this parses are plain
/// lowercase words with no embedded quotes or backslashes.
fn extract_quoted_strings(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some(end_rel) = body[i + 1..].find('"') {
                let end = i + 1 + end_rel;
                out.push(body[i + 1..end].to_string());
                i = end + 1;
                continue;
            }
            break;
        }
        i += 1;
    }
    out
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
pub fn apply_object_alias_exceptions(mut object_names: Vec<String>) -> Vec<String> {
    for exception in OBJECT_ALIAS_EXCEPTIONS {
        let canonical_present = object_names.iter().any(|n| n == exception.canonical);
        let alias_present = object_names.iter().any(|n| n == exception.alias);
        if canonical_present && !alias_present {
            object_names.push(exception.alias.to_string());
        }
    }
    object_names
}

/// Classify the union of `subject_names` (already scoped to `table2`) and
/// `object_names` (already scoped to `table`, exceptions already applied via
/// [`apply_object_alias_exceptions`]) into one [`DerivedAttr`] per distinct name:
/// [`Side::Subject`] (subject-list only), [`Side::Object`] (object-list only), or
/// [`Side::Both`] (present in both lists).
pub fn classify(subject_names: &[String], object_names: &[String]) -> Vec<DerivedAttr> {
    let subject_set: BTreeSet<&String> = subject_names.iter().collect();
    let object_set: BTreeSet<&String> = object_names.iter().collect();

    let mut all_names: BTreeSet<&String> = BTreeSet::new();
    all_names.extend(subject_set.iter().copied());
    all_names.extend(object_set.iter().copied());

    all_names
        .into_iter()
        .map(|name| {
            let side = match (subject_set.contains(name), object_set.contains(name)) {
                (true, true) => Side::Both,
                (true, false) => Side::Subject,
                (false, true) => Side::Object,
                (false, false) => unreachable!("name came from subject_set or object_set"),
            };
            DerivedAttr {
                name: name.clone(),
                side,
            }
        })
        .collect()
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

    /// ATL round-1 adversary miss #2 (orchestrator ruled: harden the parser): a
    /// quoted word inside a `//` or `/* */` COMMENT within the table body must
    /// NOT become a derived attribute name. Reproduced by the impl-aware
    /// adversary (artifact /var/tmp/7b-atl-p3/adir/): appending
    /// `// TODO(upstream): add "cgroup" object attribute in a future release`
    /// inside the table's braces produced a phantom 19th name and a false-drift
    /// exit 1. The comment styles below mirror the real fixtures' own
    /// conventions - `tests/fixtures/1.4.5/object-attr.c` uses both `//` line
    /// comments (line 27 `// For NULL`, line 58) and `/* */` block comments
    /// (lines 51) in this same file family; upstream C permits either inside an
    /// initializer list, so the extractor must be comment-aware.
    #[test]
    fn extract_table_names_ignores_quoted_words_inside_comments() {
        let src = "\
static const nv_t table[] = {
{\tALL_OBJ, \t\"all\" },
{\tPATH, \t\t\"path\" },\t// the \"fullpath\" spelling was never accepted upstream
/* {\tCGROUP,\t\"cgroup\" }, a row proposed but not merged */
{\tFMODE,\t\t\"mode\" },
// TODO(upstream): add \"magic\" object attribute in a future release
};
";
        let names = extract_table_names(src, "table").expect("commented table parses");
        assert_eq!(
            names,
            ["all", "path", "mode"],
            "quoted words inside //-line and /* */-block comments must not \
             become attribute names (phantom-token fail-open): {names:?}"
        );
    }

    /// `find_declaration`'s LEFT word-boundary check must be load-bearing: when
    /// a PREFIXED identifier declaration (`xtable2[]`, whose byte suffix
    /// contains `table2[]`) precedes the real `table2[]` declaration, extraction
    /// must skip the prefixed decoy and return the real table's rows. A
    /// boundary check gutted by mutation (accepting any match, or matching the
    /// decoy) yields the decoy's names instead. (ATL round-1 mutation survivors
    /// in find_declaration, parse.rs lines 133-138: the +/==/||/! boundary
    /// arithmetic all survived because no fixture exercised a prefixed
    /// identifier.)
    #[test]
    fn extract_table_names_skips_prefixed_identifier_declaration() {
        let src = "\
static const nv_t xtable2[] = {
{\tFOO,   \"decoy\"\t},
};

static const nv_t table2[] = {
{\tALL_SUBJ,   \"all\"\t},
{\tAUID,       \"auid\"\t},
};
";
        let names = extract_table_names(src, "table2")
            .expect("the real table2 declaration must be found past the xtable2 decoy");
        assert_eq!(
            names,
            ["all", "auid"],
            "extraction must come from the REAL table2, never the prefixed \
             xtable2 decoy: {names:?}"
        );
    }

    /// The mirror case: a source where ONLY the prefixed identifier
    /// (`xtable2[]`) exists must fail CLOSED - `table2` genuinely has no
    /// declaration there, and silently extracting the decoy's rows would be a
    /// wrong-table parse presented as success.
    #[test]
    fn extract_table_names_fails_closed_when_only_prefixed_identifier_exists() {
        let src = "\
static const nv_t xtable2[] = {
{\tFOO,   \"decoy\"\t},
};
";
        let err = extract_table_names(src, "table2")
            .expect_err("an xtable2-only source has no table2 declaration; must be rejected");
        assert!(!err.is_empty(), "error message must not be empty");
    }
}
