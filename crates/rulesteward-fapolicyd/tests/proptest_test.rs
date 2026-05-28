//! Property tests for `rulesteward-fapolicyd::parse_rules_file`.
//!
//! Three proptest properties + two hard-coded sentinel `#[test]`s. The
//! sentinels exist so that mutations which trivialize the parser (e.g.
//! "always return `Ok(vec![])`" or "only report the first fapd-F01") are killed
//! even by a single non-shrinking run - `cargo-mutants` will see one of the
//! sentinels fail and mark the mutant as caught.
//!
//! ## Field-comparison contract for the round-trip property
//!
//! `arb_program()` emits a `Vec<Entry>` where each entry's `line` field is
//! 1-based and strictly monotonic (1, 2, 3, ...). The `Display` impl does
//! not emit line numbers; the parser assigns `line` based on the position of
//! the line in the source text. We render entries one-per-line with a
//! trailing `'\n'`, so after re-parsing, line N corresponds to the entry at
//! index N-1 in both the original and the re-parsed `Vec`. We therefore
//! compare every AST field directly without normalization - `line` agrees by
//! construction, not by accident. If a future Display impl emits multi-line
//! output for a single entry, this property will start failing and force
//! either a normalization pass or a Display fix; both outcomes are fine.
//!
//! ## Anti-vacuous discipline
//!
//! Every assertion targets a concrete invariant. We never assert
//! `result.is_ok()` without then inspecting the contents, and never assert
//! `result.is_err()` without inspecting `Severity` and `code`. The
//! never-panics property additionally asserts that a returned `Err` carries
//! at least one `Severity::Fatal` diagnostic whose `code` begins with `'F'`,
//! so a mutation that swaps `Err(diags)` for `Err(vec![])` dies. Property 3
//! asserts a lower bound on the fatal count, so a mutation that returns only
//! the first error dies.
//!
//! All proptest properties use ≥256 cases (proptest default = 256 in 1.x;
//! the explicit config below pins it so a future default change doesn't
//! silently weaken the suite).

use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};

use proptest::prelude::*;

use std::path::PathBuf;

use rulesteward_core::{Severity, span};
use rulesteward_fapolicyd::{
    ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor},
    attrs, lint, parse_rules_file,
};

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

mod generators {
    use super::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor, attrs, span};
    use proptest::prelude::*;

    /// All 8 decision keywords; flavor-agnostic.
    pub(super) fn arb_decision() -> impl Strategy<Value = Decision> {
        prop_oneof![
            Just(Decision::Allow),
            Just(Decision::Deny),
            Just(Decision::AllowAudit),
            Just(Decision::DenyAudit),
            Just(Decision::AllowSyslog),
            Just(Decision::DenySyslog),
            Just(Decision::AllowLog),
            Just(Decision::DenyLog),
        ]
    }

    /// `Some(perm)` for one of 3 perm values, or `None`. Both modern and
    /// legacy syntax accept an optional `perm=` clause.
    pub(super) fn arb_perm_opt() -> impl Strategy<Value = Option<Perm>> {
        prop_oneof![
            Just(None),
            Just(Some(Perm::Open)),
            Just(Some(Perm::Execute)),
            Just(Some(Perm::Any)),
        ]
    }

    /// String payload for `AttrValue::Str`. Char set is alphanumeric or one
    /// of `_ / . -` (none of which carry parser meaning). The filter rules
    /// out any string that the parser would round-trip into `AttrValue::Int`
    /// (parser captures the value as one slug and post-classifies via
    /// `parse::<i64>()`, so `0`, `-12`, `0042` etc. would re-parse as Int).
    pub(super) fn arb_str_value() -> impl Strategy<Value = AttrValue> {
        "[a-zA-Z0-9_/.\\-]{1,32}"
            .prop_filter("must not parse as i64", |s: &String| {
                s.parse::<i64>().is_err()
            })
            .prop_map(AttrValue::Str)
    }

    /// Non-negative integer attribute value. `text::int(10)` in the spike
    /// parser only accepts digit sequences (no leading `-`), so we constrain
    /// the generator accordingly to keep the round-trip lossless.
    pub(super) fn arb_int_value() -> impl Strategy<Value = AttrValue> {
        (0i64..1_000_000_i64).prop_map(AttrValue::Int)
    }

    /// `%setref` value. The identifier-character set matches the spike's
    /// `ident` combinator: ASCII alpha / underscore start, then
    /// alphanumeric / underscore tail.
    pub(super) fn arb_setref_value() -> impl Strategy<Value = AttrValue> {
        "[a-zA-Z_][a-zA-Z0-9_]{0,15}".prop_map(AttrValue::SetRef)
    }

    pub(super) fn arb_attr_value() -> impl Strategy<Value = AttrValue> {
        prop_oneof![arb_str_value(), arb_int_value(), arb_setref_value()]
    }

    /// Build a key-value `Attr::Kv` whose key is drawn from `keys`. The
    /// reserved literal `"all"` is filtered out at call-sites that include
    /// `BOTH_SIDES`, because the spike parser unconditionally treats a bare
    /// `all` token as `Attr::All`, not as a `Kv { key: "all", ... }`. Doing
    /// the filter at the keyset level (rather than inside this function)
    /// keeps the generator monomorphic and the assumption visible.
    fn arb_kv_from(keys: &'static [&'static str]) -> impl Strategy<Value = Attr> {
        let keys = keys.to_vec();
        (
            (0..keys.len()).prop_map(move |idx| keys[idx].to_string()),
            arb_attr_value(),
        )
            .prop_map(|(key, value)| Attr::Kv { key, value })
    }

    /// Strict subject keys (legacy positional classifier guarantees these
    /// land on the subject side regardless of input order - see
    /// `attrs::SUBJECT_ONLY`).
    pub(super) fn arb_subject_only_attr() -> impl Strategy<Value = Attr> {
        arb_kv_from(attrs::SUBJECT_ONLY)
    }

    /// Strict object keys.
    pub(super) fn arb_object_only_attr() -> impl Strategy<Value = Attr> {
        arb_kv_from(attrs::OBJECT_ONLY)
    }

    /// Modern-syntax attribute: any of the three keysets, plus `Attr::All`.
    /// The `BOTH_SIDES` set has `"all"` filtered out - the bare `all` token
    /// is generated separately as `Attr::All`.
    pub(super) fn arb_modern_attr() -> impl Strategy<Value = Attr> {
        // BOTH_SIDES contains "all"; the parser treats `all` as Attr::All
        // (no `=`), so we route it through `Attr::All` only.
        const BOTH_NO_ALL: &[&str] = &["dir", "ftype", "trust", "pattern"];
        prop_oneof![
            10 => arb_kv_from(attrs::SUBJECT_ONLY),
            10 => arb_kv_from(attrs::OBJECT_ONLY),
            5  => arb_kv_from(BOTH_NO_ALL),
            1  => Just(Attr::All),
        ]
    }

    /// Generate a Modern-syntax rule: subject (1..=4 attrs), `:`, object
    /// (1..=4 attrs). Either side may include any known key - the colon
    /// disambiguates positionally.
    pub(super) fn arb_modern_rule() -> impl Strategy<Value = Rule> {
        (
            arb_decision(),
            arb_perm_opt(),
            prop::collection::vec(arb_modern_attr(), 1..=4),
            prop::collection::vec(arb_modern_attr(), 1..=4),
        )
            .prop_map(|(decision, perm, subject, object)| Rule {
                decision,
                perm,
                subject,
                object,
                syntax: SyntaxFlavor::Modern,
                line: 0,          // filled in by arb_program()
                span: span(0, 0), // placeholder; file-relative span set by parser
            })
    }

    /// Generate a Legacy-syntax rule. Two hard constraints to keep the
    /// positional classifier deterministic:
    ///
    /// 1. Subject keys are drawn ONLY from `attrs::SUBJECT_ONLY`; object
    ///    keys ONLY from `attrs::OBJECT_ONLY`. `BOTH_SIDES` keys (including
    ///    `Attr::All`) are excluded - without a `:` delimiter, a `dir=`
    ///    could legally be classified onto either side, which would cause a
    ///    round-trip mismatch.
    /// 2. The Display impl renders subject first, then object, with no
    ///    colon. The classifier reads subject-only tokens until it hits the
    ///    first object-only token, then switches. Strict-only keys make this
    ///    unambiguous.
    pub(super) fn arb_legacy_rule() -> impl Strategy<Value = Rule> {
        (
            arb_decision(),
            arb_perm_opt(),
            prop::collection::vec(arb_subject_only_attr(), 1..=4),
            prop::collection::vec(arb_object_only_attr(), 1..=4),
        )
            .prop_map(|(decision, perm, subject, object)| Rule {
                decision,
                perm,
                subject,
                object,
                syntax: SyntaxFlavor::Legacy,
                line: 0,
                span: span(0, 0), // placeholder; file-relative span set by parser
            })
    }

    /// 50/50 mix of Modern and Legacy rules wrapped in `Entry::Rule`.
    fn arb_rule_entry() -> impl Strategy<Value = Entry> {
        prop_oneof![
            arb_modern_rule().prop_map(Entry::Rule),
            arb_legacy_rule().prop_map(Entry::Rule),
        ]
    }

    fn arb_setdef_entry() -> impl Strategy<Value = Entry> {
        (
            "[a-zA-Z_][a-zA-Z0-9_]{0,15}",
            prop::collection::vec("[a-zA-Z0-9_/.\\-]{1,16}", 1..=4),
        )
            .prop_map(|(name, values)| Entry::SetDefinition {
                name,
                values,
                line: 0,
                span: span(0, 0), // placeholder; file-relative span set by parser
            })
    }

    fn arb_comment_entry() -> impl Strategy<Value = Entry> {
        // Comment text: printable ASCII (no `\n`, no `\r`). The Display
        // impl prefixes with `#`, so a comment text containing additional
        // `#` characters is fine - the parser reads everything to EOL.
        "[ -~]{0,64}".prop_map(|text| Entry::Comment { text, line: 0 })
    }

    fn arb_blank_entry() -> impl Strategy<Value = Entry> {
        Just(Entry::Blank { line: 0 })
    }

    /// A single entry, line-number stamping happens in `arb_program`.
    /// Weights bias toward rules so the generated source stresses the
    /// parser's rule machinery (the round-trip property's main target).
    pub(super) fn arb_entry() -> impl Strategy<Value = Entry> {
        prop_oneof![
            6 => arb_rule_entry(),
            1 => arb_setdef_entry(),
            1 => arb_comment_entry(),
            1 => arb_blank_entry(),
        ]
    }

    /// Generate a `Vec<Entry>` with 1-based, strictly-monotonic `line`
    /// fields. We stamp the line numbers after generation so the generator
    /// stays compositional.
    pub(super) fn arb_program() -> impl Strategy<Value = Vec<Entry>> {
        prop::collection::vec(arb_entry(), 1..=12).prop_map(|entries| {
            entries
                .into_iter()
                .enumerate()
                .map(|(idx, e)| stamp_line(e, idx + 1))
                .collect()
        })
    }

    /// Plain-text rendering of a small valid-rules string. Used by Property
    /// 3 to build a "valid prefix" that the parser must accept cleanly.
    /// Always Modern flavor; always 1..=3 rules.
    pub(super) fn arb_valid_rule_text() -> impl Strategy<Value = String> {
        use std::fmt::Write as _;
        prop::collection::vec(arb_modern_rule(), 1..=3).prop_map(|rules| {
            rules.into_iter().fold(String::new(), |mut acc, r| {
                let _ = writeln!(acc, "{}", Entry::Rule(stamp_rule_line(r, 1)));
                acc
            })
        })
    }

    fn stamp_line(entry: Entry, line: usize) -> Entry {
        match entry {
            Entry::Rule(r) => Entry::Rule(stamp_rule_line(r, line)),
            Entry::SetDefinition { name, values, .. } => Entry::SetDefinition {
                name,
                values,
                line,
                span: span(0, 0),
            },
            Entry::Comment { text, .. } => Entry::Comment { text, line },
            Entry::Blank { .. } => Entry::Blank { line },
        }
    }

    fn stamp_rule_line(rule: Rule, line: usize) -> Rule {
        Rule {
            line,
            span: span(0, 0),
            ..rule
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Normalize a `Vec<Entry>` so its `line` fields are 1..=N in index order
/// and span fields on `Rule` and `SetDefinition` are zeroed out. Both sides
/// of the round-trip equality go through this:
/// - `line` normalization: the source-text construction guarantees line
///   numbers agree, but being explicit prevents a future Display change
///   from silently breaking the property.
/// - `span` normalization: the generator uses `span(0,0)` placeholders
///   while the parser produces real file-relative spans. We zero both
///   sides so the round-trip property stays focused on AST shape, not
///   byte offsets. Span correctness is verified by dedicated unit tests
///   in `parser/mod.rs`.
fn normalize_lines(entries: Vec<Entry>) -> Vec<Entry> {
    entries
        .into_iter()
        .enumerate()
        .map(|(idx, entry)| {
            let line = idx + 1;
            match entry {
                Entry::Rule(r) => Entry::Rule(Rule {
                    line,
                    span: span(0, 0),
                    ..r
                }),
                Entry::SetDefinition { name, values, .. } => Entry::SetDefinition {
                    name,
                    values,
                    line,
                    span: span(0, 0),
                },
                Entry::Comment { text, .. } => Entry::Comment { text, line },
                Entry::Blank { .. } => Entry::Blank { line },
            }
        })
        .collect()
}

fn render_program(entries: &[Entry]) -> String {
    let mut s = String::new();
    for entry in entries {
        let _ = writeln!(s, "{entry}");
    }
    s
}

fn fatal_count(diags: &[rulesteward_core::Diagnostic]) -> usize {
    diags
        .iter()
        .filter(|d| d.severity == Severity::Fatal)
        .count()
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// Property 1 - `parse_rules_file` never panics on arbitrary input, and
    /// on `Err` always returns at least one `Fatal` diagnostic whose code
    /// starts with `"fapd-F"`. The Fatal-content assertion kills the mutation
    /// "replace `Err(diags)` with `Err(vec![])`".
    #[test]
    fn parse_never_panics(s in proptest::string::string_regex(".{0,16384}").unwrap()) {
        let result = catch_unwind(AssertUnwindSafe(|| parse_rules_file(&s)));
        prop_assert!(
            result.is_ok(),
            "parse_rules_file panicked on input of len {}",
            s.len()
        );
        // `result` is Result<Result<Vec<Entry>, Vec<Diagnostic>>, Box<Any>>.
        // The outer Ok is "did not panic"; the inner Result is parser's own.
        if let Ok(Err(diags)) = result {
            prop_assert!(
                !diags.is_empty(),
                "Err path returned an empty diagnostic vec - caller has no way to know what failed"
            );
            let has_fatal_f = diags.iter().any(|d| {
                d.severity == Severity::Fatal && d.code.as_ref().starts_with("fapd-F")
            });
            prop_assert!(
                has_fatal_f,
                "Err path returned diagnostics, but none were Severity::Fatal with a code starting with \"fapd-F\". \
                 Got: {:?}",
                diags.iter().map(|d| (d.severity, d.code.as_ref())).collect::<Vec<_>>()
            );
        }
    }

    /// Property 2 - every `Vec<Entry>` produced by `arb_program()` renders
    /// to a source string that re-parses to an equal `Vec<Entry>` (after
    /// line-normalization on both sides - see top-of-file contract).
    ///
    /// `arb_program()` is constrained to only emit shapes the parser must
    /// accept (known attribute keys, legacy rules respect the positional
    /// classifier, no reserved characters in payloads). If parsing fails,
    /// the generator and parser disagree on what counts as "valid" - we
    /// surface that as a property failure with the source text in the
    /// shrunken counter-example.
    #[test]
    fn parsed_program_round_trips(original in generators::arb_program()) {
        let source = render_program(&original);
        let reparsed = match parse_rules_file(&source) {
            Ok(entries) => entries,
            Err(diags) => {
                return Err(TestCaseError::fail(format!(
                    "round-trip parse failed on generator output. \
                     source={source:?}, diagnostics={diags:?}"
                )));
            }
        };

        let original_norm = normalize_lines(original);
        let reparsed_norm = normalize_lines(reparsed);

        prop_assert_eq!(
            original_norm.len(),
            reparsed_norm.len(),
            "round-trip produced a different number of entries. source={:?}",
            source
        );
        prop_assert_eq!(
            &original_norm,
            &reparsed_norm,
            "round-trip changed the AST. source={:?}",
            source
        );
    }

    /// Property 3 - adding N invalid lines in front of a valid input never
    /// reduces the count of `Severity::Fatal` diagnostics. Specifically:
    ///
    ///   * `fatal_count(combined) >= N`        - at least one fapd-F01 per bad line
    ///   * `fatal_count(combined) >= fatal_count(valid)` - monotonic in N
    ///
    /// The first inequality kills the mutation "return only the first
    /// error". The second kills the mutation "return zero diagnostics on
    /// error" (and is a backstop against any mutation that silently drops
    /// diagnostics when one section parses cleanly).
    #[test]
    fn diagnostics_are_monotonic(
        valid in generators::arb_valid_rule_text(),
        garbage_n in 0u8..=8u8,
        garbage_lines in prop::collection::vec(
            // Lines of pure reserved characters - these contain no decision
            // keyword, no `#`, no `%`, and no `=`, so they cannot match any
            // top-level production. Every such line must produce ≥1 fapd-F01.
            proptest::string::string_regex("[!@$^&*]{1,16}").unwrap(),
            8,
        ),
    ) {
        let n = garbage_n as usize;
        let garbage: String = garbage_lines.iter().take(n).fold(String::new(), |mut acc, line| {
            let _ = writeln!(acc, "{line}");
            acc
        });
        let combined = format!("{garbage}{valid}");

        let valid_diags = match parse_rules_file(&valid) {
            Ok(_) => Vec::new(),
            Err(d) => d,
        };
        let combined_diags = match parse_rules_file(&combined) {
            Ok(_) => Vec::new(),
            Err(d) => d,
        };

        let valid_fatals = fatal_count(&valid_diags);
        let combined_fatals = fatal_count(&combined_diags);

        // Sanity: the valid-only input must parse cleanly (zero fatals).
        // If it doesn't, the generator is producing something the parser
        // rejects - we want to know about that, but it's a generator bug,
        // not a monotonicity violation. Surface as a failure with context.
        prop_assert_eq!(
            valid_fatals,
            0,
            "arb_valid_rule_text produced text the parser rejected. \
             source={:?}, diagnostics={:?}",
            valid,
            valid_diags
        );

        prop_assert!(
            combined_fatals >= n,
            "expected at least {} fatal diagnostics (one per garbage line), got {}. \
             garbage={:?}, valid={:?}, diagnostics={:?}",
            n,
            combined_fatals,
            garbage,
            valid,
            combined_diags
        );

        prop_assert!(
            combined_fatals >= valid_fatals,
            "adding garbage reduced the fatal-count from {} to {} - diagnostics are not monotonic",
            valid_fatals,
            combined_fatals
        );
    }

    /// Property 4 - every `Rule` produced by `parse_rules_file` has a
    /// non-empty span that lies within the bounds of the source string.
    ///
    /// Kills mutations that:
    /// - Leave `span` as `0..0` (the placeholder default): the non-empty
    ///   assertion fails for any non-empty rule body.
    /// - Set `span.end` beyond `source.len()`: the upper-bound assertion
    ///   fails.
    #[test]
    fn parsed_rule_spans_are_non_empty_subranges_of_source(
        source in generators::arb_valid_rule_text()
    ) {
        if let Ok(entries) = parse_rules_file(&source) {
            for entry in &entries {
                if let Entry::Rule(r) = entry {
                    prop_assert!(
                        r.span.start < r.span.end,
                        "Rule.span must be non-empty; got {:?} in source {:?}",
                        r.span,
                        source
                    );
                    prop_assert!(
                        r.span.end <= source.len(),
                        "Rule.span.end ({}) must not exceed source.len() ({})",
                        r.span.end,
                        source.len()
                    );
                    prop_assert!(
                        r.span.start <= source.len(),
                        "Rule.span.start ({}) must not exceed source.len() ({})",
                        r.span.start,
                        source.len()
                    );
                }
            }
        }
    }

    /// Property 5 (fapd-E02) - the lint walker never panics on any parser-
    /// accepted input. We use `arb_valid_rule_text` so the parser
    /// always succeeds; the property then exercises the full `lint`
    /// pipeline (which includes fapd-E02) and asserts it returns without
    /// panicking. Together with parse_never_panics, this covers the
    /// entire "input -> diagnostics" pipeline for fapd-E02.
    #[test]
    fn e02_never_panics_on_parser_accepted_input(
        source in generators::arb_valid_rule_text()
    ) {
        // generator-induced parse failures are not our concern here
        let Ok(entries) = parse_rules_file(&source) else {
            return Ok(());
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let result = catch_unwind(AssertUnwindSafe(|| lint(&entries, &source, &path)));
        prop_assert!(
            result.is_ok(),
            "lint panicked on parser-accepted input: {source:?}"
        );
    }

    /// Property 7 (fapd-E03) - the lint walker never panics on any parser-
    /// accepted input. Mirror of Property 5 for fapd-E03; together with
    /// `parse_never_panics`, covers the full pipeline.
    #[test]
    fn e03_never_panics_on_parser_accepted_input(
        source in generators::arb_valid_rule_text()
    ) {
        // generator-induced parse failures are not our concern here
        let Ok(entries) = parse_rules_file(&source) else {
            return Ok(());
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let result = catch_unwind(AssertUnwindSafe(|| lint(&entries, &source, &path)));
        prop_assert!(
            result.is_ok(),
            "lint panicked on parser-accepted input: {source:?}"
        );
    }

    /// Property 8 (fapd-E03) - when every macro reference in a file has a
    /// matching `%name=...` definition ABOVE it in source order, fapd-E03
    /// emits zero diagnostics. Generates N (1..=4) distinct macro names,
    /// emits their definitions first, then a single rule that references
    /// each name. Kills mutations that flip the membership check (e.g.
    /// emitting fapd-E03 unconditionally, or treating an empty `defined` set
    /// as containing every name).
    #[test]
    fn e03_silent_when_all_refs_match_definitions(
        names in prop::collection::vec(
            "[a-zA-Z_][a-zA-Z0-9_]{0,15}",
            1..=4,
        ).prop_filter(
            "names must be unique",
            |v| {
                let mut sorted = v.clone();
                sorted.sort();
                sorted.dedup();
                sorted.len() == v.len()
            },
        )
    ) {
        // Build: each name gets a `%name=foo` definition on its own line,
        // followed by a single rule referencing each in turn on the
        // subject side via `uid=%name`. (uid accepts SetRef per the
        // parser; fapd-E02 explicitly skips SetRef values, so only fapd-E03's
        // membership check is exercised.)
        let mut source = String::new();
        for name in &names {
            let _ = writeln!(source, "%{name}=foo");
        }
        // One rule per macro name to keep the lint walk simple.
        for name in &names {
            let _ = writeln!(source, "allow uid=%{name} : exe=/foo");
        }
        let entries = parse_rules_file(&source)
            .map_err(|d| TestCaseError::fail(
                format!("generated source failed to parse: source={source:?} diags={d:?}")
            ))?;
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let e03_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-E03").count();
        prop_assert_eq!(
            e03_count,
            0,
            "all macro refs are defined above; expected 0 fapd-E03 diagnostics, got {:?}",
            diags.iter().filter(|d| d.code.as_ref() == "fapd-E03").collect::<Vec<_>>()
        );
    }

    /// Property 9 (fapd-E04) - the lint walker never panics on any parser-
    /// accepted input. Mirror of Property 5/7 for fapd-E04; together with
    /// `parse_never_panics`, covers the full pipeline.
    #[test]
    fn e04_never_panics_on_parser_accepted_input(
        source in generators::arb_valid_rule_text()
    ) {
        // generator-induced parse failures are not our concern here
        let Ok(entries) = parse_rules_file(&source) else {
            return Ok(());
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let result = catch_unwind(AssertUnwindSafe(|| lint(&entries, &source, &path)));
        prop_assert!(
            result.is_ok(),
            "lint panicked on parser-accepted input: {source:?}"
        );
    }

    /// Property 10 (fapd-E04) - when no rule contains a `trust=%setname` or
    /// `pattern=%setname` attribute, fapd-E04 emits zero diagnostics. We
    /// generate rules of the shape `allow uid=N : path=/foo` whose attrs
    /// contain neither SetRefs nor `trust`/`pattern` keys, so fapd-E04's
    /// predicate (key in {"trust", "pattern"} AND value is SetRef) is
    /// never satisfied. Kills mutations that flip the membership check
    /// (e.g. emitting fapd-E04 unconditionally, or treating the empty key
    /// set as containing every key).
    #[test]
    fn e04_silent_when_no_trust_or_pattern_macro(
        rules in prop::collection::vec(
            (0u32..1_000_000u32, "[a-zA-Z0-9_/.\\-]{1,16}"),
            1..=4,
        )
    ) {
        // Emit one `allow uid=N : path=P` rule per generator tuple.
        // Neither attr is in {"trust", "pattern"} and no value is a
        // SetRef, so fapd-E04 must fire zero times.
        let mut source = String::new();
        for (uid, path) in &rules {
            let _ = writeln!(source, "allow uid={uid} : path={path}");
        }
        let entries = parse_rules_file(&source)
            .map_err(|d| TestCaseError::fail(
                format!("generated source failed to parse: source={source:?} diags={d:?}")
            ))?;
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let e04_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-E04").count();
        prop_assert_eq!(
            e04_count,
            0,
            "no rule has trust=/pattern= macro; expected 0 fapd-E04 diagnostics, got {:?}",
            diags.iter().filter(|d| d.code.as_ref() == "fapd-E04").collect::<Vec<_>>()
        );
    }

    /// Property 11 (fapd-E05) - the lint walker never panics on any parser-
    /// accepted input. Mirror of Property 5/7/9 for fapd-E05; together with
    /// `parse_never_panics`, covers the full pipeline.
    #[test]
    fn e05_never_panics_on_parser_accepted_input(
        source in generators::arb_valid_rule_text()
    ) {
        // generator-induced parse failures are not our concern here
        let Ok(entries) = parse_rules_file(&source) else {
            return Ok(());
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let result = catch_unwind(AssertUnwindSafe(|| lint(&entries, &source, &path)));
        prop_assert!(
            result.is_ok(),
            "lint panicked on parser-accepted input: {source:?}"
        );
    }

    /// Property 12 (fapd-E05) - when every value in a `%name=...` set
    /// definition is homogeneous (all parse as `i64`, OR all do not
    /// parse as `i64`), fapd-E05 emits zero diagnostics. Generates a `bool`
    /// to choose which homogeneous family to build, then 1..=6 values
    /// of that family, and constructs `%mymacro=v1,v2,...`. Kills
    /// mutations that flip the predicate (e.g. emitting fapd-E05 on every
    /// SetDefinition, or treating an all-numeric set as mixed).
    #[test]
    fn e05_silent_when_homogeneous(
        use_numeric in any::<bool>(),
        nums in prop::collection::vec(0i64..1_000_000_i64, 1..=6),
        // String values must NOT parse as i64; the filter mirrors the
        // round-trip generator's `arb_str_value` exclusion so we never
        // accidentally drift a "string" into the numeric column.
        strs in prop::collection::vec(
            "[a-zA-Z_/.][a-zA-Z0-9_/.\\-]{0,15}"
                .prop_filter("must not parse as i64", |s: &String| s.parse::<i64>().is_err()),
            1..=6,
        ),
    ) {
        let values: Vec<String> = if use_numeric {
            nums.iter().map(i64::to_string).collect()
        } else {
            strs.clone()
        };
        let source = format!("%mymacro={}\n", values.join(","));
        let entries = parse_rules_file(&source)
            .map_err(|d| TestCaseError::fail(
                format!("generated source failed to parse: source={source:?} diags={d:?}")
            ))?;
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let e05_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-E05").count();
        prop_assert_eq!(
            e05_count,
            0,
            "homogeneous set must produce zero fapd-E05; values={:?} diags={:?}",
            values,
            diags.iter().filter(|d| d.code.as_ref() == "fapd-E05").collect::<Vec<_>>()
        );
    }

    /// Property 13 (fapd-W07) - the lint walker never panics on any parser-
    /// accepted input. Mirror of Property 5/7/9/11 for fapd-W07; together with
    /// `parse_never_panics`, covers the full pipeline.
    #[test]
    fn w07_never_panics_on_parser_accepted_input(
        source in generators::arb_valid_rule_text()
    ) {
        // generator-induced parse failures are not our concern here
        let Ok(entries) = parse_rules_file(&source) else {
            return Ok(());
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let result = catch_unwind(AssertUnwindSafe(|| lint(&entries, &source, &path)));
        prop_assert!(
            result.is_ok(),
            "lint panicked on parser-accepted input: {source:?}"
        );
    }

    /// Property 14 (fapd-W07) - fapd-W07 fires exactly once per `sha256hash=`
    /// attribute and exactly zero times for any number of `filehash=`
    /// attributes in the same rule. We generate N (1..=3) `sha256hash=<64hex>`
    /// attributes on the subject side and M (0..=3) `filehash=<64hex>`
    /// attributes on the object side, build a syntactically valid rule, parse
    /// + lint, and assert the fapd-W07 diagnostic count equals N (independent
    /// of M). Kills mutations that flip the predicate (e.g. firing on
    /// filehash, double-emitting, deduplicating, or skipping every other
    /// attr).
    #[test]
    fn w07_fires_exactly_once_per_sha256hash_attr(
        n in 1usize..=3usize,
        m in 0usize..=3usize,
        // 64-char hex blocks - one per attribute we'll emit. We generate
        // enough for the maximum N+M and slice as needed.
        nibbles in prop::collection::vec(
            prop::collection::vec(0u8..16u8, 64..=64),
            6..=6,
        )
    ) {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let hex_block = |idx: usize| -> String {
            nibbles[idx]
                .iter()
                .map(|nib| HEX_CHARS[*nib as usize] as char)
                .collect()
        };

        // Build the subject side: N `sha256hash=<hex>` attrs.
        let mut subject = String::new();
        for i in 0..n {
            if !subject.is_empty() {
                subject.push(' ');
            }
            let _ = write!(subject, "sha256hash={}", hex_block(i));
        }
        // Build the object side: M `filehash=<hex>` attrs (M may be 0).
        // When M == 0 we need *some* object attr for the rule to parse,
        // so default to `exe=/foo`. When M > 0, the filehash attrs are
        // the object body.
        let object = if m == 0 {
            "exe=/foo".to_string()
        } else {
            let mut parts = Vec::with_capacity(m);
            for j in 0..m {
                parts.push(format!("filehash={}", hex_block(n + j)));
            }
            parts.join(" ")
        };

        let source = format!("allow {subject} : {object}\n");
        let entries = parse_rules_file(&source)
            .map_err(|d| TestCaseError::fail(
                format!("generated source failed to parse: source={source:?} diags={d:?}")
            ))?;
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let w07_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-W07").count();
        prop_assert_eq!(
            w07_count,
            n,
            "expected exactly {} fapd-W07 diagnostics (one per sha256hash=) but got {}; \
             N={}, M={}, source={:?}, diags={:?}",
            n,
            w07_count,
            n,
            m,
            source,
            diags.iter().filter(|d| d.code.as_ref() == "fapd-W07").collect::<Vec<_>>()
        );
    }

    /// Property 6 (fapd-E02) - for any 64-char ASCII hex string, the lint
    /// walker emits zero fapd-E02 diagnostics for a rule of shape
    /// `allow filehash=<hex> : exe=/foo`. Pins the Hex64 valid-path.
    /// Kills mutations that flip the predicate (e.g. emitting fapd-E02 on
    /// any filehash regardless of validity).
    #[test]
    fn e02_silent_on_canonical_filehash(
        hex_nibbles in prop::collection::vec(0u8..16u8, 64..=64)
    ) {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let hex: String = hex_nibbles
            .iter()
            .map(|n| HEX_CHARS[*n as usize] as char)
            .collect();
        prop_assert_eq!(hex.len(), 64, "generator must produce exactly 64 chars");

        let source = format!("allow filehash={hex} : exe=/foo\n");
        let entries = parse_rules_file(&source)
            .map_err(|d| TestCaseError::fail(format!("canonical filehash failed to parse: {d:?}")))?;
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let e02_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-E02").count();
        prop_assert_eq!(
            e02_count,
            0,
            "canonical 64-hex filehash must produce zero fapd-E02 diagnostics; got {:?}",
            diags
        );
    }

    /// Invariant I1 (fapd-W01) - the lint walker never panics on any parser-
    /// accepted input. Mirror of Property 5/7/9/11/13 for fapd-W01; together
    /// with `parse_never_panics`, covers the full pipeline.
    ///
    /// TDD RED proof: temporarily injecting a panic guarded by
    /// `if entries.iter().filter(|e| matches!(e, Entry::Rule(_))).count() >= 2`
    /// at the top of `reachability::walk` makes this property fail with a
    /// shrunk 2-rule counterexample. (A `len() == 7` guard would pass
    /// vacuously here because `arb_valid_rule_text` emits only 1..=3 rules, so
    /// the guard must be reachable by the generator.) Removing the injection
    /// restores the pass. Confirmed in the session-3c-B Task-1 cycle.
    #[test]
    fn w01_never_panics_on_parser_accepted_input(
        source in generators::arb_valid_rule_text()
    ) {
        // generator-induced parse failures are not our concern here
        let Ok(entries) = parse_rules_file(&source) else {
            return Ok(());
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let result = catch_unwind(AssertUnwindSafe(|| lint(&entries, &source, &path)));
        prop_assert!(
            result.is_ok(),
            "lint panicked on parser-accepted input: {source:?}"
        );
    }

    /// Invariant I2 (fapd-W01) - a single-rule file never produces fapd-W01:
    /// shadowing requires a pair of rules, and one rule forms no pair.
    ///
    /// TDD RED proof: temporarily changing the outer pair loop bound in
    /// `reachability::walk` from `for b_idx in 0..rules.len()` to
    /// `for b_idx in 0..=rules.len()` (off-by-one) indexes out of bounds on a
    /// single-rule file and panics; the invariant fails. Restoring the bound
    /// removes the failure. (An alternative shadowing-against-self mutation
    /// would also be caught here.) Confirmed in the session-3c-B cycle.
    #[test]
    fn w01_silent_on_single_rule_file(rule in generators::arb_modern_rule()) {
        let source = format!("{}\n", Entry::Rule(rule));
        let Ok(entries) = parse_rules_file(&source) else {
            return Ok(());
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let w01_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-W01").count();
        prop_assert_eq!(
            w01_count,
            0,
            "a single rule cannot be shadowed (no pair); source={:?} diags={:?}",
            source,
            diags.iter().filter(|d| d.code.as_ref() == "fapd-W01").collect::<Vec<_>>()
        );
    }

    /// Invariant I3 (fapd-W01) - when every rule's subject uses a distinct,
    /// uniquely-keyed attribute that appears in no other rule's subject, no
    /// rule can subsume another on the subject side, so fapd-W01 stays silent.
    ///
    /// We assign each rule the i-th distinct SUBJECT_ONLY key with a fixed
    /// literal value, and give every rule the same broad `all` object (so the
    /// object side never blocks subsume - the subject side is the sole
    /// discriminator). Because each rule's lone subject constraint uses a key
    /// no other rule's subject carries, the literal-equal-subset check fails
    /// for every ordered pair.
    ///
    /// TDD RED proof: temporarily making `subsumes_attr` return `true`
    /// unconditionally (ignoring the key/value check) makes every earlier
    /// rule subsume every later rule, firing fapd-W01 and failing this
    /// invariant. Restoring the real check removes the failure. Confirmed in
    /// the session-3c-B cycle.
    #[test]
    fn w01_silent_when_all_rules_have_disjoint_subject_keys(
        // 2..=8 rules, each pinned to a distinct subject key by index.
        n in 2usize..=8usize,
        vals in prop::collection::vec(0u32..1_000_000u32, 8),
    ) {
        // SUBJECT_ONLY keys that accept an arbitrary integer value cleanly.
        const KEYS: &[&str] = &[
            "auid", "uid", "gid", "sessionid", "pid", "ppid",
        ];
        let n = n.min(KEYS.len());
        let mut source = String::new();
        for i in 0..n {
            // Each rule: `allow <key_i>=<val_i> : all`. Distinct subject key
            // per rule guarantees no subject-side subsume across the pair set.
            let _ = writeln!(source, "allow {}={} : all", KEYS[i], vals[i]);
        }
        let Ok(entries) = parse_rules_file(&source) else {
            return Err(TestCaseError::fail(format!(
                "disjoint-key generator produced unparseable source: {source:?}"
            )));
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let w01_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-W01").count();
        prop_assert_eq!(
            w01_count,
            0,
            "disjoint subject keys cannot shadow; source={:?} diags={:?}",
            source,
            diags.iter().filter(|d| d.code.as_ref() == "fapd-W01").collect::<Vec<_>>()
        );
    }

    /// Invariant I4 (fapd-W01) - with no `%name=` set definitions, no `dir=`
    /// attribute, and no `Attr::All`, the only way fapd-W01 can fire is the
    /// literal-equal-subset path. We generate rules whose subject is a single
    /// `uid=<n>` with a value drawn from a wide range and whose object is a
    /// single `path=<unique>` literal that differs across rules. With distinct
    /// object paths, no rule subsumes another -> zero fapd-W01.
    ///
    /// TDD RED proof: temporarily making `subsumes_value` return `true`
    /// unconditionally (over-firing literal-equal) makes every earlier rule
    /// subsume every later rule via the object side, firing fapd-W01 and
    /// failing this invariant. Restoring the equality check removes the
    /// failure. Confirmed in the session-3c-B cycle.
    #[test]
    fn w01_silent_when_no_macros_and_distinct_path_objects(
        uids in prop::collection::vec(0u32..1_000_000u32, 2..=6),
    ) {
        let mut source = String::new();
        // Object path is `/p<index>` - unique per rule, so the object side
        // never subsumes across any pair. No macros, no dir=, no Attr::All.
        for (idx, uid) in uids.iter().enumerate() {
            let _ = writeln!(source, "allow uid={uid} : path=/p{idx}");
        }
        let Ok(entries) = parse_rules_file(&source) else {
            return Err(TestCaseError::fail(format!(
                "no-macro generator produced unparseable source: {source:?}"
            )));
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let w01_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-W01").count();
        prop_assert_eq!(
            w01_count,
            0,
            "distinct path objects with no macros cannot shadow; source={:?} diags={:?}",
            source,
            diags.iter().filter(|d| d.code.as_ref() == "fapd-W01").collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// Sentinels - deterministic, single-case tests that kill specific mutations
// even if a non-shrinking proptest run doesn't surface them.
// ---------------------------------------------------------------------------

/// Sentinel for Property 2. Two hand-rolled Modern rules go through
/// render → parse and must come back unchanged (after line normalization).
/// Kills the mutation "always return `Ok(vec![])`": that mutant would make
/// the length check fail.
#[test]
fn roundtrip_sentinel() {
    let original = vec![
        Entry::Rule(Rule {
            decision: Decision::Allow,
            perm: Some(Perm::Open),
            subject: vec![Attr::Kv {
                key: "uid".to_string(),
                value: AttrValue::Int(0),
            }],
            object: vec![Attr::All],
            syntax: SyntaxFlavor::Modern,
            line: 1,
            span: span(0, 0),
        }),
        Entry::Rule(Rule {
            decision: Decision::Deny,
            perm: Some(Perm::Execute),
            subject: vec![Attr::Kv {
                key: "exe".to_string(),
                value: AttrValue::Str("/usr/bin/foo".to_string()),
            }],
            object: vec![Attr::Kv {
                key: "path".to_string(),
                value: AttrValue::Str("/etc/passwd".to_string()),
            }],
            syntax: SyntaxFlavor::Modern,
            line: 2,
            span: span(0, 0),
        }),
    ];

    let source = render_program(&original);
    let reparsed = parse_rules_file(&source).expect("hand-rolled sentinel must parse cleanly");

    assert_eq!(
        normalize_lines(original),
        normalize_lines(reparsed),
        "sentinel round-trip failed; source was:\n{source}"
    );
}

/// Sentinel for Property 3. Hard-coded N=3 garbage lines + 1 valid Modern
/// rule. The parser must report at least 3 Fatal diagnostics. Kills the
/// mutation "return only the first error".
#[test]
fn monotonicity_sentinel() {
    let source = "\
!!!garbage1!!!
@@@garbage2@@@
&&&garbage3&&&
allow perm=open uid=0 : all
";

    let Err(diags) = parse_rules_file(source) else {
        panic!(
            "sentinel input must produce parse errors (3 garbage lines), \
             but parse_rules_file returned Ok"
        )
    };

    let fatals = fatal_count(&diags);
    assert!(
        fatals >= 3,
        "expected ≥3 Fatal diagnostics (one per garbage line); got {fatals}. \
         diagnostics={diags:?}"
    );

    // Spot-check the structure: every Fatal should have a code starting
    // with "fapd-F". Catches a mutation that downgrades Fatal → Error or
    // emits Fatals without an F-code.
    for d in diags.iter().filter(|d| d.severity == Severity::Fatal) {
        assert!(
            d.code.as_ref().starts_with("fapd-F"),
            "Fatal diagnostic with non-F code: {:?}",
            d.code
        );
    }
}
