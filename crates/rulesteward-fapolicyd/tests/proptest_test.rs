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

use std::cmp::Ordering;
use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use proptest::prelude::*;

use rulesteward_core::{Severity, span};
use rulesteward_fapolicyd::{
    LintContext, TrustDb,
    ast::{Attr, AttrValue, Decision, Entry, Perm, Rule, SyntaxFlavor},
    attrs, fagenrules_cmp, lint, lint_cross_file, lint_orphans, lint_with_context,
    parse_rules_file,
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

    /// `Some(perm)` for one of 3 perm values, or `None`. MODERN (colon) syntax
    /// only: the colon-format grammar accepts an optional `perm=` clause.
    /// Legacy (no-colon) syntax does NOT accept `perm=` - use `arb_perm_legacy`.
    /// Primary source: fapolicyd rules.c:957-965 gates perm on `RULE_FMT_COLON`.
    pub(super) fn arb_perm_opt() -> impl Strategy<Value = Option<Perm>> {
        prop_oneof![
            Just(None),
            Just(Some(Perm::Open)),
            Just(Some(Perm::Execute)),
            Just(Some(Perm::Any)),
        ]
    }

    /// Legacy (no-colon) rules NEVER carry a `perm=` clause. fapolicyd
    /// rules.c:957-965 gates the perm field on `RULE_FMT_COLON`; the no-colon
    /// format rejects it with "Field type (perm) is unknown". Always returns
    /// `None` so that the legacy round-trip generator reflects the corrected
    /// grammar (issue #272 fix).
    pub(super) fn arb_perm_legacy() -> impl Strategy<Value = Option<Perm>> {
        Just(None)
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
            .prop_map(|(key, value)| Attr::Kv {
                key,
                value,
                span: 0..0,
            })
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

    /// Generate a Legacy-syntax rule. Three hard constraints to keep the
    /// positional classifier deterministic and match the corrected grammar:
    ///
    /// 1. Subject keys are drawn ONLY from `attrs::SUBJECT_ONLY`; object
    ///    keys ONLY from `attrs::OBJECT_ONLY`. `BOTH_SIDES` keys (including
    ///    `Attr::All`) are excluded - without a `:` delimiter, a `dir=`
    ///    could legally be classified onto either side, which would cause a
    ///    round-trip mismatch.
    /// 2. The Display impl renders subject first, then object, with no
    ///    colon. Post-#546, the classifier (`legacy_classify` +
    ///    `positional_split`) classifies each token INDEPENDENTLY by name,
    ///    mirroring upstream `nv_split` (rules.c) - there is no positional
    ///    "switch point" at all. This generator still emits subject-attrs
    ///    before object-attrs purely so the rendered text reads naturally
    ///    for debugging a shrunk failure, not because the classifier
    ///    requires that order. Strict-only keys (drawn only from
    ///    `SUBJECT_ONLY` / `OBJECT_ONLY`, never `BOTH_SIDES`) keep the
    ///    round-trip unambiguous regardless of ordering.
    /// 3. `perm` is ALWAYS `None` for legacy rules. fapolicyd rules.c:957-965
    ///    gates perm on `RULE_FMT_COLON`; the no-colon format rejects `perm=`.
    ///    Using `arb_perm_opt()` here would generate round-trip inputs that the
    ///    FIXED parser rejects, breaking the round-trip property (issue #272).
    pub(super) fn arb_legacy_rule() -> impl Strategy<Value = Rule> {
        (
            arb_decision(),
            arb_perm_legacy(),
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

/// Zero the span field of a single `Attr` so round-trip comparison focuses on
/// AST shape, not byte offsets. `Attr::All` has no span field.
fn zero_attr_span(attr: Attr) -> Attr {
    match attr {
        Attr::Kv { key, value, .. } => Attr::Kv {
            key,
            value,
            span: span(0, 0),
        },
        Attr::All => Attr::All,
    }
}

/// Normalize a `Vec<Entry>` so its `line` fields are 1..=N in index order
/// and all span fields (on `Rule`, `SetDefinition`, and `Attr::Kv`) are
/// zeroed out. Both sides of the round-trip equality go through this:
/// - `line` normalization: the source-text construction guarantees line
///   numbers agree, but being explicit prevents a future Display change
///   from silently breaking the property.
/// - `span` normalization: the generator uses `span(0,0)` placeholders
///   while the parser produces real file-relative spans. We zero both
///   sides so the round-trip property stays focused on AST shape, not
///   byte offsets. Span correctness is verified by dedicated unit tests
///   in `parser/mod.rs`. `Attr::Kv.span` is also zeroed here since the
///   3f impl pipeline populates per-attribute byte ranges that the
///   generator does not synthesize.
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
                    subject: r.subject.into_iter().map(zero_attr_span).collect(),
                    object: r.object.into_iter().map(zero_attr_span).collect(),
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
        let result =
            catch_unwind(AssertUnwindSafe(|| parse_rules_file(&s, Path::new("prop.rules"))));
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

    /// Property - no diagnostic emitted by the path-aware parser ever carries the
    /// retired "<source>" placeholder or a None source_id. Regression guard for
    /// G-spec-drift gap #3: a direct caller (simulate / trustdb cross-check / fuzz)
    /// must never observe the placeholder that lint_file used to rewrite.
    #[test]
    fn parser_diagnostics_never_use_placeholder(
        s in proptest::string::string_regex(".{0,4096}").unwrap()
    ) {
        let file = std::path::Path::new("prop.rules");
        if let Err(diags) = parse_rules_file(&s, file) {
            for d in &diags {
                prop_assert_eq!(
                    d.file.as_path(),
                    file,
                    "diagnostic file must be the supplied path, got {:?}",
                    d.file
                );
                prop_assert_eq!(
                    d.source_id.as_deref(),
                    Some("prop.rules"),
                    "diagnostic source_id must be populated, was {:?}",
                    d.source_id
                );
            }
        }
    }

    /// Property - every fapd-F01 diagnostic carries a FILE-relative span: the line
    /// implied by counting newlines before span.start must equal the diagnostic's
    /// own `line` field, and the span must be in-bounds. Guards the line-relative
    /// span regression where a parse error on line N>1 rendered its ariadne caret
    /// on line 1.
    ///
    /// The generator prepends 1..=4 cleanly-parsing lines before a guaranteed-
    /// failing junk line so the error always lands on line >= 2. A purely-random
    /// string almost always fails on line 1 (where line- and file-relative spans
    /// coincide) and so never exercises this regression - the targeted shape is
    /// what makes the property RED against the line-relative bug.
    #[test]
    fn f01_span_is_file_relative_and_consistent_with_line(
        (lead, junk) in (1usize..=4, "!![^\r\n]{0,16}")
    ) {
        let mut s = String::new();
        for _ in 0..lead {
            s.push_str("allow uid=0 : all\n");
        }
        s.push_str(&junk);
        s.push('\n');
        let file = std::path::Path::new("prop.rules");
        let diags = parse_rules_file(&s, file).expect_err("the junk line must fail to parse");
        for d in &diags {
            prop_assert!(d.span.start <= d.span.end, "span start..end inverted: {:?}", d.span);
            prop_assert!(
                d.span.end <= s.len(),
                "span {:?} out of bounds for source len {}",
                d.span,
                s.len()
            );
            // A manual newline count is fine here: the `bytecount` crate's SIMD
            // path that clippy::naive_bytecount suggests is not worth a dev-dep
            // for a <=4 KiB proptest input. Byte-indexed (not `s[..]`) to stay
            // panic-free on non-char-boundary offsets.
            #[allow(clippy::naive_bytecount)]
            let line_of_span_start =
                s.as_bytes()[..d.span.start].iter().filter(|&&b| b == b'\n').count() + 1;
            prop_assert_eq!(
                line_of_span_start,
                d.line,
                "span.start {} sits on line {} but diagnostic claims line {}",
                d.span.start,
                line_of_span_start,
                d.line
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
        let reparsed = match parse_rules_file(&source, Path::new("prop.rules")) {
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

        let valid_diags = match parse_rules_file(&valid, Path::new("prop.rules")) {
            Ok(_) => Vec::new(),
            Err(d) => d,
        };
        let combined_diags = match parse_rules_file(&combined, Path::new("prop.rules")) {
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
        if let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) {
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
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
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
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
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
        let entries = parse_rules_file(&source, Path::new("prop.rules"))
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
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
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
        let entries = parse_rules_file(&source, Path::new("prop.rules"))
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
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
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
        let entries = parse_rules_file(&source, Path::new("prop.rules"))
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
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
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
        let entries = parse_rules_file(&source, Path::new("prop.rules"))
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
        let entries = parse_rules_file(&source, Path::new("prop.rules"))
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
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
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
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
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
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
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
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
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

    /// Invariant I1 (fapd-S02) - the lint walker never panics on any parser-
    /// accepted input. Mirror of the per-code never-panics properties; together
    /// with `parse_never_panics`, covers the full pipeline for fapd-S02.
    ///
    /// TDD RED proof: temporarily inserting `panic!("boom")` at the top of
    /// `macros::s02` makes this property fail with a shrunk counterexample.
    /// Removing the injection restores the pass. Confirmed in the session-3c-B
    /// Task-3 cycle.
    #[test]
    fn s02_never_panics_on_parser_accepted_input(
        source in generators::arb_valid_rule_text()
    ) {
        // generator-induced parse failures are not our concern here
        let Ok(entries) = parse_rules_file(&source, Path::new("prop.rules")) else {
            return Ok(());
        };
        let path = PathBuf::from("/tmp/proptest.rules");
        let result = catch_unwind(AssertUnwindSafe(|| lint(&entries, &source, &path)));
        prop_assert!(
            result.is_ok(),
            "lint panicked on parser-accepted input: {source:?}"
        );
    }

    /// Invariant I2 (fapd-S02) - when every `%name=` macro definition precedes
    /// every rule in source order, fapd-S02 emits zero diagnostics: no macro is
    /// defined after the first rule, so the file-top window is never violated.
    /// We generate N (1..=4) distinct macro definitions followed by M (1..=3)
    /// rules, all in one source string with definitions first.
    ///
    /// TDD RED proof: temporarily flipping the emit guard in `macros::s02` from
    /// `if seen_rule` to `if !seen_rule` makes every pre-rule macro fire,
    /// over-firing and failing this invariant. Restoring the guard removes the
    /// failure. Confirmed in the session-3c-B Task-3 cycle.
    #[test]
    fn s02_silent_when_all_macros_precede_all_rules(
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
        ),
        rule_uids in prop::collection::vec(0u32..1_000_000u32, 1..=3),
    ) {
        // All macro definitions first, then all rules. Each macro is a single
        // all-string value so fapd-E05 (mixed type) never fires; each macro is
        // defined-but-unreferenced so fapd-E03 (undefined ref) never fires.
        let mut source = String::new();
        for name in &names {
            let _ = writeln!(source, "%{name}=/usr/bin/foo");
        }
        for uid in &rule_uids {
            let _ = writeln!(source, "allow uid={uid} : all");
        }
        let entries = parse_rules_file(&source, Path::new("prop.rules"))
            .map_err(|d| TestCaseError::fail(
                format!("generated source failed to parse: source={source:?} diags={d:?}")
            ))?;
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let s02_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-S02").count();
        prop_assert_eq!(
            s02_count,
            0,
            "all macros precede all rules; expected 0 fapd-S02, got {:?}",
            diags.iter().filter(|d| d.code.as_ref() == "fapd-S02").collect::<Vec<_>>()
        );
    }

    /// Invariant I3 (fapd-S02) - one rule followed by K (1..=5) macro
    /// definitions fires exactly K fapd-S02 diagnostics: every macro after the
    /// first rule is an offender, one diagnostic each.
    ///
    /// TDD RED proof: temporarily inserting `break;` after the first push in
    /// `macros::s02`'s loop makes it emit only one diagnostic regardless of K,
    /// failing the `== k` count assertion for K >= 2. Restoring the loop
    /// removes the failure. Confirmed in the session-3c-B Task-3 cycle.
    #[test]
    fn s02_fires_once_per_macro_after_first_rule(
        names in prop::collection::vec(
            "[a-zA-Z_][a-zA-Z0-9_]{0,15}",
            1..=5,
        ).prop_filter(
            "names must be unique",
            |v| {
                let mut sorted = v.clone();
                sorted.sort();
                sorted.dedup();
                sorted.len() == v.len()
            },
        ),
    ) {
        let k = names.len();
        // One rule first, then K macro definitions - all K are post-rule
        // offenders. Single all-string values keep fapd-E05 silent; the macros
        // are unreferenced so fapd-E03 stays silent.
        let mut source = String::from("allow uid=0 : all\n");
        for name in &names {
            let _ = writeln!(source, "%{name}=/usr/bin/foo");
        }
        let entries = parse_rules_file(&source, Path::new("prop.rules"))
            .map_err(|d| TestCaseError::fail(
                format!("generated source failed to parse: source={source:?} diags={d:?}")
            ))?;
        let path = PathBuf::from("/tmp/proptest.rules");
        let diags = lint(&entries, &source, &path);
        let s02_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-S02").count();
        prop_assert_eq!(
            s02_count,
            k,
            "expected exactly {} fapd-S02 (one per post-rule macro) but got {}; source={:?}",
            k,
            s02_count,
            source
        );
    }

    /// Property (fapd-W04) - a `deny all : all` in the first file makes every
    /// allow in every later file unreachable: lint_cross_file emits exactly one
    /// fapd-W04 per later-file allow.
    #[test]
    fn w04_deny_all_shadows_every_later_allow(
        n in 1usize..=5usize,
        uids in prop::collection::vec(0u32..1_000_000u32, 5),
    ) {
        let mut files: Vec<(PathBuf, Vec<Entry>)> = Vec::new();
        files.push((
            PathBuf::from("rules.d/00-deny.rules"),
            parse_rules_file("deny all : all\n", Path::new("prop.rules")).expect("deny-all parses"),
        ));
        for (i, uid) in uids.iter().enumerate().take(n) {
            let src = format!("allow uid={uid} : path=/p{i}\n");
            files.push((
                PathBuf::from(format!("rules.d/{:02}-allow.rules", 10 + i)),
                parse_rules_file(&src, Path::new("prop.rules")).expect("allow parses"),
            ));
        }
        let diags = lint_cross_file(&files);
        let w04 = diags.iter().filter(|d| d.code.as_ref() == "fapd-W04").count();
        prop_assert_eq!(
            w04, n,
            "deny all:all in file 0 must shadow all {} later allows; got {}",
            n, w04
        );
    }

    /// Property (fapd-W04) - with no deny anywhere, lint_cross_file emits zero
    /// fapd-W04 (W04 requires an earlier-file deny to shadow an allow).
    #[test]
    fn w04_silent_when_no_deny(
        uids in prop::collection::vec(0u32..1_000_000u32, 1..=5),
    ) {
        let mut files: Vec<(PathBuf, Vec<Entry>)> = Vec::new();
        for (i, uid) in uids.iter().enumerate() {
            let src = format!("allow uid={uid} : path=/p{i}\n");
            files.push((
                PathBuf::from(format!("rules.d/{:02}-allow.rules", 10 + i)),
                parse_rules_file(&src, Path::new("prop.rules")).expect("allow parses"),
            ));
        }
        let diags = lint_cross_file(&files);
        let w04 = diags.iter().filter(|d| d.code.as_ref() == "fapd-W04").count();
        prop_assert_eq!(w04, 0, "no deny rule -> zero W04, got {}", w04);
    }

    /// Property (fapd-C01) - lint_cross_file emits fapd-C01 for a rules.d file
    /// iff its filename does NOT begin with exactly two ASCII digits then `-`.
    #[test]
    fn c01_fires_iff_filename_lacks_two_digit_prefix(
        stem in "[a-zA-Z0-9_.-]{1,20}",
    ) {
        let fname = format!("{stem}.rules");
        let fb = fname.as_bytes();
        let has_prefix =
            fb.len() >= 3 && fb[0].is_ascii_digit() && fb[1].is_ascii_digit() && fb[2] == b'-';
        let files = vec![(PathBuf::from(format!("rules.d/{fname}")), Vec::new())];
        let diags = lint_cross_file(&files);
        let c01 = diags.iter().filter(|d| d.code.as_ref() == "fapd-C01").count();
        prop_assert_eq!(
            c01,
            usize::from(!has_prefix),
            "C01 must fire iff `{}` lacks the NN- prefix (has_prefix={}); got {}",
            fname, has_prefix, c01
        );
    }

    /// Property (fapd-W08) - within one rule, fapd-W08 fires exactly once per
    /// literal `dir=` value lacking a trailing slash (never for one that has it).
    #[test]
    fn w08_fires_once_per_slashless_literal_dir(
        dirs in prop::collection::vec(("[a-z]{1,8}", any::<bool>()), 1..=5),
    ) {
        let expected = dirs.iter().filter(|(_, slash)| !slash).count();
        let mut object = String::new();
        for (i, (seg, slash)) in dirs.iter().enumerate() {
            if i > 0 {
                object.push(' ');
            }
            let _ = write!(object, "dir=/{seg}{}", if *slash { "/" } else { "" });
        }
        let source = format!("allow uid=0 : {object}\n");
        let entries = parse_rules_file(&source, Path::new("prop.rules")).map_err(|d| {
            TestCaseError::fail(format!("generated source must parse: {source:?} {d:?}"))
        })?;
        let diags = lint(&entries, &source, Path::new("/tmp/proptest.rules"));
        let w08 = diags.iter().filter(|d| d.code.as_ref() == "fapd-W08").count();
        prop_assert_eq!(
            w08, expected,
            "expected {} W08 (one per slashless literal dir) in {:?}; got {}",
            expected, source, w08
        );
    }

    /// Property (fagenrules_cmp) - the comparator is a strict total order:
    /// reflexive, antisymmetric, and transitive. (Vec::sort_by requires this.)
    #[test]
    fn fagenrules_cmp_is_total_order(
        names in prop::collection::vec("[a-zA-Z0-9_.-]{1,12}", 1..=6),
    ) {
        let paths: Vec<PathBuf> =
            names.iter().map(|n| PathBuf::from(format!("{n}.rules"))).collect();
        for a in &paths {
            prop_assert_eq!(fagenrules_cmp(a, a), Ordering::Equal, "reflexivity on {:?}", a);
            for b in &paths {
                prop_assert_eq!(
                    fagenrules_cmp(a, b),
                    fagenrules_cmp(b, a).reverse(),
                    "antisymmetry on {:?} vs {:?}", a, b
                );
            }
        }
        for a in &paths {
            for b in &paths {
                for c in &paths {
                    if fagenrules_cmp(a, b) != Ordering::Greater
                        && fagenrules_cmp(b, c) != Ordering::Greater
                    {
                        prop_assert_ne!(
                            fagenrules_cmp(a, c),
                            Ordering::Greater,
                            "transitivity: {:?} <= {:?} <= {:?} but a > c", a, b, c
                        );
                    }
                }
            }
        }
    }

    /// Property (fagenrules_cmp) - sorting any permutation of
    /// `[2-x, 9-x, 10-x, 100-x]` yields the natural (version) order that real
    /// `ls -v` (and thus fagenrules) produces.
    #[test]
    fn fagenrules_cmp_sorts_numeric_prefixes_naturally(
        mut perm in Just(vec![
            PathBuf::from("2-x.rules"),
            PathBuf::from("9-x.rules"),
            PathBuf::from("10-x.rules"),
            PathBuf::from("100-x.rules"),
        ]).prop_shuffle(),
    ) {
        perm.sort_by(|a, b| fagenrules_cmp(a, b));
        let got: Vec<String> =
            perm.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        prop_assert_eq!(
            got,
            vec![
                "2-x.rules".to_string(),
                "9-x.rules".to_string(),
                "10-x.rules".to_string(),
                "100-x.rules".to_string(),
            ],
            "natural sort of a shuffled permutation must restore 2,9,10,100 order"
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
                span: span(0, 0),
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
                span: span(0, 0),
            }],
            object: vec![Attr::Kv {
                key: "path".to_string(),
                value: AttrValue::Str("/etc/passwd".to_string()),
                span: span(0, 0),
            }],
            syntax: SyntaxFlavor::Modern,
            line: 2,
            span: span(0, 0),
        }),
    ];

    let source = render_program(&original);
    let reparsed = parse_rules_file(&source, Path::new("prop.rules"))
        .expect("hand-rolled sentinel must parse cleanly");

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

    let Err(diags) = parse_rules_file(source, Path::new("prop.rules")) else {
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
    // with "fapd-F". Catches a mutation that downgrades Fatal -> Error or
    // emits Fatals without an F-code.
    for d in diags.iter().filter(|d| d.severity == Severity::Fatal) {
        assert!(
            d.code.as_ref().starts_with("fapd-F"),
            "Fatal diagnostic with non-F code: {:?}",
            d.code
        );
    }
}

// ---------------------------------------------------------------------------
// Trust-DB proptest helpers
// ---------------------------------------------------------------------------

/// Build a temporary LMDB trust.db fixture from a key slice and return the
/// `TrustDb` handle plus the `TempDir` that keeps the directory alive.
///
/// # Panics
///
/// Panics on any LMDB error (the fixture is under our full control).
#[allow(unsafe_code)]
fn build_proptest_trustdb(keys: &[&str]) -> (TrustDb, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("proptest tempdir");
    // SAFETY: opens a freshly-created tempdir LMDB env RW to build a
    // proptest fixture; no other process touches it.
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .max_dbs(1)
            .open(tmp.path())
            .expect("build_proptest_trustdb: open env failed")
    };
    let mut wtxn = env.write_txn().expect("build_proptest_trustdb: write_txn");
    let db: heed::Database<heed::types::Bytes, heed::types::Bytes> = env
        .create_database(&mut wtxn, Some("trust.db"))
        .expect("build_proptest_trustdb: create_database");
    for key in keys {
        let value = b"1 12345 aabbccdd0011223344556677889900aabbccdd0011223344556677889900aabb";
        db.put(&mut wtxn, key.as_bytes(), value)
            .expect("build_proptest_trustdb: put");
    }
    wtxn.commit().expect("build_proptest_trustdb: commit");
    drop(env);
    let trust_db = rulesteward_fapolicyd::open_trustdb_readonly(tmp.path()).expect("open ro");
    (trust_db, tmp)
}

// ---------------------------------------------------------------------------
// fapd-W06 + fapd-X01 proptest properties
// Keep case counts modest: each case builds an LMDB fixture (heed I/O is not free).
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]

    /// W06 both-absent predicate: for any (path, db-key-set, disk-present-set)
    /// triple, W06 fires iff the path is NOT in the db-key-set AND NOT in the
    /// disk-present-set. We model the disk side with real tempfiles so
    /// Path::exists() is exercised, but keep the path count small to avoid
    /// test-suite I/O overhead.
    ///
    /// Generator: N (1..=4) unique guaranteed-absent base paths under
    /// /nonexistent/rs-trap/prop/<idx>; each is independently in-db (bool) or
    /// on-disk (bool). We build the DB from the in-db subset, create real temp
    /// files for the on-disk subset, then run lint_with_context on a file that
    /// references all N paths via path= attrs. W06 must fire exactly once per
    /// path that is NEITHER in-db NOR on-disk.
    ///
    /// Kills mutations that:
    /// - Drop the !db.contains_path check -> fires when path is in DB (over-fires).
    /// - Drop the !Path::exists() check -> fires when path exists on disk (over-fires).
    /// - Invert the conjunction -> fires when EITHER is true (over-fires).
    #[test]
    fn w06_fires_iff_absent_from_db_and_disk(
        cases in prop::collection::vec(
            (any::<bool>(), any::<bool>()),
            1usize..=4usize,
        )
    ) {
        let tmp_disk = tempfile::tempdir().expect("tempdir for disk files");

        // Build per-case paths: index-addressed under /nonexistent/rs-trap/prop/<i>
        // for "truly absent" and under tmp_disk for "disk-present".
        let mut db_keys: Vec<String> = Vec::new();
        let mut disk_paths: Vec<PathBuf> = Vec::new();
        let mut all_paths: Vec<String> = Vec::new();
        let mut expected_fires: usize = 0;

        for (idx, (in_db, on_disk)) in cases.iter().enumerate() {
            let absent_path = format!("/nonexistent/rs-trap/prop/{idx}");
            if *in_db {
                db_keys.push(absent_path.clone());
                all_paths.push(absent_path);
                // in_db -> no fire
            } else if *on_disk {
                // Create a real tempfile so Path::exists() returns true.
                let disk_path = tmp_disk.path().join(format!("present_{idx}"));
                std::fs::write(&disk_path, b"").expect("create disk file");
                let disk_str = disk_path.to_str().expect("utf8").to_owned();
                disk_paths.push(disk_path);
                all_paths.push(disk_str);
                // on_disk but not in_db -> no fire (on-disk presence is sufficient)
            } else {
                // Neither in DB nor on disk -> fire.
                all_paths.push(absent_path);
                expected_fires += 1;
            }
        }

        let db_key_refs: Vec<&str> = db_keys.iter().map(String::as_str).collect();
        let (db, _tmp_db) = build_proptest_trustdb(&db_key_refs);

        // Build a rules source: one rule per path using path= attr.
        let mut source = String::new();
        for p in &all_paths {
            let _ = writeln!(source, "allow all : path={p}");
        }
        let rule_file = PathBuf::from("/tmp/prop_w06.rules");
        let entries = parse_rules_file(&source, &rule_file)
            .map_err(|d| TestCaseError::fail(format!("W06 proptest source must parse: {d:?}")))?;

        let ctx = LintContext {
            trustdb: Some(&db),
            ..Default::default()
        };
        let diags = lint_with_context(&entries, &source, &rule_file, &ctx);
        let w06_count = diags.iter().filter(|d| d.code.as_ref() == "fapd-W06").count();

        prop_assert_eq!(
            w06_count,
            expected_fires,
            "W06 must fire exactly once per path absent from BOTH DB and disk; \
             source={:?} db_keys={:?} expected={} got={}",
            source, db_keys, expected_fires, w06_count
        );

        // Disk paths are kept alive via disk_paths vec until here.
        drop(disk_paths);
    }

    /// X01 exact-reference invariant: any key that is exactly referenced by a
    /// path=/exe= rule is NEVER an orphan (regardless of what other keys exist).
    ///
    /// Generator: N (1..=4) keys; a random subset (1..=N) is referenced by
    /// exact path= rules. Only the unreferenced keys should appear as orphans.
    /// Asserts the count matches exactly.
    ///
    /// Kills mutations that:
    /// - Treat path= as prefix-match -> over-covers -> fewer orphans reported.
    /// - Ignore exact matches entirely -> all keys are orphans (under-reports).
    #[test]
    fn x01_exact_reference_never_orphan(
        keys_and_refs in prop::collection::vec(
            (any::<bool>(), 0u32..=999_999u32),
            1usize..=4usize,
        )
    ) {
        let base_keys: Vec<String> = keys_and_refs
            .iter()
            .enumerate()
            .map(|(i, _)| format!("/nonexistent/rs-trap/xprop/{i}"))
            .collect();
        let db_key_refs: Vec<&str> = base_keys.iter().map(String::as_str).collect();
        let (db, _tmp_db) = build_proptest_trustdb(&db_key_refs);

        // For each key, the bool says whether it's referenced by an exact path= rule.
        let referenced_count = keys_and_refs.iter().filter(|(referenced, _)| *referenced).count();
        let unreferenced_count = base_keys.len() - referenced_count;

        let mut source = String::new();
        for (i, (referenced, uid)) in keys_and_refs.iter().enumerate() {
            if *referenced {
                let _ = writeln!(source, "allow uid={uid} : path=/nonexistent/rs-trap/xprop/{i}");
            }
        }
        // If no references at all, add a dummy allow with a non-matching path
        // so the file parses (at least one rule).
        if referenced_count == 0 {
            let _ = writeln!(source, "allow uid=0 : path=/nonexistent/rs-trap/xprop/dummy");
        }

        let rule_file = PathBuf::from("rules.d/10-x.rules");
        let entries = parse_rules_file(&source, &rule_file)
            .map_err(|d| TestCaseError::fail(format!("X01 exact-ref proptest must parse: {d:?}")))?;

        let files = vec![(rule_file, entries)];
        let diags = lint_orphans(&files, &db);

        if unreferenced_count == 0 {
            prop_assert!(
                diags.is_empty(),
                "all keys referenced -> zero orphans; got {} diags; source={:?}",
                diags.len(), source
            );
        } else {
            prop_assert_eq!(
                diags.len(),
                1,
                "unreferenced keys exist -> exactly 1 X01 summary; got {} diags; source={:?}",
                diags.len(), source
            );
            // The summary message must mention the orphan count.
            let msg = &diags[0].message;
            let count_token = if unreferenced_count == 1 {
                "1 entry".to_string()
            } else {
                format!("{unreferenced_count} entries")
            };
            prop_assert!(
                msg.contains(&count_token),
                "X01 message must mention orphan count \"{count_token}\"; got: {msg:?}"
            );
        }
    }

    /// X01 dir-prefix invariant: any key that starts with a referenced dir=
    /// prefix is NEVER an orphan.
    ///
    /// Generator: a prefix string (under /nonexistent/rs-trap/xdir/), N (1..=4)
    /// keys under that prefix, and M (1..=4) keys with a different prefix that
    /// are unreferenced. The dir= rule covers the N under-prefix keys;
    /// the M outside-prefix keys are orphans.
    ///
    /// Kills mutations that:
    /// - Treat dir= as exact-match -> all prefixed keys become orphans.
    /// - Use contains() instead of starts_with() -> prefix check is wrong.
    #[test]
    fn x01_dir_prefix_covers_keys(
        n in 1usize..=4usize,
        m in 0usize..=4usize,
    ) {
        let prefix = "/nonexistent/rs-trap/xdir/covered/";
        let other = "/nonexistent/rs-trap/xdir/other/";

        let mut all_keys: Vec<String> = Vec::new();
        for i in 0..n {
            all_keys.push(format!("{prefix}key{i}"));
        }
        for j in 0..m {
            all_keys.push(format!("{other}key{j}"));
        }

        let db_key_refs: Vec<&str> = all_keys.iter().map(String::as_str).collect();
        let (db, _tmp_db) = build_proptest_trustdb(&db_key_refs);

        // One rule: dir= references the covered prefix (with trailing slash).
        let source = format!("allow all : dir={prefix}\n");
        let rule_file = PathBuf::from("rules.d/10-dir.rules");
        let entries = parse_rules_file(&source, &rule_file)
            .map_err(|d| TestCaseError::fail(format!("X01 dir-prefix proptest must parse: {d:?}")))?;

        let files = vec![(rule_file, entries)];
        let diags = lint_orphans(&files, &db);

        // The "other" keys are orphans. n covered keys are NOT orphans.
        if m == 0 {
            prop_assert!(
                diags.is_empty(),
                "dir= covers all keys -> zero orphans; got {} diags",
                diags.len()
            );
        } else {
            prop_assert_eq!(
                diags.len(),
                1,
                "m={} other keys are orphans -> exactly 1 X01 summary; got {} diags; source={:?}",
                m, diags.len(), source
            );
            let msg = &diags[0].message;
            let count_token = if m == 1 {
                "1 entry".to_string()
            } else {
                format!("{m} entries")
            };
            prop_assert!(
                msg.contains(&count_token),
                "X01 message must mention orphan count \"{count_token}\"; got: {msg:?}"
            );
        }
    }

    /// X01 all-all suppression invariant: when any allow all:all rule is present,
    /// lint_orphans returns zero diagnostics regardless of how many DB keys are
    /// orphaned.
    ///
    /// Generator: N (1..=6) DB keys, none referenced explicitly, plus the
    /// all:all allow rule. The presence of allow all:all must fully suppress X01.
    ///
    /// Kills the mutation `is_allow -> true unconditionally` combined with
    /// `is_all -> false` (the two must both hold). More directly kills
    /// mutations that skip the suppression check.
    #[test]
    fn x01_allow_all_all_suppresses(
        n in 1usize..=6usize,
    ) {
        let keys: Vec<String> = (0..n)
            .map(|i| format!("/nonexistent/rs-trap/xall/{i}"))
            .collect();
        let db_key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let (db, _tmp_db) = build_proptest_trustdb(&db_key_refs);

        let source = "allow all : all\n";
        let rule_file = PathBuf::from("rules.d/10-allow-all.rules");
        let entries = parse_rules_file(source, &rule_file)
            .map_err(|d| TestCaseError::fail(format!("all:all source must parse: {d:?}")))?;

        let files = vec![(rule_file, entries)];
        let diags = lint_orphans(&files, &db);

        prop_assert!(
            diags.is_empty(),
            "allow all:all must fully suppress X01 regardless of orphan count; \
             n={n} keys={:?} got {} diags: {diags:?}",
            keys, diags.len()
        );
    }
}
