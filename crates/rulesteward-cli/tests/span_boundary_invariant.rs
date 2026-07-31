//! Cross-backend span-boundary invariant (issue #595, session 9m lane 4).
//!
//! Every `Diagnostic` any backend emits eventually reaches the DEFAULT human
//! renderer, which converts the diagnostic's BYTE span into the CHARACTER span
//! ariadne 0.6 indexes by (`rulesteward-cli/src/output/human.rs`,
//! `byte_span_to_char_span`). `ariadne::Label::new` asserts
//! `span.start() <= span.end()` (`ariadne-0.6.0/src/lib.rs:145`), so a
//! backend-produced span that survives the conversion inverted aborts the
//! process instead of printing a diagnostic.
//!
//! # What this file is, and what it is not
//!
//! It is PARSER-PRODUCED evidence. Each test drives a backend's PUBLIC entry
//! point with generated source text and asserts the invariant on every
//! `Diagnostic` the backend REALLY produced. A test that hand-builds
//! `Diagnostic { span: 4..6, .. }` and feeds it to the renderer proves the
//! renderer survives that value; it proves nothing about whether a parser can
//! produce it. Those unit tests live in `human.rs` and are a different claim.
//!
//! It is NOT a proof of unreachability. A green run says exactly this: over the
//! inputs these generators explore, no backend emitted a span that is inverted
//! or mid-character. It does not say no such input exists. A static reading of
//! the six backends (whole-line spans in auditd / sshd / sysctld / sudoers /
//! selinux, and `body_start_in_file + <chumsky cursor>` in fapolicyd, where
//! chumsky's `&str` cursors are char boundaries by construction) says the same
//! thing more strongly, and this file is the mechanical check on that reading.
//!
//! Its lasting value is as a NET: the obvious next change in this area is
//! narrowing some backend's whole-line span to a sub-line one. When that lands,
//! this file is what fails loudly instead of shipping a latent panic.
//!
//! # Anti-vacuity
//!
//! "Zero diagnostics" and "every diagnostic passed" are indistinguishable to an
//! assertion loop, so an instrument that parsed nothing must never report clean.
//! That is the same rule the mutation gate applies with `total_mutants > 0`, and
//! it has to hold at three levels here, because a guard at one level happily
//! reports green while the level below it is empty:
//!
//! 1. **Per ARM, not per backend.** Three backends' entry points are a `match`,
//!    and the two arms are different SPAN ORIGINS - for fapolicyd the `Err` arm
//!    is `rich_to_diagnostic`'s chumsky spans and the `Ok` arm is `lints` over
//!    `fixup_attr`'s sub-line spans, the only sub-line spans in the tree. The
//!    `Ok` arm is also the low-traffic one, so a single per-backend total in the
//!    hundreds can sit on top of an `Ok` arm that has gone to zero. Every
//!    declared arm is counted and asserted separately, and the arm list is
//!    declared by the TEST rather than inferred from what the driver returned,
//!    so an arm that ran in zero cases is caught too.
//! 2. **Per multibyte source, per ARM.** Every `is_char_boundary` check is
//!    trivially true on an ASCII source, so an all-ASCII run passes every count
//!    above while testing nothing this file exists to test. Diagnostics from
//!    non-ASCII sources are counted separately and asserted non-zero - and per
//!    arm, not per backend, because the arms are fed by different inputs. A
//!    leading BOM reaches fapolicyd's `Ok` arm but is a parse error for auditd,
//!    so auditd's `Err` arm can carry hundreds of multibyte diagnostics while
//!    its `Ok` arm sees none. Measured at ZERO in 1 of 9 runs before auditd's
//!    `VALID_LINES` gained a non-ASCII entry that parses.
//! 3. **Per target gating.** `rulesteward_selinux::lints::check_enforcing`
//!    returns an empty `Vec` unless the target is `Rhel9`/`Rhel10`, and
//!    `check_policy_type` unless it is `Rhel8`, so a `None` target would have
//!    generated thousands of cases, asserted over zero diagnostics, and reported
//!    green. Each pass gets the target that makes it fire, and each is its own
//!    arm under guard 1.
//!
//! All three guards have been fired against known-bad input rather than merely
//! written: a guard that has never been observed to fail is not evidence.

use std::cell::Cell;
use std::path::Path;

use proptest::prelude::*;
use proptest::test_runner::{TestCaseResult, TestRunner};
use rulesteward_core::Diagnostic;

/// Cases per backend. Six backends at this count keep the whole file well
/// inside a normal `cargo test -p rulesteward-cli` run while still exploring
/// several thousand generated lines per backend.
const CASES: u32 = 256;

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// One multibyte fragment, one arm per UTF-8 length class.
///
/// | class          | scalar(s)                      | UTF-8 bytes |
/// |----------------|--------------------------------|-------------|
/// | CJK            | U+65E5, U+672C, U+8A9E         | 3           |
/// | combining mark | `e` + U+0301 (COMBINING ACUTE) | 1 + 2       |
/// | 4-byte emoji   | U+1F600                        | 4           |
///
/// The emoji is not decoration: it is the only class with THREE distinct
/// interior byte offsets, so an off-by-one that first appears at interior
/// offset +3 is invisible to a 3-byte-only alphabet. The combining mark is one
/// grapheme cluster spanning two scalars, so it fails any "count graphemes"
/// mistake. Contains no `\n`; [`backend_source`] owns line structure.
fn multibyte_piece() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("\u{65e5}\u{672c}\u{8a9e}".to_string()),
        Just("caf\u{e9}".to_string()),
        Just("e\u{301}".to_string()),
        Just("\u{1f600}".to_string()),
        Just("\u{1f600}\u{65e5}".to_string()),
    ]
}

/// Source text for one backend, in two deliberately different shapes.
///
/// The mix is what makes this evidence rather than decoration. A generator that
/// only produces unparseable garbage exercises the error path and nothing else;
/// a generator that only produces clean input produces few diagnostics and can
/// assert nothing. Both shapes are needed because for three of the six backends
/// the entry point is a `match` and the two arms are different SPAN ORIGINS
/// (see [`ArmDiags`]):
///
/// - **CLEAN** (weight 1): every line is exactly one entry from `valid_lines`,
///   so the whole source parses and the `Ok` arm runs. For fapolicyd that arm is
///   `lints` over `fixup_attr` sub-line spans - the only path in the tree that
///   produces a span narrower than a whole line, and therefore the only arm that
///   could ever exhibit #595 from real parser output. Leaving it to chance is
///   not acceptable for a guard the suite gates on: the mixed shape alone
///   reached it in roughly 13 of 256 cases, close enough to zero that an
///   unlucky seed could have flipped the per-arm assertion into a flake.
/// - **MIXED** (weight 3): keywords spliced with multibyte fragments inside the
///   same line, weighted 3:1. Produces malformed lines for the `Err` arm and
///   lands multibyte inside otherwise-valid ones.
///
/// A UTF-8 BOM (U+FEFF, 3 bytes) is generated only at offset 0, the one position
/// it is meaningful and the one position a backend treats specially
/// (`rulesteward-fapolicyd/src/parser/mod.rs:73-79`). It is applied to BOTH
/// shapes, and it exercises the `body_start_in_file + UTF8_BOM.len()` offset.
///
/// Do NOT generalise the BOM into "the way a clean source can also be
/// non-ASCII". That is backend-SPECIFIC, and for one backend it is inverted.
/// Probed against the real entry points on 2026-07-30:
///
/// ```text
/// fapolicyd  "allow perm=open all : all\n"                -> Ok arm
/// fapolicyd  "\u{FEFF}allow perm=open all : all\n"        -> Ok arm, non-ASCII
/// auditd     "-w /etc/passwd -p wa -k identity\n"         -> Ok arm
/// auditd     "\u{FEFF}-w /etc/passwd -p wa -k identity\n" -> Err arm,
///                                    "unknown flag '\u{FEFF}-w'"
/// ```
///
/// So the BOM carries fapolicyd's clean `Ok` arm past the multibyte counter, and
/// is redundant for sshd (which sees plenty of multibyte on its `Ok` arm anyway),
/// but for auditd a leading BOM REMOVES the source from the `Ok` arm entirely: it
/// is a parse error, not a tolerated prefix. auditd's clean `Ok` arm gets its
/// non-ASCII coverage from a multibyte entry inside its `VALID_LINES` instead.
/// Round 2 (issue #595): `trailing_newline` makes the closing `\n` after the
/// LAST line optional. Every source this generator produced used to end in
/// `\n` unconditionally, which is also true of every `VALID_LINES` entry above -
/// none of them is itself multibyte at its very last byte - so no case here
/// ever drove a backend's whole-line span arithmetic over a source whose
/// final byte is a UTF-8 continuation byte. That shape forces `human.rs`'s
/// `byte_span_to_char_span` to walk its boundary scan all the way to
/// `source.len()` before finding one - the end-of-source case an earlier,
/// hand-rolled version of that scan mishandled (see `human.rs`'s
/// `multibyte_source`, widened the same way in the same commit, for that
/// scan's own coverage of this shape). It is also a shape a real config
/// file legitimately has (a file with no trailing newline). This does not
/// change what is ASSERTED - `check_span` and the anti-vacuity counters are
/// unchanged - only the range of sources the six backends are driven with,
/// additionally exercising every backend's LAST-LINE span arithmetic.
fn backend_source(
    keywords: &'static [&'static str],
    valid_lines: &'static [&'static str],
) -> impl Strategy<Value = String> {
    let clean_line = prop::sample::select(valid_lines).prop_map(str::to_string);
    let mixed_line = prop::collection::vec(
        prop_oneof![
            3 => prop::sample::select(keywords).prop_map(str::to_string),
            1 => multibyte_piece(),
        ],
        1..4,
    )
    .prop_map(|pieces| pieces.concat());
    let body = prop_oneof![
        1 => prop::collection::vec(clean_line, 1..7),
        3 => prop::collection::vec(mixed_line, 1..7),
    ];
    (any::<bool>(), body, any::<bool>()).prop_map(|(leading_bom, lines, trailing_newline)| {
        let mut src = String::new();
        if leading_bom {
            src.push('\u{feff}');
        }
        let last = lines.len() - 1;
        for (i, line) in lines.into_iter().enumerate() {
            src.push_str(&line);
            if i != last || trailing_newline {
                src.push('\n');
            }
        }
        src
    })
}

// ---------------------------------------------------------------------------
// The invariant
// ---------------------------------------------------------------------------

/// Assert the span invariant for one diagnostic against the source it came from.
///
/// The failure messages carry the diagnostic's code AND the generated source:
/// a bare `assert!` here would be un-triageable, since the whole point of the
/// test is that nobody knows in advance which backend or which input would
/// break it.
///
/// `is_char_boundary` returns true for `0` and for `source.len()`, so the
/// `>= source.len()` arm only admits genuinely past-the-end offsets - which the
/// renderer saturates rather than inverts.
fn check_span(backend: &str, source: &str, d: &Diagnostic) -> TestCaseResult {
    prop_assert!(
        d.span.start <= d.span.end,
        "{backend}: diagnostic [{code}] carries the INVERTED span {start}..{end}; \
         ariadne::Label::new asserts start <= end and aborts the process. source: {source:?}",
        code = d.code,
        start = d.span.start,
        end = d.span.end,
    );
    prop_assert!(
        source.is_char_boundary(d.span.start) || d.span.start >= source.len(),
        "{backend}: diagnostic [{code}] span START {start} is mid-character in the source, \
         so the byte -> char conversion cannot be trusted to stay ordered. source: {source:?}",
        code = d.code,
        start = d.span.start,
    );
    prop_assert!(
        source.is_char_boundary(d.span.end) || d.span.end >= source.len(),
        "{backend}: diagnostic [{code}] span END {end} is mid-character in the source, \
         so the byte -> char conversion cannot be trusted to stay ordered. source: {source:?}",
        code = d.code,
        end = d.span.end,
    );
    Ok(())
}

/// One backend's diagnostics for a single generated source, labelled by SPAN
/// ORIGIN.
///
/// A list of labelled groups rather than a flat `Vec<Diagnostic>` because the
/// anti-vacuity counters have to be per-ARM. Where a backend's entry point is a
/// `match`, exactly ONE arm runs per case and the two arms are different span
/// origins: for fapolicyd the `Err` side is `rich_to_diagnostic`'s chumsky spans
/// (`parser/error.rs:26-38`) and the `Ok` side is `lints` over `fixup_attr`'s
/// shifted sub-line spans (`parser/mod.rs:211-217`). The `Ok` side is both the
/// low-traffic one AND the only path in the whole tree that surfaces a
/// `fixup_attr` span - it is the entire reason fapolicyd is in this file.
///
/// A single per-backend total lets the busy arm mask the interesting one going
/// to zero: a generator or parser change that stops producing parseable input
/// would leave the total in the hundreds while covering zero sub-line spans,
/// and the run would report clean. That is the same "an instrument that parsed
/// nothing must never report clean" rule the selinux target gating already
/// forced, applied one level down.
type ArmDiags = (&'static str, Vec<Diagnostic>);

/// Drive one backend over `CASES` generated sources, asserting [`check_span`]
/// on every diagnostic and refusing to pass unless EVERY declared arm produced
/// at least one diagnostic and at least one diagnostic came from a source
/// containing a non-ASCII scalar.
///
/// Three guards, each closing a different way to report clean while asserting
/// nothing:
///
/// 1. Per-ARM count `> 0`. See [`ArmDiags`].
/// 2. `arms` is declared by the CALLER, so an arm that ran in zero cases is
///    caught too - not just one that ran and produced nothing. A counter keyed
///    only by labels the driver happened to return would silently drop it.
/// 3. Multibyte-source count `> 0`, ALSO PER ARM. Every `is_char_boundary`
///    assertion in [`check_span`] is trivially true on an ASCII source, so an
///    all-ASCII run satisfies both counts above while testing nothing this file
///    exists to test. Per-backend was not enough: auditd's `Err` arm carries
///    ~500 multibyte diagnostics per run and would have covered an `Ok` arm fed
///    entirely by ASCII sources - measured at ZERO non-ASCII `Ok`-arm
///    diagnostics in 1 of 9 runs. Same masking shape as guard 1, one axis over.
///
/// Written against `TestRunner` directly rather than the `proptest!` macro
/// because these assertions have to run AFTER the whole run, over counters
/// accumulated across cases. A separate `#[test]` reading a `static` counter
/// would depend on test execution order and is not an option.
fn run_backend(
    backend: &str,
    arms: &'static [&'static str],
    strategy: &impl Strategy<Value = String>,
    drive: fn(&str) -> Vec<ArmDiags>,
) {
    // `Cell` rather than a plain `usize` behind `&mut`: `TestRunner::run` takes
    // an `impl Fn`, not an `impl FnMut`, so the closure below cannot hold a
    // mutable borrow of these counters. `Cell` is the standard single-threaded
    // interior-mutability escape hatch, and for a `Copy` payload it costs
    // nothing at runtime - `get`/`set` with no borrow flag, unlike `RefCell`.
    let per_arm: Vec<Cell<usize>> = arms.iter().map(|_| Cell::new(0usize)).collect();
    let per_arm_multibyte: Vec<Cell<usize>> = arms.iter().map(|_| Cell::new(0usize)).collect();
    // `failure_persistence: None` because the default `SourceParallel` policy
    // cannot resolve a source file from a hand-driven `TestRunner` (it warns on
    // every run) and would otherwise scatter regression files outside this
    // lane's owned paths. The shrunk failing input is in the panic message, so
    // nothing diagnostic is lost.
    let mut runner = TestRunner::new(ProptestConfig {
        cases: CASES,
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    let outcome = runner.run(strategy, |src| {
        let source_is_multibyte = !src.is_ascii();
        for (label, diags) in drive(&src) {
            let idx = arms
                .iter()
                .position(|declared| *declared == label)
                .expect("driver returned an arm label its test did not declare");
            per_arm[idx].set(per_arm[idx].get() + diags.len());
            if source_is_multibyte {
                per_arm_multibyte[idx].set(per_arm_multibyte[idx].get() + diags.len());
            }
            for d in &diags {
                check_span(backend, &src, d)?;
            }
        }
        Ok(())
    });
    if let Err(e) = outcome {
        panic!("{backend}: span-boundary invariant violated: {e}");
    }

    for (label, count) in arms.iter().zip(&per_arm) {
        assert!(
            count.get() > 0,
            "ANTI-VACUITY FAILURE: {backend} arm `{label}` produced ZERO diagnostics across \
             {CASES} cases, so that arm asserted nothing while the run reported green. Each \
             arm is a distinct SPAN ORIGIN, so a sibling arm's healthy count does not cover \
             it. Either the generator stopped reaching this arm, or the entry point is gated \
             (see check_enforcing / check_policy_type, silent at the wrong --target). Fix the \
             generator; do not relax this assertion and do not fold the arms together."
        );
    }
    for (label, count) in arms.iter().zip(&per_arm_multibyte) {
        assert!(
            count.get() > 0,
            "ANTI-VACUITY FAILURE: every diagnostic {backend} examined on arm `{label}` came \
             from an ASCII-only source, which makes every is_char_boundary assertion in \
             check_span trivially true for that arm. A sibling arm's multibyte traffic does \
             NOT cover it: the arms are different span origins and are fed by different \
             inputs (a leading BOM, for one, reaches fapolicyd's Ok arm but sends auditd's \
             source to the Err arm). Give this arm a VALID_LINES entry that is non-ASCII and \
             parses; do not relax this assertion."
        );
    }

    // Printed so a reviewer can see WHERE the work happened, not merely that a
    // total was non-zero. Counts are unseeded and vary run to run; they are a
    // cross-check on the assertions above, never a pass condition themselves.
    // `cargo test -- --nocapture` shows them.
    let breakdown: Vec<String> = arms
        .iter()
        .zip(&per_arm)
        .zip(&per_arm_multibyte)
        .map(|((label, count), multibyte)| {
            format!(
                "{label} = {} ({} from multibyte)",
                count.get(),
                multibyte.get()
            )
        })
        .collect();
    eprintln!(
        "span_boundary_invariant: {backend} over {CASES} cases: {}",
        breakdown.join(", ")
    );
}

// ---------------------------------------------------------------------------
// Backend drivers - each mirrors the CLI's own drive sequence
// ---------------------------------------------------------------------------

/// fapolicyd: the ONLY backend with a sub-line span origin, and the only one
/// whose spans come from a chumsky cursor rather than `split('\n')` arithmetic.
/// Its two arms are DIFFERENT span origins and are counted separately - see
/// [`ArmDiags`] for why the `Ok` arm cannot be allowed to hide behind the
/// `Err` arm's volume.
const FAPD_ARM_PARSE_ERR: &str = "Err: rich_to_diagnostic chumsky spans";
const FAPD_ARM_LINT: &str = "Ok: lints over fixup_attr sub-line spans";

fn drive_fapolicyd(src: &str) -> Vec<ArmDiags> {
    let file = Path::new("/etc/fapolicyd/rules.d/10-generated.rules");
    match rulesteward_fapolicyd::parse_rules_file(src, file) {
        Ok(entries) => vec![(
            FAPD_ARM_LINT,
            rulesteward_fapolicyd::lints::lint(&entries, src, file),
        )],
        Err(diags) => vec![(FAPD_ARM_PARSE_ERR, diags)],
    }
}

const AUDITD_ARM_PARSE_ERR: &str = "Err: parse_error_to_diagnostic";
const AUDITD_ARM_LINT: &str = "Ok: lints over LocatedRule spans";

fn drive_auditd(src: &str) -> Vec<ArmDiags> {
    let file = Path::new("/etc/audit/rules.d/10-generated.rules");
    match rulesteward_auditd::parser::parse_rules_str_located(src, file) {
        Ok(rules) => vec![(
            AUDITD_ARM_LINT,
            rulesteward_auditd::lints::lint(
                &rules,
                rulesteward_auditd::lints::LintOptions::default(),
                Some(rulesteward_auditd::TargetVersion::Rhel9),
            ),
        )],
        Err(errs) => vec![(
            AUDITD_ARM_PARSE_ERR,
            errs.iter()
                .map(rulesteward_auditd::lints::parse_error_to_diagnostic)
                .collect(),
        )],
    }
}

const SSHD_ARM_PARSE_ERR: &str = "Err: parse_error_to_diagnostic";
const SSHD_ARM_LINT: &str = "Ok: lints over Directive spans";

fn drive_sshd(src: &str) -> Vec<ArmDiags> {
    let file = Path::new("/etc/ssh/sshd_config");
    match rulesteward_sshd::parse_config_str_located(src, file) {
        Ok(blocks) => vec![(
            SSHD_ARM_LINT,
            rulesteward_sshd::lints::lint(
                &blocks,
                file,
                &rulesteward_sshd::SshdLintContext::default(),
            ),
        )],
        Err(errs) => vec![(
            SSHD_ARM_PARSE_ERR,
            errs.iter()
                .map(rulesteward_sshd::lints::parse_error_to_diagnostic)
                .collect(),
        )],
    }
}

/// sysctld fuses parse and lint, and both calls run on every case, so there is
/// no `match` to split: one arm. The targeted call is still made so the
/// version-aware W02/W04 baseline passes (which anchor at a real assignment
/// line when the key is present) are reached.
const SYSCTLD_ARM: &str = "lint_str + lint_str_with_target";

fn drive_sysctld(src: &str) -> Vec<ArmDiags> {
    let file = Path::new("/etc/sysctl.d/99-generated.conf");
    let mut diags = rulesteward_sysctld::parser::lint_str(src, file);
    diags.extend(rulesteward_sysctld::parser::lint_str_with_target(
        src,
        file,
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    ));
    vec![(SYSCTLD_ARM, diags)]
}

/// sudoers' `parse` is TOTAL - it never fails - so there is no error arm to
/// split out; malformed lines surface as `sudo-F01` from `lint`.
const SUDOERS_ARM: &str = "parse (total) + lint";

fn drive_sudoers(src: &str) -> Vec<ArmDiags> {
    let file = Path::new("/etc/sudoers");
    let parsed = rulesteward_sudoers::parse(src, file);
    vec![(
        SUDOERS_ARM,
        rulesteward_sudoers::lints::lint(
            std::slice::from_ref(&parsed),
            &rulesteward_sudoers::SudoersLintContext::default(),
        ),
    )]
}

/// selinux: BOTH passes are `--target`-gated in opposite directions, so each
/// gets the target that actually makes it fire, and each is counted as its own
/// arm. `se-W01` is silent outside `Rhel9`/`Rhel10` and `se-W02` outside
/// `Rhel8`; passing `None` to either (or the same target to both) silently
/// zeroes that pass, which is exactly what the per-arm guard catches. Both run
/// on every case, so unlike the `match`-shaped backends these two arms are
/// concurrent rather than exclusive.
const SELINUX_ARM_ENFORCING: &str = "check_enforcing (se-W01, Rhel9)";
const SELINUX_ARM_POLICY_TYPE: &str = "check_policy_type (se-W02, Rhel8)";

fn drive_selinux(src: &str) -> Vec<ArmDiags> {
    let file = Path::new("/etc/selinux/config");
    let config = rulesteward_selinux::config::parse_selinux_config(src);
    vec![
        (
            SELINUX_ARM_ENFORCING,
            rulesteward_selinux::lints::check_enforcing(
                &config,
                Some(rulesteward_selinux::TargetVersion::Rhel9),
                file,
            ),
        ),
        (
            SELINUX_ARM_POLICY_TYPE,
            rulesteward_selinux::lints::check_policy_type(
                &config,
                Some(rulesteward_selinux::TargetVersion::Rhel8),
                file,
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// One test per backend
// ---------------------------------------------------------------------------

#[test]
fn fapolicyd_spans_are_ordered_and_char_aligned() {
    const KEYWORDS: &[&str] = &[
        "allow perm=open all : all",
        "deny_audit perm=any uid=0 : all",
        "allow exe=/usr/bin/x : ftype=text/plain",
        "deny perm=execute dir=/tmp : all",
        "%lang=python",
        "# a comment",
        "allow ",
        "uid=0 ",
        "perm=open ",
        " : all",
    ];
    const ARMS: &[&str] = &[FAPD_ARM_PARSE_ERR, FAPD_ARM_LINT];
    // Syntactically COMPLETE lines only: the CLEAN shape splices nothing into
    // them, so a source built from these parses and reaches the `Ok` arm.
    const VALID_LINES: &[&str] = &[
        "allow perm=open all : all",
        "deny_audit perm=any uid=0 : all",
        "allow exe=/usr/bin/x : ftype=text/plain",
        "deny perm=execute dir=/tmp : all",
        "# a comment",
    ];
    run_backend(
        "fapolicyd",
        ARMS,
        &backend_source(KEYWORDS, VALID_LINES),
        drive_fapolicyd as fn(&str) -> Vec<ArmDiags>,
    );
}

#[test]
fn auditd_spans_are_ordered_and_char_aligned() {
    const KEYWORDS: &[&str] = &[
        "-w /etc/passwd -p wa -k identity",
        "-a always,exit -F arch=b64 -S execve -k exec",
        "-a always,exit -F arch=b32 -S open -F exit=-EACCES -k access",
        "-D",
        "-b 8192",
        "-f 1",
        "# a comment",
        "-F perm=wa",
        "-p rwxa",
        "-w ",
    ];
    const ARMS: &[&str] = &[AUDITD_ARM_PARSE_ERR, AUDITD_ARM_LINT];
    // Syntactically COMPLETE lines only: the CLEAN shape splices nothing into
    // them, so a source built from these parses and reaches the `Ok` arm.
    //
    // The last entry is a non-ASCII line that PARSES, and it is here because
    // auditd is the one backend where the BOM cannot do that job. Probed
    // against the real entry point on 2026-07-30:
    //
    //   "-w /etc/passwd -p wa -k identity"          -> Ok arm, 79 lint diags, ASCII
    //   "-w /etc/passwd -p wa -k identity\u{1F600}" -> Ok arm, 81 lint diags, non-ASCII
    //   "\u{FEFF}-w /etc/passwd -p wa -k identity"  -> Err arm ("unknown flag")
    //
    // The emoji lands in the `-k` key, which auditd carries verbatim, so the
    // rule still parses and the lint passes still run over it. Without this
    // entry auditd's `Ok` arm is fed almost entirely by ASCII sources, where
    // every `is_char_boundary` assertion in `check_span` is trivially true, and
    // the per-arm multibyte guard below would sit one unlucky seed from a flake
    // (measured 0 non-ASCII `Ok`-arm diagnostics in 1 of 9 runs before this
    // line existed). Do not remove it as decoration.
    const VALID_LINES: &[&str] = &[
        "-w /etc/passwd -p wa -k identity",
        "-a always,exit -F arch=b64 -S execve -k exec",
        "-a always,exit -F arch=b32 -S open -F exit=-EACCES -k access",
        "-D",
        "-b 8192",
        "-f 1",
        "# a comment",
        "-w /etc/passwd -p wa -k identity\u{1f600}",
    ];
    run_backend(
        "auditd",
        ARMS,
        &backend_source(KEYWORDS, VALID_LINES),
        drive_auditd as fn(&str) -> Vec<ArmDiags>,
    );
}

#[test]
fn sshd_spans_are_ordered_and_char_aligned() {
    const KEYWORDS: &[&str] = &[
        "PermitRootLogin yes",
        "PermitEmptyPasswords yes",
        "Port 22",
        "X11Forwarding yes",
        "Ciphers aes256-ctr",
        "ClientAliveInterval 0",
        "Match User root",
        "Banner \"unterminated",
        "# a comment",
        "Subsystem sftp ",
    ];
    const ARMS: &[&str] = &[SSHD_ARM_PARSE_ERR, SSHD_ARM_LINT];
    // Syntactically COMPLETE lines only: the CLEAN shape splices nothing into
    // them, so a source built from these parses and reaches the `Ok` arm.
    const VALID_LINES: &[&str] = &[
        "PermitRootLogin yes",
        "PermitEmptyPasswords yes",
        "Port 22",
        "X11Forwarding yes",
        "Ciphers aes256-ctr",
        "ClientAliveInterval 0",
        "# a comment",
    ];
    run_backend(
        "sshd",
        ARMS,
        &backend_source(KEYWORDS, VALID_LINES),
        drive_sshd as fn(&str) -> Vec<ArmDiags>,
    );
}

#[test]
fn sysctld_spans_are_ordered_and_char_aligned() {
    const KEYWORDS: &[&str] = &[
        "kernel.randomize_va_space = 2",
        "kernel.kptr_restrict = 0",
        "kernel.kptr_restrict = 1",
        "net.ipv4.ip_forward=1",
        "fs.suid_dumpable = 1",
        "-kernel.nothing",
        "# a comment",
        "; another comment",
        "kernel.dmesg_restrict",
        " = 2",
    ];
    const ARMS: &[&str] = &[SYSCTLD_ARM];
    // Syntactically COMPLETE lines only: the CLEAN shape splices nothing into
    // them, so a source built from these parses cleanly. This backend has a
    // single fused arm rather than an Ok/Err split, so the clean shape is here
    // for input variety and for the semantic passes that only fire on
    // well-formed input, not to reach a second arm.
    const VALID_LINES: &[&str] = &[
        "kernel.randomize_va_space = 2",
        "kernel.kptr_restrict = 0",
        "kernel.kptr_restrict = 1",
        "net.ipv4.ip_forward=1",
        "fs.suid_dumpable = 1",
        "# a comment",
    ];
    run_backend(
        "sysctld",
        ARMS,
        &backend_source(KEYWORDS, VALID_LINES),
        drive_sysctld as fn(&str) -> Vec<ArmDiags>,
    );
}

#[test]
fn sudoers_spans_are_ordered_and_char_aligned() {
    const KEYWORDS: &[&str] = &[
        "root ALL=(ALL) ALL",
        "%wheel ALL=(ALL:ALL) NOPASSWD: ALL",
        "Defaults !authenticate",
        "Defaults env_reset",
        "User_Alias ADMINS = alice, bob",
        "Cmnd_Alias SHELLS = /bin/sh, /bin/bash",
        "alice ALL=(root) /bin/ls",
        "# a comment",
        "root ALL=",
        "ALL",
    ];
    const ARMS: &[&str] = &[SUDOERS_ARM];
    // Syntactically COMPLETE lines only: the CLEAN shape splices nothing into
    // them, so a source built from these parses cleanly. This backend has a
    // single fused arm rather than an Ok/Err split, so the clean shape is here
    // for input variety and for the semantic passes that only fire on
    // well-formed input, not to reach a second arm.
    const VALID_LINES: &[&str] = &[
        "root ALL=(ALL) ALL",
        "%wheel ALL=(ALL:ALL) NOPASSWD: ALL",
        "Defaults !authenticate",
        "Defaults env_reset",
        "alice ALL=(root) /bin/ls",
        "# a comment",
    ];
    run_backend(
        "sudoers",
        ARMS,
        &backend_source(KEYWORDS, VALID_LINES),
        drive_sudoers as fn(&str) -> Vec<ArmDiags>,
    );
}

#[test]
fn selinux_spans_are_ordered_and_char_aligned() {
    const KEYWORDS: &[&str] = &[
        "SELINUX=enforcing",
        "SELINUX=permissive",
        "SELINUX=disabled",
        "SELINUXTYPE=targeted",
        "SELINUXTYPE=mls",
        "SELINUXTYPE=minimum",
        "# a comment",
        "SELINUX=",
        "SELINUXTYPE=",
    ];
    const ARMS: &[&str] = &[SELINUX_ARM_ENFORCING, SELINUX_ARM_POLICY_TYPE];
    // Syntactically COMPLETE lines only: the CLEAN shape splices nothing into
    // them, so a source built from these is a well-formed /etc/selinux/config.
    // This backend's two arms are concurrent target-gated passes, not an Ok/Err
    // split, so the clean shape is here to reach the present-but-wrong-value
    // branch of each pass rather than to reach a second arm.
    const VALID_LINES: &[&str] = &[
        "SELINUX=enforcing",
        "SELINUX=permissive",
        "SELINUX=disabled",
        "SELINUXTYPE=targeted",
        "SELINUXTYPE=mls",
        "# a comment",
    ];
    run_backend(
        "selinux",
        ARMS,
        &backend_source(KEYWORDS, VALID_LINES),
        drive_selinux as fn(&str) -> Vec<ArmDiags>,
    );
}
