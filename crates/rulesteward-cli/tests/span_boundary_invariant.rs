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
//! assertion loop. Each backend therefore counts the diagnostics it actually
//! examined and FAILS if that count is zero across the whole run. An instrument
//! that parsed nothing must never report clean. This is the same guard the
//! mutation gate applies with `total_mutants > 0`, and it is load-bearing here:
//! `rulesteward_selinux::lints::check_enforcing` returns an empty `Vec` unless
//! the target is `Rhel9`/`Rhel10`, and `check_policy_type` unless it is `Rhel8`,
//! so a `None` target would have made that arm generate thousands of cases,
//! assert over zero diagnostics, and report green.

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

/// Source text for one backend: that backend's REAL keywords interleaved with
/// the multibyte alphabet, one generated line per element.
///
/// The keyword mix is what makes this evidence rather than decoration. A
/// generator that only produces unparseable garbage exercises the error path
/// and nothing else; a generator that only produces clean input produces zero
/// diagnostics and asserts nothing. Weighting keywords 3:1 over multibyte
/// fragments gets both: real syntax reaches the semantic passes' span-emitting
/// paths, and the interleaved multibyte both lands inside otherwise-valid lines
/// and produces malformed lines for the parse-error paths.
///
/// A UTF-8 BOM (U+FEFF, 3 bytes) is generated only at offset 0, the one
/// position it is meaningful and the one position a backend treats specially
/// (`rulesteward-fapolicyd/src/parser/mod.rs:73-79`).
fn backend_source(keywords: &'static [&'static str]) -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        3 => prop::sample::select(keywords).prop_map(str::to_string),
        1 => multibyte_piece(),
    ];
    let line = prop::collection::vec(piece, 1..4).prop_map(|pieces| pieces.concat());
    (any::<bool>(), prop::collection::vec(line, 1..7)).prop_map(|(leading_bom, lines)| {
        let mut src = String::new();
        if leading_bom {
            src.push('\u{feff}');
        }
        for line in lines {
            src.push_str(&line);
            src.push('\n');
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

/// Drive one backend over `CASES` generated sources, asserting [`check_span`]
/// on every diagnostic and refusing to pass if the run examined none.
///
/// Written against `TestRunner` directly rather than the `proptest!` macro
/// because the anti-vacuity assertion has to run AFTER the whole run, over a
/// counter accumulated across cases. A separate `#[test]` reading a `static`
/// counter would depend on test execution order and is not an option.
fn run_backend(
    backend: &str,
    strategy: &impl Strategy<Value = String>,
    drive: fn(&str) -> Vec<Diagnostic>,
) {
    let examined = Cell::new(0usize);
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
        let diags = drive(&src);
        examined.set(examined.get() + diags.len());
        for d in &diags {
            check_span(backend, &src, d)?;
        }
        Ok(())
    });
    if let Err(e) = outcome {
        panic!("{backend}: span-boundary invariant violated: {e}");
    }
    assert!(
        examined.get() > 0,
        "ANTI-VACUITY FAILURE: {backend} produced ZERO diagnostics across {CASES} cases, \
         so this arm asserted nothing while reporting green. Either the generator never \
         reaches a span-emitting path, or the entry point is gated (see \
         check_enforcing / check_policy_type, which are silent at the wrong --target). \
         Fix the generator; do not relax this assertion."
    );
    // Printed so a reviewer can see the arm did real work, not just that it
    // was non-zero. `cargo test -- --nocapture` shows it.
    eprintln!(
        "span_boundary_invariant: {backend} examined {} diagnostics across {CASES} cases",
        examined.get()
    );
}

// ---------------------------------------------------------------------------
// Backend drivers - each mirrors the CLI's own drive sequence
// ---------------------------------------------------------------------------

/// fapolicyd: the ONLY backend with a sub-line span origin, and the only one
/// whose spans come from a chumsky cursor rather than `split('\n')` arithmetic.
/// Both arms are asserted on: the `Err` arm is `rich_to_diagnostic`
/// (`parser/error.rs:26-38`), the sole chumsky-span path in the tree.
fn drive_fapolicyd(src: &str) -> Vec<Diagnostic> {
    let file = Path::new("/etc/fapolicyd/rules.d/10-generated.rules");
    match rulesteward_fapolicyd::parse_rules_file(src, file) {
        Ok(entries) => rulesteward_fapolicyd::lints::lint(&entries, src, file),
        Err(diags) => diags,
    }
}

fn drive_auditd(src: &str) -> Vec<Diagnostic> {
    let file = Path::new("/etc/audit/rules.d/10-generated.rules");
    match rulesteward_auditd::parser::parse_rules_str_located(src, file) {
        Ok(rules) => rulesteward_auditd::lints::lint(
            &rules,
            rulesteward_auditd::lints::LintOptions::default(),
            Some(rulesteward_auditd::TargetVersion::Rhel9),
        ),
        Err(errs) => errs
            .iter()
            .map(rulesteward_auditd::lints::parse_error_to_diagnostic)
            .collect(),
    }
}

fn drive_sshd(src: &str) -> Vec<Diagnostic> {
    let file = Path::new("/etc/ssh/sshd_config");
    match rulesteward_sshd::parse_config_str_located(src, file) {
        Ok(blocks) => rulesteward_sshd::lints::lint(
            &blocks,
            file,
            &rulesteward_sshd::SshdLintContext::default(),
        ),
        Err(errs) => errs
            .iter()
            .map(rulesteward_sshd::lints::parse_error_to_diagnostic)
            .collect(),
    }
}

/// sysctld fuses parse and lint. Both the target-less and the targeted entry
/// points run, so the version-aware W02/W04 baseline passes (which anchor at a
/// real assignment line when the key is present) are reached too.
fn drive_sysctld(src: &str) -> Vec<Diagnostic> {
    let file = Path::new("/etc/sysctl.d/99-generated.conf");
    let mut diags = rulesteward_sysctld::parser::lint_str(src, file);
    diags.extend(rulesteward_sysctld::parser::lint_str_with_target(
        src,
        file,
        Some(rulesteward_sysctld::TargetVersion::Rhel9),
    ));
    diags
}

/// sudoers' `parse` is TOTAL - it never fails - so there is no error arm to
/// assert separately; malformed lines surface as `sudo-F01` from `lint`.
fn drive_sudoers(src: &str) -> Vec<Diagnostic> {
    let file = Path::new("/etc/sudoers");
    let parsed = rulesteward_sudoers::parse(src, file);
    rulesteward_sudoers::lints::lint(
        std::slice::from_ref(&parsed),
        &rulesteward_sudoers::SudoersLintContext::default(),
    )
}

/// selinux: BOTH passes are `--target`-gated in opposite directions, so each
/// gets the target that actually makes it fire. `se-W01` is silent outside
/// `Rhel9`/`Rhel10` and `se-W02` outside `Rhel8`; passing `None` to either (or
/// the same target to both) would make this arm vacuous, which the
/// anti-vacuity assertion in `run_backend` exists to catch.
fn drive_selinux(src: &str) -> Vec<Diagnostic> {
    let file = Path::new("/etc/selinux/config");
    let config = rulesteward_selinux::config::parse_selinux_config(src);
    let mut diags = rulesteward_selinux::lints::check_enforcing(
        &config,
        Some(rulesteward_selinux::TargetVersion::Rhel9),
        file,
    );
    diags.extend(rulesteward_selinux::lints::check_policy_type(
        &config,
        Some(rulesteward_selinux::TargetVersion::Rhel8),
        file,
    ));
    diags
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
    run_backend(
        "fapolicyd",
        &backend_source(KEYWORDS),
        drive_fapolicyd as fn(&str) -> Vec<Diagnostic>,
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
    run_backend(
        "auditd",
        &backend_source(KEYWORDS),
        drive_auditd as fn(&str) -> Vec<Diagnostic>,
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
    run_backend(
        "sshd",
        &backend_source(KEYWORDS),
        drive_sshd as fn(&str) -> Vec<Diagnostic>,
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
    run_backend(
        "sysctld",
        &backend_source(KEYWORDS),
        drive_sysctld as fn(&str) -> Vec<Diagnostic>,
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
    run_backend(
        "sudoers",
        &backend_source(KEYWORDS),
        drive_sudoers as fn(&str) -> Vec<Diagnostic>,
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
    run_backend(
        "selinux",
        &backend_source(KEYWORDS),
        drive_selinux as fn(&str) -> Vec<Diagnostic>,
    );
}
