//! Semantic lint passes over parsed `sudoers(5)` files.
//!
//! Code split (one file per semantic family; the parallel pipelines each fill ONE
//! file's bodies, mirroring the sshd / auditd crates' Phase-0 freeze):
//! * `aliases` - sudo-E01 (undefined-alias reference), sudo-W03 (dead alias)
//!   (#331).
//! * `tags` - sudo-W01 (NOPASSWD on ALL; #330), sudo-W02 (`Cmnd_Alias`
//!   transitively expands to ALL under NOPASSWD; #332).
//! * `stig` - sudo-W04 (Defaults setting weaker than the sudo STIG baseline)
//!   (#333).
//! * `catalog` - the machine-readable `sudo-` code catalog (frozen Phase 0).
//!
//! The dispatcher [`lint`] runs every pass for real (so `rulesteward sudoers lint`
//! works end to end and a clean file exits 0). In Phase 0 only `sudo-F01` emits
//! (one Fatal per [`Malformed`](crate::ast::LineKind::Malformed) logical line); the
//! e01/w01..w04 passes are `Vec::new()` stubs filled by the later pipelines. Pass
//! modules are `pub` so each pipeline's tests can call their own entrypoint
//! directly.

pub mod aliases;
pub mod catalog;
pub mod f01;
pub mod stig;
pub mod tags;
pub mod tokens;

use rulesteward_core::Diagnostic;

use crate::ast::SudoersFile;

/// Inputs the lint passes share beyond the parsed files.
///
/// Phase 0 carries no fields - the sudo STIG findings (#333) are version-agnostic,
/// so there is intentionally NO `--target` rail (unlike the sshd / sysctld
/// backends). The struct exists so the later passes can grow shared context
/// without changing the [`lint`] signature. `#[non_exhaustive]` is deliberately
/// NOT used: the struct is constructed by both the CLI and the in-crate tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct SudoersLintContext {}

/// Build a byte-anchored `Diagnostic` with the sudoers emission convention: column
/// 1 (line-start) and the source-id set to the file path's display string.
///
/// Re-exported from the shared `rulesteward-core` helper (issue #289); the lint
/// passes emit through `crate::lints::anchored`.
pub use rulesteward_core::anchored;

/// Re-exported from the `f01` module (#433 split) so `f01` keeps resolving
/// bare both here (the [`lint`] dispatcher) and in this module's own test
/// module's `use super::{..., f01, ...}` import.
pub use f01::f01;

/// Run every semantic lint pass over the parsed `files` and return the merged
/// diagnostic list, in catalog order for byte-stable output.
///
/// Takes a SLICE so the include/dir resolution seam (#334) only populates the
/// slice and never changes this signature. In Phase 0 only [`f01`] emits; the
/// other passes are stubs.
#[must_use]
pub fn lint(files: &[SudoersFile], ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = aliases::e01(files, ctx);
    diags.extend(f01(files, ctx));
    diags.extend(tokens::f02(files, ctx));
    diags.extend(tags::w01(files, ctx));
    diags.extend(tags::w02(files, ctx));
    diags.extend(aliases::w03(files, ctx));
    diags.extend(stig::w04(files, ctx));
    diags.extend(tags::w05(files, ctx));
    diags
}

#[cfg(test)]
mod tests {
    use super::{SudoersLintContext, f01, lint};
    use crate::parser::parse;
    use crate::resolve;
    use std::path::Path;

    fn parse_one(src: &str) -> Vec<crate::ast::SudoersFile> {
        vec![parse(src, Path::new("/etc/sudoers"))]
    }

    #[test]
    fn f01_emits_one_fatal_per_malformed_line() {
        // Both malformed lines sit in REAL source text (not a synthesized
        // include-resolution marker), so both anchor (#382): a non-empty byte
        // span into the file's own source, plus a source_id so ariadne can
        // render a caret snippet -- matching the auditd/sshd line-level F01
        // convention. "also garbage" on line 3 (not the file's first line)
        // pins the running byte-offset rather than a hardcoded 0..0.
        let files = parse_one("frobnicate\nroot ALL=(ALL) ALL\nalso garbage\n");
        let diags = f01(&files, &SudoersLintContext::default());
        assert_eq!(diags.len(), 2, "two malformed lines -> two sudo-F01");
        for d in &diags {
            assert_eq!(d.code, "sudo-F01");
            assert_eq!(d.severity, rulesteward_core::Severity::Fatal);
            assert!(
                d.source_id.is_some(),
                "a line-level sudo-F01 (a malformed line in real source) must be \
                 anchored so ariadne can render a snippet; got {d:?}"
            );
            assert_eq!(
                d.source_id.as_deref(),
                Some("/etc/sudoers"),
                "source-id is the file path display string"
            );
            assert!(
                !d.span.is_empty(),
                "an anchored sudo-F01 carries a real (non-empty) byte span; got {d:?}"
            );
        }
        // The first malformed line is line 1 ("frobnicate", bytes 0..10); the
        // second is line 3 ("also garbage", bytes 30..42 -- after "frobnicate\n"
        // (10 + 1 bytes) plus the clean "root ALL=(ALL) ALL\n" line (19 bytes)
        // in between).
        assert_eq!(diags[0].line, 1);
        assert_eq!(
            diags[0].span,
            0..10,
            "span must cover the raw 'frobnicate' line, not a hardcoded 0..0"
        );
        assert_eq!(diags[1].line, 3);
        assert_eq!(
            diags[1].span,
            30..42,
            "span must cover the raw 'also garbage' line, not the file start"
        );
    }

    #[test]
    fn f01_anchors_a_real_malformed_line_but_not_a_missing_include_marker() {
        // Two distinct "unparseable" cases sudo-F01 must treat DIFFERENTLY
        // (#382), exercised together through the real `resolve_target` ->
        // `f01` path:
        // * `garbage line` (line 3) is a genuinely malformed LINE inside REAL
        //   source text: the parser's `LineKind::Malformed` carries a real,
        //   non-empty byte span into `parent`'s own source, so it ANCHORS.
        // * the missing `@include does_not_exist` target (line 2) has NO real
        //   backing source: the resolver synthesizes a single-line marker
        //   `SudoersFile` with an EMPTY `source` and `Span::default()` (see
        //   `resolve::malformed_marker`) -- there is no byte range for ariadne
        //   to key, so it MUST stay UNANCHORED (no source_id), even though the
        //   real directive line number (2) is still carried: sudoers always
        //   knows which `@include` failed, unlike an `io`-level "file
        //   unreadable" case, which never becomes a sudo-F01 Diagnostic at all
        //   in this crate (a top-level read failure is a plain tool-failure
        //   exit -- see `commands/sudoers.rs` in the CLI crate -- not routed
        //   through `lints::lint`).
        let dir = tempfile::tempdir().expect("tempdir");
        let parent_path = dir.path().join("parent");
        std::fs::write(
            &parent_path,
            "root ALL=(ALL:ALL) ALL\n@include does_not_exist\ngarbage line\n",
        )
        .expect("write parent");

        let files = resolve::resolve_target(&parent_path)
            .expect("resolve a file with a missing @include and a malformed line");
        let mut diags = f01(&files, &SudoersLintContext::default());
        diags.sort_by_key(|d| d.line);
        assert_eq!(
            diags.len(),
            2,
            "one sudo-F01 for the missing include, one for the malformed line; got {diags:?}"
        );
        for d in &diags {
            assert_eq!(d.code, "sudo-F01");
            assert_eq!(d.severity, rulesteward_core::Severity::Fatal);
        }

        let missing_include = &diags[0];
        assert_eq!(
            missing_include.line, 2,
            "the @include directive sits on line 2 of parent"
        );
        assert_eq!(
            missing_include.span,
            0..0,
            "the synthetic missing-include marker has no real byte span to carry"
        );
        assert!(
            missing_include.source_id.is_none(),
            "a missing-include sudo-F01 has no real backing source, so it must \
             stay unanchored; got {missing_include:?}"
        );

        let malformed_line = &diags[1];
        assert_eq!(
            malformed_line.line, 3,
            "the garbage line is line 3 of parent"
        );
        assert_eq!(
            malformed_line.span,
            47..59,
            "span must cover the raw 'garbage line' text within parent's full source"
        );
        let parent_display = parent_path.display().to_string();
        assert_eq!(
            malformed_line.source_id.as_deref(),
            Some(parent_display.as_str()),
            "a line-level sudo-F01 anchors to its real file so ariadne can \
             render a snippet; got {malformed_line:?}"
        );
    }

    #[test]
    fn f01_carries_the_malformed_message() {
        let files = parse_one("frobnicate\n");
        let diags = f01(&files, &SudoersLintContext::default());
        assert_eq!(diags.len(), 1);
        assert!(
            !diags[0].message.trim().is_empty(),
            "the F01 message describes why the line is malformed"
        );
    }

    #[test]
    fn clean_file_produces_no_diagnostics() {
        // A STIG-clean sudoers file emits nothing: no malformed lines, no weakening
        // Defaults, and the merged missing-required check (#347, #363) is satisfied
        // by the `use_pty` + `logfile` + `timestamp_timeout` lines.
        let files = parse_one(
            "Defaults env_reset\nDefaults use_pty\nDefaults logfile=/var/log/sudo.log\nDefaults timestamp_timeout=5\nroot ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n",
        );
        let diags = lint(&files, &SudoersLintContext::default());
        assert!(
            diags.is_empty(),
            "a STIG-clean file produces no diagnostics; got {diags:?}"
        );
    }

    #[test]
    fn lint_dispatcher_emits_f01_for_a_malformed_file() {
        // The dispatcher routes a malformed line to F01. (W04's merged
        // missing-required check also fires here since this minimal file sets no
        // hardening; assert on F01 specifically rather than the total count.)
        let files = parse_one("this is not valid sudoers\n");
        let diags = lint(&files, &SudoersLintContext::default());
        let f01: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F01").collect();
        assert_eq!(f01.len(), 1, "one malformed line -> one F01; got {diags:?}");
    }

    #[test]
    fn lint_spans_multiple_files() {
        // The slice signature lets #334 feed several SudoersFiles; F01 reports
        // across all of them. (W04 absence also fires once for the merged slice
        // since neither file sets the hardening; assert on F01 specifically.)
        let mut files = parse_one("root ALL=(ALL) ALL\n");
        files.extend(parse_one("garbage here\n"));
        let diags = lint(&files, &SudoersLintContext::default());
        let f01: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F01").collect();
        assert_eq!(
            f01.len(),
            1,
            "the malformed second file yields one F01; got {diags:?}"
        );
    }

    /// Dispatcher-level integration test: the public `lint()` function must emit
    /// exactly one `sudo-F02` (Fatal) for a file containing a relative-path command.
    ///
    /// This test is RED now because `tokens::f02` is a stub AND it is NOT wired
    /// into the `lint()` dispatcher. It goes GREEN ONLY when the implementer BOTH
    /// fills `f02()` AND adds `diags.extend(tokens::f02(files, ctx))` to `lint()`.
    ///
    /// Fixture: `root ALL=(ALL:ALL) ALL\nalice ALL = bin/ls\n`
    /// - `root ALL=(ALL:ALL) ALL` is a clean anchor line (satisfies W04 absence
    ///   check is still present, but this test only asserts on sudo-F02).
    /// - `alice ALL = bin/ls` contains a relative-path command that visudo rejects
    ///   (rc=1, "expected a fully-qualified path name").
    ///
    /// Oracle: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
    ///
    /// This is the "wiring" guard: a correct `f02()` body that is never called via
    /// `lint()` makes all per-module `tokens::tests` GREEN but this test RED.
    #[test]
    fn lint_dispatcher_routes_f02_for_relative_path_command() {
        // Input chosen to produce exactly one sudo-F02: the relative-path command
        // `bin/ls` on alice's line. root's line is clean.
        let files = parse_one("root ALL=(ALL:ALL) ALL\nalice ALL = bin/ls\n");
        let diags = lint(&files, &SudoersLintContext::default());
        let f02: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02.len(),
            1,
            "the dispatcher must route exactly one sudo-F02 (Fatal) for a relative-path \
             command via lint(); got {diags:?} -- this is RED until f02 is both filled \
             AND wired into lint() with diags.extend(tokens::f02(files, ctx))"
        );
        assert_eq!(
            f02[0].severity,
            rulesteward_core::Severity::Fatal,
            "sudo-F02 must be Fatal; got {:?}",
            f02[0].severity
        );
    }

    /// Dispatcher wiring guard for sudo-W05 (#370, the STIG-strict broad any-NOPASSWD
    /// check): the public `lint()` must emit exactly one `sudo-W05` (Warning) for a
    /// NOPASSWD-on-a-specific-command user-spec.
    ///
    /// RED until the implementer BOTH fills the `tags::w05` body AND wires
    /// `diags.extend(tags::w05(files, ctx))` into `lint()`. A correct `w05` body that
    /// is never called via `lint()` would make the per-module `tags::w05_tests` GREEN
    /// but leave this test RED (the "wiring" guard, mirroring the F02 case).
    ///
    /// Fixture: `root ALL=(ALL:ALL) ALL` is a clean anchor line; `alice ALL=(root)
    /// NOPASSWD: /usr/bin/systemctl` is the specific-command NOPASSWD hazard. Both
    /// verified `visudo -c -f` rc 0 (sudo 1.9.17p2). Other passes (e.g. W04's merged
    /// absence check) also fire on this minimal file, so the assertion filters to
    /// `sudo-W05` specifically rather than the total count.
    #[test]
    fn lint_dispatcher_routes_w05_for_nopasswd_on_specific_command() {
        let files =
            parse_one("root ALL=(ALL:ALL) ALL\nalice ALL=(root) NOPASSWD: /usr/bin/systemctl\n");
        let diags = lint(&files, &SudoersLintContext::default());
        let w05: Vec<_> = diags.iter().filter(|d| d.code == "sudo-W05").collect();
        assert_eq!(
            w05.len(),
            1,
            "the dispatcher must route exactly one sudo-W05 (Warning) via lint(); got \
             {diags:?} -- RED until w05 is both filled AND wired into lint() with \
             diags.extend(tags::w05(files, ctx))"
        );
        assert_eq!(
            w05[0].severity,
            rulesteward_core::Severity::Warning,
            "sudo-W05 must be Warning; got {:?}",
            w05[0].severity
        );
    }

    /// End-to-end dedup guard (#370): a NOPASSWD-on-ALL user-spec routes to `sudo-W01`
    /// through `lint()` and must NOT also raise `sudo-W05`. Complements the per-module
    /// dedup test by pinning the boundary at the dispatcher level (both passes run).
    /// Fixture `alice ALL = NOPASSWD: ALL` verified `visudo -c -f` rc 0 (sudo 1.9.17p2).
    #[test]
    fn lint_dispatcher_nopasswd_on_all_is_w01_only_not_w05() {
        let files = parse_one("alice ALL = NOPASSWD: ALL\n");
        let diags = lint(&files, &SudoersLintContext::default());
        assert_eq!(
            diags.iter().filter(|d| d.code == "sudo-W01").count(),
            1,
            "the NOPASSWD-on-ALL line raises exactly one sudo-W01; got {diags:?}"
        );
        assert_eq!(
            diags.iter().filter(|d| d.code == "sudo-W05").count(),
            0,
            "the NOPASSWD-on-ALL line must NOT also raise sudo-W05 (dedup); got {diags:?}"
        );
    }
}
