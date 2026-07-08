//! Per-position token-validation lint pass (#346): sudo-F02 (the file contains a
//! token that `visudo -c` rejects but the current `RuleSteward` classifier keeps as
//! a clean spec). Severity Fatal -- the file will not load.
//!
//! # Scope (v1, issue #346)
//!
//! Four invalid-token positions, each grounded via `visudo -c` on Rocky Linux 9
//! (sudo 1.9.17p2, 2026-06-30):
//!
//! 1. **`#<digits>` in COMMAND position** (e.g. `alice ALL = /bin/ls #2`):
//!    visudo rejects this as a syntax error (rc=1). The inline-comment stripper
//!    in stage 1 preserves `#<digits>` when preceded by whitespace/comma/`%` (it
//!    is a UID/GID token in those positions), so this reaches the AST as
//!    `CmndItem::Cmnd("/bin/ls #2")`. F02 detects the `#<digits>` suffix in the
//!    command token.
//!
//! 2. **`#<digits>` in Defaults-VALUE position** (e.g.
//!    `Defaults env_reset #2 reasons`): visudo rejects this (rc=1, message
//!    "Success" at the `#2` position -- a quirk of the visudo error reporter).
//!    The inline-comment stripper preserves `#<digits>` after a space, so the
//!    value reaches the AST as `DefaultSetting { name: "env_reset #2 reasons",
//!    value: None }` (the whole thing becomes the setting name). F02 detects a
//!    `#<digits>` substring in the setting name or value.
//!
//! 3. **Relative-path command** (e.g. `alice ALL = bin/ls`): visudo reports
//!    "expected a fully-qualified path name" (rc=1). `RuleSteward` keeps this as
//!    `CmndItem::Cmnd("bin/ls")`. F02 detects a command token whose path (after
//!    stripping any leading `!` negation prefixes) contains `/` but does not start
//!    with `/`. A `!`-negated absolute path (`!/bin/su`) is VALID (visudo rc=0)
//!    and must not fire.
//!
//! 4. **Malformed group subject**: two sub-cases, both grounded against visudo
//!    (Rocky Linux 9, sudo 1.9.17p2, 2026-06-30):
//!    - **Embedded whitespace** (`%bad group ALL = ALL`, rc=1): `RuleSteward`
//!      parses `%bad` as the user and `group ALL` as the host. F02 detects a
//!      `%`-prefixed user whose host token contains whitespace.
//!    - **Invalid char in group name** (`%bad!group ALL = ALL`, rc=1): the `!`,
//!      `(`, or `)` char sits inside the user token itself (no whitespace split
//!      occurs). F02 checks each `%`-prefixed user token's name for these chars.
//!      Note: `%#NNN` (GID form) is valid (rc=0) and is excluded from this check.
//!
//! ## Issue #375 tail (Case-4/Case-5 completeness)
//!
//! Three more visudo-rejected shapes outside the four positions above, all
//! grounded via local `visudo -cf` 1.9.17p2, 2026-07-02:
//!
//! 5. **Runas-position group defects**: `CmndSpec.runas.users` /
//!    `.groups` (the `(runas_user:runas_group)` group on an individual
//!    command) are never scanned by the subject-position walk above. Two
//!    sub-rules: (a) the Case-4(b) denylist (plus embedded whitespace),
//!    applied directly to every runas.users/groups token; (b) a
//!    runas.groups token starting with `%` is invalid regardless of
//!    denylist chars (the post-colon position already denotes a group).
//! 6. **Lone `!` command**: `CmndItem::Cmnd("!")` -- a negation with nothing
//!    to negate. Keyed off the exact token `"!"`, not `starts_with('!')`, so
//!    `!ALL` and `!/bin/su` are unaffected.
//! 7. **GID-then-non-digit subject**: a `%#<digits><non-digit>` or `%#<all
//!    non-digit>` name (e.g. `%#1000abc`, `%#abc`) is not a pure GID and has
//!    no denylist char, but is still visudo-rejected.
//!
//! ## Issue #407 (runas / Defaults `#`-GID false negatives, parser-level root cause)
//!
//! `(root:#1000abc)` and bare `(#1000abc)` used to reach `RuleSteward` as
//! `CmndSpec { runas: None, cmnd: Cmnd("(root:") }` / `Cmnd("(")` -- the
//! `strip_inline_comment` classifier (parser.rs) misread the `#` after `:` /
//! `(` as a real comment and swallowed the rest of the line (including the
//! command), so `check_runas` below never even saw the malformed token: ZERO
//! diagnostics for a `visudo -c`-rejected file. The same root cause hit the
//! `Defaults` scope sigils: `Defaults:#1000` / `Defaults>#1000` / `Defaults@#1000`
//! (all visudo rc=0) folded to a FALSE-POSITIVE `Malformed` / sudo-F01 because
//! their `#<digits>` scope target was stripped as a comment, while the invalid
//! `Defaults:#1000abc` / `Defaults>#1000abc` / `Defaults@#1000abc` (visudo rc=1)
//! either stayed silent or mis-reported. Fixed by widening
//! `strip_inline_comment`'s `prev_allows_uid` predicate to allow `:` / `(` / `>` /
//! `@`, extending the GID-tail check (Rule 3 in `check_runas`) to the bare (non-`%`)
//! form in BOTH `runas.users` and `runas.groups`, and adding the same
//! `is_malformed_gid_tail` structural check to the User (`:`), Runas (`>`) and Host
//! (`@`) `Defaults` scopes in `check_defaults`. visudo lexes `#<digits>` uniformly
//! in all three scope positions (pure digit run valid; digit-run + non-digit tail
//! a syntax error); the `!` command scope is left to fold to F01 (every `#`-command
//! target is invalid). MISS 2 -- the letter-first `(root:#abc)` runas FN on the
//! delicate `next_is_digit` gate -- is a tracked follow-up, out of scope here.
//!
//! # Must-NOT-regress (valid, no F02)
//!
//! - `User_Alias FOO = #1000`: the `#1000` follows `=` in an alias DEFINITION
//!   and is a valid UID member (visudo -c: rc=0 with only an "unused alias"
//!   warning). F02 must never fire on alias member positions.
//! - `!/bin/su` or `/bin/ls, !/bin/su`: negated absolute-path commands are valid
//!   (visudo rc=0). The `!` prefix is stripped before the path check.
//! - `%#1000 ALL = ALL`: GID-referenced group subject is valid (visudo rc=0).
//! - Any ordinary valid sudoers line (root rule, Defaults, `%wheel` rule, etc.).

mod command_specs;
mod defaults;
mod group_subject;
mod runas;
mod shared;

use rulesteward_core::Diagnostic;

use crate::ast::{LineKind, SudoersFile};
use crate::lints::SudoersLintContext;

use command_specs::check_command_specs;
use defaults::check_defaults;
use group_subject::check_group_subject;

/// sudo-F02: a token that `visudo -c` rejects is present in the file but the
/// `RuleSteward` classifier produced a clean (non-Malformed) AST node. Operator
/// signal: the file will not load. Fatal severity.
///
/// Covers four per-position cases (see module doc + issue #346):
/// 1. `#<digits>` in command position.
/// 2. `#<digits>` in Defaults setting name or value.
/// 3. Relative-path command: path (after stripping `!` negation) contains `/`
///    but does not start with `/`. `!/bin/su` (negated absolute) does NOT fire.
/// 4. Malformed group subject: `%name` with embedded whitespace OR `%name`
///    containing an invalid char (`!`, `(`, `)`) in the group name portion.
///
/// Each diagnostic names the offending token / position in its message and is
/// anchored at the containing line.
#[must_use]
pub fn f02(files: &[SudoersFile], _ctx: &SudoersLintContext) -> Vec<Diagnostic> {
    let mut diags = Vec::new();
    for file in files {
        for logical in &file.lines {
            match &logical.kind {
                LineKind::UserSpec(spec) => {
                    check_user_spec(file, logical, spec, &mut diags);
                }
                LineKind::Defaults(entry) => {
                    check_defaults(file, logical, entry, &mut diags);
                }
                // Alias defs, includes, blanks, comments, and Malformed lines are
                // not checked: alias member `#<digits>` are valid UIDs (not command
                // position), and Malformed lines already emit sudo-F01.
                _ => {}
            }
        }
    }
    diags
}

/// Cases 1, 3, 4: check a `UserSpec` line for per-position invalid tokens.
fn check_user_spec(
    file: &SudoersFile,
    logical: &crate::ast::LogicalLine,
    spec: &crate::ast::UserSpec,
    diags: &mut Vec<Diagnostic>,
) {
    check_command_specs(file, logical, spec, diags);
    check_group_subject(file, logical, spec, diags);
}

#[cfg(test)]
mod tests {
    use super::f02;
    use crate::lints::{SudoersLintContext, f01};
    use crate::parser::parse;
    use std::path::Path;

    /// Parse one source string into the single-element file slice the passes take.
    fn files(src: &str) -> Vec<crate::ast::SudoersFile> {
        vec![parse(src, Path::new("/etc/sudoers"))]
    }

    /// Run f02 over `src` and return the diagnostics.
    fn lint(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        let f = files(src);
        f02(&f, &SudoersLintContext::default())
    }

    /// Run f01 over `src` and return the diagnostics (for the tests that pin a
    /// shape as a PARSE failure caught by sudo-F01 rather than a clean-spec F02).
    fn lint_f01(src: &str) -> Vec<rulesteward_core::Diagnostic> {
        let f = files(src);
        f01(&f, &SudoersLintContext::default())
    }

    /// Count f02 (sudo-F02) diagnostics.
    fn f02_count(src: &str) -> usize {
        lint(src).iter().filter(|d| d.code == "sudo-F02").count()
    }

    // -----------------------------------------------------------------------
    // Oracle grounding (Rocky Linux 9, sudo 1.9.17p2, verified 2026-06-30):
    //
    //   Case 1: `root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls #2\n`
    //           -> visudo rc=1, "syntax error" at col 21
    //   Case 2: `root ALL=(ALL:ALL) ALL\nDefaults env_reset #2 reasons\n`
    //           -> visudo rc=1, "Success" at col 20 (visudo quirk)
    //   Case 3: `root ALL=(ALL:ALL) ALL\nalice ALL = bin/ls\n`
    //           -> visudo rc=1, "expected a fully-qualified path name"
    //   Case 4: `root ALL=(ALL:ALL) ALL\n%bad group ALL = ALL\n`
    //           -> visudo rc=1, "syntax error" at col 12
    //   Not-regress 1: `root ALL=(ALL:ALL) ALL\nUser_Alias FOO = #1000\n`
    //           -> visudo rc=0 (warning "unused User_Alias 'FOO'" only)
    //   Not-regress 2: `root ALL=(ALL:ALL) ALL\nDefaults env_reset\nDefaults use_pty\n%wheel ALL=(ALL) ALL\n`
    //           -> visudo rc=0, "parsed OK"
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Case 1: #<digits> in COMMAND position
    // -----------------------------------------------------------------------

    /// `alice ALL = /bin/ls #2` -- visudo rc=1 syntax error.
    ///
    /// The inline-comment stripper preserves `#2` (preceded by whitespace, so it
    /// looks like a UID token). The command reaches the AST as the string
    /// `/bin/ls #2`. F02 must fire exactly once, the diagnostic must have code
    /// `sudo-F02` and severity Fatal, and the message must name the offending
    /// token position (command or `#<digits>`).
    #[test]
    fn f02_hash_digits_in_command_position_fires() {
        // Fixture: visudo -c rc=1, syntax error at the `#2` in command position.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls #2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for `#digits` in command position; got {diags:?}"
        );
        assert_eq!(
            f02_diags[0].severity,
            rulesteward_core::Severity::Fatal,
            "F02 must be Fatal"
        );
        assert!(
            f02_diags[0].message.contains("#2")
                || f02_diags[0].message.to_lowercase().contains("command"),
            "F02 message must name the offending token (#2) or its position; got {:?}",
            f02_diags[0].message
        );
    }

    /// `#2` in COMMAND position fires even when it immediately follows the `=`.
    ///
    /// `alice ALL = #2` -- the command is `#2` itself (not an annotation after a
    /// valid command). visudo rejects this with `expected a fully-qualified path
    /// name` (rc=1): a bare `#<digits>` in command position is not a valid path.
    /// F02 must fire. Note: the inline-comment stripper keeps `#2` here (preceded
    /// by whitespace), so the command reaches the AST as `CmndItem::Cmnd("#2")` --
    /// the `#<digits>`-in-command check (not the relative-path check) fires.
    #[test]
    fn f02_hash_digits_bare_command_fires() {
        // Fixture: visudo rejects `alice ALL = #2` with "expected a fully-qualified
        // path name" (rc=1). Distinct from the `#2`-suffix case (Case 1a) where
        // visudo says "syntax error" -- but both reach F02's `#<digits>` branch.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = #2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for bare `#digits` command; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // Case 2: #<digits> in Defaults-VALUE position
    // -----------------------------------------------------------------------

    /// `Defaults env_reset #2 reasons` -- visudo rc=1.
    ///
    /// The inline-comment stripper preserves `#2` (preceded by whitespace). The
    /// whole `env_reset #2 reasons` becomes the setting name in the AST. F02 must
    /// fire exactly once with code `sudo-F02` and severity Fatal.
    #[test]
    fn f02_hash_digits_in_defaults_value_fires() {
        // Fixture: visudo -c rc=1, "Success" (quirk) at the `#2` position.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults env_reset #2 reasons\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for `#digits` in Defaults value; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        // Message should reference the offending token or position.
        assert!(
            f02_diags[0].message.contains("#2")
                || f02_diags[0].message.to_lowercase().contains("defaults")
                || f02_diags[0].message.to_lowercase().contains("setting"),
            "F02 message must name the token or position; got {:?}",
            f02_diags[0].message
        );
    }

    /// `Defaults secure_path=/usr/bin #3` -- `#3` in the VALUE (after `=`).
    ///
    /// visudo rejects this (rc=1). F02 must fire.
    #[test]
    fn f02_hash_digits_in_defaults_assigned_value_fires() {
        // Fixture: same oracle case, but the `#digits` appears in the assigned value.
        // Verified by oracle analogy: the strip_inline_comment function keeps any
        // `#<digits>` preceded by whitespace, so `/usr/bin #3` is preserved in the
        // AST value, and visudo rejects it as a syntax error at the `#`.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults secure_path=/usr/bin #3\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for `#digits` in Defaults assigned value; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // #405 follow-up: a literal `,` CAN now precede `#<digits>` in a Defaults
    // value (the #405 escape/quote-aware split lets it survive), and the two
    // ways it gets there are NOT distinguishable from the final value string --
    // see the `has_hash_digits` doc comment above for the full grounding.
    // -----------------------------------------------------------------------

    #[test]
    fn f02_does_not_flag_hash_after_comma_in_a_quoted_defaults_value() {
        // Oracle: `Defaults badpass_message="Wrong\,#5"` -- visudo -c rc=0
        // (accepts). `has_hash_digits` does NOT flag this, but the reason is the
        // `,` immediately before the `#` and the `,` arm being the unchecked
        // (dead) branch -- NOT the quoting. `has_hash_digits` is quote-blind, so
        // this is only a no-flag because the `,` predecessor is not in the
        // checked set. (A whitespace/`%`-preceded `#<digits>` inside the SAME
        // quotes -- e.g. `passprompt="Enter #5 now"` -- would STILL false-fire;
        // that quote-blindness defect is the tracked high-priority follow-up and
        // is intentionally NOT covered by this test.) Pins the current no-flag
        // for the `,`-glued case so closing the `,` gap does not regress it.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults badpass_message=\"Wrong\\,#5\"\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            0,
            "`,`-glued `#5` is on the unchecked comma arm; must not fire F02: {diags:?}"
        );
    }

    #[test]
    fn f02_known_gap_does_not_flag_hash_after_escaped_comma_in_unquoted_defaults_value() {
        // Oracle: `Defaults badpass_message=Wrong\,#5` (UNQUOTED) -- visudo -c
        // rc=1 ("Success" quirk position, same quirk as
        // `f02_hash_digits_in_defaults_value_fires`). This SHOULD fire F02 but
        // currently does not: `DefaultSetting` stores the value verbatim
        // (`"Wrong\,#5"`, backslash retained per the #370 precedent), which is
        // byte-for-byte IDENTICAL to the quoted-valid case above -- there is no
        // way to tell them apart without the AST tracking whether the source was
        // quote-delimited. This test PINS the known gap (documents it as a
        // named, tracked test) rather than leaving it silently unflagged; if a
        // future change fixes this without regressing the quoted case above,
        // update this assertion to expect 1 diagnostic.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults badpass_message=Wrong\\,#5\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            0,
            "known gap: unquoted escaped `,#5` is visudo-invalid but not yet \
             flagged (see the has_hash_digits doc comment); update this test if \
             that gap gets closed: {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // #407 follow-up: `#`-token tail in a `Defaults` scope TARGET (`:`/`>`/`@`)
    // -----------------------------------------------------------------------
    //
    // The #407 parser fix widened `strip_inline_comment`'s `prev_allows_uid`
    // predicate to allow `:` / `>` / `@` before a `#<digits>` token. That is
    // required for the VALID scope targets `Defaults:#1000` (user UID),
    // `Defaults>#1000` (runas UID) and `Defaults@#1000` (a host literally named
    // `#1000`) -- all visudo rc=0 -- to survive the comment strip; previously the
    // whole `<sigil>#1000 !lecture` was swallowed as a comment and the line folded
    // to `Malformed("Defaults<sigil> scope is missing its target")`, a FALSE
    // POSITIVE. But the SAME widening lets the INVALID `Defaults:#1000abc` /
    // `Defaults>#1000abc` / `Defaults@#1000abc` (a `#<digits>` token with a
    // non-digit tail, visudo rc=1) reach the AST as a clean `DefaultsEntry` with a
    // `#`-prefixed binding. visudo lexes `#<digits>` UNIFORMLY in all three scope
    // positions (grounded, visudo/cvtsudoers 1.9.17p2, 2026-07-03), so all three
    // get the same `is_malformed_gid_tail` structural check `check_runas` uses and
    // the same `sudo-F02` code (a clean-spec-that-visudo-rejects defect). The host
    // (`@`) message avoids the word "GID" since the token is a host name.
    //
    // The `!` (command) scope is NOT in `prev_allows_uid`: both `Defaults!#1000`
    // and `Defaults!#1000abc` are visudo rc=1, so leaving the `#<digits>` target to
    // strip as a comment folds the line to `Malformed` / sudo-F01 -- the correct
    // outcome (every `#`-command target is invalid, nothing valid to preserve).
    // The `!`-scope no-regression is pinned by `f02_defaults_cmnd_scope_hash_*`.

    /// `Defaults:#1000abc !lecture` -- a `Defaults:` user-scope target that is a
    /// `#`-GID whose digit run is followed by a non-digit tail.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at col 15 (the `abc` tail).
    /// Verified locally: visudo 1.9.17p2, 2026-07-03. RED before the
    /// `check_defaults` scope-target check: the #407 predicate widening let this
    /// parse to a clean `DefaultsEntry { scope: User("#1000abc") }` with ZERO
    /// diagnostics.
    #[test]
    fn f02_defaults_user_scope_gid_form_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults:#1000abc !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults:#1000abc` scope target (digit run followed by letters) is \
             visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults:#1000 !lecture` -- the VALID pure-GID `Defaults:` user-scope
    /// target (#407's critical non-regression control for the Defaults path).
    ///
    /// A bare `f02_diags.is_empty()` alone is satisfiable by the OLD, BROKEN
    /// parse too (the pre-#407 comment-swallow folded the line to Malformed, so
    /// F02 trivially found no clean Defaults entry to flag). This test also
    /// asserts the AST shape so the regression can't hide behind an
    /// empty-diagnostics vacuity: the scope target must survive as
    /// `User("#1000")`.
    ///
    /// Oracle: `visudo -c` rc=0, "parsed OK"; `cvtsudoers -f json` shows the
    /// binding as `{"userid": 1000}`. Verified locally: visudo/cvtsudoers
    /// 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_defaults_user_scope_pure_gid_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nDefaults:#1000 !lecture\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults:#1000` is a valid pure-GID user-scope target -- must NOT \
             fire F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::Defaults(entry) = &f[0].lines[1].kind else {
            panic!(
                "expected the second logical line to classify as a Defaults entry, \
                 not be swallowed by the comment strip; got {:?}",
                f[0].lines[1].kind
            );
        };
        assert_eq!(
            entry.scope,
            crate::ast::DefaultsScope::User("#1000".to_string()),
            "the pure-GID user-scope target must survive as `User(\"#1000\")`"
        );
    }

    /// `Defaults>#1000abc !lecture` -- a `Defaults>` RUNAS-scope target that is a
    /// `#`-GID whose digit run is followed by a non-digit tail.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at col 15 (the `abc` tail).
    /// Verified locally: visudo 1.9.17p2, 2026-07-03. RED before the `>` was added
    /// to `prev_allows_uid` + the Runas-scope check: previously `>#1000abc`
    /// stripped as a comment, folding the line to `Malformed` / sudo-F01 -- so this
    /// asserts the code is now `sudo-F02` (not F01) with the runas-scope message.
    #[test]
    fn f02_defaults_runas_scope_gid_form_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults>#1000abc !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults>#1000abc` runas-scope target (digit run followed by letters) \
             is visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("runas-scope"),
            "the runas-scope message must name the runas scope; got {:?}",
            f02_diags[0].message
        );
    }

    /// `Defaults>#1000 !lecture` -- the VALID pure-UID `Defaults>` runas-scope
    /// target. Non-regression control (was a false-positive sudo-F01 before the
    /// `>` predicate widening). Asserts the AST scope survives as `Runas("#1000")`
    /// so the fix can't hide behind empty-diagnostics vacuity.
    ///
    /// Oracle: `visudo -c` rc=0, "parsed OK"; `cvtsudoers -f json` binding
    /// `{"userid": 1000}`. Verified locally: visudo/cvtsudoers 1.9.17p2,
    /// 2026-07-03.
    #[test]
    fn f02_defaults_runas_scope_pure_gid_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nDefaults>#1000 !lecture\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults>#1000` is a valid pure-UID runas-scope target -- must NOT \
             fire F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::Defaults(entry) = &f[0].lines[1].kind else {
            panic!(
                "expected a Defaults entry, not a comment-swallowed Malformed; got {:?}",
                f[0].lines[1].kind
            );
        };
        assert_eq!(
            entry.scope,
            crate::ast::DefaultsScope::Runas("#1000".to_string()),
            "the pure-UID runas-scope target must survive as `Runas(\"#1000\")`"
        );
    }

    /// `Defaults@#1000abc !lecture` -- a `Defaults@` HOST-scope target that is a
    /// `#`-token whose digit run is followed by a non-digit tail. GROUNDED (this
    /// contradicted the initial "host is an arbitrary string literal" assumption):
    /// visudo lexes `#<digits>` in the host position the same as `:`/`>`, so
    /// `#1000abc` is a syntax error even though `#1000` alone is a valid host.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at col 15 (the `abc` tail).
    /// Verified locally: visudo 1.9.17p2, 2026-07-03. RED before the `@` predicate
    /// widening + Host-scope check: previously stripped to `Malformed` / sudo-F01.
    /// Asserts the code is now `sudo-F02` with a HOST-appropriate message that does
    /// NOT call the token a GID.
    #[test]
    fn f02_defaults_host_scope_hash_tail_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults@#1000abc !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults@#1000abc` host-scope target (digit run followed by letters) \
             is visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("host-scope"),
            "the host-scope message must name the host scope; got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("GID"),
            "the host-scope target is a host name, not a GID -- the message must not \
             call it a GID; got {:?}",
            f02_diags[0].message
        );
    }

    /// `Defaults@#1000 !lecture` -- the VALID host-scope target: a host literally
    /// named `#1000` (visudo rc=0, `cvtsudoers` binding `{"hostname": "#1000"}`).
    /// Non-regression control (was a false-positive sudo-F01 before the `@`
    /// predicate widening). Asserts the AST scope survives as `Host("#1000")`.
    ///
    /// Verified locally: visudo/cvtsudoers 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_defaults_host_scope_pure_digit_hash_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nDefaults@#1000 !lecture\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults@#1000` is a valid host literally named `#1000` -- must NOT \
             fire F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::Defaults(entry) = &f[0].lines[1].kind else {
            panic!(
                "expected a Defaults entry, not a comment-swallowed Malformed; got {:?}",
                f[0].lines[1].kind
            );
        };
        assert_eq!(
            entry.scope,
            crate::ast::DefaultsScope::Host("#1000".to_string()),
            "the valid `#1000` host-scope target must survive as `Host(\"#1000\")`"
        );
    }

    /// `!` (command) scope non-regression: BOTH `Defaults!#1000` and
    /// `Defaults!#1000abc` are visudo rc=1 ("expected a fully-qualified path
    /// name"). `!` is NOT in `prev_allows_uid`, so the `#<digits>` target strips as
    /// a comment and the line folds to `Malformed` / sudo-F01 -- the correct
    /// outcome (there is no valid `#`-command target to preserve). Pins that the
    /// `:`/`>`/`@` widening did NOT accidentally start emitting a Defaults-scope
    /// F02 for the command scope, and that F01 still fires.
    #[test]
    fn f02_defaults_cmnd_scope_hash_targets_stay_f01_no_f02() {
        for src in [
            "root ALL=(ALL:ALL) ALL\nDefaults!#1000 !lecture\n",
            "root ALL=(ALL:ALL) ALL\nDefaults!#1000abc !lecture\n",
        ] {
            let f02_diags: Vec<_> = lint(src)
                .into_iter()
                .filter(|d| d.code == "sudo-F02")
                .collect();
            assert!(
                f02_diags.is_empty(),
                "the `!` command scope must not emit a Defaults-scope F02 ({src:?}); \
                 got {f02_diags:?}"
            );
            let f01_diags: Vec<_> = lint_f01(src)
                .into_iter()
                .filter(|d| d.code == "sudo-F01")
                .collect();
            assert_eq!(
                f01_diags.len(),
                1,
                "the invalid `#`-command Defaults scope must fold to exactly one \
                 sudo-F01 ({src:?}); got {f01_diags:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // #407 round-2: `Defaults` scope target is a COMMA LIST -- validate per
    // element, not the whole raw binding string.
    // -----------------------------------------------------------------------
    //
    // A `Defaults` scope target can bind to multiple users / runas-users / hosts
    // via a comma list. The parser stores the binding as ONE raw string, so a
    // naive `is_malformed_gid_tail(whole_binding)` mis-fires: `"#1000,alice"`
    // starts with `#` and has a non-digit tail (`,alice`) -> a FALSE POSITIVE on
    // a visudo rc=0 line; and `"alice,#1000abc"` does NOT start with `#` -> a
    // FALSE NEGATIVE on a visudo rc=1 line. The fix splits on `,` and validates
    // each element. Grounded (visudo/cvtsudoers 1.9.17p2, 2026-07-03).

    /// `Defaults:#1000,alice !lecture` -- a valid two-element user list (a UID
    /// plus a plain username). visudo rc=0 (`cvtsudoers` Binding: `userid 1000`
    /// then `username alice`). RED before the per-element split: the whole
    /// binding `"#1000,alice"` was validated as one string (starts `#`, non-digit
    /// tail) and wrongly fired F02. Must be CLEAN.
    #[test]
    fn f02_defaults_user_scope_list_uid_then_name_no_f02() {
        let f02_diags: Vec<_> = lint("root ALL=(ALL:ALL) ALL\nDefaults:#1000,alice !lecture\n")
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults:#1000,alice` is a valid UID+name user list -- must NOT fire \
             F02; got {f02_diags:?}"
        );
    }

    /// `Defaults:#1000,#1001 !lecture` -- two pure-UID elements. visudo rc=0.
    /// Control: both elements are valid GIDs, so the per-element split must leave
    /// the line clean (a whole-string check would fire on `"#1000,#1001"`).
    #[test]
    fn f02_defaults_user_scope_list_two_uids_no_f02() {
        let f02_diags: Vec<_> = lint("root ALL=(ALL:ALL) ALL\nDefaults:#1000,#1001 !lecture\n")
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults:#1000,#1001` is two valid UIDs -- must NOT fire F02; got \
             {f02_diags:?}"
        );
    }

    /// `Defaults>#1000,root !lecture` -- valid runas list (UID + name). rc=0.
    /// RED before the per-element split (whole binding `"#1000,root"` mis-fired).
    #[test]
    fn f02_defaults_runas_scope_list_uid_then_name_no_f02() {
        let f02_diags: Vec<_> = lint("root ALL=(ALL:ALL) ALL\nDefaults>#1000,root !lecture\n")
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults>#1000,root` is a valid runas list -- must NOT fire F02; got \
             {f02_diags:?}"
        );
    }

    /// `Defaults@#1000,localhost !lecture` -- valid host list (`#1000` a host
    /// literally named `#1000`, plus `localhost`). rc=0. RED before the split.
    #[test]
    fn f02_defaults_host_scope_list_hash_then_name_no_f02() {
        let f02_diags: Vec<_> = lint("root ALL=(ALL:ALL) ALL\nDefaults@#1000,localhost !lecture\n")
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults@#1000,localhost` is a valid host list -- must NOT fire F02; \
             got {f02_diags:?}"
        );
    }

    /// `Defaults:alice,#1000abc !lecture` -- companion FALSE-NEGATIVE case: the
    /// SECOND element `#1000abc` is a malformed GID tail (visudo rc=1, "syntax
    /// error" at col 21). RED before the per-element split: the raw binding
    /// `"alice,#1000abc"` does not start with `#`, so the whole-string check was
    /// silent. After: exactly one F02 that NAMES the specific bad element
    /// `#1000abc` (NOT the whole binding, and NOT the valid `alice`).
    #[test]
    fn f02_defaults_user_scope_list_second_element_bad_gid_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults:alice,#1000abc !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults:alice,#1000abc` has a malformed 2nd GID element and must fire \
             exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("#1000abc"),
            "the F02 must name the specific bad element `#1000abc`; got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("alice"),
            "the F02 must NOT name the valid element or the whole raw binding; got {:?}",
            f02_diags[0].message
        );
    }

    /// `Defaults@#1000abc,localhost !lecture` -- host list whose FIRST element is
    /// a malformed `#`-tail (visudo rc=1). Fires one F02 naming `#1000abc` with a
    /// HOST-appropriate message (no "GID"); the valid `localhost` element does
    /// not fire.
    ///
    /// The `!message.contains("localhost")` assertion is the discriminator that
    /// makes this a genuine fail-before witness: under the OLD whole-string check
    /// the message interpolated the entire binding `#1000abc,localhost` (which
    /// contains `localhost`); the per-element split names ONLY the bad element.
    #[test]
    fn f02_defaults_host_scope_list_first_element_bad_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults@#1000abc,localhost !lecture\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults@#1000abc,localhost` has a malformed 1st host element and must \
             fire exactly one F02; got {diags:?}"
        );
        assert!(
            f02_diags[0].message.contains("#1000abc")
                && f02_diags[0].message.contains("host-scope"),
            "the host-scope F02 must name `#1000abc` and the host scope; got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("localhost"),
            "the F02 must name ONLY the bad element, not the whole raw binding \
             (which contains the valid `localhost`); got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("GID"),
            "a host-scope target is not a GID -- the message must not say GID; got {:?}",
            f02_diags[0].message
        );
    }

    // -----------------------------------------------------------------------
    // #426: empty comma-list member in a `Defaults:` scope target.
    //
    // visudo/cvtsudoers 1.9.17p2 rejects (rc=1) an empty member in a Defaults
    // scope User/Runas/Host list -- a leading `,`, an interior `,,` / `, ,`, or an
    // empty quoted `""` member. Previously a silent false-negative. Approach A
    // (#426): a new `split_scope_binding` captures the FULL comma list (honoring
    // sudo's `elem (WS* ',' WS* elem)*` grammar -- whitespace around a comma
    // continues the list; quotes/backslash protect commas and internal space), so
    // `Defaults:#1000, #1001` is one two-member list instead of a truncated
    // `#1000,` that leaked `#1001` into the settings `#<digits>` scan (the
    // pre-existing FALSE-POSITIVE this also fixes). Each member is then split with
    // the quote/escape-aware `split_default_settings` (which trims), the `#`-GID
    // tail check runs over every member, and sudo-F02 fires on any leading/interior
    // empty member or any exactly-`""` member (one diagnostic per line). A trailing
    // double comma / dangling comma greedily absorbs the next token, leaving no
    // settings, so it routes to the F01 "no settings" Fatal. Grounded 2026-07-04.
    // -----------------------------------------------------------------------

    /// #426 helper: the sudo-F02 diagnostics for a single Defaults `line`, run
    /// under a valid user-spec header so the file otherwise parses cleanly.
    fn f02s(line: &str) -> Vec<rulesteward_core::Diagnostic> {
        lint(&format!("root ALL=(ALL:ALL) ALL\n{line}\n"))
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect()
    }

    /// #426 helper: all Fatal diagnostics (sudo-F01 OR sudo-F02) for a Defaults
    /// `line`. An empty scope member surfaces as F02 when a real setting survives
    /// (interior/leading empty), but greedy list absorption can route a TRAILING
    /// empty (`alice,,`) or a dangling comma (`#1000,`) to F01 "no settings" -- both
    /// are Fatal and both match visudo rc=1, so those cases assert on Fatal-ness.
    fn fatals(line: &str) -> Vec<rulesteward_core::Diagnostic> {
        let f = files(&format!("root ALL=(ALL:ALL) ALL\n{line}\n"));
        let ctx = SudoersLintContext::default();
        f01(&f, &ctx)
            .into_iter()
            .chain(f02(&f, &ctx))
            .filter(|d| d.severity == rulesteward_core::Severity::Fatal)
            .collect()
    }

    /// `Defaults:#1000,,alice` -- interior empty member (visudo rc=1, caret at the
    /// second `,`). Must fire exactly one Fatal sudo-F02 naming the emptiness.
    #[test]
    fn f02_defaults_user_scope_interior_empty_member_fires() {
        let d = f02s("Defaults:#1000,,alice env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults:#1000,,alice` (rc=1) must fire one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            d[0].message.contains("empty") && d[0].message.contains("user"),
            "the F02 must name the empty user-scope member; got {:?}",
            d[0].message
        );
    }

    /// `Defaults:,alice` -- leading empty member (visudo rc=1). Must fire one F02.
    #[test]
    fn f02_defaults_user_scope_leading_empty_member_fires() {
        let d = f02s("Defaults:,alice env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults:,alice` (rc=1) must fire one F02; got {d:?}"
        );
        assert!(d[0].message.contains("empty"), "got {:?}", d[0].message);
    }

    /// `Defaults:alice,, env_reset` -- a TRAILING double comma (visudo rc=1, caret
    /// at the `,,`). Under the boundary rework the list greedily absorbs `env_reset`
    /// to fill the pending member, leaving no settings, so this routes to the F01
    /// "no settings" Fatal rather than the F02 empty-member Fatal -- either way the
    /// invalid line is flagged.
    #[test]
    fn defaults_user_scope_trailing_double_comma_fires_fatal() {
        let d = fatals("Defaults:alice,, env_reset");
        assert!(
            !d.is_empty(),
            "`Defaults:alice,,` (rc=1) must fire a Fatal; got {d:?}"
        );
    }

    /// `Defaults:#1000, env_reset` -- a dangling comma. sudo absorbs `env_reset` as
    /// the second list member, leaving the Defaults entry with no settings (visudo
    /// rc=1). The boundary rework surfaces it as the F01 "no settings" Fatal.
    #[test]
    fn defaults_user_scope_dangling_comma_no_settings_fires_fatal() {
        let d = fatals("Defaults:#1000, env_reset");
        assert!(
            !d.is_empty(),
            "`Defaults:#1000, env_reset` (rc=1) must fire a Fatal; got {d:?}"
        );
    }

    /// `Defaults:""` -- a sole empty QUOTED member (visudo rc=1). An empty quoted
    /// member cannot be produced by whitespace truncation, so it fires at any
    /// position.
    #[test]
    fn f02_defaults_user_scope_empty_quoted_sole_member_fires() {
        let d = f02s("Defaults:\"\" env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults:\"\"` (rc=1) must fire one F02; got {d:?}"
        );
        assert!(d[0].message.contains("empty"), "got {:?}", d[0].message);
    }

    /// `Defaults:"",alice` -- empty quoted member in LEADING position (rc=1).
    #[test]
    fn f02_defaults_user_scope_empty_quoted_leading_member_fires() {
        let d = f02s("Defaults:\"\",alice env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults:\"\",alice` (rc=1) must fire one F02; got {d:?}"
        );
    }

    /// `Defaults:alice,""` -- empty quoted member in TRAILING position (rc=1). The
    /// quoted-empty check is position-independent (unlike the plain trailing-empty
    /// exclusion), because `""` can never come from truncation.
    #[test]
    fn f02_defaults_user_scope_empty_quoted_trailing_member_fires() {
        let d = f02s("Defaults:alice,\"\" env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults:alice,\"\"` (rc=1) must fire one F02; got {d:?}"
        );
    }

    /// `Defaults>,root` -- leading empty member in a RUNAS scope list (rc=1).
    #[test]
    fn f02_defaults_runas_scope_leading_empty_member_fires() {
        let d = f02s("Defaults>,root env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults>,root` (rc=1) must fire one F02; got {d:?}"
        );
        assert!(
            d[0].message.contains("empty") && d[0].message.contains("runas"),
            "got {:?}",
            d[0].message
        );
    }

    /// `Defaults@,localhost` -- leading empty member in a HOST scope list (rc=1).
    #[test]
    fn f02_defaults_host_scope_leading_empty_member_fires() {
        let d = f02s("Defaults@,localhost env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults@,localhost` (rc=1) must fire one F02; got {d:?}"
        );
        assert!(
            d[0].message.contains("empty") && d[0].message.contains("host"),
            "got {:?}",
            d[0].message
        );
    }

    /// `Defaults:alice, , bob` -- an interior member that is WHITESPACE-ONLY (a
    /// comma, a space, a comma). visudo rc=1 (caret at the 2nd comma); its twin
    /// `Defaults:root , root` is rc=0, so the defect is specifically the empty
    /// middle member. Pins that a member is treated as empty AFTER trimming (a
    /// `split_scope_binding` that skipped the trim would see `" "` and wrongly stay
    /// silent -- a false-negative that would otherwise survive the whole suite).
    #[test]
    fn f02_defaults_user_scope_interior_whitespace_only_member_fires() {
        let d = f02s("Defaults:alice, , bob env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults:alice, , bob` (rc=1, whitespace-only middle member) must fire one F02; got {d:?}"
        );
        assert!(d[0].message.contains("empty"), "got {:?}", d[0].message);
    }

    /// `Defaults>#1000,,root` -- interior empty member in a RUNAS list (rc=1).
    /// Non-user-scope coverage of the interior-empty path.
    #[test]
    fn f02_defaults_runas_scope_interior_empty_member_fires() {
        let d = f02s("Defaults>#1000,,root env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults>#1000,,root` (rc=1) must fire one F02; got {d:?}"
        );
        assert!(
            d[0].message.contains("empty") && d[0].message.contains("runas"),
            "got {:?}",
            d[0].message
        );
    }

    /// `Defaults@"",localhost` -- empty quoted member in a HOST list (rc=1).
    /// Non-user-scope coverage of the quoted-empty path.
    #[test]
    fn f02_defaults_host_scope_empty_quoted_member_fires() {
        let d = f02s("Defaults@\"\",localhost env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults@\"\",localhost` (rc=1) must fire one F02; got {d:?}"
        );
        assert!(
            d[0].message.contains("empty") && d[0].message.contains("host"),
            "got {:?}",
            d[0].message
        );
    }

    /// `Defaults:"a b"` -- a quoted scope member with INTERNAL whitespace and no
    /// settings (visudo rc=1: no parameters). The quote-aware `split_scope_binding`
    /// keeps `"a b"` as the whole (settingless) list, so the entry has no settings
    /// -> F01. Pins the in-boundary quote handling: a quote-BLIND boundary split
    /// would stop at the interior space, leak `b"` as spurious settings, and wrongly
    /// stay silent on a visudo-rejected line.
    #[test]
    fn defaults_user_scope_quoted_internal_ws_no_settings_fires_fatal() {
        let d = fatals("Defaults:\"a b\"");
        assert!(
            !d.is_empty(),
            "`Defaults:\"a b\"` (rc=1, no settings) must fire a Fatal; got {d:?}"
        );
    }

    /// `Defaults:a\ b` -- an ESCAPED space in a scope member with no settings
    /// (visudo rc=1). The escape-aware boundary keeps `a\ b` as the whole list ->
    /// F01. An escape-blind boundary split would stop at the escaped space and leak
    /// `b` as spurious settings.
    #[test]
    fn defaults_user_scope_escaped_ws_no_settings_fires_fatal() {
        let d = fatals("Defaults:a\\ b");
        assert!(
            !d.is_empty(),
            "`Defaults:a\\ b` (rc=1, no settings) must fire a Fatal; got {d:?}"
        );
    }

    /// `Defaults:"a\" b"` -- an ESCAPED QUOTE inside a quoted member, an internal
    /// space, and no settings (visudo rc=1). The in-quote escape keeps the quote
    /// open across the space so `"a\" b"` is the whole list -> F01. Dropping the
    /// in-quote escape handling would close the quote at `\"`, stop at the space,
    /// and leak spurious settings.
    #[test]
    fn defaults_user_scope_escaped_quote_in_quotes_no_settings_fires_fatal() {
        let d = fatals("Defaults:\"a\\\" b\"");
        assert!(
            !d.is_empty(),
            "`Defaults:\"a\\\" b\"` (rc=1, no settings) must fire a Fatal; got {d:?}"
        );
    }

    /// `Defaults:#1000 ,#1001` -- valid two-UID list with the space BEFORE the comma
    /// (visudo rc=0). Pins the forward-peek that continues the list across a space
    /// preceding a separator comma: a peek that searched for the first WHITESPACE
    /// (instead of the first NON-whitespace) would truncate to `#1000`, leak
    /// `,#1001` into the settings `#<digits>` scan, and false-positive.
    #[test]
    fn f02_defaults_user_scope_space_before_comma_uid_list_no_fp() {
        let d = f02s("Defaults:#1000 ,#1001 env_reset");
        assert!(
            d.is_empty(),
            "`Defaults:#1000 ,#1001` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// A `#<digits>` token in a Defaults value preceded by a NON-ASCII whitespace
    /// byte (vertical tab 0x0B here; NEL 0x85 / NBSP 0xA0 behave the same) is still
    /// a token visudo rejects (rc=1), exactly like its ASCII-space twin
    /// `Defaults env_reset #2`, so it must fire sudo-F02. Pins
    /// `strip_inline_comment`'s `prev_allows_uid` on `char::is_whitespace`; a
    /// narrowing to `u8::is_ascii_whitespace` would silently strip the `#2` as a
    /// comment (a false-negative regression -- caught by the #426 adversarial loop).
    #[test]
    fn f02_defaults_value_hash_digits_after_non_ascii_whitespace_fires() {
        let d = f02s("Defaults env_reset\u{0B}#2 reasons");
        assert!(
            !d.is_empty(),
            "a `#<digits>` after a 0x0B whitespace byte must fire F02 like its ASCII \
             twin; got {d:?}"
        );
    }

    // --- must-NOT-fire regression guards (the R1/R2 false-positives) ---

    /// `Defaults:root, root` -- a VALID two-member user list with a space after
    /// the comma (visudo rc=0). The boundary rework captures the whole list
    /// (`root, root`), so both members are seen and neither is empty. (Under the
    /// old first-whitespace split this truncated to `root,`.)
    #[test]
    fn f02_defaults_user_scope_space_after_comma_two_members_no_f02() {
        let d = f02s("Defaults:root, root env_reset");
        assert!(
            d.is_empty(),
            "`Defaults:root, root` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults:#1000, #1001` -- valid two-UID list, space after comma (visudo
    /// rc=0). THE PRE-EXISTING FALSE-POSITIVE the boundary rework fixes: the old
    /// first-whitespace split truncated the binding to `#1000,` and leaked `#1001`
    /// into the settings string, where the `#<digits>` value scan fired a spurious
    /// Fatal. The rework keeps `#1000, #1001` as one two-member list -> nothing
    /// leaks -> no F02.
    #[test]
    fn f02_defaults_user_scope_space_after_comma_two_uids_no_fp() {
        let d = f02s("Defaults:#1000, #1001 env_reset");
        assert!(
            d.is_empty(),
            "`Defaults:#1000, #1001` is valid (rc=0) -- the 2nd UID must NOT leak \
             into the settings scan; got {d:?}"
        );
    }

    /// `Defaults@a, b` -- valid two-member HOST list, space after comma (rc=0).
    #[test]
    fn f02_defaults_host_scope_space_after_comma_no_f02() {
        let d = f02s("Defaults@a, b env_reset");
        assert!(
            d.is_empty(),
            "`Defaults@a, b` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults:"a,,b"` -- ONE quoted user token with literal commas (visudo
    /// rc=0). THE R1 regression: a quote-blind `split(',')` sees an empty middle
    /// member and false-POSITIVES. The quote-aware `split_default_settings` keeps
    /// it as one non-empty member.
    #[test]
    fn f02_defaults_user_scope_quoted_literal_commas_no_f02() {
        let d = f02s("Defaults:\"a,,b\" env_reset");
        assert!(
            d.is_empty(),
            "`Defaults:\"a,,b\"` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults:alice\,` -- ONE escaped-comma user token (visudo rc=0). The
    /// escape-aware splitter keeps it as one non-empty member (no phantom empty).
    #[test]
    fn f02_defaults_user_scope_escaped_comma_no_f02() {
        let d = f02s("Defaults:alice\\, env_reset");
        assert!(
            d.is_empty(),
            "`Defaults:alice\\,` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults:alice," "` -- valid (visudo rc=0); the `" "` member is quoted
    /// whitespace, NOT empty. The quote-aware boundary rework captures the whole
    /// list intact (`alice," "`) -- the quoted interior space does not end the list
    /// -- and the exact `== "\"\""` match ensures a quoted `" "` is never treated
    /// as an empty member.
    #[test]
    fn f02_defaults_user_scope_quoted_whitespace_member_no_f02() {
        let d = f02s("Defaults:alice,\" \" env_reset");
        assert!(
            d.is_empty(),
            "`Defaults:alice,\" \"` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults:alice, #1001` -- valid name+UID list, space after comma (rc=0).
    /// Companion FP-fix witness: the old truncation leaked `#1001` into the
    /// settings scan; the rework keeps it a scope member so nothing fires.
    #[test]
    fn f02_defaults_user_scope_space_list_name_then_uid_no_fp() {
        let d = f02s("Defaults:alice, #1001 env_reset");
        assert!(
            d.is_empty(),
            "`Defaults:alice, #1001` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults>#1000, #1001` -- valid two-UID RUNAS list, space after comma
    /// (rc=0). FP-fix witness in the runas scope.
    #[test]
    fn f02_defaults_runas_scope_space_list_two_uids_no_fp() {
        let d = f02s("Defaults>#1000, #1001 env_reset");
        assert!(
            d.is_empty(),
            "`Defaults>#1000, #1001` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults@host1, #1001` -- valid HOST list, space after comma (rc=0). A host
    /// literally named `#1001` is fine; the rework must not leak it into settings.
    #[test]
    fn f02_defaults_host_scope_space_list_name_then_hashname_no_fp() {
        let d = f02s("Defaults@host1, #1001 env_reset");
        assert!(
            d.is_empty(),
            "`Defaults@host1, #1001` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults:root ,root` / `Defaults:root , root` -- whitespace BEFORE the
    /// comma (and on both sides) still continues the list (visudo rc=0). Pins the
    /// state machine's "a whitespace run ends the list only if no comma is adjacent"
    /// rule against a mutant that ends the list at the first space.
    #[test]
    fn f02_defaults_user_scope_space_before_comma_no_f02() {
        assert!(
            f02s("Defaults:root ,root env_reset").is_empty(),
            "`Defaults:root ,root` is valid (rc=0) -- must NOT fire"
        );
        assert!(
            f02s("Defaults:root , root env_reset").is_empty(),
            "`Defaults:root , root` is valid (rc=0) -- must NOT fire"
        );
    }

    /// `Defaults:#1000, %grp` -- valid UID + `%group` list, space after comma
    /// (rc=0). A `%group` member must not be misread as empty or leaked.
    #[test]
    fn f02_defaults_user_scope_space_list_uid_then_group_no_f02() {
        let d = f02s("Defaults:#1000, %grp env_reset");
        assert!(
            d.is_empty(),
            "`Defaults:#1000, %grp` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults:alice, env_reset setenv` -- valid (visudo rc=0): `env_reset` is
    /// greedily absorbed as the second USER (the comma demands another member), and
    /// `setenv` is the (surviving) setting. Must NOT fire -- pins that greedy
    /// absorption does not spuriously flag a valid line as no-settings/empty.
    #[test]
    fn f02_defaults_user_scope_comma_absorbs_word_but_settings_survive_no_fatal() {
        assert!(
            fatals("Defaults:alice, env_reset setenv").is_empty(),
            "`Defaults:alice, env_reset setenv` is valid (rc=0) -- must NOT fire any Fatal"
        );
    }

    /// `Defaults:#1000, #1001abc` -- valid list boundary but the SECOND member is a
    /// malformed `#`-GID tail (visudo rc=1). Exposing every member of the correctly
    /// bounded list to the GID-tail check catches it; the F02 names `#1001abc`.
    #[test]
    fn f02_defaults_user_scope_space_list_second_member_bad_gid_fires() {
        let d = f02s("Defaults:#1000, #1001abc env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults:#1000, #1001abc` has a malformed 2nd GID member -- must fire one F02; got {d:?}"
        );
        assert!(
            d[0].message.contains("#1001abc"),
            "the F02 must name the specific bad member `#1001abc`; got {:?}",
            d[0].message
        );
    }

    /// `Defaults:#1000abc,,alice` -- BOTH a malformed `#`-GID first member AND an
    /// interior empty. The empty scan is gated behind `diags.len() == before`, so
    /// the line fires EXACTLY ONE F02 (the GID one), not two. Pins the one-per-line
    /// gate so a future change can't double-report.
    #[test]
    fn f02_defaults_user_scope_gid_defect_and_empty_member_single_f02() {
        let d = f02s("Defaults:#1000abc,,alice env_reset");
        assert_eq!(
            d.len(),
            1,
            "a line with a bad GID AND an empty member must fire exactly one F02; got {d:?}"
        );
        assert!(
            d[0].message.contains("#1000abc") && !d[0].message.contains("empty"),
            "the single F02 must be the GID one (the gate suppresses the empty scan); got {:?}",
            d[0].message
        );
    }

    // -----------------------------------------------------------------------
    // #429: empty comma-list member in the `Defaults!` (Cmnd) scope.
    //
    // visudo/cvtsudoers 1.9.17p2 rejects (rc=1) an empty member in a Defaults
    // Cmnd scope command list -- a leading `,`, an interior `,,`, or an empty
    // quoted `""` member -- exactly like the User/Runas/Host scopes #426 already
    // covers. Today `check_defaults_scope` (tokens/defaults.rs) matches only
    // `DefaultsScope::{User,Runas,Host}` and falls through to `_ => None` for
    // `Cmnd`, so the Cmnd scope never runs the empty-member check: a documented
    // false-negative. The `#<digits>` command-target non-regression
    // (`f02_defaults_cmnd_scope_hash_targets_stay_f01_no_f02`, ~L580) is
    // UNAFFECTED and must stay green: an invalid `#`-command target still
    // strips as a comment and folds to Malformed/sudo-F01, not F02. Grounded
    // visudo 1.9.17p2, 2026-07-05.
    // -----------------------------------------------------------------------

    /// `Defaults!/bin/ls,,/bin/cat env_reset` -- interior empty member in the
    /// Cmnd scope list (visudo rc=1, syntax error at the second `,`). Must fire
    /// exactly one Fatal sudo-F02. The message-word assertion is deliberately
    /// scope-word-agnostic (asserts only `"empty"`): the recommended impl uses
    /// `scope_word = "command"`, but that wording is the implementer's choice,
    /// not yet locked, so this test does not couple to it (tighten to also
    /// assert the scope word once the wording is decided).
    #[test]
    fn f02_defaults_cmnd_scope_interior_empty_member_fires() {
        let d = f02s("Defaults!/bin/ls,,/bin/cat env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,,/bin/cat` (rc=1) must fire one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(d[0].message.contains("empty"), "got {:?}", d[0].message);
    }

    /// `Defaults!/bin/ls, ,/bin/cat env_reset` -- an interior member that is
    /// WHITESPACE-ONLY (a comma, a space, a comma) in the Cmnd scope list. visudo
    /// rc=1 (syntax error, caret at the 2nd comma). Mirrors the User-scope
    /// precedent `f02_defaults_user_scope_interior_whitespace_only_member_fires`
    /// (~L927): pins that a member is treated as empty AFTER trimming, so the
    /// impl MUST split into members via `split_default_settings` (whose middle
    /// token trims to `""`). A naive substring-scan impl
    /// (`binding.contains(",,") || binding.starts_with(',') ||
    /// binding.contains("\"\"")`) passes the plain `,,`/leading/quoted cases yet
    /// is WRONG -- it misses `", ,"`, which only member-splitting detects. RED
    /// today because the Cmnd scope is still a no-op in `check_defaults_scope`.
    #[test]
    fn f02_defaults_cmnd_scope_interior_whitespace_only_member_fires() {
        let d = f02s("Defaults!/bin/ls, ,/bin/cat env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls, ,/bin/cat` (rc=1, whitespace-only middle member) \
             must fire one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(d[0].message.contains("empty"), "got {:?}", d[0].message);
    }

    /// `Defaults!,/bin/ls env_reset` -- leading empty member in the Cmnd scope
    /// list (visudo rc=1, syntax error at the `,`). Must fire one F02.
    #[test]
    fn f02_defaults_cmnd_scope_leading_empty_member_fires() {
        let d = f02s("Defaults!,/bin/ls env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!,/bin/ls` (rc=1) must fire one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(d[0].message.contains("empty"), "got {:?}", d[0].message);
    }

    /// `Defaults!"",/bin/ls env_reset` -- empty QUOTED member in LEADING position
    /// in the Cmnd scope list (visudo rc=1, "empty string"). Must fire one F02.
    #[test]
    fn f02_defaults_cmnd_scope_empty_quoted_member_fires() {
        let d = f02s("Defaults!\"\",/bin/ls env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!\"\",/bin/ls` (rc=1) must fire one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(d[0].message.contains("empty"), "got {:?}", d[0].message);
    }

    /// `Defaults!/bin/ls,/bin/cat env_reset` -- a VALID two-member Cmnd list, no
    /// empty member (visudo rc=0, "parsed OK"). Regression guard: must stay
    /// clean both before and after the #429 fix lands.
    #[test]
    fn f02_defaults_cmnd_scope_valid_list_no_f02() {
        let d = f02s("Defaults!/bin/ls,/bin/cat env_reset");
        assert!(
            d.is_empty(),
            "`Defaults!/bin/ls,/bin/cat` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults!/bin/ls, env_reset` -- a dangling trailing comma in the Cmnd
    /// scope (visudo rc=1, "expected a fully-qualified path name" -- sudo
    /// greedily absorbs `env_reset` as the second Cmnd list member, leaving the
    /// Defaults entry with no settings). Mirrors
    /// `defaults_user_scope_dangling_comma_no_settings_fires_fatal` (~L842):
    /// `split_scope_binding` is sigil-agnostic, so the dangling comma already
    /// absorbs the pending element today, routing this to the F01 "no settings"
    /// Fatal independent of the #429 Cmnd-scope empty-member fix. Regression
    /// guard: must stay a Fatal both before and after the fix.
    #[test]
    fn defaults_cmnd_scope_dangling_comma_no_settings_fires_fatal() {
        let d = fatals("Defaults!/bin/ls, env_reset");
        assert!(
            !d.is_empty(),
            "`Defaults!/bin/ls, env_reset` (rc=1) must fire a Fatal; got {d:?}"
        );
    }

    // -----------------------------------------------------------------------
    // #451: a non-leading `#`-prefixed (or otherwise non-path) member of a
    // `Defaults!` (Cmnd) scope comma-list that is NOT a fully-qualified path
    // survives to the AST unflagged. `check_defaults_scope`'s Cmnd arm runs the
    // #429 empty-member check but deliberately sets `check_gid_tail: false` (see
    // the long comment on `check_defaults` in `defaults.rs`): a bare digit run is
    // a VALID GID in the User/Runas/Host scopes but visudo REJECTS it outright in
    // command position ("expected a fully-qualified path name"), so the shared
    // `is_malformed_gid_tail` "pure digits = valid" predicate is the wrong tool
    // here. This section grounds and pins a DEDICATED Cmnd-member path-validity
    // check: a member must be the reserved `ALL` (bare or `!`-negated), a
    // `Cmnd_Alias`-shaped reference (`[A-Z][A-Z0-9_]*`, mirroring
    // `lints/aliases.rs::is_alias_ref`), or a (`!`-negatable) fully-qualified path
    // (starts with `/` after stripping leading `!`). Anything else -- a `#<digits>`
    // token (tail or pure), a `%group`/`%#gid` group reference, a quoted literal,
    // a relative path, a lowercase bareword, a digest-spec fragment truncated out
    // of its `sha224:<hex> /path` pairing, or a lone `!` -- is visudo-rejected and
    // must fire exactly one Fatal `sudo-F02` naming the offending member. All
    // cases grounded locally: `visudo -cf`, Rocky Linux 9, sudo 1.9.17p2,
    // 2026-07-08 (rockylinux/rockylinux:9 image, `dnf install sudo`).
    // -----------------------------------------------------------------------

    /// `Defaults!/bin/ls,#1000abc env_reset` -- a `#`-GID-shaped member with a
    /// non-digit tail. Oracle: `visudo -cf` rc=1, "expected a fully-qualified path
    /// name" at the `#1000abc` member. Must fire exactly one Fatal `sudo-F02`
    /// naming `#1000abc`.
    #[test]
    fn f02_defaults_cmnd_scope_hash_digits_then_letters_member_fires() {
        let d = f02s("Defaults!/bin/ls,#1000abc env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,#1000abc` (rc=1) must fire exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            d[0].message.contains("#1000abc"),
            "the F02 must name the offending member `#1000abc`; got {:?}",
            d[0].message
        );
    }

    /// `Defaults!/bin/ls,#1000 env_reset` -- a PURE-digit `#`-GID member. Unlike
    /// the User/Runas/Host scopes (where a pure `#<digits>` is a valid UID/GID),
    /// visudo rejects a bare `#<digits>` in COMMAND position outright. Oracle:
    /// `visudo -cf` rc=1, "expected a fully-qualified path name" at `#1000`. This
    /// is the case that specifically discriminates a dedicated path-validity check
    /// from a reused `is_malformed_gid_tail` (which would wrongly treat pure
    /// digits as valid here). Must fire exactly one Fatal `sudo-F02`.
    #[test]
    fn f02_defaults_cmnd_scope_pure_digit_hash_member_fires() {
        let d = f02s("Defaults!/bin/ls,#1000 env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,#1000` (rc=1) must fire exactly one F02 -- a pure \
             digit run is STILL invalid in Cmnd position; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            d[0].message.contains("#1000"),
            "the F02 must name the offending member `#1000`; got {:?}",
            d[0].message
        );
    }

    /// `Defaults!/bin/ls,%group env_reset` -- a `%group` member. `%group` is valid
    /// in the User/Host scope member grammar but NOT in a Cmnd list. Oracle:
    /// `visudo -cf` rc=1, "syntax error" at `%group`. Must fire exactly one Fatal
    /// `sudo-F02`.
    #[test]
    fn f02_defaults_cmnd_scope_percent_group_member_fires() {
        let d = f02s("Defaults!/bin/ls,%group env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,%group` (rc=1) must fire exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            d[0].message.contains("%group"),
            "the F02 must name the offending member `%group`; got {:?}",
            d[0].message
        );
    }

    /// `Defaults!/bin/ls,%#1000 env_reset` -- a `%#<gid>` (GID-form group)
    /// member. Also invalid in Cmnd position despite being a well-formed group
    /// reference elsewhere. Oracle: `visudo -cf` rc=1, "syntax error" at
    /// `%#1000`. Must fire exactly one Fatal `sudo-F02`.
    #[test]
    fn f02_defaults_cmnd_scope_gid_group_form_member_fires() {
        let d = f02s("Defaults!/bin/ls,%#1000 env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,%#1000` (rc=1) must fire exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            d[0].message.contains("%#1000"),
            "the F02 must name the offending member `%#1000`; got {:?}",
            d[0].message
        );
    }

    /// `Defaults!/bin/ls,bin/cat env_reset` -- a RELATIVE-path member (mirrors
    /// Case 3's command-position relative-path check, but here the member sits in
    /// a Defaults Cmnd-scope comma list rather than a `CmndSpec`). Oracle:
    /// `visudo -cf` rc=1, "expected a fully-qualified path name" at `bin/cat`.
    /// Must fire exactly one Fatal `sudo-F02`.
    #[test]
    fn f02_defaults_cmnd_scope_relative_path_member_fires() {
        let d = f02s("Defaults!/bin/ls,bin/cat env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,bin/cat` (rc=1) must fire exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            d[0].message.contains("bin/cat"),
            "the F02 must name the offending member `bin/cat`; got {:?}",
            d[0].message
        );
    }

    /// `Defaults!/bin/ls,"foo" env_reset` -- a double-quoted literal member.
    /// Quoting does not exempt a Cmnd member from the fully-qualified-path
    /// requirement (unlike a Defaults SETTING value, where a clean quoted region
    /// is a literal). Oracle: `visudo -cf` rc=1, "expected a fully-qualified path
    /// name" at `"foo"`. Must fire exactly one Fatal `sudo-F02`.
    #[test]
    fn f02_defaults_cmnd_scope_quoted_non_path_member_fires() {
        let d = f02s("Defaults!/bin/ls,\"foo\" env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,\"foo\"` (rc=1) must fire exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults!/bin/ls,ls env_reset` -- a lowercase bareword member: neither a
    /// fully-qualified path NOR `Cmnd_Alias`-shaped (alias names are
    /// `[A-Z][A-Z0-9_]*`, `lints/aliases.rs::is_alias_ref`). Oracle: `visudo -cf`
    /// rc=1, "expected a fully-qualified path name" at `ls`. This is the
    /// discriminating case for the alias-name-SHAPE gate: a naive "any bareword
    /// with no `/` survives" impl would wrongly let this through. Must fire
    /// exactly one Fatal `sudo-F02`.
    #[test]
    fn f02_defaults_cmnd_scope_lowercase_bareword_member_fires() {
        let d = f02s("Defaults!/bin/ls,ls env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,ls` (rc=1) must fire exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            d[0].message.contains("ls"),
            "the F02 must name the offending member `ls`; got {:?}",
            d[0].message
        );
    }

    /// `Defaults!/bin/ls,! env_reset` -- a LONE `!` member (a negation with
    /// nothing to negate; mirrors #375 Rule 2's `CmndItem::Cmnd("!")` check for
    /// ordinary command specs, but here in a Defaults Cmnd-scope comma list).
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `!`. Must fire a Fatal
    /// `sudo-F02` (message-word assertion deliberately loose: only that it fires,
    /// not the exact wording for an empty-after-strip member).
    #[test]
    fn f02_defaults_cmnd_scope_lone_bang_member_fires() {
        let d = f02s("Defaults!/bin/ls,! env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,!` (rc=1) must fire exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults!/bin/ls, #1000 env_reset` -- whitespace AFTER the comma before a
    /// bad member (`split_default_settings` trims each member, so this must
    /// behave identically to the no-space form). Oracle: `visudo -cf` rc=1,
    /// "expected a fully-qualified path name" at `#1000`. Must fire exactly one
    /// Fatal `sudo-F02` naming `#1000`.
    #[test]
    fn f02_defaults_cmnd_scope_space_after_comma_bad_member_fires() {
        let d = f02s("Defaults!/bin/ls, #1000 env_reset");
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls, #1000` (rc=1) must fire exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            d[0].message.contains("#1000"),
            "the F02 must name the offending member `#1000`; got {:?}",
            d[0].message
        );
    }

    /// `Defaults!sha224:<hex> /bin/ls env_reset` -- a digest-spec fragment
    /// (`sha224:<hex>`) written as if it paired with a following `/bin/ls`
    /// command, the way a digest pairs with a command in an ordinary `Cmnd_Spec`.
    /// It does NOT survive that way here: `split_scope_binding` ends the Cmnd
    /// scope list at the whitespace before `/bin/ls` (no comma follows across
    /// it, per the parser's "a whitespace run ends the list only if no comma is
    /// adjacent" rule), so the scope target is the single member
    /// `sha224:<hex>` alone and `/bin/ls env_reset` becomes one bogus setting
    /// name. Oracle: `visudo -cf` rc=1, "syntax error" (sudo's own grammar does
    /// not accept a digest-spec here either). The lone scope member
    /// `sha224:<hex>` is neither a fully-qualified path, `ALL`, nor
    /// alias-shaped, so it must fire exactly one Fatal `sudo-F02`.
    #[test]
    fn f02_defaults_cmnd_scope_digest_prefixed_sole_target_fires() {
        let d = f02s(
            "Defaults!sha224:2ed3ef2b9b19f47e1a0a1943c50c0c9b57f27bb9e2f8b6c8a1e0c6e4 \
             /bin/ls env_reset",
        );
        assert_eq!(
            d.len(),
            1,
            "a digest-spec fragment as the sole Cmnd-scope target (rc=1) must fire \
             exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults!/bin/ls,sha224:<hex> /bin/cat env_reset` -- the same digest-spec
    /// fragment, now as the SECOND member of a comma list (`split_scope_binding`
    /// still ends the list at the whitespace before `/bin/cat`, since no comma
    /// follows it). Oracle: `visudo -cf` rc=1, "syntax error". Must fire exactly
    /// one Fatal `sudo-F02` naming the digest fragment (not the valid `/bin/ls`).
    #[test]
    fn f02_defaults_cmnd_scope_digest_prefixed_list_member_fires() {
        let d = f02s(
            "Defaults!/bin/ls,sha224:2ed3ef2b9b19f47e1a0a1943c50c0c9b57f27bb9e2f8b6c8a1e0c6e4 \
             /bin/cat env_reset",
        );
        assert_eq!(
            d.len(),
            1,
            "`Defaults!/bin/ls,sha224:<hex>` (rc=1) must fire exactly one F02; got {d:?}"
        );
        assert_eq!(d[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            d[0].message.contains("sha224:"),
            "the F02 must name the offending digest-spec member; got {:?}",
            d[0].message
        );
        assert!(
            !d[0].message.contains("/bin/ls,sha224"),
            "the F02 must name ONLY the bad member, not the whole raw binding \
             (which contains the valid `/bin/ls`); got {:?}",
            d[0].message
        );
    }

    /// `Defaults!/bin/ls env_reset` -- the single-member VALID case from #451's
    /// own example line (minus the offending second member). Oracle: `visudo -cf`
    /// rc=0, "parsed OK". Regression control: must NOT emit any new diagnostic.
    #[test]
    fn f02_defaults_cmnd_scope_single_valid_absolute_path_no_f02() {
        let d = f02s("Defaults!/bin/ls env_reset");
        assert!(
            d.is_empty(),
            "`Defaults!/bin/ls` is a valid single Cmnd-scope path (rc=0) -- must \
             NOT fire; got {d:?}"
        );
    }

    /// `Defaults!/bin/ls,!/bin/cat env_reset` -- a `!`-negated absolute-path
    /// member (mirrors the ordinary command-position negation exemption: a
    /// negated absolute path is valid). Oracle: `visudo -cf` rc=0, "parsed OK".
    /// Must NOT fire.
    #[test]
    fn f02_defaults_cmnd_scope_negated_absolute_path_member_no_f02() {
        let d = f02s("Defaults!/bin/ls,!/bin/cat env_reset");
        assert!(
            d.is_empty(),
            "`Defaults!/bin/ls,!/bin/cat` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults!ALL env_reset` -- the reserved `ALL` as the sole Cmnd-scope
    /// target. Oracle: `visudo -cf` rc=0, "parsed OK". Must NOT fire.
    #[test]
    fn f02_defaults_cmnd_scope_bare_all_no_f02() {
        let d = f02s("Defaults!ALL env_reset");
        assert!(
            d.is_empty(),
            "`Defaults!ALL` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Defaults!/bin/ls,!ALL env_reset` -- a `!`-negated `ALL` member. Oracle:
    /// `visudo -cf` rc=0, "parsed OK". Must NOT fire.
    #[test]
    fn f02_defaults_cmnd_scope_negated_all_member_no_f02() {
        let d = f02s("Defaults!/bin/ls,!ALL env_reset");
        assert!(
            d.is_empty(),
            "`Defaults!/bin/ls,!ALL` is valid (rc=0) -- must NOT fire; got {d:?}"
        );
    }

    /// `Cmnd_Alias LS = /bin/ls` then `Defaults!LS env_reset` -- an alias
    /// reference as the SOLE Cmnd-scope target. Oracle: `visudo -cf` rc=0,
    /// "parsed OK". An alias-name-shaped member must NOT be flagged as an invalid
    /// path even though it contains no `/`.
    #[test]
    fn f02_defaults_cmnd_scope_alias_reference_sole_member_no_f02() {
        let d: Vec<_> =
            lint("root ALL=(ALL:ALL) ALL\nCmnd_Alias LS = /bin/ls\nDefaults!LS env_reset\n")
                .into_iter()
                .filter(|d| d.code == "sudo-F02")
                .collect();
        assert!(
            d.is_empty(),
            "`Defaults!LS` (LS a defined Cmnd_Alias) is valid (rc=0) -- must NOT \
             fire; got {d:?}"
        );
    }

    /// `Cmnd_Alias LS = /bin/ls` then `Defaults!/bin/ls,LS env_reset` -- the same
    /// alias reference as the SECOND member of a comma list. Oracle: `visudo -cf`
    /// rc=0, "parsed OK". Must NOT fire.
    #[test]
    fn f02_defaults_cmnd_scope_alias_reference_list_member_no_f02() {
        let d: Vec<_> = lint(
            "root ALL=(ALL:ALL) ALL\nCmnd_Alias LS = /bin/ls\nDefaults!/bin/ls,LS env_reset\n",
        )
        .into_iter()
        .filter(|d| d.code == "sudo-F02")
        .collect();
        assert!(
            d.is_empty(),
            "`Defaults!/bin/ls,LS` (LS a defined Cmnd_Alias) is valid (rc=0) -- \
             must NOT fire; got {d:?}"
        );
    }

    // -----------------------------------------------------------------------
    // #407 round-3 (tests-only): pin the scope early-return guard
    // `if diags.len() > before { return; }` and the parser's quote-retention.
    // -----------------------------------------------------------------------
    //
    // The early-return means "a malformed scope target already flagged the line
    // -> skip the setting/value check", faithful to visudo's first-error-wins.
    // These tests pin its exact `>` semantics so the mutation gate cannot flip it
    // to `<` / `==` / `>=` silently. The value-check setting used is
    // `secure_path=/usr/bin #3`: visudo rejects the `#3` in the value (rc=1,
    // grounded 1.9.17p2, 2026-07-03), and the Case-2 value check fires on it
    // standalone (see `f02_hash_digits_in_defaults_assigned_value_fires`).

    /// Malformed scope element AND a malformed setting value on ONE line
    /// (`Defaults:#1000abc secure_path=/usr/bin #3`, visudo rc=1). The scope check
    /// fires an F02 and the early-return skips the value check, so EXACTLY ONE F02
    /// (the scope one) is emitted.
    ///
    /// Kills the `> -> <` and `> -> ==` mutants: both make `diags.len() > before`
    /// false after one scope push (`before+1 < before` and `before+1 == before`
    /// are both false), so the fn falls through to the value check and emits a
    /// SECOND F02 -- this test's `== 1` assertion then fails.
    #[test]
    fn f02_defaults_scope_defect_early_returns_before_value_check() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults:#1000abc secure_path=/usr/bin #3\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a malformed scope target must early-return and emit EXACTLY ONE F02 \
             (the scope one), not also run the value check; got {diags:?}"
        );
        assert!(
            f02_diags[0].message.contains("user-scope")
                && f02_diags[0].message.contains("#1000abc"),
            "the single F02 must be the SCOPE diagnostic naming `#1000abc`; got {:?}",
            f02_diags[0].message
        );
        assert!(
            !f02_diags[0].message.contains("setting contains"),
            "the value-check F02 must NOT have run (early-return); got {:?}",
            f02_diags[0].message
        );
    }

    /// VALID scope AND a malformed setting value on one line
    /// (`Defaults:root secure_path=/usr/bin #3`, visudo rc=1). The valid `:root`
    /// scope pushes no diagnostic, so `diags.len() > before` is false and the fn
    /// MUST fall through to the value check, which fires its F02.
    ///
    /// Kills the `> -> >=` mutant: with no scope push, `before >= before` is true,
    /// so the mutant returns early and SKIPS the value check -> zero diagnostics --
    /// this test's `>= 1` (and the value-message) assertion then fails. (Also
    /// reds under `==`, a free bonus.)
    #[test]
    fn f02_defaults_valid_scope_still_runs_value_check() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults:root secure_path=/usr/bin #3\n");
        let value_f02: Vec<_> = diags
            .iter()
            .filter(|d| d.code == "sudo-F02" && d.message.contains("setting contains"))
            .collect();
        assert_eq!(
            value_f02.len(),
            1,
            "a valid scope must NOT early-return -- the value check must still fire \
             its F02 for the malformed `#3` value; got {diags:?}"
        );
        assert_eq!(value_f02[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults:"#1000abc" !lecture` -- a QUOTED literal username (visudo rc=0,
    /// VALID). Guard test: correctness depends on the parser KEEPING the quotes in
    /// the scope binding (`"#1000abc"`), so `strip_prefix('#')` returns `None` and
    /// `is_malformed_gid_tail` never trips. A future parser change that strips the
    /// surrounding quotes would silently turn this valid line into a false-positive
    /// F02; lock the current behavior now.
    #[test]
    fn f02_defaults_user_scope_quoted_literal_name_no_f02() {
        let src = "root ALL=(ALL:ALL) ALL\nDefaults:\"#1000abc\" !lecture\n";
        let f02_diags: Vec<_> = lint(src)
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`Defaults:\"#1000abc\"` is a valid quoted literal username -- must NOT \
             fire F02 (the quote must survive so the `#` gate is not tripped); got \
             {f02_diags:?}"
        );
        // Pin the quote-retention that makes the above hold: the binding is kept
        // verbatim WITH its surrounding quotes.
        let f = files(src);
        let crate::ast::LineKind::Defaults(entry) = &f[0].lines[1].kind else {
            panic!("expected a Defaults entry; got {:?}", f[0].lines[1].kind);
        };
        assert_eq!(
            entry.scope,
            crate::ast::DefaultsScope::User("\"#1000abc\"".to_string()),
            "the quoted scope binding must retain its surrounding quotes"
        );
    }

    // -----------------------------------------------------------------------
    // Case 3: relative-path command
    // -----------------------------------------------------------------------

    /// `alice ALL = bin/ls` -- visudo rc=1, "expected a fully-qualified path name".
    ///
    /// `RuleSteward` parses this as `CmndItem::Cmnd("bin/ls")`. F02 must fire once.
    #[test]
    fn f02_relative_path_command_fires() {
        // Fixture: visudo -c rc=1, "expected a fully-qualified path name" at `bin/ls`.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for a relative-path command; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("bin/ls")
                || f02_diags[0].message.to_lowercase().contains("relative")
                || f02_diags[0].message.to_lowercase().contains("path"),
            "F02 message must name the offending path or call it relative; got {:?}",
            f02_diags[0].message
        );
    }

    /// `alice ALL = /bin/ls some/rel/arg` -- fully-qualified command WITH a
    /// relative-looking ARGUMENT must NOT fire F02.
    ///
    /// Oracle: `alice ALL = /bin/ls some/rel/arg` -- visudo rc=0 (accepted). The
    /// relative-path check must inspect ONLY the command token (`/bin/ls`), not
    /// the argument tokens that follow. An impl that splits on whitespace and
    /// checks any word containing `/` but not starting with `/` would false-positive
    /// on `some/rel/arg`.
    ///
    /// This test is GREEN now (stub emits nothing) and MUST STAY GREEN after the
    /// correct implementation, which scopes the check to the command path only.
    #[test]
    fn f02_relative_arg_on_qualified_command_no_f02() {
        // Fixture: visudo -c rc=0 (accepted). The argument `some/rel/arg` is a
        // relative path but it is NOT the command token -- it is a command argument.
        // The relative-path check must NOT flag arguments, only the command itself.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls some/rel/arg\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a fully-qualified command `/bin/ls` with a relative argument `some/rel/arg` \
             must NOT fire F02 -- only the command token is checked, not its arguments; \
             got {f02_diags:?}"
        );
    }

    /// `alice ALL = sub/dir/cmd` -- a multi-segment relative path also fires.
    #[test]
    fn f02_multi_segment_relative_path_fires() {
        // Fixture: same oracle case; any path containing `/` but not starting with
        // `/` is rejected by visudo.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = sub/dir/cmd\n");
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nalice ALL = sub/dir/cmd\n"),
            1,
            "multi-segment relative path also fires F02; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Case 4: malformed group subject
    // -----------------------------------------------------------------------

    /// `%bad group ALL = ALL` -- visudo rc=1, syntax error at the space after `%bad`.
    ///
    /// `RuleSteward` parses `%bad` as the user and `group ALL` as the host list, so
    /// the structural parse succeeds. F02 must detect the malformed group token.
    #[test]
    fn f02_malformed_group_subject_fires() {
        // Fixture: visudo -c rc=1, "syntax error" at col 12 (the space in `%bad group`).
        // The `%` prefix indicates a Unix group; group names may not contain spaces.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "exactly one F02 for malformed group subject `%bad group`; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("%bad")
                || f02_diags[0].message.to_lowercase().contains("group")
                || f02_diags[0].message.to_lowercase().contains("subject"),
            "F02 message must name the offending group token or position; got {:?}",
            f02_diags[0].message
        );
    }

    // -----------------------------------------------------------------------
    // MUST-NOT-REGRESS: valid files produce NO sudo-F02
    // -----------------------------------------------------------------------

    /// `User_Alias FOO = #1000` -- the `#1000` after `=` in an alias DEFINITION
    /// is a valid UID member per `visudo -x` (rc=0; only an "unused alias" warning).
    ///
    /// F02 must NOT fire: alias member positions are not command/Defaults positions.
    #[test]
    fn f02_alias_uid_member_is_valid_no_f02() {
        // Fixture: visudo -c rc=0 (warning "unused User_Alias FOO" only, not an error).
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nUser_Alias FOO = #1000\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a UID alias member `#1000` is valid and must produce no F02; got {f02_diags:?}"
        );
    }

    /// A plain valid sudoers file (root rule, Defaults, %wheel) produces no F02.
    #[test]
    fn f02_clean_file_no_f02() {
        // Fixture: visudo -c rc=0, "parsed OK".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint(
            "root ALL=(ALL:ALL) ALL\nDefaults env_reset\nDefaults use_pty\n%wheel ALL=(ALL) ALL\n",
        );
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a clean valid sudoers file must produce no F02; got {f02_diags:?}"
        );
    }

    /// A fully-qualified command (`/bin/ls`) does NOT fire F02 (only relative paths do).
    #[test]
    fn f02_fully_qualified_path_is_valid_no_f02() {
        // Fixture: `alice ALL = /bin/ls` -- visudo -c rc=0. Not a relative path.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a fully-qualified path `/bin/ls` must not fire F02; got {f02_diags:?}"
        );
    }

    /// A well-formed group subject (`%wheel`) is valid; F02 must not fire.
    #[test]
    fn f02_valid_group_subject_no_f02() {
        // Fixture: `%wheel ALL=(ALL) ALL` -- visudo -c rc=0. The group name has no space.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL) ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%wheel` is a valid group subject and must not fire F02; got {f02_diags:?}"
        );
    }

    /// `#1000 ALL = /bin/ls` -- `#1000` in USER (subject) position is a valid UID
    /// user-spec, NOT a command-position `#<digits>`. F02 must not fire.
    #[test]
    fn f02_uid_in_user_subject_position_is_valid_no_f02() {
        // Fixture: `#1000 ALL = /bin/ls` -- visudo -c rc=0. The #1000 is a UID
        // subject, which is valid. Same disambiguation the w01 test uses.
        let diags = lint("root ALL=(ALL:ALL) ALL\n#1000 ALL = /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`#1000` in user-subject position is valid and must not fire F02; got {f02_diags:?}"
        );
    }

    /// Multiple invalid tokens in separate lines fire once per line.
    #[test]
    fn f02_multiple_invalid_lines_fire_per_line() {
        // Two lines that each contain an invalid token; F02 should fire once per line.
        // Fixture: visudo rejects both lines (rc=1).
        let diags = lint(
            "root ALL=(ALL:ALL) ALL\n\
             alice ALL = /bin/ls #2\n\
             bob ALL = bin/ls\n",
        );
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            2,
            "two invalid lines must fire two F02 diagnostics; got {diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Defect 1 (FALSE POSITIVE fix): `!`-negated commands in Case 3
    // Grounded: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
    // -----------------------------------------------------------------------

    /// `alice ALL = !/bin/su` -- a `!`-negated ABSOLUTE path is VALID.
    ///
    /// Oracle: visudo -cf rc=0 ("parsed OK").
    /// The `!` prefix is a command negation in sudoers; the underlying path `/bin/su`
    /// is absolute. Case 3 must NOT fire because stripping the leading `!` reveals an
    /// absolute path.
    ///
    /// Before fix: fires (FP) because `!/bin/su` does not start with `/`.
    #[test]
    fn f02_bang_negated_absolute_path_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // `!/bin/su` is the standard sudoers syntax for "deny /bin/su".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = !/bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`!/bin/su` is a valid negated absolute command and must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `alice ALL = /bin/ls, !/bin/su` -- list form with a negated absolute path.
    ///
    /// Oracle: visudo -cf rc=0 ("parsed OK").
    /// The comma-separated list containing `/bin/ls` (allow) and `!/bin/su` (deny)
    /// is a standard sudoers pattern. Case 3 must NOT fire on `!/bin/su`.
    ///
    /// Before fix: fires (FP) because `!/bin/su` does not start with `/`.
    #[test]
    fn f02_bang_negated_absolute_in_list_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls, !/bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`/bin/ls, !/bin/su` list with negated absolute must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `alice ALL = !bin/su` -- `!`-negated RELATIVE path MUST still fire F02.
    ///
    /// Oracle: visudo -cf rc=1, "expected a fully-qualified path name".
    /// Stripping the `!` reveals `bin/su` which is relative. F02 must fire.
    ///
    /// This test is GREEN before and after the fix (the fix must preserve this).
    #[test]
    fn f02_bang_negated_relative_path_fires() {
        // Fixture: visudo -cf rc=1, "expected a fully-qualified path name".
        // `!bin/su` is a negated relative path -- visudo rejects it.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = !bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`!bin/su` is a negated relative path and MUST fire F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // Defect 2 (FALSE NEGATIVE fix): invalid chars in `%group` name (Case 4)
    //
    // Grounded char class (Rocky Linux 9, sudo 1.9.17p2, 2026-06-30):
    //   REJECTED in group name: `!`, `(`, `)`, space, tab (and `:`, `=` which
    //   cause Malformed/F01 before F02 can fire -- those are not F02 cases).
    //   ACCEPTED in group name: letters, digits, `_`, `-`, `.`, `/`, `@`, `+`,
    //   `~`, `\`, `[`, `,`, `#` (as `%#NNN` GID form).
    // -----------------------------------------------------------------------

    /// `%bad!group ALL = ALL` -- visudo rc=1, "syntax error" at col 10.
    ///
    /// Oracle: `!` is not a valid char in a sudoers group name. The parser produces
    /// `UserSpec` with `users=["%bad!group"]` (the `!` is inside the token, not
    /// whitespace-split), so it reaches F02 as a clean `UserSpec`. Case 4 must fire.
    ///
    /// Before fix: Case 4 only checks embedded whitespace -- stays silent (FN).
    #[test]
    fn f02_group_name_with_bang_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `!` in `%bad!group`.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad!group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad!group` has `!` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
        assert!(
            f02_diags[0].message.contains("%bad!group")
                || f02_diags[0].message.to_lowercase().contains("group")
                || f02_diags[0].message.to_lowercase().contains("subject"),
            "F02 message must name the group token; got {:?}",
            f02_diags[0].message
        );
    }

    /// `%bad(group ALL = ALL` -- visudo rc=1, "syntax error" (paren in group name).
    ///
    /// Oracle: `(` is not valid in a sudoers group name. The parser produces
    /// `UserSpec` with `users=["%bad(group"]`, so F02 Case 4 must fire.
    #[test]
    fn f02_group_name_with_open_paren_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `(` in `%bad(group`.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad(group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad(group` has `(` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%bad)group ALL = ALL` -- visudo rc=1, "syntax error" (close-paren in group name).
    #[test]
    fn f02_group_name_with_close_paren_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `)` in `%bad)group`.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad)group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad)group` has `)` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // Round-3 Fix 3: group-name char class completed via exhaustive grounding.
    //
    // Exhaustive visudo -cf probe of every printable-ASCII char CH in the middle of
    // a `%bad<CH>group` SUBJECT token (rockylinux:9, sudo 1.9.17p2, 2026-06-30):
    //   REJECTED (rc=1): `!  "  #  (  )  :  =  >`  (8 chars)
    //   ACCEPTED (rc=0): the other 86 printable-ASCII chars AND non-ASCII (accented letters).
    // Of the 8 rejected, the parser marks `#`, `:`, `=` as Malformed -> caught by
    // sudo-F01, so they never reach F02. The 5 that reach F02 as a clean UserSpec
    // are exactly `! ( ) > "`. Round-2 caught only `! ( )`; `>` and `"` were missed.
    // -----------------------------------------------------------------------

    /// `%bad>group ALL = ALL` -- visudo rc=1, "syntax error" (`>` in group name).
    ///
    /// Oracle: `>` is invalid in a sudoers group name (rc=1). The parser keeps a
    /// clean `UserSpec` with `users=["%bad>group"]`, so F02 Case 4 must fire.
    /// Round-2 missed this (`>` was not in the denylist).
    #[test]
    fn f02_group_name_with_gt_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `>` in `%bad>group`.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30 (exhaustive probe).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad>group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad>group` has `>` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%bad"group ALL = ALL` -- visudo rc=1 (`"` in group name).
    ///
    /// Oracle: `"` is invalid in a sudoers group name (rc=1). The parser keeps a
    /// clean `UserSpec` with `users=["%bad\"group"]`, so F02 Case 4 must fire.
    /// Round-2 missed this (`"` was not in the denylist).
    #[test]
    fn f02_group_name_with_dquote_fires() {
        // Fixture: visudo -cf rc=1 at the `"` in `%bad"group`.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30 (exhaustive probe).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad\"group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%bad\"group` has `\"` in the group name and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%bad<group ALL = ALL` -- visudo rc=0; `<` is ACCEPTED (pins the `<`/`>`
    /// asymmetry: `<` valid, `>` invalid). Must NOT fire F02.
    #[test]
    fn f02_group_name_with_lt_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK". `<` is a valid group-name char even
        // though the mirror `>` is not (grounded asymmetry).
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30 (exhaustive probe).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad<group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%bad<group` is valid (`<` accepted; asymmetric with `>`) -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Defect 2: valid sibling guards -- these must NOT fire F02
    // -----------------------------------------------------------------------

    /// `%bad/group ALL = ALL` -- visudo rc=0; `/` is a valid char in a group name.
    #[test]
    fn f02_group_name_with_slash_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // `/` is valid in group names (e.g. system/admin groups on some distros).
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad/group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%bad/group` is valid (/ accepted in group name) -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `%bad@group ALL = ALL` -- visudo rc=0; `@` is valid in group names.
    #[test]
    fn f02_group_name_with_at_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%bad@group ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%bad@group` is valid (@ accepted in group name) -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `%1000abc ALL = ALL` -- visudo rc=0; digits + alpha are valid in group names.
    #[test]
    fn f02_group_name_alphanumeric_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%1000abc ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%1000abc` is valid (digits+alpha in group name) -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `%#1000 ALL = ALL` -- visudo rc=0; `%#NNN` is the GID form, valid.
    ///
    /// This is distinct from the `%bad!group` user token: `%#1000` starts with `%#`
    /// and is a GID-referenced group subject. F02 must not fire.
    #[test]
    fn f02_group_gid_form_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // `%#1000` means "the group with GID 1000" -- a valid sudoers syntax.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000 ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%#1000` (GID group form) is valid -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Defect 3: has_hash_digits simplification / mutation kill tests
    //
    // Reachability analysis (2026-06-30, refined round-3):
    //   has_hash_digits is called on:
    //     (a) individual CmndSpec command tokens (comma-split BEFORE call, so no `,`
    //         in the string at call time)
    //     (b) Defaults setting name / value strings (also comma-split before call)
    //   The `,` preceding-char branch is DEAD CODE in both call sites and is removed.
    //   The `%` preceding-char branch is REACHABLE and NOT equivalent to whitespace:
    //   for `/bin/prog %#2` the byte immediately before `#` is `%`, so only a `%` arm
    //   returns true (round-3 restored it after round-2 wrongly dropped it -- see the
    //   f02_percent_hash_digits_* tests above). visudo rejects `%#digits` in both
    //   command and Defaults-value positions (rc=1, grounded rockylinux:9 2026-06-30).
    // -----------------------------------------------------------------------

    /// `/bin/ls2` -- the digit `2` appears IN the path (not after `#`). Must not fire.
    ///
    /// This test kills the `&& -> ||` mutant on line 207: if the condition were `||`,
    /// any `#` in the string (even not followed by digits) would fire; this path
    /// has no `#` at all, so it stays silent regardless. But combined with the
    /// `#` assertion below, it pins that the digit check is necessary.
    #[test]
    fn f02_digit_in_path_no_hash_no_f02() {
        // Fixture: visudo -cf rc=0. `/bin/ls2` is a valid absolute path.
        // Kills the && -> || mutant: the `||` form would check if `bytes[i] == b'#'`
        // OR if the next byte is a digit -- but we need BOTH. This path (/bin/ls2)
        // has no `#`, so a byte at position 6 is `2` not `#`; neither condition
        // fires alone.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`/bin/ls2` has a digit but no `#`-prefix -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `alice ALL = /bin/ls #2` -- `#2` preceded by whitespace in a command token.
    ///
    /// This test (already present as `f02_hash_digits_in_command_position_fires`)
    /// kills the `p == b','`->`!=` and the `,`/`%` `|| -> &&` mutants by verifying
    /// that whitespace-preceded `#digits` DOES fire. The simplified `has_hash_digits`
    /// (whitespace + start-of-string only) fires correctly via the whitespace arm.
    ///
    /// NOTE: this duplicates `f02_hash_digits_in_command_position_fires` above to make
    /// the killing intent explicit for Defect 3.
    #[test]
    fn f02_hash_digits_after_whitespace_fires_kills_survivors() {
        // Fixture: visudo -cf rc=1.
        // Verified: Rocky Linux 9, sudo 1.9.17p2, 2026-06-30.
        // Kills: `p == b','`->`!=` (the negated comma check would suppress whitespace
        // cases because b' ' != b','); `|| -> &&` (whitespace-only would need BOTH
        // comma and whitespace, never true for a space-preceded `#`).
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls #2\n"),
            1,
            "whitespace-preceded `#2` in command must fire F02"
        );
        // Also confirm the bare-at-start case (kills the start-of-string -> false mutant):
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nalice ALL = #2\n"),
            1,
            "`#2` at start of command token must fire F02"
        );
    }

    // -----------------------------------------------------------------------
    // Round-3 Fix 1 (REGRESSION): `%#<digits>` glued in command / Defaults-value
    // must fire F02. Round-2 dropped the `%` preceding-char arm of has_hash_digits
    // on the (wrong) claim it was caught by the whitespace arm. It is NOT: for
    // `/bin/prog %#2` the byte immediately before `#` is `%`, not whitespace, so
    // only a `%`-preceding arm reaches the return. Parent commit 14b13d2 fired
    // correctly; these tests restore + pin that behavior.
    //
    // Grounding (rockylinux:9, sudo 1.9.17p2, 2026-06-30, visudo -cf):
    //   `alice ALL = /bin/prog %#2`   -> rc=1 (syntax error at col 24)
    //   `Defaults passprompt=x%#2`    -> rc=1 (col 23)
    // -----------------------------------------------------------------------

    /// `alice ALL = /bin/prog %#2` -- `%#2` glued in a command arg. visudo rc=1.
    ///
    /// `strip_inline_comment` keeps `#2` because it is `#<digit>` preceded by `%`
    /// (Exception 2, a GID token). The command reaches the AST as
    /// `/bin/prog %#2`; the byte before `#` is `%` (not whitespace), so this only
    /// fires if `has_hash_digits` has the `%`-preceding arm.
    #[test]
    fn f02_percent_hash_digits_in_command_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `%#2`.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/prog %#2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`/bin/prog %#2` (%-preceded #digits in command) must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults passprompt=x%#2` -- `%#2` glued in a Defaults value. visudo rc=1.
    ///
    /// `strip_inline_comment` keeps `#2` (preceded by `%`), so the value reaches the
    /// AST as `x%#2`; the byte before `#` is `%`. Fires only with the `%`-preceding arm.
    #[test]
    fn f02_percent_hash_digits_in_defaults_value_fires() {
        // Fixture: visudo -cf rc=1 at col 23.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=x%#2\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`Defaults passprompt=x%#2` (%-preceded #digits in value) must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // -----------------------------------------------------------------------
    // Round-3 Fix 2: kill the `has_hash_digits` `&& -> ||` mutation survivor
    // (the `bytes[i] == b'#' && next_is_ascii_digit` guard). Two grounded rc=0
    // inputs distinguish `&&` from `||` where the CORRECT `&&` stays silent but
    // `||` wrongly fires:
    //   (Case A) a `#` NOT followed by a digit at a whitespace-preceded slot.
    //   (Case B) a digit NOT preceded by `#` at a whitespace-preceded slot.
    // -----------------------------------------------------------------------

    /// Case A: `Defaults passprompt="a #x b"` -- a quoted `#` NOT followed by a digit.
    ///
    /// Oracle: visudo -cf rc=0 (a `#` inside a double-quoted value is literal, and
    /// `#x` is not a `#<digits>` token). `strip_inline_comment` KEEPS the quoted `#`
    /// (Exception 3), so `has_hash_digits` receives a string containing `#x`. The
    /// correct `&&` form: `#`==`#` (true) AND next-is-digit (`x`, false) -> no fire.
    /// The `||` mutant: `#`==`#` (true) OR ... -> true -> would WRONGLY fire F02.
    #[test]
    fn f02_quoted_hash_nondigit_no_f02_kills_and_to_or() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // Kills `has_hash_digits` `&& -> ||`: a `#` reaches the fn but is followed by
        // a non-digit; only `&&` stays silent, `||` fires.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"a #x b\"\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a quoted `#x` (# not followed by a digit) is visudo-valid -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// Case B: `alice ALL = /bin/prog a5` -- a digit `5` NOT preceded by `#`, at a
    /// whitespace-preceded slot (`a` follows the space, `5` follows `a`).
    ///
    /// Oracle: visudo -cf rc=0 (`a5` is a free-form command argument). The string
    /// `/bin/prog a5` reaches `has_hash_digits` (no `#` stripped). The correct `&&`:
    /// no byte is `#`, so never fires. The `||` mutant: at the `a` slot (preceded by
    /// whitespace, `prev_ok=true`) the next byte `5` IS a digit, so `||` returns true
    /// -> would WRONGLY fire F02.
    #[test]
    fn f02_digit_after_space_no_hash_no_f02_kills_and_to_or() {
        // Fixture: visudo -cf rc=0, "parsed OK". A command with a `a5` argument.
        // Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // Kills `has_hash_digits` `&& -> ||`: a digit at a whitespace-preceded slot+1
        // makes the `||` right-hand side true even though no `#` is present.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/prog a5\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`/bin/prog a5` (digit not preceded by `#`) is visudo-valid -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Round-4 Fix: pure-GID guard over-exempts `#`-prefix group names
    //
    // The guard `!name.starts_with('#')` was meant to exempt the valid pure-GID
    // form `%#1000` from the denylist check. But it over-exempts ANY name that
    // starts with `#`, including `#1000>x`, `#1000!x`, etc. -- these have a
    // denylist char after the `#<digits>` prefix and are visudo-rejected (rc=1).
    //
    // Grounding (rockylinux:9, sudo 1.9.17p2, 2026-06-30, visudo -cf):
    //   `%#1000>x ALL = ALL`  -> rc=1 (syntax error at col 7, the `>`)
    //   `%#1000!x ALL = ALL`  -> rc=1 (syntax error at col 10, the `!`)
    //   `%#1000 ALL = ALL`    -> rc=0 (valid pure-GID form, must stay silent)
    //   `%#1000abc ALL = ALL` -> rc=1 (syntax error; no denylist char present
    //                                  so out of scope for this fix -- the
    //                                  `#<digits><alpha>` class is a separate gap)
    //
    // The correct exemption: pure-GID form = `#` followed by one or more ASCII
    // digits and NOTHING else.
    // -----------------------------------------------------------------------

    /// `%#1000>x ALL = ALL` -- visudo rc=1; `>` follows the digits in a `#`-prefix
    /// group name. The old guard `!name.starts_with('#')` exempts this and stays
    /// silent (FALSE NEGATIVE). The fixed guard recognises `#1000>x` as NOT a pure
    /// GID (contains a non-digit after `#`) and runs the denylist, which finds `>`.
    ///
    /// Oracle: rockylinux:9, sudo 1.9.17p2, visudo -cf rc=1 "syntax error" at col 7.
    #[test]
    fn f02_hash_prefix_group_name_with_gt_fires() {
        // Fixture: visudo -cf rc=1. Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // RED before fix (old `!starts_with('#')` exempts `#1000>x` entirely).
        // GREEN after fix (`is_pure_gid` is false for `#1000>x` -> denylist fires on `>`).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000>x ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%#1000>x` has `>` in group name after digits -- must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%#1000!x ALL = ALL` -- visudo rc=1; `!` follows the digits.
    ///
    /// Companion to the `>` case: same over-exemption in the old guard.
    ///
    /// Oracle: rockylinux:9, sudo 1.9.17p2, visudo -cf rc=1 "syntax error" at col 10.
    #[test]
    fn f02_hash_prefix_group_name_with_bang_fires() {
        // Fixture: visudo -cf rc=1. Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // RED before fix; GREEN after fix (`is_pure_gid` false -> denylist finds `!`).
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000!x ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%#1000!x` has `!` in group name after digits -- must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%#1000 ALL = ALL` -- visudo rc=0; pure-GID form MUST stay silent after the fix.
    ///
    /// The fix must preserve the pure-GID exemption exactly: `is_pure_gid` is true
    /// for `#1000` (all-digit rest), so the denylist does NOT run. No F02.
    ///
    /// NOTE: already covered by `f02_group_gid_form_no_f02` above; this companion
    /// test makes the Round-4 must-not-regress intent explicit.
    #[test]
    fn f02_pure_gid_group_still_silent_after_fix() {
        // Fixture: visudo -cf rc=0. Verified: rockylinux:9, sudo 1.9.17p2, 2026-06-30.
        // GREEN before AND after fix.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000 ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%#1000` is the valid pure-GID form -- must NOT fire F02 after the fix; got {f02_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Issue #375: out-of-scope tail (Case-4/Case-5 completeness pass)
    //
    // Three visudo-rejected shapes that sit OUTSIDE the four documented F02
    // positions above (deferred from #346's post-GREEN adversarial review):
    //   1. Runas-position group defects: a malformed `%group`/`%#gid` token
    //      inside a `(...)` runas spec (RunasSpec.users / RunasSpec.groups),
    //      which check_user_spec's Case-4 walk never scans today (it only
    //      inspects UserSpec.users, the SUBJECT list).
    //   2. Lone `!` command with no path: `CmndItem::Cmnd("!")`, a negation
    //      with nothing to negate.
    //   3. `%#<digits><non-digit>`: a GID-looking name whose digit run is
    //      followed by a non-digit, non-denylist char (e.g. `1000abc`) -- the
    //      existing denylist `{! ( ) > "}` never matches plain alnum tails.
    //
    // All fixtures grounded via local `visudo -cf` 1.9.17p2 (matches the
    // rockylinux:9 sudo version this file's other oracle comments cite),
    // 2026-07-02. See raw grounding transcript in the task's GROUNDING section.
    // -----------------------------------------------------------------------

    // --- Shape 1: runas-position group defects -----------------------------

    /// `alice ALL = (grpbad!x) /bin/ls` -- issue #375's literal example.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `!` (col 20). The `!` sits
    /// inside the `RUNAS_USER` token (before any `:`), so `RunasSpec.users =
    /// ["grpbad!x"]`. `check_user_spec`'s Case-4 walk only inspects
    /// `UserSpec.users` (the SUBJECT list before ` = `), never `CmndSpec.runas`,
    /// so today this fires ZERO sudo-F02 diagnostics (RED).
    #[test]
    fn f02_runas_user_position_bang_in_name_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `!` in `(grpbad!x)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02 (matches this file's
        // rockylinux:9 sudo 1.9.17p2 oracle baseline).
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (grpbad!x) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a `!` inside a runas-USER-position token is visudo-rejected and must fire \
             exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (%grpbad!x) /bin/ls` -- `%group` form (`RUNAS_USER` position)
    /// with a Case-4 denylist char (`!`) inside the group name.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `!`. This is the direct
    /// runas-position analog of the existing SUBJECT-position
    /// `f02_group_name_with_bang_fires` test -- same denylist char, different
    /// AST field (`RunasSpec.users` instead of `UserSpec.users`).
    #[test]
    fn f02_runas_user_position_pct_group_bang_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `!` in `(%grpbad!x)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%grpbad!x) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a `%group` runas-USER token with `!` in the name must fire exactly one F02; \
             got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (root:grp!x) /bin/ls` -- a bare (non-`%`) name in the
    /// `RUNAS_GROUP` position (after `:`) with a Case-4 denylist char (`!`).
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `!`. `RunasSpec.groups =
    /// ["grp!x"]`; the walk must cover BOTH `RunasSpec.users` and
    /// `RunasSpec.groups`, not just the pre-colon list.
    #[test]
    fn f02_runas_group_position_bang_in_name_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the `!` in `(root:grp!x)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:grp!x) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a `!` inside a runas-GROUP-position (post-colon) token must fire exactly \
             one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (root : %grp) /bin/ls` -- issue #375's literal example.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at `%grp` (col 21). Grounded
    /// separately (no embedded whitespace, no denylist char):
    /// `alice ALL = (root:%grp) /bin/ls` is ALSO rc=1 at the `%grp` token, and
    /// `alice ALL = (root:grp) /bin/ls` (same name, no `%`) is rc=0 "parsed OK".
    /// So the defect here is the bare `%`-PREFIX ITSELF inside the `RUNAS_GROUP`
    /// position -- unlike the pre-colon `RUNAS_USER` list (where `%group` is the
    /// normal, valid way to name a group), the post-colon `RUNAS_GROUP` list
    /// already denotes groups, so a `%` prefix there is categorically invalid
    /// regardless of the name's contents. This is DISTINCT from the Case-4(b)
    /// denylist-char mechanism (`grp` alone contains no denylist char) --
    /// implementer: this is a THIRD mechanism, not a reuse of the denylist walk.
    #[test]
    fn f02_runas_group_position_pct_prefix_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at `%grp` in `(root : %grp)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root : %grp) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a bare `%`-prefixed token in the RUNAS_GROUP (post-colon) position is \
             visudo-rejected regardless of denylist chars and must fire exactly one \
             F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (root) /bin/ls` -- a plain runas user, no groups. Valid.
    #[test]
    fn f02_runas_user_position_plain_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(root)` is a valid runas-user spec -- must NOT fire F02; got {f02_diags:?}"
        );
    }

    /// `alice ALL = (root:wheel) /bin/ls` -- a bare (non-`%`) group name after
    /// `:`. Valid: the `RUNAS_GROUP` position never uses a `%` prefix.
    #[test]
    fn f02_runas_group_position_bare_name_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:wheel) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(root:wheel)` is a valid runas group-list entry -- must NOT fire F02; \
             got {f02_diags:?}"
        );
    }

    /// `alice ALL = (%wheel) /bin/ls` -- `%group` form in the `RUNAS_USER`
    /// position with a well-formed name. Valid.
    #[test]
    fn f02_runas_user_position_pct_group_valid_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%wheel) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(%wheel)` is a valid runas-user group reference -- must NOT fire F02; \
             got {f02_diags:?}"
        );
    }

    /// `alice ALL = (root:#1000) /bin/ls` -- pure-GID form in the `RUNAS_GROUP`
    /// position (no `%` prefix needed for a GID either). Valid.
    #[test]
    fn f02_runas_group_position_gid_form_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:#1000) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(root:#1000)` is a valid runas GID-group entry -- must NOT fire F02; \
             got {f02_diags:?}"
        );
    }

    /// `alice ALL = (%wheel:root) /bin/ls` -- both runas lists populated and
    /// valid (a `%group` runas-user, a bare-name runas-group). Valid.
    #[test]
    fn f02_runas_both_positions_valid_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%wheel:root) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(%wheel:root)` has both a valid runas-user and runas-group -- must NOT \
             fire F02; got {f02_diags:?}"
        );
    }

    // Post-GREEN adversarial-impl finding: the GID-tail (Rule 3) structural check
    // fires for a SUBJECT-position `%#1000abc` (see
    // `f02_gid_form_digits_then_letters_fires` in Shape 3 below) but NOT for the
    // SAME token in the RUNAS-USER position -- `check_runas`'s `runas.users` loop
    // only runs the denylist (`first_invalid_char`), which finds no denylist char
    // in `%#1000abc` and stays silent. These tests pin the consistency: the
    // GID-tail defect must fire in the runas-user position too.

    /// `alice ALL = (%#1000abc) /bin/ls` -- the runas-USER analog of the
    /// subject-position `f02_gid_form_digits_then_letters_fires`: a `%#`-GID
    /// token whose digit run is followed by letters, with no denylist char.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at `abc` (col 20). The token
    /// survives `strip_inline_comment` (the `#` is preceded by `%` and followed
    /// by a digit, so it is kept as a GID token) and reaches `check_runas` as a
    /// clean `RunasSpec.users = ["%#1000abc"]`. RED today: the runas-user loop
    /// only checks the denylist, and `1000abc` has no denylist char, so F02 is
    /// silent -- the GID-tail structural check is not applied in this position.
    #[test]
    fn f02_runas_user_gid_form_digits_then_letters_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at `abc` in `(%#1000abc)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%#1000abc) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(%#1000abc)` runas-user (digit run followed by letters, no denylist char) \
             is visudo-rejected and must fire exactly one F02, mirroring the \
             subject-position case; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (%#0z) /bin/ls` -- runas-USER `%#`-GID with a single-digit
    /// run (`0`) immediately followed by a letter (`z`). Sibling of the case
    /// above at the shortest-digit-run boundary.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `z` (col 17). `is_pure_gid`
    /// is false for `#0z` (the rest is not all-digit), so once the GID-tail check
    /// is applied to `runas.users` this must fire; RED today for the same reason.
    #[test]
    fn f02_runas_user_gid_form_short_digit_run_then_letter_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at `z` in `(%#0z)`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%#0z) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(%#0z)` runas-user (single-digit GID run then a letter) is visudo-rejected \
             and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (%#1000) /bin/ls` -- the runas-USER pure-GID form MUST stay
    /// clean after the GID-tail check is added (the exemption must be preserved,
    /// exactly as `f02_runas_group_position_gid_form_no_f02` pins for the group
    /// position and `f02_group_gid_form_no_f02` pins for the subject position).
    #[test]
    fn f02_runas_user_pure_gid_form_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (%#1000) /bin/ls\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(%#1000)` is the valid pure-GID runas-user form -- must NOT fire F02 after \
             the GID-tail check is applied to the runas-user position; got {f02_diags:?}"
        );
    }

    // --- #407: runas-GROUP `#`-GID token + bare (non-`%`) runas-USER `#`-GID
    // token, both false-negatives via `strip_inline_comment` -----------------
    //
    // Root cause distinct from the `%#1000abc` cases above: `strip_inline_comment`'s
    // `prev_allows_uid` predicate (parser.rs) did not allow `:` (the runas-group
    // separator) or `(` (the runas open-paren) to precede a `#<digits>` token, so
    // for `(root:#1000abc)` / `(#1000abc)` the ENTIRE REST OF THE LINE -- including
    // the real command -- was swallowed as an inline comment. The line reached the
    // AST as `CmndSpec { runas: None, cmnd: Cmnd("(root:") }` / `Cmnd("(")`, so
    // `check_runas` was never even invoked with the malformed token: RuleSteward
    // emitted ZERO diagnostics for a file `visudo -c` rejects outright (rc=1).
    // Fixed by widening `prev_allows_uid` (parser.rs) plus a GID-tail check on the
    // `runas.groups` loop and broadening the `runas.users` GID-tail check to the
    // bare (non-`%`) form (both in `check_runas` below).

    /// `alice ALL = (root:#1000abc) /bin/su` -- a runas-GROUP (post-colon) `#`-GID
    /// token whose digit run is followed by a non-digit tail.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at the `abc` tail (col 22).
    /// Verified locally: sudo/visudo 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_runas_group_gid_form_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:#1000abc) /bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(root:#1000abc)` runas-group (digit run followed by letters, no \
             denylist char) is visudo-rejected and must fire exactly one F02; \
             got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (#1000abc) /bin/su` -- the BARE (no `%`) runas-USER form
    /// (no colon at all, so the whole `(...)` is `runas.users`) with the same
    /// malformed GID/UID tail. Distinct from the already-covered `%#1000abc`
    /// case: no `%` prefix, so the OLD `user.strip_prefix('%')`-gated GID-tail
    /// check in `check_runas` would not have applied even if the token had
    /// reached it.
    ///
    /// Oracle: `visudo -c` rc=1, "syntax error" at the `abc` tail (col 17).
    /// Verified locally: sudo/visudo 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_runas_user_bare_hash_gid_form_digits_then_letters_fires() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (#1000abc) /bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(#1000abc)` bare runas-user GID/UID form (digit run then letters, \
             no `%`, no denylist char) is visudo-rejected and must fire exactly \
             one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (root:#1000) /bin/su` -- the VALID pure-GID runas-GROUP form
    /// (#407's critical non-regression control).
    ///
    /// A bare `f02_diags.is_empty()` assertion alone is satisfiable by the OLD,
    /// BROKEN parse too: the comment-swallowing bug truncates the line to
    /// `CmndSpec { runas: None, cmnd: Cmnd("(root:") }` before `check_runas` (or
    /// any command-position check) ever runs, so F02 trivially finds nothing --
    /// a false pass masking real data loss (the command `/bin/su` vanishes
    /// silently). This test additionally asserts the AST shape so the
    /// regression can't hide behind an empty-diagnostics vacuity.
    ///
    /// Oracle: `visudo -c` rc=0, "parsed OK"; `cvtsudoers -f json` shows
    /// `"runasgroups": [{"usergroup": "#1000"}]`. Verified locally: sudo/visudo
    /// 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_runas_group_gid_form_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nalice ALL = (root:#1000) /bin/su\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(root:#1000)` is a valid runas GID-group entry -- must NOT fire \
             F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::UserSpec(spec) = &f[0].lines[1].kind else {
            panic!("expected the second logical line to classify as a UserSpec");
        };
        let runas = spec.host_groups[0].cmnd_specs[0]
            .runas
            .as_ref()
            .expect("runas group must be populated -- not swallowed by the comment strip");
        assert_eq!(runas.users, vec!["root".to_string()]);
        assert_eq!(runas.groups, vec!["#1000".to_string()]);
        assert_eq!(
            spec.host_groups[0].cmnd_specs[0].cmnd,
            crate::ast::CmndItem::Cmnd("/bin/su".to_string()),
            "the real command must survive -- not be truncated into the runas group"
        );
    }

    /// `alice ALL = (#1000) /bin/su` -- the VALID bare pure-GID/UID runas-USER
    /// form (no colon). Sibling non-regression control to the group-position
    /// test above.
    ///
    /// Oracle: `visudo -c` rc=0, "parsed OK"; `cvtsudoers -f json` shows
    /// `"runasusers": [{"userid": 1000}]`. Verified locally: sudo/visudo
    /// 1.9.17p2, 2026-07-03.
    #[test]
    fn f02_runas_user_bare_hash_pure_gid_no_f02_and_parses_correctly() {
        let src = "root ALL=(ALL:ALL) ALL\nalice ALL = (#1000) /bin/su\n";
        let diags = lint(src);
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`(#1000)` is a valid bare runas-user GID/UID entry -- must NOT fire \
             F02; got {f02_diags:?}"
        );
        let f = files(src);
        let crate::ast::LineKind::UserSpec(spec) = &f[0].lines[1].kind else {
            panic!("expected the second logical line to classify as a UserSpec");
        };
        let runas = spec.host_groups[0].cmnd_specs[0]
            .runas
            .as_ref()
            .expect("runas group must be populated -- not swallowed by the comment strip");
        assert_eq!(runas.users, vec!["#1000".to_string()]);
        assert_eq!(
            spec.host_groups[0].cmnd_specs[0].cmnd,
            crate::ast::CmndItem::Cmnd("/bin/su".to_string()),
            "the real command must survive -- not be truncated into the runas group"
        );
    }

    // -----------------------------------------------------------------------
    // #424 (MISS 2 from #407's module doc, "letter-first" runas `#`-GID):
    // `strip_inline_comment`'s Exception-2 gate requires BOTH `prev_allows_uid`
    // AND `next_is_digit` before it treats a `#` as a UID/GID token rather than a
    // real comment. The #407 fix above widened `prev_allows_uid` to include `:` /
    // `(` (so the DIGIT-first `(root:#1000abc)` / `(#1000abc)` shapes survive the
    // strip and reach `check_runas`'s GID-tail check). But a LETTER-first shape --
    // `#abc`, no digits at all after the `#` -- still fails `next_is_digit`
    // regardless of that widening, so the `#` is STILL misread as a real comment
    // and swallows the rest of the physical line (the closing paren AND the real
    // command). `check_runas` never even runs on the malformed token: RuleSteward's
    // own line/user-spec parser is lenient about the resulting unbalanced `(root:`
    // remainder (unlike visudo, which correctly reports a syntax error for it), so
    // it silently folds to a clean-looking `CmndSpec` -- ZERO diagnostics for a
    // file `visudo -c` rejects (rc=1). Distinct root cause from the digit-first
    // case: there the `#` DOES survive the strip and `is_malformed_gid_tail`
    // catches the non-digit tail; here the `#` never survives the strip at all,
    // so `check_runas` has nothing to inspect.
    //
    // Oracle grounding (`visudo -c -f`, sudo 1.9.17p2, verified 2026-07-04; every
    // file is `root ALL=(ALL:ALL) ALL` + the probed line):
    //   alice ALL = (root:#abc) /bin/su -> rc=1 (syntax error, caret on `#abc`)
    //   alice ALL = (#abc) /bin/su      -> rc=1 (syntax error, caret on `#abc`)
    // -----------------------------------------------------------------------

    /// `alice ALL = (root:#abc) /bin/su` -- runas-GROUP (post-colon) letter-first
    /// `#`-GID token: NO digits at all after the `#`.
    ///
    /// RED today: `strip_inline_comment` fails `next_is_digit` for `#abc`
    /// (`a` is not a digit) and swallows `#abc) /bin/su` as a comment, leaving
    /// `alice ALL = (root:` -- an unbalanced-paren remainder `RuleSteward`'s own
    /// parser folds into a clean spec, never invoking `check_runas` on the
    /// malformed token. Zero diagnostics for a `visudo -c`-rejected file.
    #[test]
    fn f02_runas_group_letter_first_hash_fires() {
        // Fixture: visudo -c -f rc=1, syntax error at `#abc` (col 17).
        // Verified locally: sudo/visudo 1.9.17p2, 2026-07-04.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:#abc) /bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(root:#abc)` runas-group (letter-first `#`, no digits at all) is \
             visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = (#abc) /bin/su` -- the BARE (no `%`, no colon) runas-USER
    /// letter-first form. Same root cause as the runas-GROUP case above, applied
    /// to the bare (non-`%`) `runas.users` position (#407's other widened arm).
    #[test]
    fn f02_runas_user_bare_letter_first_hash_fires() {
        // Fixture: visudo -c -f rc=1, syntax error at `#abc` (col 12).
        // Verified locally: sudo/visudo 1.9.17p2, 2026-07-04.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (#abc) /bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(#abc)` bare runas-user (letter-first `#`, no digits at all) is \
             visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// REGRESSION GUARD (#424 must not break #407): the DIGIT-first
    /// `(root:#1000abc)` form (already fixed by #407, see
    /// `f02_runas_group_gid_form_digits_then_letters_fires` above) must STILL
    /// fire exactly one F02 after any fix for the letter-first shape. A fix that
    /// replaces (rather than extends) the digit-gated exception -- e.g. widening
    /// `next_is_digit` into "any non-whitespace char" globally -- would also
    /// misread ordinary inline comments as UID/GID tokens; re-asserting this
    /// specific #407 case here keeps the #424 section self-contained regression
    /// evidence. GREEN now, must stay GREEN.
    #[test]
    fn f02_runas_group_digit_first_hash_still_fires_after_424() {
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = (root:#1000abc) /bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "digit-first `(root:#1000abc)` (#407) must still fire exactly one F02 \
             after any letter-first (#424) fix; got {diags:?}"
        );
    }

    /// #424 Round 2 (mutation-survivor coverage, F02-observable): a letter-first
    /// `(root:#abc)` runas group as the SECOND spec of a comma-separated
    /// `Cmnd_Spec_List` -- `alice ALL = /bin/ls, (root:#abc) /bin/su`. The runas
    /// `(` here is preceded by the `,` command-list separator (not `=`), so its
    /// `#abc` token survives the strip only because `paren_opens_runas` classifies
    /// a `,`-preceded `(` as a runas open. `visudo -c` rc=1 (caret on `#abc`), and
    /// F02 must fire exactly once on the malformed runas group.
    ///
    /// Kills the line-334 `bytes[j] == b',' -> !=` mutant in `paren_opens_runas`:
    /// under that mutant a `,`-preceded `(` returns false (`,` != `,` is false, `,`
    /// != `=`... clean returns true), so `in_runas_paren` is never set here, the
    /// `#abc` is stripped as a comment, the malformed token vanishes, and F02 goes
    /// silent (count 0). The `,`-preceded runas open is the arm no earlier test
    /// (all `=`-preceded) exercised.
    #[test]
    fn f02_runas_group_after_comma_letter_first_hash_fires() {
        // Oracle: visudo -c -f rc=1, "syntax error" caret on `#abc` (col 24).
        // Verified locally: sudo/visudo 1.9.17p2, 2026-07-04.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls, (root:#abc) /bin/su\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`(root:#abc)` as the 2nd (comma-separated) spec has a letter-first \
             malformed runas group (visudo rc=1) and must fire exactly one F02; the \
             `,`-preceded runas open must be recognized; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    // --- Shape 2: lone `!` command with no path -----------------------------

    /// `alice ALL = !` -- issue #375's literal example: a bare negation with no
    /// command to negate.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the `!` (col 14). The parser
    /// keeps this as `CmndItem::Cmnd("!")` (an ordinary command token whose
    /// content happens to be exactly `"!"`), so today's Case-3 relative-path
    /// check does not fire (`"!".trim_start_matches('!')` is `""`, which
    /// contains no `/`) and no other case matches it either -- F02 is silent.
    #[test]
    fn f02_lone_bang_command_no_path_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the bare `!`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = !\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a lone `!` command with no path is visudo-rejected and must fire exactly \
             one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = /bin/ls, !` -- a lone trailing `!` after a comma-separated
    /// valid command. Only the SECOND `Cmnd_Spec` (`!` alone) is malformed.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at the trailing `!` (col 23).
    /// `split_cmnd_specs` produces two `CmndSpec`s: `/bin/ls` (valid) and `!`
    /// (the lone-bang defect). F02 must fire once (only for the second).
    #[test]
    fn f02_lone_bang_after_comma_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at the trailing lone `!`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls, !\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a lone trailing `!` command in a comma list must fire exactly one F02 \
             (the valid `/bin/ls` sibling must not); got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `alice ALL = !ALL` -- negated `ALL` is a DIFFERENT, VALID construct; must
    /// NOT be conflated with the lone-bang-no-command defect above.
    ///
    /// Oracle: `visudo -cf` rc=0, "parsed OK". Source-verified AST shape
    /// (`parse_cmnd_spec`, parser.rs): the command token is the full string
    /// `"!ALL"`, and the `cmnd_token == "ALL"` reserved-word check compares that
    /// FULL string (`"!ALL" != "ALL"`), so this becomes `CmndItem::Cmnd("!ALL")`
    /// -- the leading `!` is kept verbatim (ast.rs `CmndItem::Cmnd` doc) -- NOT
    /// `CmndItem::All`. That makes this a sharp guard for the lone-`!` check: an
    /// over-broad impl keyed on `token.starts_with('!')` would WRONGLY fire on
    /// `Cmnd("!ALL")`, so the implementer must key the lone-bang defect off the
    /// EXACT token `"!"`, not a `!` prefix.
    #[test]
    fn f02_bang_negated_all_no_f02() {
        // Fixture: visudo -cf rc=0, "parsed OK".
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\nalice ALL = !ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`!ALL` is a valid negated-ALL command, distinct from a lone `!` -- must \
             NOT fire F02; got {f02_diags:?}"
        );
    }

    // --- Shape 3: `%#<digits><non-digit>` GID-then-letters form -------------

    /// `%#1000abc ALL = ALL` -- issue #375's literal example: a digit run
    /// immediately followed by letters, with no Case-4 denylist char present.
    ///
    /// Oracle: `visudo -cf` rc=1, "syntax error" at `abc` (col 11). `is_pure_gid`
    /// is already `false` for `#1000abc` (the rest is not all-digit), so the
    /// existing denylist WOULD run -- but `abc` contains none of
    /// `{! ( ) > "}`, so F02 stays silent today. This is a distinct
    /// GID-structural-validation gap (module doc already calls it out: "a
    /// separate gap"), not a denylist-char miss.
    #[test]
    fn f02_gid_form_digits_then_letters_fires() {
        // Fixture: visudo -cf rc=1, "syntax error" at `abc` in `%#1000abc`.
        // Verified locally: visudo 1.9.17p2, 2026-07-02.
        let diags = lint("root ALL=(ALL:ALL) ALL\n%#1000abc ALL = ALL\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`%#1000abc` (digit run followed by letters, no denylist char) is \
             visudo-rejected and must fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `%#abc ALL = ALL` -- a `%#` immediately followed by a non-digit (zero
    /// leading digits). visudo-rejected, but it is an F01 (parse-failure) case,
    /// NOT an F02 (clean-spec defect) case -- the crucial distinction from the
    /// `%#1000abc` shape above.
    ///
    /// Why this is F01 not F02 (source-verified, `strip_inline_comment`,
    /// parser.rs Exception 2): the `#` in `%#abc` is preceded by `%` (a
    /// UID/GID-allowing position) but is NOT followed by a digit (`a`). So the
    /// stripper treats it as a genuine inline comment and drops everything from
    /// the `#` onward, collapsing the subject token to a bare `%`. A lone `%`
    /// group with no name fails to parse -> `LineKind::Malformed` -> sudo-F01
    /// (the anchored parse error from #382, present on this session branch).
    /// It therefore never reaches F02 as a clean spec.
    ///
    /// Contrast `%#1000abc`: there the `#` IS followed by a digit (`1`), so the
    /// stripper keeps `#1000abc`, the line parses to a clean `UserSpec` with
    /// `users = ["%#1000abc"]`, and F02's GID-structural check is what must fire.
    /// The digit-run-then-letters shape is a clean-spec F02 defect; the
    /// no-digit-run shape is an F01 parse failure.
    ///
    /// Oracle: `visudo -cf` on `%#abc ALL = ALL` is rc=1 "empty group" (a parse
    /// error), consistent with the F01 classification. Verified locally: visudo
    /// 1.9.17p2, 2026-07-02.
    #[test]
    fn f02_gid_form_hash_then_letters_only_is_f01_not_f02() {
        let src = "root ALL=(ALL:ALL) ALL\n%#abc ALL = ALL\n";
        // The `%#abc` line collapses to `%` (inline-comment strip) -> Malformed
        // -> sudo-F01 must fire on it.
        let f01_diags: Vec<_> = lint_f01(src)
            .into_iter()
            .filter(|d| d.code == "sudo-F01")
            .collect();
        assert_eq!(
            f01_diags.len(),
            1,
            "`%#abc` collapses to a bare `%` (# not followed by a digit) and must fire \
             exactly one sudo-F01 parse error; got {f01_diags:?}"
        );
        assert_eq!(f01_diags[0].severity, rulesteward_core::Severity::Fatal);
        // And it must NOT be double-reported as an F02 clean-spec defect.
        let f02_diags: Vec<_> = lint(src)
            .into_iter()
            .filter(|d| d.code == "sudo-F02")
            .collect();
        assert!(
            f02_diags.is_empty(),
            "`%#abc` is an F01 parse failure, not an F02 clean-spec defect -- F02 must \
             stay silent to avoid double-reporting; got {f02_diags:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Issue #423 (HIGH FALSE POSITIVE): `has_hash_digits` is QUOTE-BLIND.
    //
    // A `#<digits>` preceded by whitespace / start-of-string / `%` that falls
    // INSIDE a DOUBLE-QUOTED Defaults value is a literal string character
    // (`visudo -c` rc=0, VALID) -- NOT a UID/GID token -- yet the quote-blind
    // `has_hash_digits` reports it and F02 fires a user-facing FALSE POSITIVE on
    // a config `visudo -c` accepts. The `has_hash_digits` doc comment already
    // flags this as the tracked high-priority follow-up (see its rustdoc above).
    //
    // Root cause confirmed against the parser (parse_one_default_setting,
    // parser.rs): for `passprompt="Enter #5 now"` the surrounding double quotes
    // are stripped and the value is stored as `Enter #5 now` -- BYTE-IDENTICAL
    // to the UNQUOTED `passprompt=Enter #5 now`. So the current AST cannot tell
    // the visudo-VALID quoted form from the visudo-INVALID unquoted form; the
    // fix must carry the quoted/unquoted distinction through the AST. That HOW
    // is the implementer's decision; these tests only pin the observable
    // behavior.
    //
    // The fix must NOT weaken any of:
    //   - the UNQUOTED `#<digits>` Defaults-value defect (still visudo rc=1);
    //   - the SINGLE-quoted form -- sudoers treats ONLY `"` as a value
    //     delimiter, so a `'` is a literal char and a `#<digits>` after a space
    //     inside `'...'` is still a comment-start -> visudo rc=1
    //     (strip_inline_comment, parser.rs, only toggles on `"`);
    //   - a `#<digits>` OUTSIDE the quoted region on a value that DOES contain a
    //     quoted span (forces quote-REGION awareness, not "value contains a
    //     quote -> skip");
    //   - the command-position `has_hash_digits` check (same fn, other caller);
    //   - the #407 GID-position validation (runas / Defaults scope `#`-GID
    //     tails), which flows through `is_malformed_gid_tail`, a DISTINCT code
    //     path from `has_hash_digits`.
    //
    // Oracle grounding (`visudo -c -f <file>`, sudo 1.9.17p2, verified
    // 2026-07-04; every file is a valid `root ALL=(ALL:ALL) ALL` line + the
    // probed line):
    //   Defaults passprompt="Enter #5 now"       -> rc=0  (VALID; issue repro)
    //   Defaults badpass_message="try #5, again" -> rc=0  (VALID; issue repro,
    //                                                      comma is inside quotes)
    //   Defaults passprompt="#5"                  -> rc=0  (VALID; bare, quoted)
    //   Defaults passprompt=Enter #5 now          -> rc=1  (INVALID; unquoted)
    //   Defaults passprompt='Enter #5 now'        -> rc=1  (INVALID; single quote
    //                                                      is NOT a delimiter)
    //   Defaults passprompt=x #1000abc            -> rc=1  (INVALID; unquoted,
    //                                                      digit run + letters)
    //   Defaults passprompt="hi" #5               -> rc=1  (INVALID; the `#5` is
    //                                                      OUTSIDE the closing
    //                                                      quote -> unquoted tail)
    //   alice ALL = /bin/ls #2                     -> rc=1 (INVALID; command pos)
    //   alice ALL = (root:#1000abc) /bin/ls        -> rc=1 (INVALID; #407 tail)
    //   alice ALL = (root:#1000) /bin/ls           -> rc=0 (VALID;   #407 pure)
    //   Defaults:#1000abc !lecture                 -> rc=1 (INVALID; #407 tail)
    //   Defaults:#1000 !lecture                    -> rc=0 (VALID;   #407 pure)
    // -----------------------------------------------------------------------

    // --- FP core (RED against current code: currently fire, must go silent) ---

    /// FP CORE (issue #423, issue repro 1): `Defaults passprompt="Enter #5 now"`
    /// -- a `#5` inside a DOUBLE-QUOTED string value. `visudo -c` rc=0 (VALID).
    /// The quote-blind `has_hash_digits` sees the stored value `Enter #5 now`
    /// (quotes stripped by `parse_one_default_setting`) and fires a FALSE
    /// POSITIVE. After the fix F02 must be SILENT. RED now (fires 1), GREEN after.
    #[test]
    fn f02_issue423_quoted_hash_digits_in_passprompt_no_f02() {
        // Oracle: `visudo -c -f` rc=0 "parsed OK". Verified 2026-07-04, sudo 1.9.17p2.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"Enter #5 now\"\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`#5` inside a double-quoted Defaults value is visudo-valid (rc=0) -- F02 \
             must NOT fire (issue #423 quote-blind false positive); got {f02_diags:?}"
        );
    }

    /// FP CORE (issue #423, issue repro 2): `Defaults badpass_message="try #5,
    /// again"` -- the `#5` and the comma both sit inside the double quotes.
    /// `visudo -c` rc=0 (VALID; the quoted comma does not split the value). The
    /// quote-blind `has_hash_digits` sees `try #5, again` and fires a FALSE
    /// POSITIVE. After the fix F02 must be SILENT. RED now (fires 1), GREEN after.
    #[test]
    fn f02_issue423_quoted_hash_digits_in_badpass_message_no_f02() {
        // Oracle: `visudo -c -f` rc=0 "parsed OK". Verified 2026-07-04, sudo 1.9.17p2.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults badpass_message=\"try #5, again\"\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`#5` inside a double-quoted Defaults value (with a quoted comma) is \
             visudo-valid (rc=0) -- F02 must NOT fire (issue #423); got {f02_diags:?}"
        );
    }

    /// FP CORE (issue #423): `Defaults passprompt="#5"` -- a bare `#5` as the
    /// whole double-quoted value. `visudo -c` rc=0 (VALID). The value is stored
    /// as `#5` (quotes stripped); `has_hash_digits` fires on the start-of-string
    /// `#5`. After the fix F02 must be SILENT. RED now (fires 1), GREEN after.
    #[test]
    fn f02_issue423_bare_quoted_hash_digits_no_f02() {
        // Oracle: `visudo -c -f` rc=0 "parsed OK". Verified 2026-07-04, sudo 1.9.17p2.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"#5\"\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "a bare `#5` as a whole double-quoted Defaults value is visudo-valid \
             (rc=0) -- F02 must NOT fire (issue #423); got {f02_diags:?}"
        );
    }

    /// FP CORE (issue #423, symmetric `%`-arm case): `Defaults passprompt="x %#2"`
    /// -- a `#2` preceded by `%` INSIDE a double-quoted string value. `visudo -c`
    /// rc=0 (VALID). The quote-blind `has_hash_digits` `%`-arm sees the stored
    /// value `x %#2` (quotes stripped) and fires a FALSE POSITIVE. After the fix
    /// F02 must be SILENT. RED now (fires 1), GREEN after. Mirrors the
    /// whitespace-preceded FP cores across the independently-load-bearing `%` arm.
    #[test]
    fn f02_issue423_quoted_pct_hash_digits_no_f02() {
        // Oracle: `visudo -c -f` rc=0 "parsed OK". Verified 2026-07-04, sudo 1.9.17p2.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"x %#2\"\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`%#2` inside a double-quoted Defaults value is visudo-valid (rc=0) -- \
             F02 must NOT fire (issue #423, `%` preceding-char arm); got {f02_diags:?}"
        );
    }

    // --- Regression guards (GREEN before AND after: the fix must not weaken) ---

    /// REGRESSION GUARD (#423, the sharp pairing): the UNQUOTED sibling
    /// `Defaults passprompt=Enter #5 now` is `visudo -c` rc=1 (INVALID) -- F02
    /// must STILL fire. This value is stored BYTE-IDENTICALLY to the quoted FP
    /// core above (`Enter #5 now`), so making the quoted form silent WITHOUT
    /// silencing this one is exactly what forces the AST to carry the quote
    /// distinction. A naive "skip all `#` in Defaults values" fix breaks this.
    /// GREEN now (fires 1), must stay GREEN.
    #[test]
    fn f02_issue423_unquoted_hash_digits_in_defaults_value_still_fires() {
        // Oracle: `visudo -c -f` rc=1 ("Success" quirk position). Verified 2026-07-04.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=Enter #5 now\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "an UNQUOTED `#5` in a Defaults value is visudo-rejected (rc=1) and must \
             STILL fire exactly one F02 -- the #423 fix must be quote-REGION-aware, \
             not skip all `#`; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// REGRESSION GUARD (#423, sharp adversarial): `Defaults passprompt='Enter #5
    /// now'` -- sudoers treats ONLY `"` as a value delimiter; a single quote is a
    /// LITERAL char, so `#5` after a space is still a comment-start and `visudo
    /// -c` REJECTS the line (rc=1). F02 must STILL fire. A fix that treats `'` (or
    /// "any quote") as a protecting delimiter would WRONGLY silence this. The
    /// value is stored WITH the single quotes (`parse_one_default_setting` only
    /// strips a surrounding `"` pair). GREEN now (fires 1), must stay GREEN.
    #[test]
    fn f02_issue423_single_quoted_hash_digits_still_fires() {
        // Oracle: `visudo -c -f` rc=1 (single quote is not a delimiter). Verified 2026-07-04.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt='Enter #5 now'\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a SINGLE-quoted `#5` is visudo-rejected (rc=1; sudoers only treats `\"` as \
             a delimiter) and must STILL fire F02 -- the fix must not treat `'` as a \
             protecting quote; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// REGRESSION GUARD (#423, the task's naive-fix example): an UNQUOTED
    /// `#1000abc` in a Defaults value (`Defaults passprompt=x #1000abc`) is
    /// `visudo -c` rc=1 (INVALID). The value reaches `has_hash_digits` as
    /// `x #1000abc`; `#1000` (a `#` + a digit run after the space) matches
    /// regardless of the `abc` tail. F02 must STILL fire. A "skip all `#` in
    /// Defaults" fix would silence this. GREEN now (fires 1), must stay GREEN.
    #[test]
    fn f02_issue423_unquoted_hash_digits_then_letters_still_fires() {
        // Oracle: `visudo -c -f` rc=1. Verified 2026-07-04, sudo 1.9.17p2.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=x #1000abc\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "an UNQUOTED `#1000abc` in a Defaults value is visudo-rejected (rc=1) and \
             must STILL fire exactly one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// REGRESSION GUARD (#423, forces quote-REGION awareness): `Defaults
    /// passprompt="hi" #5` -- the `#5` sits OUTSIDE the closing double quote (it
    /// is in the unquoted tail), so `visudo -c` REJECTS the line (rc=1). Because
    /// `"hi" #5` is not a clean surrounding-quote pair, `parse_one_default_setting`
    /// keeps the value verbatim (`"hi" #5`) and `has_hash_digits` fires on the
    /// whitespace-preceded `#5`. F02 must STILL fire. A coarse "the value contains
    /// a `\"` -> skip `has_hash_digits`" fix would WRONGLY silence this; only a fix
    /// that tracks WHICH region the `#5` falls in keeps it firing. GREEN now
    /// (fires 1), must stay GREEN.
    #[test]
    fn f02_issue423_hash_digits_after_closing_quote_still_fires() {
        // Oracle: `visudo -c -f` rc=1 (the `#5` is outside the quoted span). Verified 2026-07-04.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"hi\" #5\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "a `#5` OUTSIDE the closing quote (unquoted tail) on a value that also has \
             a quoted span is visudo-rejected (rc=1) and must STILL fire F02 -- the fix \
             must be quote-REGION-aware, not skip any value containing a quote; got \
             {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// REGRESSION GUARD (#423): `has_hash_digits` is ALSO called on COMMAND
    /// tokens. A quote-awareness change to the Defaults-value path must not weaken
    /// the command-position check: `alice ALL = /bin/ls #2` is `visudo -c` rc=1
    /// and must STILL fire F02. GREEN now (fires 1), must stay GREEN.
    #[test]
    fn f02_issue423_command_position_hash_digits_still_fires() {
        // Oracle: `visudo -c -f` rc=1 (syntax error at `#2`). Verified 2026-06-30 / 2026-07-04.
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nalice ALL = /bin/ls #2\n"),
            1,
            "the command-position `#2` check (a separate `has_hash_digits` caller) must \
             still fire F02 after the #423 Defaults-value fix"
        );
    }

    /// REGRESSION GUARD (#423 must not touch #407): the `#`-GID position checks
    /// flow through `is_malformed_gid_tail`, a DISTINCT code path from
    /// `has_hash_digits`, so a quote-awareness fix to `has_hash_digits` must leave
    /// them exactly as-is. Malformed `#`-GID tails still fire; valid pure
    /// `#<digits>` GIDs stay clean. All four grounded (`visudo -c -f`, sudo
    /// 1.9.17p2, 2026-07-04): runas group `(root:#1000abc)` rc=1 /
    /// `(root:#1000)` rc=0; Defaults user-scope `:#1000abc` rc=1 / `:#1000` rc=0.
    /// GREEN now, must stay GREEN.
    #[test]
    fn f02_issue423_407_gid_validation_unchanged() {
        // Malformed `#`-GID tails must still fire (visudo rc=1).
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nalice ALL = (root:#1000abc) /bin/ls\n"),
            1,
            "#407 runas-group `#1000abc` tail (is_malformed_gid_tail path) must still \
             fire F02"
        );
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nDefaults:#1000abc !lecture\n"),
            1,
            "#407 Defaults user-scope `#1000abc` tail must still fire F02"
        );
        // Valid pure `#<digits>` GIDs must stay clean (visudo rc=0).
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nalice ALL = (root:#1000) /bin/ls\n"),
            0,
            "#407 valid pure-GID runas group `#1000` must NOT fire F02"
        );
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nDefaults:#1000 !lecture\n"),
            0,
            "#407 valid pure-GID Defaults user-scope `#1000` must NOT fire F02"
        );
    }

    /// STRENGTHENING (issue #423, impl-aware adversarial review): a `#<digits>`
    /// in an UNQUOTED GAP between TWO separate double-quoted regions. The value
    /// `"a" #5 "b"` starts AND ends with `"`, so a naive clean-pair strip
    /// (`strip_prefix('"').and_then(strip_suffix('"'))`) wrongly treats it as one
    /// quoted region and silences F02 -- but `visudo -c` rc=1 (INVALID): a
    /// Defaults value is a single token, so anything after the first closing
    /// quote breaks the grammar. The `#5` is genuinely unquoted -> F02 must fire.
    /// Forces true region-tracking (interior must have no UNESCAPED `"`), not a
    /// start+end-quote check. RED against the first #423 fix; GREEN after narrowing.
    #[test]
    fn f02_issue423_unquoted_hash_between_two_quoted_regions_still_fires() {
        // Oracle: `visudo -c -f` rc=1 (INVALID). Verified 2026-07-04, sudo 1.9.17p2.
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"a\" #5 \"b\"\n"),
            1,
            "`#5` in an unquoted gap between two quoted regions (visudo rc=1) must \
             STILL fire F02 -- the value is not one clean quoted region"
        );
    }

    /// REGRESSION GUARD (issue #423, bounds the region-tracking fix): a value with
    /// an ESCAPED inner quote (`"a\" #5 b"`) IS one clean quoted region --
    /// `visudo -c` rc=0 (VALID), the `#5` is a literal inside the string. F02 must
    /// STAY SILENT. Excludes a lazy over-correction that fires on ANY interior `"`
    /// (which would wrongly flag this valid escaped-quote value). GREEN before AND
    /// after the fix.
    #[test]
    fn f02_issue423_escaped_inner_quote_one_region_stays_silent() {
        // Oracle: `visudo -c -f` rc=0 (VALID; escaped inner quote). Verified
        // 2026-07-04, sudo 1.9.17p2.
        assert_eq!(
            f02_count("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"a\\\" #5 b\"\n"),
            0,
            "an ESCAPED inner quote keeps the value one clean quoted region \
             (visudo rc=0) -- F02 must NOT fire (do not over-correct on interior \
             escaped quotes)"
        );
    }

    // -----------------------------------------------------------------------
    // #424 (parked from #423's impl-aware review): a `#<digits>` GLUED (no
    // whitespace) immediately after a Defaults value's CLOSING double quote.
    //
    // Distinct root cause from every #423 case above: those are all downstream of
    // `parse_one_default_setting` / `value_double_quoted` (the value already
    // reached the parser with the `#` intact, and #423's fix decides whether to
    // scan it). Here the defect is EARLIER, in `strip_inline_comment` itself
    // (parser.rs): its Exception-2 `prev_allows_uid` set allows `,` / `%` / `:` /
    // `(` / `>` / `@` / whitespace / start before a `#<digits>` token, but NOT `"`
    // (a closing double quote). So `Defaults passprompt="a"#5` never reaches
    // `parse_one_default_setting` with the `#5` intact at all -- the `#`
    // (preceded by `"`, not in the allowed set) is misread as a REAL comment and
    // the whole `#5` is stripped before parsing, leaving a clean
    // `Defaults passprompt="a"` (`value_double_quoted=true`, value `"a"`). Zero
    // diagnostics for a file `visudo -c` rejects (rc=1): the `#5` is a genuinely
    // invalid token OUTSIDE the quote, not a comment.
    //
    // Contrast (must stay silent): `Defaults passprompt="a"#foo` (visudo rc=0) IS
    // a real trailing comment -- `strip_inline_comment`'s `next_is_digit` gate
    // already excludes it (no digit immediately after `#`), so this shape never
    // reaches the digit-token exception at all, regardless of any `"` fix.
    //
    // Oracle grounding (`visudo -c -f`, sudo 1.9.17p2, verified 2026-07-04; every
    // file is `root ALL=(ALL:ALL) ALL` + the probed line):
    //   Defaults passprompt="a"#5   -> rc=1 (INVALID; caret on `#5`, "Success" quirk)
    //   Defaults passprompt="a"#5x  -> rc=1 (INVALID; same caret position)
    //   Defaults passprompt="a"#foo -> rc=0 (VALID; a real trailing comment)
    // -----------------------------------------------------------------------

    /// `Defaults passprompt="a"#5` -- a `#<digits>` glued directly to a closing
    /// double quote, no whitespace. RED today: `strip_inline_comment` misreads
    /// the `#5` as a real comment (its `prev_allows_uid` set omits `"`) and drops
    /// it before the value ever reaches `has_hash_digits`, so F02 stays silent.
    #[test]
    fn f02_issue424_hash_digits_glued_after_closing_quote_fires() {
        // Fixture: visudo -c -f rc=1, caret on `#5` ("Success" quirk position).
        // Verified locally: sudo/visudo 1.9.17p2, 2026-07-04.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"a\"#5\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`passprompt=\"a\"#5` (a `#<digits>` glued directly after the closing \
             quote, no whitespace) is visudo-rejected (rc=1) and must fire exactly \
             one F02; got {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// `Defaults passprompt="a"#5x` -- same glued shape, digit run followed by a
    /// letter. `visudo -c -f` rc=1 (INVALID), same as the pure-digit form above:
    /// visudo's lexer treats the glued `#5x` as one invalid token regardless of
    /// what follows the leading digit. Must ALSO fire F02 -- a fix scoped to
    /// "exactly `#<digits>` with nothing after" would wrongly leave this one
    /// silent.
    #[test]
    fn f02_issue424_hash_digits_then_letters_glued_after_closing_quote_fires() {
        // Fixture: visudo -c -f rc=1, caret on `#5x`. Verified locally:
        // sudo/visudo 1.9.17p2, 2026-07-04.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"a\"#5x\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert_eq!(
            f02_diags.len(),
            1,
            "`passprompt=\"a\"#5x` (glued digit-then-letter tail after the closing \
             quote) is visudo-rejected (rc=1) and must fire exactly one F02; got \
             {diags:?}"
        );
        assert_eq!(f02_diags[0].severity, rulesteward_core::Severity::Fatal);
    }

    /// GUARD (must stay silent): `Defaults passprompt="a"#foo` -- a REAL trailing
    /// comment glued to the closing quote (no digit immediately after `#`).
    /// `visudo -c -f` rc=0 (VALID). Blocks an over-fix that treats ANY `#` glued
    /// after a closing quote as invalid: the `next_is_digit` gate must still
    /// distinguish a real comment (`#foo`) from an invalid glued token (`#5`).
    /// GREEN now, must stay GREEN.
    #[test]
    fn f02_issue424_hash_comment_glued_after_closing_quote_stays_silent() {
        // Fixture: visudo -c -f rc=0 "parsed OK". Verified locally: sudo/visudo
        // 1.9.17p2, 2026-07-04.
        let diags = lint("root ALL=(ALL:ALL) ALL\nDefaults passprompt=\"a\"#foo\n");
        let f02_diags: Vec<_> = diags.iter().filter(|d| d.code == "sudo-F02").collect();
        assert!(
            f02_diags.is_empty(),
            "`passprompt=\"a\"#foo` is a real trailing comment glued to the closing \
             quote (visudo rc=0, no digit after `#`) -- must NOT fire F02; got \
             {f02_diags:?}"
        );
    }
}
