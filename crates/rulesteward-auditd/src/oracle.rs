//! Differential-oracle adapter for the `auditd` backend (session 9k-1).
//!
//! This module is the product side of the Tier-1 replay test described in
//! `CONTRIBUTING.md` "Differential oracle contract". It exists so
//! `crates/rulesteward-auditd/tests/auditd_corpus_oracle.rs` can compare what
//! `RuleSteward` says about one physical `audit.rules` line against what the REAL
//! `auditctl -R` said about that same line, recorded in the committed corpus
//! under `tests/corpus/auditd-oracle/`.
//!
//! # This is an ADAPTER, not a second parser
//!
//! [`product_verdict`] MUST delegate to [`crate::parser::parse_rules_str`], the
//! exact entry point the CLI takes, and MUST NOT contain rule-specific logic.
//! A differential whose product side reimplements the grammar is
//! self-referential: it proves the reimplementation agrees with the corpus and
//! says nothing about the parser an administrator actually runs. The mechanical
//! guard is one grep - this file must never `use crate::ast::`. If it needs to
//! inspect the AST to reach a verdict, it has stopped being an adapter.
//!
//! The adapter deliberately sits over the PARSER only, never the lints. Some
//! divergences this test finds are caught downstream by `au-E02`/`E04`/`E05`;
//! conflating parse with lint would let a lint mask a parser bug. Each XFAIL
//! entry in the test states whether it is covered elsewhere or is a genuine
//! blind spot, which turns that list into a triaged defect register rather than
//! a suppression list.
//!
//! # Why the capture side classifies here and not in bash
//!
//! `tests/corpus/auditd-oracle/capture_auditd.sh` records raw facts only:
//! the rule line, the exit code, and both output streams, verbatim. It makes no
//! verdict. [`classify_capture`] turns those raw facts into an oracle verdict,
//! which puts the one piece of logic that decides "did the daemon accept this?"
//! under `cargo test`, `clippy`, the coverage floor and the mutation gate. The
//! first draft of this lane put that decision in an untested `grep -qF` inside
//! the capture script, and it silently recorded `-D` - the first line of
//! essentially every real `audit.rules` file - as a parse REJECT.

/// `RuleSteward`'s answer for one physical `audit.rules` line.
///
/// The derives are load-bearing: the replay test compares, debug-prints and
/// copies these values when reporting a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `RuleSteward` parses the line without error.
    Accept,
    /// `RuleSteward` refuses the line.
    Reject,
}

/// The real `auditctl -R` answer for one line, recovered from the raw capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureVerdict {
    /// `auditctl` parsed the line and got as far as the netlink send, which the
    /// unprivileged capture container refuses. Parsing succeeded.
    Accept,
    /// `auditctl` refused the line, naming `complaint` as the diagnostic that
    /// proves it got far enough to object to the CONTENT.
    Reject {
        /// The matched entry from the capture-grounded complaint table.
        complaint: &'static str,
    },
    /// The capture cannot support any verdict for this line. Kept in the corpus
    /// rather than dropped: deleting the row would destroy the artifact proving
    /// the blind spot exists, and would hide a future `auditctl` change that
    /// starts diagnosing the line.
    Unusable(Unusable),
}

/// Why a captured row cannot yield an oracle verdict.
///
/// Only [`Unusable::SilentNonAddLine`] and [`Unusable::SandboxLimited`] are ever
/// tolerated, and then only for an id on the test's named `UNOBSERVABLE` table.
/// The other three indicate the capture environment itself was wrong and must
/// fail the run outright, with no allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// `rc == 4`: `auditctl` bailed before parsing because the container lacks
    /// `CAP_AUDIT_CONTROL`. A valid and an invalid rule are byte-identical here.
    /// The capture must abort with rc 2.
    NoCapability,
    /// `rc == 0`: the rule LOADED, which means audit netlink is live and the
    /// capture just mutated the HOST ruleset. The capture must abort with rc 2.
    Loaded,
    /// rc 1 with both streams empty, for a line whose LEADING flag IS on the
    /// [`SILENT_SUCCESS_LEADING_FLAGS`] list (i.e. [`silence_is_conclusive`]
    /// returns `false` for it): a control op (`-D`, `-b`, ...) whose SUCCESS
    /// path is just as silent as a genuine parse refusal, so this rc-1-silent
    /// capture cannot be attributed to either outcome. This is the historical
    /// bug this module exists to fix: a first draft treated every silent `-D`
    /// as REJECT, which is exactly the case this variant refuses to guess at.
    SilentNonAddLine,
    /// A diagnostic that reports a container limitation rather than a property
    /// of the rule (for example a kernel feature bitmap read over the same
    /// netlink that is being denied).
    SandboxLimited,
    /// rc 1 with non-empty output that matches no known table entry. A hard
    /// failure: a new `auditctl` diagnostic must never be absorbed silently.
    UnrecognisedDiagnostic,
    /// An exit code outside `{0, 1, 4}`.
    UnexpectedRc,
}

/// `RuleSteward`'s verdict for one already comment-stripped, trimmed physical
/// `audit.rules` line.
///
/// Delegates to [`crate::parser::parse_rules_str`] and nothing else. The
/// "exactly one rule" condition is load-bearing: `StripConfig::AUDITD` comment
/// stripping makes a line that vanishes entirely return `Ok(vec![])`, which is
/// not an accept of the original line.
#[must_use]
pub fn product_verdict(line: &str) -> Verdict {
    match crate::parser::parse_rules_str(line) {
        Ok(rules) if rules.len() == 1 => Verdict::Accept,
        // Comment-stripped to nothing (`Ok(vec![])`), defensively more than
        // one rule from a single physical line, or a parse error: none of
        // these is an accept of the original line.
        _ => Verdict::Reject,
    }
}

/// Recovers the real `auditctl -R` verdict from one row of raw captured facts.
///
/// `line` is required because the raw facts alone are ambiguous: `(rc=1, "",
/// "")` is produced identically by `-D` (parsed, then the netlink send failed
/// silently inside `setopt()`) and by a genuinely refused rule. No pure function
/// of `(rc, stdout, stderr)` can separate those two, so the flag is consulted
/// through [`silence_is_conclusive`]: silence is conclusive evidence of a parse
/// REFUSAL only for an add-shaped line (`-w`/`-a`), because a successfully
/// PARSED add-shaped line is always LOUD under this sandbox (it reaches the
/// `audit_add_rule_data` netlink call and prints `Error sending add rule data
/// request`, caught by the accept probe below before this ever runs). A
/// control-shaped line (`-D`/`-b`/...) is silent on EITHER outcome, so its
/// silence proves nothing and must fall through to
/// [`Unusable::SilentNonAddLine`] instead of being called a refusal. Getting
/// this backwards is exactly the historical bug this module exists to fix: a
/// first draft treated every silent `-D` as REJECT.
///
/// The evaluation order is load-bearing. In particular, the accept probe must
/// precede the parse-complaint probe, because an accepted line's stderr ALSO
/// carries the companion string `There was an error in line 1 of <file>`; that
/// companion must never enter the complaint table.
#[must_use]
pub fn classify_capture(line: &str, rc: i32, stdout: &str, stderr: &str) -> CaptureVerdict {
    // 1. rc gate. `rc == 1` is the only value that can carry a real verdict;
    // {0, 4} are safety/environment outcomes and anything else is unexpected.
    match rc {
        0 => return CaptureVerdict::Unusable(Unusable::Loaded),
        4 => return CaptureVerdict::Unusable(Unusable::NoCapability),
        1 => {}
        _ => return CaptureVerdict::Unusable(Unusable::UnexpectedRc),
    }

    // 2. Accept probe. MUST precede the complaint probe: an accepted
    // add-shaped line's stderr also carries the companion
    // "There was an error in line N of <file>" string, which must never be
    // read as a parse complaint on its own (see
    // `companion_string_alone_is_not_an_accept_probe`).
    if stderr.contains(ADD_RULE_NETLINK_REFUSED) {
        return CaptureVerdict::Accept;
    }

    // 3. Sandbox-limited probes: a feature-bitmap query this sandbox's
    // blocked `AUDIT_GET` cannot complete, not a genuine parse complaint
    // about the rule's own content.
    if SANDBOX_LIMITED_SUBSTRINGS
        .iter()
        .any(|substr| stderr.contains(substr))
    {
        return CaptureVerdict::Unusable(Unusable::SandboxLimited);
    }

    // 4. Complaint table: a genuine, cited `auditctl` parse diagnostic.
    if let Some(&complaint) = KNOWN_PARSE_COMPLAINTS
        .iter()
        .find(|&&substr| stderr.contains(substr))
    {
        return CaptureVerdict::Reject { complaint };
    }

    // 5. Silence (rc 1, both streams empty). Conclusive evidence of a parse
    // refusal only when `silence_is_conclusive` says this line's leading
    // flag is not on the silent-success-path denylist.
    if stdout.is_empty() && stderr.is_empty() {
        return if silence_is_conclusive(line) {
            CaptureVerdict::Reject {
                complaint: SILENT_REFUSAL_COMPLAINT,
            }
        } else {
            CaptureVerdict::Unusable(Unusable::SilentNonAddLine)
        };
    }

    // 6. rc 1 with non-empty output matching no known table entry: a hard
    // failure, never silently absorbed as an ordinary reject.
    CaptureVerdict::Unusable(Unusable::UnrecognisedDiagnostic)
}

/// The substring `handle_request`/`auditctl.c` prints when an add-shaped
/// rule's (`-w`/`-a`) netlink send fails for ANY reason - including, under
/// this unprivileged capture sandbox, `EPERM` on a rule that in fact parsed
/// successfully. Its presence therefore proves the line reached the netlink
/// call, i.e. parsing succeeded; see [`classify_capture`]'s accept probe.
const ADD_RULE_NETLINK_REFUSED: &str = "Error sending add rule data request";

/// Feature-bitmap-gated diagnostics that report a LIMITATION of this capture
/// sandbox (a blocked `AUDIT_GET` netlink query, `libaudit.c`'s
/// `audit_get_features()`) rather than a property of the rule's own content.
/// See [`Unusable::SandboxLimited`] and this module's `UNOBSERVABLE`
/// counterparts (`rocky9-filesystem-list` / `reset-lost-probe`) in the replay
/// test.
const SANDBOX_LIMITED_SUBSTRINGS: &[&str] = &[
    "filter is not supported by the kernel",
    "Field option not supported by kernel:",
];

/// Known `auditctl` parse-complaint diagnostics, each naming the field/value
/// problem it found while parsing a rule's CONTENT. Every string here is
/// emitted via `err_msgtab`'s direct-`fprintf` `audit_number_to_errmsg` path
/// (`errormsg.h`), which is why each is visible even under `-R`'s
/// `MSG_SYSLOG` mode (see `PROVENANCE.md` "`MSG_SYSLOG` under -R"). At most
/// one entry can ever match a given stderr, since each names a distinct
/// field/value problem.
const KNOWN_PARSE_COMPLAINTS: &[&str] = &[
    "-F unknown field:",
    "-C unknown field:",
    "-F value should be number for",
    "Permission can only contain",
];

/// Placeholder complaint attached to a [`CaptureVerdict::Reject`] recovered
/// from silence alone (rc 1, empty stdout and stderr, a line whose leading
/// flag is NOT on [`SILENT_SUCCESS_LEADING_FLAGS`]). Unlike the
/// [`KNOWN_PARSE_COMPLAINTS`] case, there is no captured diagnostic text to
/// name here - the evidence for this verdict is the absence of the loud
/// accept probe, not a matched substring - so this constant exists only to
/// satisfy `Reject`'s `&'static str` field. No test asserts on its content;
/// the divergence tables compare on the `Reject` variant alone.
const SILENT_REFUSAL_COMPLAINT: &str = "(no diagnostic text: rc=1 with empty stdout/stderr, refused during parsing before any netlink send)";

/// Leading `auditctl` flags whose SUCCESS path performs its netlink round trip
/// directly inside `setopt()`'s own `case` arm, with no distinct print on
/// failure - unlike the shared add-rule path (`-w`/`-a`) that always prints
/// `Error sending add rule data request` when its netlink send fails. For a
/// line whose leading flag is on this list, an observed `(rc=1, "", "")`
/// capture is therefore AMBIGUOUS: it is produced identically by a successful
/// parse whose netlink send was silently refused (EPERM, under this sandbox)
/// and by a genuine parse refusal, so [`silence_is_conclusive`] returns `false`
/// for these and the row becomes [`Unusable::SilentNonAddLine`] rather than a
/// guessed verdict.
///
/// Source-grounded against `audit-userspace` `src/auditctl.c` `setopt()`,
/// confirmed byte-identical in shape across the three RHEL8/9/10-shipped tags
/// v3.1.2 / v3.1.5 / v4.0.3 (session 2026-07-26 read of
/// <https://github.com/linux-audit/audit-userspace>):
///
/// - `-D` (`case 'D':`, v3.1.2 L982 / v3.1.5 L1000 / v4.0.3 L1005): an
///   unconditional field-count mismatch IS loud (`audit_msg(LOG_ERR, "Wrong
///   number of options for Delete all request")`); the success path
///   (`retval = delete_all_rules(fd);`) prints nothing on failure. Matches this
///   crate's own `-D` grounding in `parser.rs`'s `delete_all_with_extra_token`.
/// - `-e` (v3.1.2 L636 / v3.1.5 L654 / v4.0.3 L659), `-f` (L650/L668/L673),
///   `-r` (L664/L682/L687), `-b` (L683/L701/L706): each calls its
///   `audit_set_*(fd, ...)` setter and, on a `<= 0` return, does `retval = -1;`
///   (or `return -1;`) with NO `audit_msg` call - silent on failure. A malformed
///   OPTARG (non-numeric) is the only loud path for these four, and is not
///   silent, so it is not part of this ambiguity.
/// - `--loginuid-immutable` (`case 1:`, L1109/L1127/L1132) and
///   `--backlog_wait_time` (`case 2:`, L1116/L1134/L1139): same shape, silent
///   on a `<= 0` / negative return.
///
/// `--reset-lost` is DELIBERATELY ABSENT (round-2 adversarial review, session
/// 2026-07-26): the first draft of this list included it on the strength of
/// `case 3:`'s shape alone (calls `audit_number_to_errmsg(rc, ...)` on
/// failure, same as the other entries here), flagged at the time as the
/// weakest-grounded entry because whether `err_msgtab` even has an `-EPERM`
/// key was unconfirmed. A live capture (`reset-lost-probe` in the corpus)
/// settled it: `audit_reset_lost` (`libaudit.c` `audit_get_features() &
/// AUDIT_FEATURE_BITMAP_LOST_RESET == 0` check, before any netlink send)
/// returns `-EAU_FIELDNOSUPPORT` in THIS sandbox (the same blocked
/// `AUDIT_GET` status call the `-s` canary exercises also blocks the
/// feature-bitmap load, so the bit always reads unset here), and that error
/// code IS an `err_msgtab` key (`errormsg.h:108`,
/// `{ -EAU_FIELDNOSUPPORT, 2, "Field option not supported by kernel:" }`),
/// printed via `audit_number_to_errmsg`'s direct `fprintf(stderr, ...)` -
/// bypassing `-R`'s `MSG_SYSLOG` mode entirely. Measured: `--reset-lost` is
/// LOUD (`Field option not supported by kernel: reset-lost`), not silent, on
/// all three EL majors. It is `Unusable::SandboxLimited` (the same
/// feature-bitmap-gated mechanism as `rocky9-filesystem-list`'s `fstype`
/// finding), never reaching this denylist's ambiguity at all. Re-adding it
/// here would be a regression: verify against the corpus first.
///
/// A denylist rather than an allowlist on purpose: an unenumerated new control
/// flag then defaults to `true` (silence IS conclusive), which produces a LOUD
/// wrong label the test's `UNOBSERVABLE`/`XFAIL` bookkeeping will visibly
/// triage, instead of silently defaulting to `Unusable` and being dropped from
/// comparison where nothing would ever triage it.
const SILENT_SUCCESS_LEADING_FLAGS: &[&str] = &[
    "-D",
    "-b",
    "-e",
    "-f",
    "-r",
    "--backlog_wait_time",
    "--loginuid-immutable",
];

/// Whether silence (rc 1, both streams empty) is conclusive evidence of a parse
/// REFUSAL for this line.
///
/// Returns `false` (NOT conclusive - fall through to
/// [`Unusable::SilentNonAddLine`]) when `line`'s leading flag is on
/// [`SILENT_SUCCESS_LEADING_FLAGS`], because that flag's own SUCCESS path is
/// silent too, so observed silence cannot be attributed to either outcome.
/// Returns `true` for everything else (in particular the add-shaped `-w`/`-a`
/// flags this corpus mostly consists of): a successful parse of one of those is
/// always LOUD (`Error sending add rule data request`, caught by
/// [`classify_capture`]'s accept probe before this function is ever consulted),
/// so silence surviving to this point can only mean the line never reached that
/// netlink call at all, i.e. it was refused during parsing.
///
/// The leading flag is taken as the first whitespace-separated token, matching
/// `audit_strsplit`'s own dispatch (see the images README): a leading flag is
/// always the option `getopt_long` dispatches on regardless of what follows it
/// on the line, so trailing tokens (`-D extra`, `-D -k mykey`) do not change
/// which arm of `setopt()` handles the line.
#[must_use]
pub fn silence_is_conclusive(line: &str) -> bool {
    let leading = line.split_whitespace().next().unwrap_or("");
    !SILENT_SUCCESS_LEADING_FLAGS.contains(&leading)
}

#[cfg(test)]
mod silence_is_conclusive_tests {
    use super::silence_is_conclusive;

    /// The bug this whole module exists to fix: a bare `-D` is NOT conclusive
    /// silence-as-refusal (its own success path is just as silent). Asserting
    /// ONLY this side would not catch the function being wired to always
    /// return `false`, hence the companion `add_shaped_line_is_conclusive`
    /// test right below it - the pair together fails under EITHER polarity
    /// inversion or a constant-return stub.
    #[test]
    fn control_flag_leading_line_is_not_conclusive() {
        assert!(
            !silence_is_conclusive("-D"),
            "-D's success path is silent (delete_all_rules on EPERM), so its \
             silence must NOT be treated as a conclusive parse refusal"
        );
        assert!(
            !silence_is_conclusive("-D -k mykey"),
            "the leading flag governs, not the trailing tokens"
        );
        assert!(!silence_is_conclusive("-b 8192"));
        assert!(!silence_is_conclusive("-e 1"));
        assert!(!silence_is_conclusive("-f 1"));
        assert!(!silence_is_conclusive("-r 100"));
        assert!(!silence_is_conclusive("--backlog_wait_time 60"));
        assert!(!silence_is_conclusive("--loginuid-immutable"));
    }

    /// `--reset-lost` is deliberately NOT on the denylist (round-2 review):
    /// the live `reset-lost-probe` corpus row shows it is always LOUD in this
    /// sandbox (`Field option not supported by kernel: reset-lost`, a
    /// `Unusable::SandboxLimited` case, not the silent-success-path ambiguity
    /// the denylist exists for), so its silence would in fact be conclusive -
    /// it just never happens to BE silent here. Pinned as its own test so a
    /// future edit that re-adds it to the denylist (undoing the round-2
    /// finding) fails visibly instead of silently.
    #[test]
    fn reset_lost_is_not_on_the_denylist_after_empirical_settlement() {
        assert!(
            silence_is_conclusive("--reset-lost"),
            "--reset-lost was removed from SILENT_SUCCESS_LEADING_FLAGS after the \
             reset-lost-probe corpus row showed it is always LOUD here, not silent; \
             re-adding it to the denylist would be an unverified regression"
        );
    }

    /// The other half of the pair above: an add-shaped line's silence IS
    /// conclusive, because a successful parse of `-w`/`-a` is always loud
    /// (`Error sending add rule data request`) and would have been caught by
    /// `classify_capture`'s accept probe before `silence_is_conclusive` is ever
    /// consulted; surviving silence for one of these can only be a refusal.
    #[test]
    fn add_shaped_line_is_conclusive() {
        assert!(
            silence_is_conclusive("-w /etc/passwd -p zz -k c"),
            "an add-shaped line's silence is conclusive evidence of refusal"
        );
        assert!(silence_is_conclusive("-a always,exit -F perm=zz -S execve"));
        assert!(
            silence_is_conclusive("garbage-not-a-flag"),
            "an unrecognised leading token is not on the denylist, so its \
             (also observed) silence is conclusive too"
        );
    }
}

/// Synthetic (no corpus row needed - pure function calls) pins on
/// `classify_capture`'s contract, added at the round-2 adversarial review
/// (session 2026-07-26) after the reviewer POSITIVE-CONTROLLED its own
/// instrument (reproduced the round-1 bug, confirmed a constant-`Accept`
/// stub, both `silence_is_conclusive` polarity inversions, an accept/complaint
/// probe reorder, and treating the fstype message as `Reject` all pass the
/// CORPUS-based comparison alone) and found that every one of the 213
/// corpus rows has `rc == 1`, so nothing in the corpus-driven test forces
/// `classify_capture` to inspect `rc` at all - `Unusable::Loaded`,
/// `NoCapability`, `UnexpectedRc` and `UnrecognisedDiagnostic` were reachable
/// in the TYPE but dead in the TEST SUITE. These tests close that gap
/// directly: they construct the raw facts by hand rather than reading them
/// from a captured row.
#[cfg(test)]
mod classify_capture_synthetic_tests {
    use super::{CaptureVerdict, Unusable, classify_capture};

    /// `rc == 0`: the rule LOADED. Regardless of line or output content, this
    /// must abort as `Unusable::Loaded` - the netlink-safety-net case a
    /// corpus that is 100% `rc == 1` can never exercise.
    #[test]
    fn rc_zero_is_always_unusable_loaded() {
        assert!(matches!(
            classify_capture("-D", 0, "", ""),
            CaptureVerdict::Unusable(Unusable::Loaded)
        ));
    }

    /// `rc == 4`: `auditctl` never ran (no `CAP_AUDIT_CONTROL`). A valid and
    /// an invalid rule are byte-identical here (both
    /// "You must be root to run this program."), so this must classify
    /// `Unusable::NoCapability` independent of stderr content.
    #[test]
    fn rc_four_is_always_unusable_no_capability() {
        assert!(matches!(
            classify_capture(
                "-w /etc/passwd -p wa",
                4,
                "",
                "You must be root to run this program.\n"
            ),
            CaptureVerdict::Unusable(Unusable::NoCapability)
        ));
    }

    /// Any `rc` outside `{0, 1, 4}` is unexpected and must not be silently
    /// folded into a REJECT/ACCEPT guess.
    #[test]
    fn unexpected_rc_is_unusable() {
        assert!(matches!(
            classify_capture("-a always,exit -S execve", 7, "", ""),
            CaptureVerdict::Unusable(Unusable::UnexpectedRc)
        ));
    }

    /// `rc == 1` with non-empty stderr that matches NO known complaint table
    /// entry must be a hard failure (`UnrecognisedDiagnostic`), never
    /// silently absorbed as an ordinary REJECT. This is the case the first
    /// draft's catch-all `_ => Reject { complaint: "some diagnostic" }` body
    /// would fail: that body has no complaint table at all, so it can never
    /// produce this variant.
    #[test]
    fn rc_one_unrecognised_nonempty_stderr_is_unusable() {
        assert!(matches!(
            classify_capture(
                "-a always,exit -S execve",
                1,
                "",
                "some brand new complaint nobody has ever seen before"
            ),
            CaptureVerdict::Unusable(Unusable::UnrecognisedDiagnostic)
        ));
    }

    /// The companion string `There was an error in line N of <file>` is
    /// printed on EVERY accepted add-shaped line ALONGSIDE
    /// `Error sending add rule data request` (see
    /// `handle_request`/`auditctl.c`), but it is not itself proof of
    /// acceptance - `handle_request` prints it whenever the netlink round
    /// trip errors for ANY reason, not only the accept case. A discriminator
    /// that keys off the companion string alone
    /// (`stderr.contains("There was an error in line")` -> Accept) passes
    /// every corpus row (the two strings are coextensive across all 213
    /// rows: measured round-2, el9, 42/42/42), so it takes a stderr carrying
    /// ONLY the companion, deliberately withholding the add-request string,
    /// to catch it.
    #[test]
    fn companion_string_alone_is_not_an_accept_probe() {
        let result = classify_capture(
            "-w /etc/passwd -p wa -k x",
            1,
            "",
            "There was an error in line 1 of /tmp/rs-oracle-line.rules",
        );
        assert!(
            !matches!(result, CaptureVerdict::Accept),
            "the companion string alone (without 'Error sending add rule data \
             request') must never be read as an accept probe; got {result:?}"
        );
    }
}

/// Synthetic pins on `product_verdict`'s "exactly one rule" guard (round-2
/// adversarial review, session 2026-07-26): the corpus itself contains ZERO
/// comment-only or blank rows (every scenario line is either a real rule or
/// unparseable), so nothing in the corpus-driven comparison forces
/// `product_verdict` to handle the `Ok(vec![])` case
/// [`product_verdict`]'s own doc calls load-bearing. A body that maps
/// `Ok(_) => Verdict::Accept` regardless of `rules.len()` passes the whole
/// corpus and only fails here.
#[cfg(test)]
mod product_verdict_tests {
    use super::{Verdict, product_verdict};

    #[test]
    fn comment_only_line_is_reject_not_accept() {
        assert_eq!(
            product_verdict("# comment only"),
            Verdict::Reject,
            "a line that vanishes entirely under comment-stripping parses to \
             Ok(vec![]), which is NOT an accept of the original line"
        );
    }

    #[test]
    fn blank_after_strip_line_is_reject_not_accept() {
        assert_eq!(
            product_verdict("   "),
            Verdict::Reject,
            "an all-whitespace line vanishes the same way a comment-only line does"
        );
    }
}
