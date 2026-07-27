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
    let _ = line;
    todo!("session 9k-1 Lane A: adapter over parser::parse_rules_str")
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
    let _ = (line, rc, stdout, stderr);
    todo!("session 9k-1 Lane A: raw-facts classifier, truth table in the session plan")
}

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
/// - `--reset-lost` (`case 3:`, L1144/L1162/L1167) is the WEAKEST-grounded
///   entry: its failure path calls `audit_number_to_errmsg(rc, ...)`, which
///   CAN print if `rc` matches a table entry in `err_msgtab` (defined outside
///   the files read this session, so whether `-EPERM` specifically is a key
///   was not confirmed). Kept on this list per the frozen session-plan design
///   (a generic permission errno is unlikely to be one of the protocol-level
///   codes that table exists for), but flagged here rather than asserted with
///   the same confidence as the other seven.
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
    "--reset-lost",
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
        assert!(!silence_is_conclusive("--reset-lost"));
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
