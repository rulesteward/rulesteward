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
    /// rc 1 with both streams empty, for a line whose flag is not on the
    /// `silence_is_conclusive` denylist. Indistinguishable from a silent parse
    /// refusal, so no verdict is possible.
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
/// through [`silence_is_conclusive`].
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

/// Whether silence (rc 1, both streams empty) is conclusive evidence of a parse
/// refusal for this line.
///
/// Backed by a DENYLIST of leading flags whose success path performs netlink
/// inside `setopt()` and therefore fails silently: `-D`, `-b`, `-e`, `-f`, `-r`,
/// `--backlog_wait_time`, `--loginuid-immutable`, `--reset-lost`. Each entry
/// carries an `auditctl.c` citation.
///
/// A denylist rather than an allowlist on purpose: an unenumerated flag then
/// gets a loud wrong label that the test triages, instead of being quietly
/// dropped from comparison, which nothing would triage.
#[must_use]
pub fn silence_is_conclusive(line: &str) -> bool {
    let _ = line;
    todo!("session 9k-1 Lane A: auditctl.c-cited denylist of silently-failing control flags")
}
