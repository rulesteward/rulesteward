//! Differential-oracle adapter for the `sudoers` backend (session 9k-1).
//!
//! Product side of the Tier-1 replay test described in `CONTRIBUTING.md`
//! "Differential oracle contract". It lets
//! `crates/rulesteward-sudoers/tests/sudoers_corpus_oracle.rs` compare
//! `RuleSteward`'s answer for a sudoers document against what the REAL
//! `visudo -c -f -` and `cvtsudoers -f json` said about that same document,
//! recorded in the committed corpus under `tests/corpus/sudoers-oracle/`.
//!
//! # Why this lives in `src/` and not in the test
//!
//! The model, the fail-closed parse and the compare are the logic whose being
//! wrong would make the differential report success while checking nothing.
//! Keeping them here subjects them to `just ci` clippy, the coverage floor and
//! the mutation gate; a `tests/`-only or feature-gated home would silently drop
//! all three.
//!
//! # Why the capture script records raw facts only
//!
//! `tests/corpus/sudoers-oracle/capture_sudoers.sh` writes `(rc, stdout,
//! stderr)` verbatim per target and makes no verdict. [`classify_visudo`] is
//! where a verdict is reached, so the decision is unit-tested and mutation-gated
//! rather than living in an untested `grep` inside bash.

use serde_json::Value;

use crate::ast::SudoersFile;

/// The real `visudo -c -f -` answer for one sudoers document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisudoVerdict {
    /// `visudo` parsed the document.
    Accept,
    /// `visudo` refused the document.
    Reject,
}

/// Fail-closed error: the captured exit code and the captured evidence text
/// disagree, so no verdict may be guessed.
///
/// Raised for a captured `rc == 0` with no `parsed OK` in stdout, for a nonzero
/// `rc` that nonetheless reports `parsed OK`, and for any rc outside `{0, 1}`.
/// Guessing in any of those cases is how a broken oracle gets recorded as a
/// clean one.
///
/// `Copy` is required by the frozen barrier test, which matches on a
/// `(accept_verdict, reject_verdict)` tuple and then names both again in the
/// failure message. Both fields are already `Copy`, so it costs nothing; the
/// constraint it buys is that a future `reason` must stay a `&'static str`
/// drawn from a fixed set rather than becoming a formatted `String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnclassifiedVisudo {
    /// The exit code as captured.
    pub rc: i32,
    /// Why the pair could not be classified.
    pub reason: &'static str,
}

/// Structure-only view of a sudoers document, comparable across `RuleSteward`'s
/// AST and `cvtsudoers -f json`'s output.
///
/// Deliberately NOT full-fidelity: full AST-vs-AST comparison is an explicit
/// follow-up, not this session. `users` / `hosts` / `commands` are flat,
/// file-wide token lists; the test compares them as multisets, so neither
/// projector needs to sort internally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureProjection {
    /// Number of `(User_List, Host_List, Cmnd_Specs)` tuples, one per
    /// `:`-separated host group, matching `cvtsudoers -f json`'s `User_Specs[]`
    /// array 1:1.
    pub tuple_count: usize,
    /// Every subject token, sigil-stripped to its bare value.
    pub users: Vec<String>,
    /// Every host token, sigil-stripped to its bare value.
    pub hosts: Vec<String>,
    /// Every command token.
    pub commands: Vec<String>,
}

/// Fail-closed error: a `cvtsudoers -f json` element did not match any key shape
/// measured against the real tool.
///
/// Silently skipping an unknown shape would shrink the projection and let the
/// comparison pass for the wrong reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CvtsudoersProjectionError {
    /// Which array the unknown element appeared in.
    pub location: &'static str,
    /// The offending element, rendered for the failure message.
    pub element: String,
}

/// Recovers the real `visudo` verdict from one row of raw captured facts.
///
/// `Ok(Accept)` iff `rc == 0` AND stdout contains `parsed OK`; `Ok(Reject)` iff
/// `rc != 0` AND stdout does NOT contain `parsed OK`; every other combination is
/// `Err(UnclassifiedVisudo)`.
///
/// `stderr` is accepted so the corpus row is passed whole and a future
/// diagnostic-level check needs no signature change; today it does not
/// participate in the decision.
pub fn classify_visudo(
    rc: i32,
    stdout: &str,
    stderr: &str,
) -> Result<VisudoVerdict, UnclassifiedVisudo> {
    let _ = (rc, stdout, stderr);
    todo!("session 9k-1 Lane C: fail-closed visudo classifier")
}

/// Projects `RuleSteward`'s parsed sudoers AST into the comparable structure view.
///
/// `CmndItem::All` projects to the literal string `ALL`. A subject or host
/// token's negation and sigil (`!`, then one of `%+#`) are stripped so the value
/// is comparable to `cvtsudoers`' bare values. For every host-group tuple the
/// SHARED `UserSpec` user list is pushed once, matching `cvtsudoers`' per-tuple
/// duplication of `User_List`.
#[must_use]
pub fn project_ast(file: &SudoersFile) -> StructureProjection {
    let _ = file;
    todo!("session 9k-1 Lane C: AST structure projection")
}

/// Projects a `cvtsudoers -f json` document into the comparable structure view.
///
/// Fail-closed on any `User_Specs[]` element whose `User_List` / `Host_List` /
/// `Cmnd_Specs[].Commands` entries do not match a key shape measured against the
/// real tool (`username`, `useralias`, `usergroup`, `netgroup`, `userid`,
/// `hostname`, `hostalias`, `command`, `cmndalias`). A companion
/// `"negated": true` is ignored, mirroring the sigil stripping [`project_ast`]
/// performs.
pub fn project_cvtsudoers_json(
    json: &Value,
) -> Result<StructureProjection, CvtsudoersProjectionError> {
    let _ = json;
    todo!("session 9k-1 Lane C: fail-closed cvtsudoers JSON projection")
}
