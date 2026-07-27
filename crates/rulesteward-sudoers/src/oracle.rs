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

use crate::ast::{CmndItem, LineKind, SudoersFile};

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
/// `rc == 1` AND stdout does NOT contain `parsed OK`; every other combination
/// (including any `rc` outside `{0, 1}`, per `visudo(8)`'s own exit-code
/// contract of 0 on success / 1 on error - see [`UnclassifiedVisudo`]) is
/// `Err(UnclassifiedVisudo)`, never guessed.
///
/// `stderr` is accepted so the corpus row is passed whole and a future
/// diagnostic-level check needs no signature change; today it does not
/// participate in the decision.
pub fn classify_visudo(
    rc: i32,
    stdout: &str,
    stderr: &str,
) -> Result<VisudoVerdict, UnclassifiedVisudo> {
    // stderr does not participate in the decision today (see the doc comment);
    // accepted only so the corpus row can be passed whole.
    let _ = stderr;
    let parsed_ok = stdout.contains("parsed OK");
    if rc == 0 && parsed_ok {
        return Ok(VisudoVerdict::Accept);
    }
    if rc == 1 && !parsed_ok {
        return Ok(VisudoVerdict::Reject);
    }
    let reason = if rc == 0 || rc == 1 {
        "rc and parsed-OK evidence disagree"
    } else {
        "rc outside the visudo(8) 0/1 exit-code contract"
    };
    Err(UnclassifiedVisudo { rc, reason })
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
    let mut tuple_count = 0usize;
    let mut users = Vec::new();
    let mut hosts = Vec::new();
    let mut commands = Vec::new();

    for line in &file.lines {
        let LineKind::UserSpec(spec) = &line.kind else {
            continue;
        };
        let stripped_users: Vec<String> = spec.users.iter().map(|u| strip_sigil(u)).collect();
        for group in &spec.host_groups {
            tuple_count += 1;
            users.extend(stripped_users.iter().cloned());
            hosts.extend(group.hosts.iter().map(|h| strip_sigil(h)));
            for cmnd_spec in &group.cmnd_specs {
                let cmnd = match &cmnd_spec.cmnd {
                    CmndItem::All => "ALL".to_string(),
                    CmndItem::Cmnd(raw) => raw.clone(),
                };
                commands.push(cmnd);
            }
        }
    }

    StructureProjection {
        tuple_count,
        users,
        hosts,
        commands,
    }
}

/// Strips a single optional leading `!` negation, then a single optional
/// leading sigil among `%+#`, from a subject/host token - so it compares
/// against `cvtsudoers`' bare values (see [`project_ast`]'s doc comment).
fn strip_sigil(token: &str) -> String {
    let after_bang = token.strip_prefix('!').unwrap_or(token);
    let after_sigil = after_bang
        .strip_prefix('%')
        .or_else(|| after_bang.strip_prefix('+'))
        .or_else(|| after_bang.strip_prefix('#'))
        .unwrap_or(after_bang);
    after_sigil.to_string()
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
    let mut tuple_count = 0usize;
    let mut users = Vec::new();
    let mut hosts = Vec::new();
    let mut commands = Vec::new();

    // A file with no `User_Specs` at all (e.g. a Defaults-only document) omits
    // the key entirely rather than emitting an empty array; that is zero
    // tuples, not a shape error. `.into_iter().flatten()` on the
    // `Option<&Vec<_>>` yields nothing in that case, with no need for a
    // placeholder empty Vec.
    let specs = json.get("User_Specs").and_then(Value::as_array);

    for spec in specs.into_iter().flatten() {
        tuple_count += 1;

        let user_list = spec.get("User_List").and_then(Value::as_array);
        for elem in user_list.into_iter().flatten() {
            let value = extract_user_list_value(elem).ok_or_else(|| CvtsudoersProjectionError {
                location: "User_List",
                element: elem.to_string(),
            })?;
            users.push(value);
        }

        let host_list = spec.get("Host_List").and_then(Value::as_array);
        for elem in host_list.into_iter().flatten() {
            let value = extract_host_list_value(elem).ok_or_else(|| CvtsudoersProjectionError {
                location: "Host_List",
                element: elem.to_string(),
            })?;
            hosts.push(value);
        }

        let cmnd_specs = spec.get("Cmnd_Specs").and_then(Value::as_array);
        for cmnd_spec in cmnd_specs.into_iter().flatten() {
            let cmnd_list = cmnd_spec.get("Commands").and_then(Value::as_array);
            for elem in cmnd_list.into_iter().flatten() {
                let value =
                    extract_command_value(elem).ok_or_else(|| CvtsudoersProjectionError {
                        location: "Cmnd_Specs[].Commands",
                        element: elem.to_string(),
                    })?;
                commands.push(value);
            }
        }
    }

    Ok(StructureProjection {
        tuple_count,
        users,
        hosts,
        commands,
    })
}

/// Extracts a `User_List[]` element's bare value: `username` / `useralias` /
/// `usergroup` / `netgroup` (all strings), or `userid` (a JSON number,
/// stringified). Any companion `"negated": true` is ignored - it mirrors
/// [`project_ast`]'s own sigil-strip normalization and does not change the
/// extracted value.
fn extract_user_list_value(elem: &Value) -> Option<String> {
    for key in ["username", "useralias", "usergroup", "netgroup"] {
        if let Some(s) = elem.get(key).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    elem.get("userid")
        .filter(|v| v.is_number())
        .map(ToString::to_string)
}

/// Extracts a `Host_List[]` element's bare value: `hostname` / `hostalias`.
fn extract_host_list_value(elem: &Value) -> Option<String> {
    for key in ["hostname", "hostalias"] {
        if let Some(s) = elem.get(key).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    None
}

/// Extracts a `Cmnd_Specs[].Commands[]` element's bare value: `command` /
/// `cmndalias`.
fn extract_command_value(elem: &Value) -> Option<String> {
    for key in ["command", "cmndalias"] {
        if let Some(s) = elem.get(key).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    None
}
