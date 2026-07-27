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
    /// Every subject token, negation-stripped and, for a sigil'd value,
    /// prefixed with its `"<type>:"` tag (see [`project_ast`]'s doc comment's
    /// "Type tags" discussion); a bare token (plain name, `ALL`, or an
    /// unexpanded alias reference) is untagged.
    pub users: Vec<String>,
    /// Every host token, negation-stripped and, for a sigil'd value (only
    /// `+netgroup` occurs on the host side), prefixed with its `"<type>:"`
    /// tag; a bare token (hostname, `ALL`, alias reference, or network
    /// address) is untagged.
    pub hosts: Vec<String>,
    /// Every command token, with a leading `!` negation stripped.
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
/// `CmndItem::All` projects to the literal string `ALL`. A subject, host, or
/// command token's leading `!` negation is stripped first: a negated command
/// like `!/usr/bin/su` needs it, and so does the literal `Cmnd("!ALL")` token
/// `parser.rs` produces for `!ALL` (it compares the raw text against `ALL`
/// before any negation strip, so the strip must recover the bare `ALL`
/// afterward). After the `!` strip, a subject/host token also gets a
/// `"<type>:"` prefix derived
/// from any remaining sigil (see "Type tags" below); a command token does
/// not (commands carry no `%+#` sigil in the sudoers grammar). For every
/// host-group tuple the SHARED `UserSpec` user list is pushed once, matching
/// `cvtsudoers`' per-tuple duplication of `User_List`.
///
/// # Type tags
///
/// Both sides of this differential previously reduced every subject/host to
/// its bare value only, discarding which sigil (here) or which distinct
/// `cvtsudoers` JSON key (in [`project_cvtsudoers_json`]) produced it. That
/// erasure was symmetric - thrown away by both projectors - so it canceled
/// exactly: a `project_ast` that dropped a sigil entirely (reading `%wheel`
/// as if it were the plain user `wheel`) still matched `cvtsudoers`'
/// `{"usergroup": "wheel"}` once both sides reduced to the bare string
/// `"wheel"`, proving nothing about sigil handling. Fix: after the `!` strip,
/// - `%group` (users only) -> `"usergroup:<group>"`.
/// - `%#gid` (users only) -> `"usergid:<gid>"` - BOTH sigils stripped, and
///   the digits canonicalized (see below).
/// - `+netgroup` (users and hosts) -> `"netgroup:<name>"`.
/// - `#uid` (users only) -> `"userid:<uid>"`, digits canonicalized.
/// - any other token (a plain username/hostname, the `ALL` keyword, an
///   unexpanded `User_Alias`/`Host_Alias` reference, or a `networkaddr`
///   host) -> untagged, the bare value itself. Distinguishing a plain name
///   from an alias reference would need cross-referencing the file's own
///   alias definitions, which this projector does not do; a `networkaddr`
///   host has no leading sigil to derive a tag from. Both are deliberately
///   left untagged, matching [`project_cvtsudoers_json`]'s inability to tell
///   `username` from `useralias` either.
///
/// # uid/gid canonicalization
///
/// `sudo_strtoid` parses a `#uid`/`%#gid` subject in base 10, so `#0100`
/// means uid 100 and `cvtsudoers` reports the canonical decimal as a JSON
/// number (`{"userid": 100}`, no leading zero). A textual sigil-strip alone
/// would produce `"0100"`, matching neither the canonical value nor the
/// right type once tags exist, so the digits are parsed and re-rendered in
/// decimal rather than only stripped.
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
        let stripped_users: Vec<String> = spec.users.iter().map(|u| tag_member(u)).collect();
        for group in &spec.host_groups {
            tuple_count += 1;
            users.extend(stripped_users.iter().cloned());
            hosts.extend(group.hosts.iter().map(|h| tag_member(h)));
            for cmnd_spec in &group.cmnd_specs {
                let cmnd = match &cmnd_spec.cmnd {
                    CmndItem::All => "ALL".to_string(),
                    CmndItem::Cmnd(raw) => strip_command_negation(raw),
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

/// Strips a single leading `!` negation from a command token, recovering the
/// bare command (or, for the literal `Cmnd("!ALL")` token, the bare `ALL`
/// keyword) that `cvtsudoers` reports via `{"command": ..., "negated":
/// true}` (see [`project_ast`]'s doc comment).
fn strip_command_negation(raw: &str) -> String {
    raw.strip_prefix('!').unwrap_or(raw).to_string()
}

/// Strips a leading `!` negation, then derives the `cvtsudoers`-comparable,
/// type-tagged value for a subject/host token (see [`project_ast`]'s doc
/// comment's "Type tags" and "uid/gid canonicalization" sections). Shared by
/// both users and hosts: `+netgroup` is valid on either side, and
/// `cvtsudoers`' `print_member_json_int` keys `typestr` on member TYPE, not
/// on which list it appears in, so tagging hosts with the same rules as
/// users costs nothing even though `%`/`%#`/`#` do not occur there in
/// practice.
fn tag_member(token: &str) -> String {
    let token = token.strip_prefix('!').unwrap_or(token);
    if let Some(digits) = token.strip_prefix("%#") {
        return format!("usergid:{}", canonicalize_decimal(digits));
    }
    if let Some(name) = token.strip_prefix('%') {
        return format!("usergroup:{name}");
    }
    if let Some(name) = token.strip_prefix('+') {
        return format!("netgroup:{name}");
    }
    if let Some(digits) = token.strip_prefix('#') {
        return format!("userid:{}", canonicalize_decimal(digits));
    }
    token.to_string()
}

/// Parses a uid/gid digit string in base 10 (matching `sudo_strtoid`) and
/// re-renders it canonically, so a leading-zero token (`#0100`) compares
/// equal to `cvtsudoers`' JSON-number report (`{"userid": 100}`). Falls back
/// to the original digits, unchanged, if they do not parse as an integer:
/// `project_ast` is infallible today (see its signature) and must never
/// panic on an unexpected token.
fn canonicalize_decimal(digits: &str) -> String {
    digits
        .parse::<u64>()
        .map_or_else(|_| digits.to_string(), |n| n.to_string())
}

/// Projects a `cvtsudoers -f json` document into the comparable structure view.
///
/// Fail-closed on any `User_Specs[]` element whose `User_List` / `Host_List` /
/// `Cmnd_Specs[].Commands` entries do not match a key shape measured against
/// the real tool: `User_List` accepts `username`, `useralias`, `usergroup`,
/// `netgroup`, `userid` (a JSON number), and `usergid` (a JSON number);
/// `Host_List` accepts `hostname`, `hostalias`, `netgroup`, and
/// `networkaddr`; `Cmnd_Specs[].Commands` accepts `command` and `cmndalias`.
/// `print_member_json_int` (the real `cvtsudoers` source) keys `typestr` on
/// member TYPE, not on which list a member appears in, so `netgroup`
/// legitimately appears in both `User_List` and `Host_List`. A companion
/// `"negated": true` is ignored, mirroring the negation stripping
/// [`project_ast`] performs.
///
/// The extracted value carries the same `"<type>:"` prefix `project_ast`
/// derives from a sigil (see that function's "Type tags" doc section):
/// `usergroup` / `netgroup` -> `"usergroup:<value>"` / `"netgroup:<value>"`;
/// `userid` / `usergid` (JSON numbers) -> `"userid:<n>"` / `"usergid:<n>"`;
/// `username`, `useralias`, `hostname`, `hostalias`, and `networkaddr` all
/// stay untagged (this projector cannot tell a plain name from an alias
/// reference, nor a network address from any other bare host token, any
/// more than [`project_ast`] can).
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

/// Extracts a `User_List[]` element's type-tagged value: `username` /
/// `useralias` stay untagged (this projector cannot tell them apart);
/// `usergroup` / `netgroup` gain a `"<type>:"` prefix; `userid` / `usergid`
/// (JSON numbers) are stringified and prefixed the same way. Any companion
/// `"negated": true` is ignored - it mirrors [`project_ast`]'s own negation
/// stripping and does not change the extracted value.
fn extract_user_list_value(elem: &Value) -> Option<String> {
    for key in ["username", "useralias"] {
        if let Some(s) = elem.get(key).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    if let Some(s) = elem.get("usergroup").and_then(Value::as_str) {
        return Some(format!("usergroup:{s}"));
    }
    if let Some(s) = elem.get("netgroup").and_then(Value::as_str) {
        return Some(format!("netgroup:{s}"));
    }
    if let Some(n) = elem.get("userid").filter(|v| v.is_number()) {
        return Some(format!("userid:{n}"));
    }
    if let Some(n) = elem.get("usergid").filter(|v| v.is_number()) {
        return Some(format!("usergid:{n}"));
    }
    None
}

/// Extracts a `Host_List[]` element's type-tagged value: `hostname` /
/// `hostalias` / `networkaddr` stay untagged (none carries a distinguishing
/// sigil on the AST side); `netgroup` gains the same `"netgroup:"` prefix a
/// user-side netgroup does.
fn extract_host_list_value(elem: &Value) -> Option<String> {
    for key in ["hostname", "hostalias", "networkaddr"] {
        if let Some(s) = elem.get(key).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    if let Some(s) = elem.get("netgroup").and_then(Value::as_str) {
        return Some(format!("netgroup:{s}"));
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
