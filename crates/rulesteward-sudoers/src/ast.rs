//! Abstract syntax for a `sudoers(5)` file.
//!
//! # Grounding (`sudoers(5)`, sudo 1.9.17p2; see the project grounding doc)
//! A sudoers file is a sequence of LOGICAL lines (physical lines joined on a
//! trailing backslash), each one of: blank / comment / alias definition /
//! `Defaults` entry / `@include`/`@includedir` directive (legacy `#include` /
//! `#includedir` accepted) / user specification. Anything that is none of these
//! and not well-formed is a parse error (`sudo-F01`).
//!
//! # Design - a RICH, frozen AST (no re-parsing in the leaf lints)
//! The leaf lint pipelines (#330 tag-state-machine, #331 alias-reference walk,
//! #332, #333 Defaults STIG) must be able to EMIT diagnostics WITHOUT re-parsing
//! the source. So this AST carries the full structure each leaf needs:
//! * [`UserSpec`] / [`CmndSpec`] expose the per-command tag list ([`Tag`]) and the
//!   `ALL`-vs-named distinction ([`CmndItem`]) the #330/#331 passes walk.
//! * [`AliasDef`] carries the raw comma-split member tokens (#331 dead-alias /
//!   undefined-alias walk).
//! * [`DefaultsEntry`] carries each setting's negation + name + optional value
//!   (#333 STIG-baseline Defaults findings).
//! * [`IncludeDirective`] distinguishes file vs dir and legacy vs modern (#334).
//!
//! Every node carries a byte [`Span`] (for ariadne rendering) and a 1-based line
//! number. This file is PURE TYPE DEFINITIONS ONLY - it is auto-excluded from the
//! mutation gate by the global `**/ast.rs` exclude, so no behavioral logic lives
//! here (it belongs in `parser.rs` / `resolve.rs` / `lints/`).

use rulesteward_core::Span;

/// A parsed `sudoers` file: its path, full source text, and classified logical
/// lines in source order.
///
/// `source` is retained so the lints can stage it for ariadne snippet rendering
/// (keyed by the display path, the diagnostics' `source_id` convention).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudoersFile {
    /// The path this file was read from (for diagnostics' `file` / `source_id`).
    pub path: std::path::PathBuf,
    /// The full source text (staged for ariadne rendering).
    pub source: String,
    /// The classified logical lines, in source order.
    pub lines: Vec<LogicalLine>,
}

/// One classified logical line (physical lines already joined on `\`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalLine {
    /// 1-based line number of the logical line's FIRST physical line.
    pub line: usize,
    /// Byte range of the logical line's raw text (across any joined physical
    /// lines) in the source.
    pub span: Span,
    /// What kind of construct this line is.
    pub kind: LineKind,
}

/// The classification of one logical line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineKind {
    /// A blank / whitespace-only line.
    Blank,
    /// A `#` comment line (NOT a `#include` directive and NOT a `#<digits>` UID
    /// subject - those are disambiguated by the parser, see the grounding doc).
    Comment,
    /// A `Defaults` entry (global or scoped).
    Defaults(DefaultsEntry),
    /// An alias definition (`User_Alias` / `Runas_Alias` / `Host_Alias` /
    /// `Cmnd_Alias`; `Cmd_Alias` is a synonym for `Cmnd_Alias`).
    Alias(AliasDef),
    /// An `@include`/`@includedir` (or legacy `#include`/`#includedir`) directive.
    Include(IncludeDirective),
    /// A user specification.
    UserSpec(UserSpec),
    /// A line that is none of the valid kinds and is not well-formed. Carries an
    /// operator-facing message describing why. Emits `sudo-F01`.
    Malformed(String),
}

/// Which of the four alias namespaces a definition belongs to.
///
/// `Cmnd` covers both the `Cmnd_Alias` keyword and its `Cmd_Alias` synonym; the
/// distinction is not retained (they are semantically identical, >= sudo 1.9.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasKind {
    /// `User_Alias` - a set of users / groups / netgroups.
    User,
    /// `Runas_Alias` - a set of run-as targets.
    Runas,
    /// `Host_Alias` - a set of hosts.
    Host,
    /// `Cmnd_Alias` (or `Cmd_Alias`) - a set of commands.
    Cmnd,
}

/// One alias definition: `<Kind>_Alias NAME = member, member, ...`.
///
/// `members` holds the RAW comma-split member tokens (each trimmed). They are not
/// further classified here - the #331 alias-reference walk reads them as-is to
/// resolve alias-to-alias references and detect undefined / dead aliases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasDef {
    /// Which alias namespace.
    pub kind: AliasKind,
    /// The alias NAME (the uppercase identifier being defined).
    pub name: String,
    /// Raw comma-split member tokens (trimmed), in source order.
    pub members: Vec<String>,
}

/// The scope a `Defaults` entry applies to.
///
/// `sudoers(5)`: `Defaults` (global), `Defaults@host`, `Defaults:user`,
/// `Defaults!cmnd`, `Defaults>runas`. White space is NOT permitted between
/// `Defaults` and the scope sigil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultsScope {
    /// Plain `Defaults` - applies globally.
    Global,
    /// `Defaults@host` - bound to a host list.
    Host(String),
    /// `Defaults:user` - bound to a user list.
    User(String),
    /// `Defaults!cmnd` - bound to a command.
    Cmnd(String),
    /// `Defaults>runas` - bound to a run-as user.
    Runas(String),
}

/// One `Defaults` setting: `name`, `!name`, `name=value`, `name+=value`, etc.
///
/// Phase 0 models the common `name` / `!name` / `name=value` forms. The `+=` /
/// `-=` list-append operators collapse to `name` + `value` here (the operator is
/// not retained); #333 can refine this if a STIG check needs the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultSetting {
    /// `true` for a `!name` clear (e.g. `!authenticate`).
    pub negated: bool,
    /// The setting name (e.g. `authenticate`, `secure_path`, `use_pty`).
    pub name: String,
    /// The assigned value when the form is `name=value`, else `None`.
    pub value: Option<String>,
}

/// A `Defaults` entry: an optional scope plus one or more settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultsEntry {
    /// What the entry applies to.
    pub scope: DefaultsScope,
    /// The comma-separated settings, in source order.
    pub settings: Vec<DefaultSetting>,
}

/// Whether an include pulls in one FILE or a DIRECTORY of files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncludeKind {
    /// `@include` / `#include` - a single file.
    Include,
    /// `@includedir` / `#includedir` - every file in a directory.
    IncludeDir,
}

/// An `@include`/`@includedir` (or legacy `#include`/`#includedir`) directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeDirective {
    /// File vs directory include.
    pub kind: IncludeKind,
    /// `true` for the legacy `#include` / `#includedir` spelling, `false` for the
    /// modern `@include` / `@includedir`.
    pub legacy: bool,
    /// The include path as written (quotes / escapes NOT yet resolved - #334).
    pub path: String,
}

/// A command tag in a `Cmnd_Spec`. The full 18-value `Tag_Spec` set from
/// `sudoers(5)`, each tag paired with its opposite.
///
/// Once a tag is set on a `Cmnd`, subsequent `Cmnd`s in the same `Cmnd_Spec_List`
/// INHERIT it unless overridden by the opposite tag (e.g. `PASSWD` overrides
/// `NOPASSWD`). The #330 tag-state-machine walks this; modelling each opposite as
/// a distinct variant lets the state machine reset cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Exec,
    NoExec,
    Follow,
    NoFollow,
    LogInput,
    NoLogInput,
    LogOutput,
    NoLogOutput,
    Mail,
    NoMail,
    Intercept,
    NoIntercept,
    Passwd,
    NoPasswd,
    Setenv,
    NoSetenv,
}

/// A run-as spec: `(runas_users)` or `(runas_users:runas_groups)`.
///
/// Both lists are RAW comma-split tokens (trimmed); an absent list is an empty
/// `Vec`. The #330/#331 passes that care about run-as targets read these as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunasSpec {
    /// The run-as user list (before the optional `:`), comma-split.
    pub users: Vec<String>,
    /// The run-as group list (after the `:`), comma-split; empty when absent.
    pub groups: Vec<String>,
}

/// One command item in a `Cmnd_Spec`: the reserved `ALL`, or a named command /
/// command alias / directory token.
///
/// Phase 0 distinguishes `ALL` (the W01/W02 hazard) from everything else; a named
/// item carries its RAW token so #331 can match it against defined `Cmnd_Alias`
/// names (an alias reference is an uppercase token equal to a defined alias name).
/// A leading `!` negation is kept on the raw token (its meaning is a lint concern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmndItem {
    /// The reserved `ALL` built-in (matches any command). The #330 NOPASSWD-on-ALL
    /// hazard and the #331 alias-transitively-expands-to-ALL walk key off this.
    All,
    /// A named command, directory, or `Cmnd_Alias` reference. The raw token is
    /// kept verbatim (including any leading `!` and any command arguments).
    Cmnd(String),
}

/// One command specification within a user-spec: an optional run-as, the tags in
/// effect, and the command.
///
/// The tags here are the EXPLICIT tags written on THIS `Cmnd_Spec` (in source
/// order). Tag INHERITANCE across the `Cmnd_Spec_List` is computed by the #330
/// pass walking the list left-to-right - the parser does not pre-resolve
/// inheritance, so the AST stays a faithful record of what was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmndSpec {
    /// The run-as spec, if a `(...)` group preceded this command.
    pub runas: Option<RunasSpec>,
    /// The explicit tags written on this command (NOT inheritance-resolved).
    pub tags: Vec<Tag>,
    /// The command (the reserved `ALL` or a named item / alias reference).
    pub cmnd: CmndItem,
}

/// A user specification: `User_List Host_List = Cmnd_Spec_List`.
///
/// Each of `users` / `hosts` is the RAW comma-split token list (trimmed). The
/// `cmnd_specs` are the comma-separated `Cmnd_Spec`s after the `=`, in source
/// order, so the #330 tag-state-machine can walk them as one list. The multi-host
/// `(: Host_List = Cmnd_Spec_List)*` continuation form is flattened: every
/// `Cmnd_Spec` from every host group is appended in source order (Phase 0 keeps
/// the common single-host form rich and does not separately model per-host groups;
/// the leaf passes that need it can be extended without re-parsing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSpec {
    /// The subject user list (comma-split): users, `%group`, `#uid`, `+netgroup`,
    /// `User_Alias` references, each optionally `!`-negated (kept verbatim).
    pub users: Vec<String>,
    /// The host list (comma-split).
    pub hosts: Vec<String>,
    /// The command specs after the `=`, in source order.
    pub cmnd_specs: Vec<CmndSpec>,
}
