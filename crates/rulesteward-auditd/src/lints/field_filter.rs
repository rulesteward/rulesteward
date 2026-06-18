//! au-E04: field <-> filter-list legality lint (issue #269).
//!
//! au-E04 is an Error-tier, load-aborting class: the kernel/auditctl aborts the
//! rule load when a `-F field=...` predicate is used on a filter list that is
//! illegal for that field. Distinct from au-E02 (operator validity), which never
//! inspects the filter list.
//!
//! # Grounding
//!
//! Per-field allowed-filter-lists table grounded in libaudit.c
//! `audit_rule_fieldpair_data`, versions 3.1.5 (el8/el9) and 4.0.3 (el10).
//! Table is identical across both versions (byte-diff clean).
//! Primary source: depth-auditd-fieldtable.md (2026-06-17 overnight grounding).
//!
//! # Scope corrections (honored here)
//!
//! - `obj_uid` / `obj_gid`: live in the uid/gid arm (libaudit.c:1641 v3.1.5)
//!   which carries NO list guard -> legal on any filter list. NOT exit-only.
//! - `perm`: guard is `!(EXIT || EXCLUDE)` (libaudit.c:1803-1805) -> legal on
//!   exit OR exclude, not exit-only.
//! - `sessionid`: legal on exclude, user, OR exit (FIELDNOFILTER guard,
//!   libaudit.c:1884-1887) -> three lists.
//! - Two feature-gated whitelists (MSGTYPECREDEXCLUDE + FS-support) are NOT
//!   flagged here: a static linter cannot determine kernel feature-flag state.

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{AuditField, AuditRule, FilterList, LocatedRule};

/// Restriction kind for a field.
///
/// Fields with no restriction are absent from the match; fields with a
/// restriction carry the set of LEGAL lists in a small inline array so the
/// check is a membership test.
#[derive(Debug, Clone, Copy)]
enum Restriction {
    /// Legal only on the exit filter list (`EAU_EXITONLY`).
    ExitOnly,
    /// Legal only on exit OR exclude (perm's guard: `!(EXIT || EXCLUDE)`).
    ExitOrExclude,
    /// Legal only on exclude or user (msgtype's `MSGTYPEEXCLUDEUSER` guard).
    ExcludeOrUser,
    /// Legal only on exclude, user, or exit (sessionid's `FIELDNOFILTER` guard).
    ExcludeUserOrExit,
    /// Legal only on the filesystem filter list (fstype's `FIELDUNAVAIL` guard).
    FilesystemOnly,
}

impl Restriction {
    /// Return true if `list` is in this field's legal set.
    fn allows(self, list: &FilterList) -> bool {
        match self {
            Restriction::ExitOnly => matches!(list, FilterList::Exit),
            Restriction::ExitOrExclude => {
                matches!(list, FilterList::Exit | FilterList::Exclude)
            }
            Restriction::ExcludeOrUser => {
                matches!(list, FilterList::Exclude | FilterList::User)
            }
            Restriction::ExcludeUserOrExit => {
                matches!(
                    list,
                    FilterList::Exclude | FilterList::User | FilterList::Exit
                )
            }
            Restriction::FilesystemOnly => matches!(list, FilterList::Filesystem),
        }
    }

    /// Human-readable description of the legal lists for the diagnostic message.
    fn legal_lists_str(self) -> &'static str {
        match self {
            Restriction::ExitOnly => "exit",
            Restriction::ExitOrExclude => "exit or exclude",
            Restriction::ExcludeOrUser => "exclude or user",
            Restriction::ExcludeUserOrExit => "exclude, user, or exit",
            Restriction::FilesystemOnly => "filesystem",
        }
    }
}

/// Return the filter-list restriction for `field`, or `None` if the field is
/// legal on any list (no guard in libaudit.c).
///
/// 14-row table per the spec (depth-auditd-fieldtable.md grounding):
///
/// | field(s)                                           | restriction          |
/// |----------------------------------------------------|----------------------|
/// | perm                                               | exit or exclude      |
/// | filetype                                           | exit only            |
/// | exit (the field, not the list)                     | exit only            |
/// | success                                            | exit only            |
/// | devmajor, devminor, inode                          | exit only            |
/// | ppid                                               | exit only            |
/// | `obj_user`, `obj_role`, `obj_type`, `obj_lev_low`, |                      |
/// |   `obj_lev_high`  (STRING obj fields)              | exit only            |
/// | dir  (watch/dir arm)                               | exit only            |
/// | path (watch/dir arm - same `AUDIT_WATCH` case)      | exit only            |
/// | msgtype                                            | exclude or user      |
/// | fstype                                             | filesystem only      |
/// | sessionid                                          | exclude, user, exit  |
/// | `obj_uid`, `obj_gid` (numeric uid/gid arm - no guard) | (unrestricted)   |
///
/// Feature-gated whitelists (MSGTYPECREDEXCLUDE, FS-support) are NOT modeled.
fn field_restriction(field: &AuditField) -> Option<Restriction> {
    match field {
        // perm: guard is !(EXIT || EXCLUDE) -> legal on exit or exclude.
        AuditField::Perm => Some(Restriction::ExitOrExclude),

        // exit-only fields: EAU_EXITONLY guard (no exclude side).
        // Covers: plain exit-only syscall fields + STRING obj fields (watch/object arm) + dir + path.
        // NOTE: obj_uid / obj_gid are in the uid/gid arm with NO list guard (see wildcard).
        // path: AUDIT_WATCH arm (libaudit.c `case AUDIT_WATCH: case AUDIT_DIR:
        //   if (flags != AUDIT_FILTER_EXIT) return -EAU_EXITONLY;`).
        // Although -w desugars to exit, the -F path= Syscall form is also exit-only
        // by the same guard; not exit-only -> auditctl aborts the rule load.
        AuditField::Filetype
        | AuditField::Exit
        | AuditField::Success
        | AuditField::DevMajor
        | AuditField::DevMinor
        | AuditField::Inode
        | AuditField::Ppid
        | AuditField::ObjUser
        | AuditField::ObjRole
        | AuditField::ObjType
        | AuditField::ObjLevLow
        | AuditField::ObjLevHigh
        | AuditField::Dir
        | AuditField::Path => Some(Restriction::ExitOnly),

        // msgtype: MSGTYPEEXCLUDEUSER guard -> exclude or user.
        AuditField::MsgType => Some(Restriction::ExcludeOrUser),

        // fstype: FIELDUNAVAIL guard -> filesystem list only.
        AuditField::Fstype => Some(Restriction::FilesystemOnly),

        // sessionid: FIELDNOFILTER guard -> exclude, user, or exit.
        AuditField::SessionId => Some(Restriction::ExcludeUserOrExit),

        // All other fields (including obj_uid / obj_gid which have no list guard)
        // are legal on any filter list.
        // Scope correction: AUD-1 over-claimed obj_uid / obj_gid as exit-only.
        _ => None,
    }
}

/// au-E04: flag (as Error) a `-F field=...` predicate used on a filter list the
/// kernel rejects for that field, which aborts the rule load.
///
/// Iterates every `Syscall` rule in the stream; for each `-F` predicate, looks
/// up the field's restriction and fires if the rule's filter list is not in the
/// legal set. Watch rules are not checked (they always target the exit list
/// implicitly and the kernel enforces their semantics separately).
#[must_use]
pub fn e04(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    for located in rules {
        let AuditRule::Syscall { list, fields, .. } = &located.rule else {
            continue;
        };

        for field_filter in fields {
            let Some(restriction) = field_restriction(&field_filter.field) else {
                continue;
            };

            if !restriction.allows(list) {
                let field_name = field_name_str(&field_filter.field);
                let list_name = filter_list_name(list);
                // Do NOT self-prefix the code: the renderer already prints the
                // `[au-E04]` tag, so an `au-E04:` here would double it. (Matches
                // every sibling pass, which emit a bare message.)
                let msg = format!(
                    "field '{field_name}' cannot be used on the '{list_name}' filter list \
                     (legal: {legal}); auditctl aborts the rule load",
                    legal = restriction.legal_lists_str(),
                );
                diags.push(super::anchored(
                    Severity::Error,
                    "au-E04",
                    located.span.clone(),
                    msg,
                    &located.file,
                    located.line,
                ));
            }
        }
    }

    diags
}

/// Return the canonical lowercase string name for an `AuditField`, matching
/// the auditctl field name used in diagnostics.
fn field_name_str(field: &AuditField) -> &'static str {
    match field {
        AuditField::A0 => "a0",
        AuditField::A1 => "a1",
        AuditField::A2 => "a2",
        AuditField::A3 => "a3",
        AuditField::Arch => "arch",
        AuditField::Auid => "auid",
        AuditField::DevMajor => "devmajor",
        AuditField::DevMinor => "devminor",
        AuditField::Dir => "dir",
        AuditField::Egid => "egid",
        AuditField::Euid => "euid",
        AuditField::Exe => "exe",
        AuditField::Exit => "exit",
        AuditField::FieldCompare => "field_compare",
        AuditField::Filetype => "filetype",
        AuditField::Fsgid => "fsgid",
        AuditField::Fstype => "fstype",
        AuditField::Fsuid => "fsuid",
        AuditField::Gid => "gid",
        AuditField::Inode => "inode",
        AuditField::Key => "key",
        AuditField::MsgType => "msgtype",
        AuditField::ObjGid => "obj_gid",
        AuditField::ObjLevHigh => "obj_lev_high",
        AuditField::ObjLevLow => "obj_lev_low",
        AuditField::ObjRole => "obj_role",
        AuditField::ObjType => "obj_type",
        AuditField::ObjUid => "obj_uid",
        AuditField::ObjUser => "obj_user",
        AuditField::Path => "path",
        AuditField::Perm => "perm",
        AuditField::Pers => "pers",
        AuditField::Pid => "pid",
        AuditField::Ppid => "ppid",
        AuditField::SaddrFam => "saddr_fam",
        AuditField::SessionId => "sessionid",
        AuditField::Sgid => "sgid",
        AuditField::SubjClr => "subj_clr",
        AuditField::SubjRole => "subj_role",
        AuditField::SubjSen => "subj_sen",
        AuditField::SubjType => "subj_type",
        AuditField::SubjUser => "subj_user",
        AuditField::Success => "success",
        AuditField::Suid => "suid",
        AuditField::Uid => "uid",
    }
}

/// Return the canonical lowercase string name for a `FilterList`.
fn filter_list_name(list: &FilterList) -> &'static str {
    match list {
        FilterList::Task => "task",
        FilterList::Exit => "exit",
        FilterList::User => "user",
        FilterList::Exclude => "exclude",
        FilterList::Filesystem => "filesystem",
    }
}
