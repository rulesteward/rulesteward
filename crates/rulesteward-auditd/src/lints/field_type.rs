//! Per-field type table for the 46 `-F` field names (pipeline P3, #193).
//!
//! The taxonomy below was drafted in Phase 0 from a survey of audit-userspace
//! `lib/fieldtab.h` + `lib/libaudit.c` (`audit_rule_fieldpair_data`) at commit
//! 3bfa048 (the crate's pinned citation commit). Pipeline P3 OWNS the match
//! body of [`field_type`] and must cite, per arm, the exact source line in
//! that commit that grounds the assignment. If the survey shows a variant is
//! missing or wrong, P3 raises `[QUESTION FOR USER]` proposing the taxonomy
//! change rather than silently editing this enum (it is Phase-0 frozen).

use crate::ast::AuditField;

/// The behavioral type of a `-F` field's VALUE, as `audit_rule_fieldpair_data`
/// treats it. Determines which comparison operators are meaningful: string
/// types accept only equality forms; numeric types accept the full relational
/// and bitmask set; the special types have their own value grammars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// Plain unsigned numeric value (e.g. `pid`, `inode`, `devmajor`).
    Numeric,
    /// Signed numeric value (e.g. `exit`, which accepts negative errno).
    NumericSigned,
    /// User id: numeric or resolved from a user name (e.g. `auid`, `uid`).
    Uid,
    /// Group id: numeric or resolved from a group name (e.g. `gid`, `egid`).
    Gid,
    /// String value compared byte-wise (e.g. `exe`, `path`, `subj_type`).
    String,
    /// CPU architecture (`arch`): `b32`/`b64` or an ELF machine name/number.
    Arch,
    /// Watch-style permission letters (`perm`): subset of `rwxa`.
    Perm,
    /// Audit record type (`msgtype`): name or number, exclude/user lists only.
    MsgType,
    /// File type (`filetype`): `file`, `dir`, `socket`, ... name or mode.
    Filetype,
    /// Audit key (`key`): free-form string with length limit.
    Key,
    /// Filesystem type (`fstype`): name or magic number.
    FsType,
    /// Socket address family (`saddr_fam`): numeric AF_* value.
    SaddrFam,
}

/// The type of each of the 46 `-F` fields.
///
/// Body is pipeline P3's (46 arms, each citing `fieldtab.h`/`libaudit.c` at
/// audit commit 3bfa048); the signature and taxonomy are Phase-0 frozen.
#[must_use]
pub fn field_type(field: &AuditField) -> FieldType {
    let _ = field;
    todo!("pipeline P3 (#193): the 46-arm field-type match, per-arm citations")
}
