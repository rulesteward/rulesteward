//! auditd rule AST types.
//!
//! Filled by pipeline P2 (issue #86).
//!
//! # Grounding
//! - Rule varieties (control/watch/syscall): `man 7 audit.rules` \[VM\].
//! - Filter lists: `/tmp/audit-src/lib/flagtab.h:25-29` (audit 3bfa048).
//! - Actions: `/tmp/audit-src/lib/actiontab.h:23-25` (audit 3bfa048).
//! - Perm classes: `/tmp/audit-src/lib/permtab.h:28-31` (audit 3bfa048).
//! - 46 `-F` field names: `/tmp/audit-src/lib/fieldtab.h:24-72` (audit 3bfa048).

/// One line from an auditd rules file (after comment-stripping).
///
/// Three varieties from `man 7 audit.rules`:
/// - Control: configure the kernel audit subsystem (`-D`, `-b`, `-f`, `-e`, `-r`,
///   `--backlog_wait_time`). Zero runtime volume.
/// - Watch: file-system watches (`-w path -p perms -k key`).
/// - Syscall: `exit`/`task`/`user`/`exclude`/`filesystem` list rules (`-a`/`-A`).
#[derive(Debug, Clone, PartialEq)]
pub enum AuditRule {
    /// Control rules: configure the audit subsystem; emit no runtime events.
    ///
    /// Examples: `-D`, `-b 8192`, `--backlog_wait_time 60000`, `-f 1`, `-e 2`, `-r 100`.
    Control(ControlRule),

    /// File-system watch: `-w path -p perms -k key`.
    ///
    /// `is_dir` is true when `path` ends with `/` (recursive watch per `man 7 audit.rules`).
    Watch {
        path: String,
        perms: PermBits,
        key: Option<String>,
        is_dir: bool,
    },

    /// Syscall rule: `-a list,action ... -S ... -F ... -C ... -k ...` (or `-A` for prepend).
    Syscall {
        list: FilterList,
        action: Action,
        syscalls: Vec<String>,
        fields: Vec<FieldFilter>,
        /// Inter-field comparisons from `-C field op field` (auditctl(8) `-C`).
        /// Distinct from `fields` (`-F field op value`): both operands are FIELD
        /// names, not a field-and-literal. AND'ed with `fields` and each other.
        field_compares: Vec<FieldComparison>,
        prepend: bool,
        key: Option<String>,
    },
}

/// Control rule variant.
///
/// Grounded in `auditctl(8)` and `man 7 audit.rules` section 2.1.
#[derive(Debug, Clone, PartialEq)]
pub enum ControlRule {
    /// `-D` -- delete all rules.
    DeleteAll,
    /// `-b N` -- set kernel backlog buffer count.
    Backlog(u64),
    /// `--backlog_wait_time N` -- milliseconds to wait on full backlog.
    BacklogWaitTime(u64),
    /// `-f N` -- failure mode: 0=silent, 1=printk, 2=panic.
    FailureMode(u8),
    /// `-e N` -- enable/disable (0=off, 1=on, 2=lock/immutable).
    Enable(u8),
    /// `-r N` -- rate limit in events/second.
    RateLimit(u64),
    /// `--loginuid-immutable` -- make the audit loginuid unchangeable once
    /// set (STIG deepening, #523). Takes NO value argument, unlike every
    /// other `ControlRule` variant above (`-b`/`-f`/`-e`/`-r` all take one):
    /// grounded verbatim in `auditctl --help` / `man auditctl(8)`: "This
    /// option tells the kernel to make loginuids unchangeable once they are
    /// set. Changing loginuids requires `CAP_AUDIT_CONTROL`." `parser.rs`
    /// recognizes `--loginuid-immutable` as a valueless control flag and
    /// ignores any trailing tokens on the line -- grounded independently in
    /// real auditctl's own dispatch for this flag (`src/auditctl.c` `case
    /// 1:`, byte-identical across the RHEL8/9/10-shipped audit-userspace
    /// tags v3.1.2/v3.1.5/v4.0.3): the handler calls
    /// `audit_set_loginuid_immutable(fd)` and either `return`s directly on
    /// success or leaves `retval == -1` on failure, so the generic leftover-
    /// argument check never runs and a trailing token is never read,
    /// validated, or rejected (confirmed CORRECT, lane-8 #541 report,
    /// 2026-07-24). This is NOT the same shape as `-D`, which rejects a
    /// trailing token via its own unconditional field-count check. STIG-
    /// required per RHEL8 V-230403 / RHEL-08-030122 and RHEL9 V-258228 /
    /// RHEL-09-654270.
    LoginuidImmutable,
}

/// Filter lists from `flagtab.h:25-29` (audit 3bfa048).
#[derive(Debug, Clone, PartialEq)]
pub enum FilterList {
    Task,
    Exit,
    User,
    Exclude,
    Filesystem,
}

/// Rule actions from `actiontab.h:23-25` (audit 3bfa048).
///
/// `Never` and `Exclude`-list rules are SUPPRESSIVE (volume = 0, direction = negative).
/// `Always` is ADDITIVE (contributes event volume).
/// `Possible` is treated as low-volume additive (uncommon in practice).
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Suppress matching events.
    Never,
    /// Possibly record (rarely used in practice).
    Possible,
    /// Always record.
    Always,
}

/// Permission bits for `-w` watches, from `auditctl(8) -p` and `permtab.h:28-31` (audit 3bfa048).
///
/// Each bit maps to a group of syscalls:
/// - `exec` -> `execve`, `execveat`
/// - `write` -> `rename`, `mkdir`, `creat`, `unlink`, ... (~20 syscalls)
/// - `read` -> `readlink`, `quotactl`, `listxattr`, ...
/// - `attr` -> `chmod`, `chown`, `setxattr`, ...
// Four bools are intentional: they model the four distinct AUDIT_PERM_* bits
// from permtab.h (r/w/x/a). A bitflags crate would be overkill for four bits.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PermBits {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub attr: bool,
}

/// One `-F field op value` filter predicate.
///
/// Field names from `fieldtab.h:24-72` (audit 3bfa048) (46 canonical names).
#[derive(Debug, Clone, PartialEq)]
pub struct FieldFilter {
    pub field: AuditField,
    pub op: CompareOp,
    pub value: String,
}

/// One `-C field op field` inter-field comparison (auditctl(8) `-C`).
///
/// Unlike [`FieldFilter`], BOTH operands are field names (e.g. `uid != euid`
/// maps to `AUDIT_COMPARE_UID_TO_EUID`, libaudit.c:1158 (audit 3bfa048), flagging a privilege
/// transition). Only the equality operators are valid: `op` is always
/// [`CompareOp::Eq`] or [`CompareOp::Ne`] (man auditctl: "There are 2 operators
/// supported - equal, and not equal").
#[derive(Debug, Clone, PartialEq)]
pub struct FieldComparison {
    pub left: AuditField,
    pub op: CompareOp,
    pub right: AuditField,
}

/// The 45 `-F` field names from `/tmp/audit-src/lib/fieldtab.h:24-72` (audit 3bfa048).
// string map: the field_name() free fn lives in lints/field_name.rs (#458; kept
// out of this mutation-excluded file so the map stays mutation-gated).
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq)]
pub enum AuditField {
    // Syscall argument registers a0..a3 (`-F a0=...`): narrow a syscall by an
    // argument value (e.g. `ioctl` request, `socketcall`/`socket` family). #164.
    A0,
    A1,
    A2,
    A3,
    Arch,
    Auid,
    DevMajor,
    DevMinor,
    Dir,
    Egid,
    Euid,
    Exe,
    Exit,
    FieldCompare,
    Filetype,
    Fsgid,
    Fstype,
    Fsuid,
    Gid,
    Inode,
    Key,
    MsgType,
    ObjGid,
    ObjLevHigh,
    ObjLevLow,
    ObjRole,
    ObjType,
    ObjUid,
    ObjUser,
    Path,
    Perm,
    Pers,
    Pid,
    Ppid,
    SaddrFam,
    SessionId,
    Sgid,
    SubjClr,
    SubjRole,
    SubjSen,
    SubjType,
    SubjUser,
    Success,
    Suid,
    Uid,
}

/// An [`AuditRule`] plus its provenance: source file, 1-based line, and the
/// byte range of the raw line within that file.
///
/// Added in Phase 0 of session 6a (#193): `parse_target` concatenates all
/// `rules.d/` files into one stream, and the semantic lint passes (duplicate,
/// shadowing, ordering) need to know which file and line each rule came from
/// to anchor diagnostics and reason about lexical load order. Plain data only
/// (this file is excluded from the mutation gate by design).
#[derive(Debug, Clone, PartialEq)]
pub struct LocatedRule {
    pub rule: AuditRule,
    /// Source file the rule was parsed from.
    pub file: std::path::PathBuf,
    /// 1-based line number within `file`.
    pub line: usize,
    /// Byte range of the rule's raw line within `file`'s content (no trailing
    /// newline), for ariadne anchoring and span-derived column backfill.
    pub span: rulesteward_core::Span,
}

/// Comparison operators for `-F field op value`.
///
/// From `auditctl(8) -F`: `=  !=  <  >  <=  >=  &  &=`
#[derive(Debug, Clone, PartialEq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    BitAnd,
    BitAndEq,
}
