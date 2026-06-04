//! auditd rule AST types.
//!
//! Filled by pipeline P2 (issue #86).
//!
//! # Grounding
//! - Rule varieties (control/watch/syscall): `man 7 audit.rules` \[VM\].
//! - Filter lists: `/tmp/audit-src/lib/flagtab.h:25-29`.
//! - Actions: `/tmp/audit-src/lib/actiontab.h:23-25`.
//! - Perm classes: `/tmp/audit-src/lib/permtab.h:28-31`.
//! - 46 `-F` field names: `/tmp/audit-src/lib/fieldtab.h:24-72`.

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

    /// Syscall rule: `-a list,action ... -S ... -F ... -k ...` (or `-A` for prepend).
    Syscall {
        list: FilterList,
        action: Action,
        syscalls: Vec<String>,
        fields: Vec<FieldFilter>,
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
}

/// Filter lists from `flagtab.h:25-29`.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterList {
    Task,
    Exit,
    User,
    Exclude,
    Filesystem,
}

/// Rule actions from `actiontab.h:23-25`.
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

/// Permission bits for `-w` watches, from `auditctl(8) -p` and `permtab.h:28-31`.
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
/// Field names from `fieldtab.h:24-72` (46 canonical names).
#[derive(Debug, Clone, PartialEq)]
pub struct FieldFilter {
    pub field: AuditField,
    pub op: CompareOp,
    pub value: String,
}

/// The 46 `-F` field names from `/tmp/audit-src/lib/fieldtab.h:24-72`.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq)]
pub enum AuditField {
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
