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
    /// Plain unsigned numeric value with the FULL relational + bitmask operator
    /// set (e.g. `pid`, `devmajor`, `devminor`). Distinct from
    /// [`FieldType::NumericEqNe`], which the daemon restricts.
    Numeric,
    /// Signed numeric value (e.g. `exit`, which accepts negative errno).
    NumericSigned,
    /// Numeric value the daemon restricts to the equality operators `=` and
    /// `!=` only (audit `EAU_OPEQNOTEQ`). `inode` is the numeric field libaudit
    /// operator-validates this way (`libaudit.c:1997-2000` @ 3bfa048): a
    /// relational or bitmask operator on it is rejected at load time. Added
    /// session 6a (#193) alongside [`FieldType::StringEqNe`] so the operator
    /// restriction is expressed purely in the type table.
    NumericEqNe,
    /// User id: numeric or resolved from a user name (e.g. `auid`, `uid`).
    Uid,
    /// Group id: numeric or resolved from a group name (e.g. `gid`, `egid`).
    Gid,
    /// String value compared byte-wise, with NO operator restriction: the
    /// daemon accepts all eight operators for these fields because libaudit's
    /// `audit_rule_fieldpair_data` does not validate the operator for them
    /// (e.g. `path`, `dir`, `subj_type`, `obj_user`, `key`). Distinct from
    /// [`FieldType::StringEqNe`], which the daemon DOES validate.
    String,
    /// String value that the daemon restricts to the equality operators `=`
    /// and `!=` only (audit `EAU_OPEQNOTEQ`). `exe` is the one string-typed
    /// field libaudit operator-validates: a relational or bitmask operator on
    /// it is rejected at load time. Added session 6a (#193) so the operator
    /// restriction is expressed purely in the type table rather than a
    /// per-field special case.
    StringEqNe,
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
///
/// Citations per arm:
/// - `Pid`: fieldtab.h:24 `AUDIT_PID=0`; libaudit.c:2006 strtol default
/// - `Ppid`: fieldtab.h:43 `AUDIT_PPID`; libaudit.c:2003 ppid+default strtol
/// - `Pers`: fieldtab.h:35 `AUDIT_PERS=10`; libaudit.c default, numeric strtol
/// - `SessionId`: fieldtab.h:49 `AUDIT_SESSIONID=25`; libaudit.c:1966, numeric strtoul
/// - `DevMajor`: fieldtab.h:51 `AUDIT_DEVMAJOR=100`; libaudit.c:1991 range, numeric
/// - `DevMinor`: fieldtab.h:52 `AUDIT_DEVMINOR=101`; libaudit.c:1991 range, numeric
/// - `Success`: fieldtab.h:55 `AUDIT_SUCCESS=104`; libaudit.c:1992 range fallthrough
/// - `A0..A3`: fieldtab.h:65-68 `AUDIT_ARG0..AUDIT_ARG3`; libaudit.c:1954 ARG range
/// - `FieldCompare`: fieldtab.h:63 `AUDIT_FIELD_COMPARE`; -C pseudo-field, unreachable in -F
/// - `Uid`: fieldtab.h:25 `AUDIT_UID=1`; libaudit.c:1721
/// - `Euid`: fieldtab.h:26 `AUDIT_EUID=2`; libaudit.c:1722
/// - `Suid`: fieldtab.h:27 `AUDIT_SUID=3`; libaudit.c:1723
/// - `Fsuid`: fieldtab.h:28 `AUDIT_FSUID=4`; libaudit.c:1724
/// - `Auid`: fieldtab.h:33-34 `AUDIT_LOGINUID`; libaudit.c:1725
/// - `ObjUid`: fieldtab.h:61 `AUDIT_OBJ_UID`; libaudit.c:1726
/// - `Gid`: fieldtab.h:29 `AUDIT_GID=5`; libaudit.c:1748
/// - `Egid`: fieldtab.h:30 `AUDIT_EGID=6`; libaudit.c:1749
/// - `Sgid`: fieldtab.h:31 `AUDIT_SGID=7`; libaudit.c:1750
/// - `Fsgid`: fieldtab.h:32 `AUDIT_FSGID=8`; libaudit.c:1751
/// - `ObjGid`: fieldtab.h:62 `AUDIT_OBJ_GID`; libaudit.c:1752
/// - `Arch`: fieldtab.h:36 `AUDIT_ARCH`; libaudit.c:1858 op=only =|!= (`EAU_OPEQNOTEQ`)
/// - `MsgType`: fieldtab.h:37 `AUDIT_MSGTYPE`; libaudit.c:1783, no op restriction
/// - `SubjUser`: fieldtab.h:38 `AUDIT_SUBJ_USER`; libaudit.c:1814, string, no op restriction
/// - `SubjRole`: fieldtab.h:39 `AUDIT_SUBJ_ROLE`; libaudit.c:1815
/// - `SubjType`: fieldtab.h:40 `AUDIT_SUBJ_TYPE`; libaudit.c:1816
/// - `SubjSen`: fieldtab.h:41 `AUDIT_SUBJ_SEN`; libaudit.c:1817
/// - `SubjClr`: fieldtab.h:42 `AUDIT_SUBJ_CLR`; libaudit.c:1818
/// - `ObjUser`: fieldtab.h:44 `AUDIT_OBJ_USER`; libaudit.c:1799
/// - `ObjRole`: fieldtab.h:45 `AUDIT_OBJ_ROLE`; libaudit.c:1800
/// - `ObjType`: fieldtab.h:46 `AUDIT_OBJ_TYPE`; libaudit.c:1801
/// - `ObjLevLow`: fieldtab.h:47 `AUDIT_OBJ_LEV_LOW`; libaudit.c:1802
/// - `ObjLevHigh`: fieldtab.h:48 `AUDIT_OBJ_LEV_HIGH`; libaudit.c:1803
/// - `Path`: fieldtab.h:56 `AUDIT_WATCH`; libaudit.c:1804 path/dir string
/// - `Dir`: fieldtab.h:58 `AUDIT_DIR`; libaudit.c:1805 dir string
/// - `Key`: fieldtab.h:70 `AUDIT_FILTERKEY`; libaudit.c:1819 key string
/// - `Inode`: fieldtab.h:53 `AUDIT_INODE=102`; libaudit.c:1997-2000 =|!= only (`EAU_OPEQNOTEQ`)
/// - `Exit`: fieldtab.h:54 `AUDIT_EXIT`; libaudit.c:1765 exit case, strtol, signed
/// - `Perm`: fieldtab.h:57 `AUDIT_PERM`; libaudit.c:1888-1892 op=only = (`EAU_OPEQ`)
/// - `Filetype`: fieldtab.h:59 `AUDIT_FILETYPE`; libaudit.c:1929-1937, no op restriction
/// - `Fstype`: fieldtab.h:60 `AUDIT_FSTYPE`; libaudit.c:1938-1941 op=only =|!= (`EAU_OPEQNOTEQ`)
/// - `SaddrFam`: fieldtab.h:72 `AUDIT_SADDR_FAM=113`; libaudit.c:1986-1990, no op restriction
/// - `Exe`: fieldtab.h:71 `AUDIT_EXE`; libaudit.c:1821-1826 op=only =|!= (`EAU_OPEQNOTEQ`)
#[must_use]
pub fn field_type(field: &AuditField) -> FieldType {
    match field {
        // Numeric (full relational + bitmask): no op restriction in libaudit.c
        // fieldtab.h lines: Pid:24, Ppid:43, Pers:35, SessionId:49, DevMajor:51,
        //   DevMinor:52, Success:55, A0-A3:65-68, FieldCompare:63 (unreachable in -F)
        AuditField::Pid
        | AuditField::Ppid
        | AuditField::Pers
        | AuditField::SessionId
        | AuditField::DevMajor
        | AuditField::DevMinor
        | AuditField::Success
        | AuditField::A0
        | AuditField::A1
        | AuditField::A2
        | AuditField::A3
        | AuditField::FieldCompare => FieldType::Numeric,

        // Uid (user-id resolution): fieldtab.h:25-34,61; libaudit.c:1721-1747
        AuditField::Uid
        | AuditField::Euid
        | AuditField::Suid
        | AuditField::Fsuid
        | AuditField::Auid
        | AuditField::ObjUid => FieldType::Uid,

        // Gid (group-id resolution): fieldtab.h:29-32,62; libaudit.c:1748-1763
        AuditField::Gid
        | AuditField::Egid
        | AuditField::Sgid
        | AuditField::Fsgid
        | AuditField::ObjGid => FieldType::Gid,

        // Arch: fieldtab.h:36 AUDIT_ARCH; libaudit.c:1858 EAU_OPEQNOTEQ (=|!= only)
        AuditField::Arch => FieldType::Arch,

        // MsgType: fieldtab.h:37 AUDIT_MSGTYPE; libaudit.c:1783, no op restriction
        AuditField::MsgType => FieldType::MsgType,

        // String (unrestricted -- no op guard in libaudit.c for these fields):
        //   subj_*: fieldtab.h:38-42; libaudit.c:1814-1818
        //   obj_user/role/type/lev: fieldtab.h:44-48; libaudit.c:1799-1803
        //   path (AUDIT_WATCH): fieldtab.h:56; libaudit.c:1804
        //   dir (AUDIT_DIR):   fieldtab.h:58; libaudit.c:1805
        //   key (AUDIT_FILTERKEY): fieldtab.h:70; libaudit.c:1819
        AuditField::SubjUser
        | AuditField::SubjRole
        | AuditField::SubjType
        | AuditField::SubjSen
        | AuditField::SubjClr
        | AuditField::ObjUser
        | AuditField::ObjRole
        | AuditField::ObjType
        | AuditField::ObjLevLow
        | AuditField::ObjLevHigh
        | AuditField::Path
        | AuditField::Dir => FieldType::String,

        // Key: fieldtab.h:70 AUDIT_FILTERKEY; libaudit.c:1819
        //   Falls through to the AUDIT_EXE block but the EAU_OPEQNOTEQ guard at
        //   libaudit.c:1825 is inside `if (field == AUDIT_EXE)`, NOT applied to key.
        AuditField::Key => FieldType::Key,

        // NumericEqNe: inode -- libaudit.c:1997-2000 EAU_OPEQNOTEQ (=|!= only)
        //   fieldtab.h:53 AUDIT_INODE=102; the restriction is an inner if-guard
        //   inside the AUDIT_DEVMAJOR..AUDIT_INODE+SUCCESS range arm.
        AuditField::Inode => FieldType::NumericEqNe,

        // NumericSigned: exit accepts negative errno; libaudit.c:1765, no op restriction
        //   fieldtab.h:54 AUDIT_EXIT
        AuditField::Exit => FieldType::NumericSigned,

        // Perm: fieldtab.h:57 AUDIT_PERM; libaudit.c:1892 EAU_OPEQ (= only)
        AuditField::Perm => FieldType::Perm,

        // Filetype: fieldtab.h:59 AUDIT_FILETYPE; libaudit.c:1929-1937, no op restriction
        AuditField::Filetype => FieldType::Filetype,

        // FsType: fieldtab.h:60 AUDIT_FSTYPE; libaudit.c:1941 EAU_OPEQNOTEQ (=|!= only)
        AuditField::Fstype => FieldType::FsType,

        // SaddrFam: fieldtab.h:72 AUDIT_SADDR_FAM=113; libaudit.c:1986-1990, no op restriction
        AuditField::SaddrFam => FieldType::SaddrFam,

        // StringEqNe: exe -- libaudit.c:1825 EAU_OPEQNOTEQ (=|!= only)
        //   fieldtab.h:71 AUDIT_EXE; the one string-typed field with an op restriction.
        AuditField::Exe => FieldType::StringEqNe,
    }
}
