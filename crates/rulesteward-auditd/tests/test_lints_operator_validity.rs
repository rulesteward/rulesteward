//! RED barrier tests for au-E02 operator-validity lint + per-field type table
//! (pipeline P3, issue #193).
//!
//! # Grounding
//! The per-field operator-validity matrix is built entirely from primary sources
//! at audit-userspace commit 3bfa048:
//!
//! - `lib/fieldtab.h` lines 24-72 -- 46 canonical `-F` field names + AUDIT_*
//!   constants (46 entries counting `auid`/`loginuid` as one logical field).
//! - `lib/libaudit.c` `audit_rule_fieldpair_data` (lines 1621-2019) -- the
//!   per-field switch that validates operator/value pairs and returns
//!   `-EAU_OPEQNOTEQ` or `-EAU_OPEQ` on rejection.
//!
//! # Key finding (verified, not assumed)
//! Only FIVE fields have an explicit operator restriction in
//! `audit_rule_fieldpair_data` (3bfa048):
//!
//! | Field(s)         | Allowed operators  | Source line  |
//! |------------------|--------------------|--------------|
//! | `exe`            | `=` and `!=` only  | libaudit.c:1825 |
//! | `arch`           | `=` and `!=` only  | libaudit.c:1858 |
//! | `fstype`         | `=` and `!=` only  | libaudit.c:1941 |
//! | `inode`          | `=` and `!=` only  | libaudit.c:1998 |
//! | `perm`           | `=` only           | libaudit.c:1892 |
//!
//! All other fields (including the string-valued `subj_*`, `obj_*`, `path`,
//! `dir`, `key`, `filetype`, etc.) have NO operator restriction in libaudit.c
//! and accept all 8 operators (`= != < > <= >= & &=`). The lint therefore emits
//! au-E02 ONLY for these five field families.
//!
//! # Scope
//! au-E02 is `-F` only.  `-C` is already parser-restricted to `=`/`!=`
//! (see `parse_field_compare` in parser.rs), so an invalid `-C` operator is a
//! parse error, not a lint finding.

use std::path::Path;

use rulesteward_auditd::{
    AuditField, TargetVersion,
    lints::field_type::{FieldType, field_type},
    lints::operator_validity::{e02, e05},
    parse_rules_str_located,
};
use rulesteward_core::Severity;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a multi-line rules string from a synthetic file path, panicking on
/// any parse error (invalid test fixture syntax is a test-author bug).
fn located(input: &str) -> Vec<rulesteward_auditd::LocatedRule> {
    let file = Path::new("/etc/audit/rules.d/99-test.rules");
    parse_rules_str_located(input, file).expect("fixture must parse")
}

/// Run e02 on one or more inline rule strings and return the diagnostics.
fn lint(input: &str) -> Vec<rulesteward_core::Diagnostic> {
    e02(&located(input))
}

/// Run e02 and assert no findings (clean pass).
fn assert_clean(input: &str) {
    let diags = lint(input);
    assert!(
        diags.is_empty(),
        "expected no au-E02 for:\n  {input}\ngot: {diags:#?}"
    );
}

/// Run e02 and assert exactly one finding with code "au-E02" and
/// `Severity::Error`, naming `field` and `op` in the message.
fn assert_e02(input: &str, field: &str, op: &str) {
    let diags = lint(input);
    assert_eq!(
        diags.len(),
        1,
        "expected exactly 1 au-E02 for:\n  {input}\ngot: {diags:#?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Error, "severity must be Error");
    assert_eq!(d.code, "au-E02", "code must be au-E02");
    assert!(
        d.message.contains(field),
        "message must name the field '{field}': '{}'",
        d.message
    );
    assert!(
        d.message.contains(op),
        "message must name the operator '{op}': '{}'",
        d.message
    );
}

// ---------------------------------------------------------------------------
// 1. field_type() unit table -- all 46 fields
//
// Each row cites the fieldtab.h entry (field name -> AUDIT_* constant) and the
// libaudit.c switch arm (or default) that determines the FieldType assignment.
//
// Key for the source refs:
//   fieldtab.h:L  -- lib/fieldtab.h line L at 3bfa048
//   libaudit.c:L  -- lib/libaudit.c line L at 3bfa048
// ---------------------------------------------------------------------------

/// `AuditField` enum -> expected `FieldType` for every one of the 46 fields.
///
/// NOTE: if a future impl returns `Numeric` for every field, these tests WILL
/// fail on the `String`/`StringEqNe`/`Arch`/`Perm`/`Uid`/`Gid`/`MsgType`/`Filetype`/`Key`/`FsType`/`SaddrFam`
/// rows. That is the adversarial property this table is designed to catch.
/// In particular `exe` -> `StringEqNe` and `path`/`dir`/`subj_*`/`obj_*`/`key` ->
/// `String`; a wrong impl lumping both into `String` would emit false-positive
/// au-E02 on the unrestricted-field negative tests in Section 3.
#[test]
#[allow(clippy::too_many_lines)]
fn field_type_covers_all_46_fields() {
    // (field, expected_type, citation_comment)
    let cases: &[(AuditField, FieldType, &str)] = &[
        // -- PID family: fieldtab.h:24-43, libaudit.c default (line 2001+)
        //    numeric, no special handling, strtol()
        (
            AuditField::Pid,
            FieldType::Numeric,
            "fieldtab.h:24 AUDIT_PID=0; libaudit.c:2006 strtol default",
        ),
        (
            AuditField::Ppid,
            FieldType::Numeric,
            "fieldtab.h:43 AUDIT_PPID; libaudit.c:2003 ppid+default strtol",
        ),
        (
            AuditField::Pers,
            FieldType::Numeric,
            "fieldtab.h:35 AUDIT_PERS=10; libaudit.c default, numeric strtol",
        ),
        // -- UID family: fieldtab.h:25-33,34, libaudit.c:1721-1747
        //    strtoul for positive, strtol for negative / name resolution
        (
            AuditField::Uid,
            FieldType::Uid,
            "fieldtab.h:25 AUDIT_UID=1; libaudit.c:1721 UID case",
        ),
        (
            AuditField::Euid,
            FieldType::Uid,
            "fieldtab.h:26 AUDIT_EUID=2; libaudit.c:1722",
        ),
        (
            AuditField::Suid,
            FieldType::Uid,
            "fieldtab.h:27 AUDIT_SUID=3; libaudit.c:1723",
        ),
        (
            AuditField::Fsuid,
            FieldType::Uid,
            "fieldtab.h:28 AUDIT_FSUID=4; libaudit.c:1724",
        ),
        (
            AuditField::Auid,
            FieldType::Uid,
            "fieldtab.h:33-34 AUDIT_LOGINUID; libaudit.c:1725",
        ),
        (
            AuditField::ObjUid,
            FieldType::Uid,
            "fieldtab.h:61 AUDIT_OBJ_UID; libaudit.c:1726",
        ),
        // -- GID family: fieldtab.h:29-32,62, libaudit.c:1748-1763
        //    strtol + gid name resolution
        (
            AuditField::Gid,
            FieldType::Gid,
            "fieldtab.h:29 AUDIT_GID=5; libaudit.c:1748 GID case",
        ),
        (
            AuditField::Egid,
            FieldType::Gid,
            "fieldtab.h:30 AUDIT_EGID=6; libaudit.c:1749",
        ),
        (
            AuditField::Sgid,
            FieldType::Gid,
            "fieldtab.h:31 AUDIT_SGID=7; libaudit.c:1750",
        ),
        (
            AuditField::Fsgid,
            FieldType::Gid,
            "fieldtab.h:32 AUDIT_FSGID=8; libaudit.c:1751",
        ),
        (
            AuditField::ObjGid,
            FieldType::Gid,
            "fieldtab.h:62 AUDIT_OBJ_GID; libaudit.c:1752",
        ),
        // -- Arch: fieldtab.h:36 AUDIT_ARCH; libaudit.c:1855-1887
        //    ONLY = and != accepted (libaudit.c:1858)
        (
            AuditField::Arch,
            FieldType::Arch,
            "fieldtab.h:36 AUDIT_ARCH; libaudit.c:1855 arch case, op=only =|!=",
        ),
        // -- MsgType: fieldtab.h:37 AUDIT_MSGTYPE; libaudit.c:1783-1797
        //    numeric or named message type; no operator restriction in switch
        (
            AuditField::MsgType,
            FieldType::MsgType,
            "fieldtab.h:37 AUDIT_MSGTYPE; libaudit.c:1783, no op restriction",
        ),
        // -- SELinux subject context strings: fieldtab.h:38-42
        //    libaudit.c:1814-1818, string fallthrough, no op restriction
        (
            AuditField::SubjUser,
            FieldType::String,
            "fieldtab.h:38 AUDIT_SUBJ_USER; libaudit.c:1814, string, no op restriction",
        ),
        (
            AuditField::SubjRole,
            FieldType::String,
            "fieldtab.h:39 AUDIT_SUBJ_ROLE; libaudit.c:1815",
        ),
        (
            AuditField::SubjType,
            FieldType::String,
            "fieldtab.h:40 AUDIT_SUBJ_TYPE; libaudit.c:1816",
        ),
        (
            AuditField::SubjSen,
            FieldType::String,
            "fieldtab.h:41 AUDIT_SUBJ_SEN; libaudit.c:1817",
        ),
        (
            AuditField::SubjClr,
            FieldType::String,
            "fieldtab.h:42 AUDIT_SUBJ_CLR; libaudit.c:1818",
        ),
        // -- SELinux object context strings: fieldtab.h:44-48
        //    libaudit.c:1799-1803, string fallthrough, no op restriction
        (
            AuditField::ObjUser,
            FieldType::String,
            "fieldtab.h:44 AUDIT_OBJ_USER; libaudit.c:1799",
        ),
        (
            AuditField::ObjRole,
            FieldType::String,
            "fieldtab.h:45 AUDIT_OBJ_ROLE; libaudit.c:1800",
        ),
        (
            AuditField::ObjType,
            FieldType::String,
            "fieldtab.h:46 AUDIT_OBJ_TYPE; libaudit.c:1801",
        ),
        (
            AuditField::ObjLevLow,
            FieldType::String,
            "fieldtab.h:47 AUDIT_OBJ_LEV_LOW; libaudit.c:1802",
        ),
        (
            AuditField::ObjLevHigh,
            FieldType::String,
            "fieldtab.h:48 AUDIT_OBJ_LEV_HIGH; libaudit.c:1803",
        ),
        // -- SessionID: fieldtab.h:49 AUDIT_SESSIONID
        //    libaudit.c:1966-1984, strtoul/strtol/unset; no op restriction. Its
        //    own FieldType (#270 AUD-3): a u32 with the unset/-1/4294967295
        //    sentinel like uid/gid (but no name resolution), so the sentinel
        //    folds for sessionid without folding plain Numeric fields like pid.
        (
            AuditField::SessionId,
            FieldType::SessionId,
            "fieldtab.h:49 AUDIT_SESSIONID=25; libaudit.c:1966-1984 u32 strtoul + unset/4294967295 sentinel (#270 AUD-3)",
        ),
        // -- DevMajor/DevMinor/Inode: fieldtab.h:51-53
        //    libaudit.c:1991 AUDIT_DEVMAJOR..AUDIT_INODE range + SUCCESS
        //    Inode: ONLY = and != (libaudit.c:1997-2000)
        (
            AuditField::DevMajor,
            FieldType::Numeric,
            "fieldtab.h:51 AUDIT_DEVMAJOR=100; libaudit.c:1991 range, numeric",
        ),
        (
            AuditField::DevMinor,
            FieldType::Numeric,
            "fieldtab.h:52 AUDIT_DEVMINOR=101; libaudit.c:1991 range, numeric",
        ),
        (
            AuditField::Inode,
            FieldType::NumericEqNe,
            "fieldtab.h:53 AUDIT_INODE=102; libaudit.c:1997-2000 =|!= only (EAU_OPEQNOTEQ); NumericEqNe per session-6a taxonomy",
        ),
        // -- Exit: fieldtab.h:54 AUDIT_EXIT; libaudit.c:1765-1781
        //    Signed (accepts negative errno). No operator restriction.
        (
            AuditField::Exit,
            FieldType::NumericSigned,
            "fieldtab.h:54 AUDIT_EXIT; libaudit.c:1765 exit case, strtol, signed",
        ),
        // -- Success: fieldtab.h:55 AUDIT_SUCCESS=104; libaudit.c:1992 (in range fallthrough)
        //    numeric strtol, no op restriction
        (
            AuditField::Success,
            FieldType::Numeric,
            "fieldtab.h:55 AUDIT_SUCCESS=104; libaudit.c:1992 range fallthrough",
        ),
        // -- Path/Dir: fieldtab.h:56-58 AUDIT_WATCH/AUDIT_DIR
        //    libaudit.c:1804-1811, string fallthrough, no op restriction
        (
            AuditField::Path,
            FieldType::String,
            "fieldtab.h:56 AUDIT_WATCH; libaudit.c:1804 path/dir string",
        ),
        (
            AuditField::Dir,
            FieldType::String,
            "fieldtab.h:58 AUDIT_DIR; libaudit.c:1805 dir string",
        ),
        // -- Perm: fieldtab.h:57 AUDIT_PERM; libaudit.c:1888-1928
        //    ONLY = accepted (libaudit.c:1892 EAU_OPEQ)
        (
            AuditField::Perm,
            FieldType::Perm,
            "fieldtab.h:57 AUDIT_PERM; libaudit.c:1888-1892 op=only =",
        ),
        // -- Filetype: fieldtab.h:59 AUDIT_FILETYPE; libaudit.c:1929-1937
        //    audit_name_to_ftype() value; no op restriction
        (
            AuditField::Filetype,
            FieldType::Filetype,
            "fieldtab.h:59 AUDIT_FILETYPE; libaudit.c:1929-1937, no op restriction",
        ),
        // -- FsType: fieldtab.h:60 AUDIT_FSTYPE; libaudit.c:1938-1953
        //    ONLY = and != (libaudit.c:1941 EAU_OPEQNOTEQ)
        (
            AuditField::Fstype,
            FieldType::FsType,
            "fieldtab.h:60 AUDIT_FSTYPE; libaudit.c:1938-1941 op=only =|!=",
        ),
        // -- Syscall args: fieldtab.h:65-68 AUDIT_ARG0..AUDIT_ARG3
        //    libaudit.c:1954-1964, strtoul/strtol; no op restriction
        (
            AuditField::A0,
            FieldType::Numeric,
            "fieldtab.h:65 AUDIT_ARG0=200; libaudit.c:1954 ARG range",
        ),
        (
            AuditField::A1,
            FieldType::Numeric,
            "fieldtab.h:66 AUDIT_ARG1; libaudit.c:1954 ARG range",
        ),
        (
            AuditField::A2,
            FieldType::Numeric,
            "fieldtab.h:67 AUDIT_ARG2; libaudit.c:1954 ARG range",
        ),
        (
            AuditField::A3,
            FieldType::Numeric,
            "fieldtab.h:68 AUDIT_ARG3; libaudit.c:1954 ARG range",
        ),
        // -- Key: fieldtab.h:70 AUDIT_FILTERKEY; libaudit.c:1819
        //    string (buf), no operator restriction in libaudit.c switch
        (
            AuditField::Key,
            FieldType::Key,
            "fieldtab.h:70 AUDIT_FILTERKEY; libaudit.c:1819 key string",
        ),
        // -- Exe: fieldtab.h:71 AUDIT_EXE; libaudit.c:1820-1828
        //    ONLY = and != (libaudit.c:1825 EAU_OPEQNOTEQ) -- the PRIMARY
        //    motivating case for au-E02.
        //    Session 6a: now maps to StringEqNe (distinct from the unrestricted
        //    String fields such as path/dir/subj_*/obj_*/key).
        (
            AuditField::Exe,
            FieldType::StringEqNe,
            "fieldtab.h:71 AUDIT_EXE; libaudit.c:1821-1826 op=only =|!= (EAU_OPEQNOTEQ); StringEqNe per session-6a taxonomy",
        ),
        // -- SaddrFam: fieldtab.h:72 AUDIT_SADDR_FAM; libaudit.c:1986-1990
        //    strtoul AF_* value; no operator restriction in switch
        (
            AuditField::SaddrFam,
            FieldType::SaddrFam,
            "fieldtab.h:72 AUDIT_SADDR_FAM=113; libaudit.c:1986-1990, no op restriction",
        ),
    ];

    // Count how many fields we cover -- the table must have exactly 44 entries.
    // fieldtab.h has 46 entries (lines 24-72 at 3bfa048), but:
    //   - auid/loginuid (lines 33-34) are one logical field, one AuditField variant
    //   - field_compare (line 63, AUDIT_FIELD_COMPARE) is a -C pseudo-field, not -F
    // 46 - 1 (loginuid alias) - 1 (field_compare is -C only) = 44
    assert_eq!(
        cases.len(),
        44,
        "expected 44 field_type() rows \
         (46 fieldtab.h names - 1 loginuid alias - 1 field_compare which is -C only)"
    );

    for (field, expected, citation) in cases {
        let got = field_type(field);
        assert_eq!(
            got, *expected,
            "field_type({field:?}) = {got:?}, want {expected:?}\n  citation: {citation}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. au-E02 fires for rejected operator/field pairings
//    (each test is a known-answer; the cited reject path is in libaudit.c
//     at commit 3bfa048)
// ---------------------------------------------------------------------------

// --- exe: only = and != accepted (libaudit.c:1825, EAU_OPEQNOTEQ) ---

/// `-F exe>=...` fires au-E02 (relational not allowed for exe).
/// Grounded: libaudit.c:1825 `if (!(op == AUDIT_NOT_EQUAL || op == AUDIT_EQUAL)) return -EAU_OPEQNOTEQ`
#[test]
fn e02_exe_greater_equal_is_error() {
    assert_e02(
        "-a always,exit -S execve -F exe>=/usr/bin/bash",
        "exe",
        ">=",
    );
}

/// `-F exe>/usr/bin` fires au-E02.
#[test]
fn e02_exe_greater_than_is_error() {
    assert_e02("-a always,exit -S execve -F exe>/usr/bin", "exe", ">");
}

/// `-F exe</usr/bin` fires au-E02.
#[test]
fn e02_exe_less_than_is_error() {
    assert_e02("-a always,exit -S execve -F exe</usr/bin", "exe", "<");
}

/// `-F exe<=/usr/bin` fires au-E02.
#[test]
fn e02_exe_less_equal_is_error() {
    assert_e02("-a always,exit -S execve -F exe<=/usr/bin", "exe", "<=");
}

/// `-F exe&0x1` fires au-E02 (bitmask not allowed for exe).
#[test]
fn e02_exe_bitand_is_error() {
    assert_e02("-a always,exit -S execve -F exe&0x1", "exe", "&");
}

/// `-F exe&=0x1` fires au-E02.
#[test]
fn e02_exe_bitand_eq_is_error() {
    assert_e02("-a always,exit -S execve -F exe&=0x1", "exe", "&=");
}

/// `-F exe=/usr/bin/bash` does NOT fire (`=` is accepted).
/// Grounded: libaudit.c:1825 accepts `AUDIT_EQUAL`.
#[test]
fn e02_exe_eq_is_clean() {
    assert_clean("-a always,exit -S execve -F exe=/usr/bin/bash");
}

/// `-F exe!=/usr/bin/bash` does NOT fire (!= is accepted).
#[test]
fn e02_exe_ne_is_clean() {
    assert_clean("-a always,exit -S execve -F exe!=/usr/bin/bash");
}

// --- arch: only = and != accepted (libaudit.c:1858, EAU_OPEQNOTEQ) ---

/// `-F arch>=b64` fires au-E02.
/// Grounded: libaudit.c:1858 `if (!(op == AUDIT_NOT_EQUAL || op == AUDIT_EQUAL)) return -EAU_OPEQNOTEQ`
#[test]
fn e02_arch_greater_equal_is_error() {
    assert_e02("-a always,exit -F arch>=b64 -S execve", "arch", ">=");
}

/// `-F arch<b32` fires au-E02.
#[test]
fn e02_arch_less_than_is_error() {
    assert_e02("-a always,exit -F arch<b32 -S execve", "arch", "<");
}

/// `-F arch&0xff` fires au-E02.
#[test]
fn e02_arch_bitand_is_error() {
    assert_e02("-a always,exit -F arch&0xff -S execve", "arch", "&");
}

/// `-F arch=b64` does NOT fire.
#[test]
fn e02_arch_eq_is_clean() {
    assert_clean("-a always,exit -F arch=b64 -S execve");
}

/// `-F arch!=b32` does NOT fire.
#[test]
fn e02_arch_ne_is_clean() {
    assert_clean("-a always,exit -F arch!=b32 -S execve");
}

// --- fstype: only = and != accepted (libaudit.c:1941, EAU_OPEQNOTEQ) ---

/// `-F fstype>ext4` fires au-E02.
/// Grounded: libaudit.c:1941 `if (!(op == AUDIT_NOT_EQUAL || op == AUDIT_EQUAL)) return -EAU_OPEQNOTEQ`
#[test]
fn e02_fstype_greater_is_error() {
    assert_e02("-a always,filesystem -F fstype>ext4", "fstype", ">");
}

/// `-F fstype&=0x1` fires au-E02.
#[test]
fn e02_fstype_bitand_eq_is_error() {
    assert_e02("-a always,filesystem -F fstype&=0x1", "fstype", "&=");
}

/// `-F fstype=ext4` does NOT fire.
#[test]
fn e02_fstype_eq_is_clean() {
    assert_clean("-a always,filesystem -F fstype=ext4");
}

/// `-F fstype!=tmpfs` does NOT fire.
#[test]
fn e02_fstype_ne_is_clean() {
    assert_clean("-a always,filesystem -F fstype!=tmpfs");
}

// --- inode: only = and != accepted (libaudit.c:1997-2000, EAU_OPEQNOTEQ) ---

/// `-F inode>100` fires au-E02.
/// Grounded: libaudit.c:1998 `if (!(op == AUDIT_NOT_EQUAL || op == AUDIT_EQUAL)) return -EAU_OPEQNOTEQ`
/// Note: inode is in the `AUDIT_DEVMAJOR`..`AUDIT_INODE` range + `SUCCESS` default arm
/// but has its OWN op check inside that arm (lines 1997-2000).
#[test]
fn e02_inode_greater_is_error() {
    assert_e02("-a always,exit -S openat -F inode>100", "inode", ">");
}

/// `-F inode<=999` fires au-E02.
#[test]
fn e02_inode_less_equal_is_error() {
    assert_e02("-a always,exit -S openat -F inode<=999", "inode", "<=");
}

/// `-F inode&0xff` fires au-E02.
#[test]
fn e02_inode_bitand_is_error() {
    assert_e02("-a always,exit -S openat -F inode&0xff", "inode", "&");
}

/// `-F inode=131` does NOT fire.
#[test]
fn e02_inode_eq_is_clean() {
    assert_clean("-a always,exit -S openat -F inode=131");
}

/// `-F inode!=131` does NOT fire.
#[test]
fn e02_inode_ne_is_clean() {
    assert_clean("-a always,exit -S openat -F inode!=131");
}

// --- perm: only = accepted (libaudit.c:1892, EAU_OPEQ) ---

/// `-F perm!=rwx` fires au-E02 (!= is not the permitted = op).
/// Grounded: libaudit.c:1892 `else if (op != AUDIT_EQUAL) return -EAU_OPEQ`
#[test]
fn e02_perm_ne_is_error() {
    assert_e02("-a always,exit -S openat -F perm!=rwx", "perm", "!=");
}

/// `-F perm>r` fires au-E02 (relational not allowed).
#[test]
fn e02_perm_greater_is_error() {
    assert_e02("-a always,exit -S openat -F perm>r", "perm", ">");
}

/// `-F perm&=r` fires au-E02 (bitmask not allowed for perm).
/// Grounded: libaudit.c:1892 only `AUDIT_EQUAL` is permitted.
#[test]
fn e02_perm_bitand_eq_is_error() {
    assert_e02("-a always,exit -S openat -F perm&=r", "perm", "&=");
}

/// `-F perm&r` fires au-E02.
#[test]
fn e02_perm_bitand_is_error() {
    assert_e02("-a always,exit -S openat -F perm&r", "perm", "&");
}

/// `-F perm=r` does NOT fire.
/// Grounded: libaudit.c:1892 `AUDIT_EQUAL` is the only accepted op.
#[test]
fn e02_perm_eq_is_clean() {
    assert_clean("-a always,exit -S openat -F perm=r");
}

// ---------------------------------------------------------------------------
// 3. Fields that accept ALL 8 operators -- au-E02 must NOT fire
//    (verifies the lint does not over-reject; adversarial vs. a constant-false
//     or over-eager impl that blanket-rejects relational on numeric fields)
// ---------------------------------------------------------------------------

/// Numeric uid family: relational + bitmask all accepted.
/// Grounded: libaudit.c:1721-1747 UID case, no op restriction.
#[test]
fn e02_uid_relational_all_clean() {
    assert_clean("-a always,exit -S execve -F uid=500");
    assert_clean("-a always,exit -S execve -F uid!=500");
    assert_clean("-a always,exit -S execve -F uid<500");
    assert_clean("-a always,exit -S execve -F uid>500");
    assert_clean("-a always,exit -S execve -F uid<=500");
    assert_clean("-a always,exit -S execve -F uid>=500");
    assert_clean("-a always,exit -S execve -F uid&0x1");
    assert_clean("-a always,exit -S execve -F uid&=0x1");
}

/// auid/loginuid: same UID case arm (libaudit.c:1725), all ops clean.
#[test]
fn e02_auid_relational_all_clean() {
    assert_clean("-a always,exit -S execve -F auid>=1000");
    assert_clean("-a always,exit -S execve -F auid!=4294967295");
}

/// GID family: libaudit.c:1748, no op restriction.
#[test]
fn e02_gid_relational_all_clean() {
    assert_clean("-a always,exit -S execve -F gid<1000");
    assert_clean("-a always,exit -S execve -F egid>=500");
}

/// exit (signed numeric): libaudit.c:1765, no op restriction.
#[test]
fn e02_exit_signed_all_clean() {
    assert_clean("-a always,exit -S openat -F exit=-13");
    assert_clean("-a always,exit -S openat -F exit!=0");
    assert_clean("-a always,exit -S openat -F exit<0");
}

/// pid: libaudit.c default, no op restriction.
#[test]
fn e02_pid_relational_all_clean() {
    assert_clean("-a always,exit -S execve -F pid>100");
    assert_clean("-a always,exit -S execve -F pid!=1");
}

/// ppid: libaudit.c:2003 (default arm), no op restriction.
#[test]
fn e02_ppid_relational_all_clean() {
    assert_clean("-a always,exit -S fork -F ppid!=0");
    assert_clean("-a always,exit -S fork -F ppid>1");
}

/// sessionid: libaudit.c:1966, no op restriction.
#[test]
fn e02_sessionid_relational_all_clean() {
    assert_clean("-a always,exit -S execve -F sessionid!=4294967295");
    assert_clean("-a always,exit -S execve -F sessionid>0");
}

/// devmajor: libaudit.c:1991 range, no op restriction beyond that arm.
#[test]
fn e02_devmajor_relational_all_clean() {
    assert_clean("-a always,exit -S openat -F devmajor!=8");
    assert_clean("-a always,exit -S openat -F devmajor>0");
}

/// devminor: same range arm, no op restriction.
#[test]
fn e02_devminor_relational_all_clean() {
    assert_clean("-a always,exit -S openat -F devminor!=0");
}

/// a0..a3: libaudit.c:1954 ARG range, no op restriction.
#[test]
fn e02_arg_registers_all_clean() {
    assert_clean("-a always,exit -S ioctl -F a1=0x5401");
    assert_clean("-a always,exit -S ioctl -F a1&0xff00");
    assert_clean("-a always,exit -S ioctl -F a2>=0");
}

/// String-valued fields (subj_*, obj_*, path, dir, key): libaudit.c
/// string fallthrough 1799-1853 has NO op restriction except for exe
/// (line 1825). All 8 operators are accepted by libaudit for these.
#[test]
fn e02_string_fields_no_restriction_all_clean() {
    // subj_user: libaudit.c:1814
    assert_clean("-a always,exit -S execve -F subj_user=system_u");
    assert_clean("-a always,exit -S execve -F subj_user!=system_u");
    // subj_type: libaudit.c:1816
    assert_clean("-a always,exit -S execve -F subj_type=init_t");
    // obj_user: libaudit.c:1799
    assert_clean("-a always,exit -S openat -F obj_user=root");
    // obj_type: libaudit.c:1801
    assert_clean("-a always,exit -S openat -F obj_type=etc_t");
    // path (AUDIT_WATCH): libaudit.c:1804
    assert_clean("-a always,exit -S openat -F path=/etc/passwd");
    // dir (AUDIT_DIR): libaudit.c:1805
    assert_clean("-a always,exit -S openat -F dir=/etc");
    // key (AUDIT_FILTERKEY): libaudit.c:1819
    assert_clean("-a always,exit -S execve -k mykey");
}

/// Unrestricted path/dir fields accept ALL 8 operators including relational
/// and bitmask.
///
/// Grounding: libaudit.c:1804-1811 (`AUDIT_WATCH` / `AUDIT_DIR` cases) fall through
/// to the string block at 1813 and reach `break` at 1854 with NO operator check.
/// Only `AUDIT_EXE` at line 1825 has the `EAU_OPEQNOTEQ` guard inside that block.
/// Cite: libaudit.c:1804 `case AUDIT_WATCH:`, 1805 `case AUDIT_DIR:`,
///       fallthrough to 1813, no op check, break at 1854.
///
/// A wrong impl that restricts every `FieldType::String` field to =/!= would
/// emit au-E02 on these valid rules and fail these tests.
#[test]
fn e02_path_relational_and_bitmask_all_clean() {
    // relational: libaudit.c:1804 AUDIT_WATCH, no EAU_OPEQNOTEQ guard
    assert_clean("-a always,exit -S openat -F path>/etc/passwd");
    assert_clean("-a always,exit -S openat -F path>=/etc");
    assert_clean("-a always,exit -S openat -F path</etc/z");
    assert_clean("-a always,exit -S openat -F path<=/etc/z");
    // bitmask: same path -- no op restriction in the switch arm
    assert_clean("-a always,exit -S openat -F path&0x1");
    assert_clean("-a always,exit -S openat -F path&=0x1");
}

/// Unrestricted dir field accepts ALL 8 operators.
///
/// Grounding: libaudit.c:1805 `case AUDIT_DIR:` falls through to 1813 with
/// no operator check; break at 1854. Same path as `AUDIT_WATCH` above.
#[test]
fn e02_dir_relational_and_bitmask_all_clean() {
    // relational: libaudit.c:1805 AUDIT_DIR, no op guard
    assert_clean("-a always,exit -S openat -F dir<=/x");
    assert_clean("-a always,exit -S openat -F dir>/tmp");
    // bitmask
    assert_clean("-a always,exit -S openat -F dir&0x1");
    assert_clean("-a always,exit -S openat -F dir&=0x2");
}

/// Unrestricted `SELinux` subject-context fields accept ALL 8 operators.
///
/// Grounding: libaudit.c:1814-1818 cases (`AUDIT_SUBJ_USER` through
/// `AUDIT_SUBJ_CLR`) fall through directly to 1819 with no op check and reach
/// break at 1854 with no guard applied. Cite: libaudit.c:1814, 1816, 1854.
#[test]
fn e02_subj_context_relational_and_bitmask_all_clean() {
    // subj_user: libaudit.c:1814
    assert_clean("-a always,exit -S execve -F subj_user>system_u");
    assert_clean("-a always,exit -S execve -F subj_user>=unconfined_u");
    assert_clean("-a always,exit -S execve -F subj_user&0x1");
    assert_clean("-a always,exit -S execve -F subj_user&=0xff");
    // subj_type: libaudit.c:1816
    assert_clean("-a always,exit -S execve -F subj_type>init_t");
    assert_clean("-a always,exit -S execve -F subj_type<=unconfined_t");
}

/// Unrestricted `SELinux` object-context fields accept ALL 8 operators.
///
/// Grounding: libaudit.c:1799-1803 cases (`AUDIT_OBJ_USER` through
/// `AUDIT_OBJ_LEV_HIGH`) fall through to the `AUDIT_WATCH`/DIR block at 1804,
/// then continue to the string block; break at 1854 with no op guard.
/// Cite: libaudit.c:1799, 1801, 1803, 1854.
#[test]
fn e02_obj_context_relational_and_bitmask_all_clean() {
    // obj_user: libaudit.c:1799
    assert_clean("-a always,exit -S openat -F obj_user>root");
    assert_clean("-a always,exit -S openat -F obj_user<system_u");
    // obj_type: libaudit.c:1801
    assert_clean("-a always,exit -S openat -F obj_type>etc_t");
    assert_clean("-a always,exit -S openat -F obj_type&0x1");
    assert_clean("-a always,exit -S openat -F obj_type&=0x80");
}

/// key (`AUDIT_FILTERKEY`) accepts ALL 8 operators.
///
/// Grounding: libaudit.c:1819 `case AUDIT_FILTERKEY:` falls through to the
/// `AUDIT_EXE` block at 1820; the op guard at 1825 is inside
/// `if (field == AUDIT_EXE) { ... }` -- it is NOT applied to `AUDIT_FILTERKEY`.
/// Execution continues past the if-block, copies the string, and reaches
/// break at 1854. Cite: libaudit.c:1819, 1821-1828 (if-guarded exe only),
/// 1829-1853 (filterkey length), 1854.
#[test]
fn e02_key_relational_and_bitmask_all_clean() {
    assert_clean("-a always,exit -S execve -F key>execpriv");
    assert_clean("-a always,exit -S execve -F key<x");
    assert_clean("-a always,exit -S execve -F key>=audit-");
    assert_clean("-a always,exit -S execve -F key&0x1");
    assert_clean("-a always,exit -S execve -F key&=0xff");
}

/// msgtype accepts ALL 8 operators including relational and bitmask.
///
/// Grounding: libaudit.c:1783-1797 handles `AUDIT_MSGTYPE`; the switch arm
/// resolves the value (name or number) and stores it, then falls to break.
/// No `EAU_OPEQNOTEQ` or `EAU_OPEQ` guard is present. Cite: libaudit.c:1783.
#[test]
fn e02_msgtype_all_clean() {
    assert_clean("-a never,exclude -F msgtype=1300");
    assert_clean("-a never,exclude -F msgtype!=1300");
    // relational: libaudit.c:1783, no op guard
    assert_clean("-a never,exclude -F msgtype>1300");
    assert_clean("-a never,exclude -F msgtype>=1300");
    assert_clean("-a never,exclude -F msgtype<1400");
    assert_clean("-a never,exclude -F msgtype<=1400");
    // bitmask: also no guard
    assert_clean("-a never,exclude -F msgtype&0x1");
    assert_clean("-a never,exclude -F msgtype&=0xff");
}

/// filetype accepts ALL 8 operators.
///
/// Grounding: libaudit.c:1929-1937 handles `AUDIT_FILETYPE`; resolves via
/// `audit_name_to_ftype()` and stores the value. No op guard. Cite: libaudit.c:1929.
#[test]
fn e02_filetype_all_clean() {
    assert_clean("-a always,exit -S openat -F filetype=file");
    assert_clean("-a always,exit -S openat -F filetype!=dir");
    // relational: libaudit.c:1929, no EAU_OPEQNOTEQ guard
    assert_clean("-a always,exit -S openat -F filetype>file");
    assert_clean("-a always,exit -S openat -F filetype>=file");
    assert_clean("-a always,exit -S openat -F filetype<socket");
    assert_clean("-a always,exit -S openat -F filetype<=socket");
    // bitmask: also no guard
    assert_clean("-a always,exit -S openat -F filetype&0x1");
    assert_clean("-a always,exit -S openat -F filetype&=0xf");
}

/// `saddr_fam` accepts ALL 8 operators.
///
/// Grounding: libaudit.c:1986-1990 handles `AUDIT_SADDR_FAM`; strtoul on the
/// `AF_*` value. No op guard. Cite: libaudit.c:1986.
#[test]
fn e02_saddr_fam_all_clean() {
    assert_clean("-a always,exit -S connect -F saddr_fam=2");
    assert_clean("-a always,exit -S connect -F saddr_fam!=0");
    // relational: libaudit.c:1986, no EAU_OPEQNOTEQ guard
    assert_clean("-a always,exit -S connect -F saddr_fam>=2");
    assert_clean("-a always,exit -S connect -F saddr_fam<10");
    // bitmask: also no guard
    assert_clean("-a always,exit -S connect -F saddr_fam&0x1");
    assert_clean("-a always,exit -S connect -F saddr_fam&=0xff");
}

/// success: libaudit.c:1992 (range fallthrough default), no op restriction.
#[test]
fn e02_success_all_clean() {
    assert_clean("-a always,exit -S openat -F success=0");
    assert_clean("-a always,exit -S openat -F success!=1");
}

// ---------------------------------------------------------------------------
// 4. -C boundary: a -C line contributes zero au-E02 findings
//    (-C is already parser-restricted to =/!= only; operator validity
//     for -C is a parse error, NOT a lint finding. au-E02 is -F only.)
// ---------------------------------------------------------------------------

/// A rule with only -C predicates and no invalid -F predicates must emit
/// zero au-E02 diagnostics, even though -C involves field comparisons.
/// Grounded: `parse_field_compare` in parser.rs restricts -C to =/!=
/// at parse time (returning a `ParseError`, not a lint `Diagnostic`).
#[test]
fn e02_c_field_compare_contributes_nothing() {
    let rules = located("-a always,exit -S execve -C uid!=euid");
    let diags = e02(&rules);
    assert!(
        diags.is_empty(),
        "a -C predicate must not produce au-E02: {diags:#?}"
    );
}

// ---------------------------------------------------------------------------
// 5. Diagnostic shape: anchored at the rule's line, column 1, whole-line span,
//    Severity::Error, code "au-E02", names field + op + auditctl rejection
// ---------------------------------------------------------------------------

/// Verify the full diagnostic shape for a known rejection case.
/// Grounded: `lints::anchored()` in mod.rs (column 1, whole-line span,
/// `source_id` = file path display string).
#[test]
fn e02_diagnostic_shape() {
    let file = Path::new("/etc/audit/rules.d/40-privesc.rules");
    // The rule is on line 1, bytes 0..len-of-raw-line.
    let input = "-a always,exit -S execve -F exe>=/usr/bin/bash";
    let rules = parse_rules_str_located(input, file).expect("must parse");
    let diags = e02(&rules);

    assert_eq!(diags.len(), 1);
    let d = &diags[0];

    assert_eq!(
        d.severity,
        Severity::Error,
        "must be Error (auditctl load fails)"
    );
    assert_eq!(d.code, "au-E02");
    assert_eq!(d.file, file);
    assert_eq!(d.line, 1, "anchored at the rule's 1-based line number");
    assert_eq!(d.column, 1, "column 1 per auditd anchoring convention");
    // Span covers the full raw line (0..len of the input line).
    assert_eq!(
        d.span,
        0..input.len(),
        "span must cover the whole raw rule line"
    );
    // source_id is set (per anchored() convention from mod.rs).
    assert_eq!(
        d.source_id.as_deref(),
        Some(file.display().to_string().as_str()),
        "source_id must be the file path's display string"
    );
    // Message names the field and the offending operator.
    assert!(
        d.message.contains("exe") && d.message.contains(">="),
        "message must name field 'exe' and operator '>=': '{}'",
        d.message
    );
    // Message should inform the user WHY (auditctl rejects at load time).
    assert!(
        d.message.contains("auditctl") || d.message.contains("load"),
        "message should reference auditctl rejection or load failure: '{}'",
        d.message
    );
}

// ---------------------------------------------------------------------------
// 6. Multiple invalid predicates in one rule -- one finding per offending -F
// ---------------------------------------------------------------------------

/// A rule with two invalid -F predicates emits exactly two au-E02 diagnostics.
/// Both share the same line/span (they are predicates within the same rule).
/// Grounded: `e02()` scans ALL `FieldFilter` entries in the rule; each invalid
/// op is an independent finding.
#[test]
fn e02_two_invalid_predicates_produce_two_findings() {
    // Both exe>= and arch& are invalid operators.
    let input = "-a always,exit -F arch>b64 -S execve -F exe>=/usr/bin/bash";
    let diags = lint(input);
    assert_eq!(
        diags.len(),
        2,
        "two invalid predicates must produce exactly 2 au-E02 findings\ngot: {diags:#?}"
    );
    // Both must be au-E02 Error.
    for d in &diags {
        assert_eq!(d.code, "au-E02");
        assert_eq!(d.severity, Severity::Error);
    }
    // One finding names "exe" and ">=", the other names "arch" and ">".
    let msgs: Vec<&str> = diags.iter().map(|d| d.message.as_str()).collect();
    assert!(
        msgs.iter().any(|m| m.contains("exe") && m.contains(">=")),
        "expected one finding for exe>=: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| m.contains("arch") && m.contains('>')),
        "expected one finding for arch>: {msgs:?}"
    );
}

/// A rule with one invalid and one valid predicate emits exactly one au-E02.
#[test]
fn e02_one_invalid_one_valid_predicate_produces_one_finding() {
    // exe>= is invalid; uid>=1000 is valid.
    let input = "-a always,exit -S execve -F uid>=1000 -F exe>=/usr/bin/bash";
    let diags = lint(input);
    assert_eq!(
        diags.len(),
        1,
        "only the invalid predicate must fire: {diags:#?}"
    );
    assert!(diags[0].message.contains("exe"));
}

// ---------------------------------------------------------------------------
// 7. Clean-corpus regression: zero au-E02 across ALL corpus scenarios
//    (every corpus file was loaded on a real host; any firing here is a
//     false positive in the lint logic)
// ---------------------------------------------------------------------------

#[test]
fn e02_zero_findings_across_all_corpus_scenarios() {
    use std::fs;

    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/auditd");

    let scenarios: Vec<_> = fs::read_dir(&corpus_root)
        .expect("corpus root must be readable")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|ft| ft.is_dir()))
        .collect();

    assert!(
        !scenarios.is_empty(),
        "expected at least one corpus scenario under {corpus_root:?}"
    );

    for entry in &scenarios {
        let scenario_name = entry.file_name();
        let scenario_dir = entry.path();

        // Discover all *.rules files within the scenario (may be a single
        // audit.rules or a rules.d/ sub-directory structure).
        let rules_files = collect_rules_files(&scenario_dir);
        assert!(
            !rules_files.is_empty(),
            "scenario {scenario_name:?} has no .rules files"
        );

        for rules_path in &rules_files {
            let content = fs::read_to_string(rules_path)
                .unwrap_or_else(|e| panic!("failed to read corpus file {rules_path:?}: {e}"));
            let Ok(rules) = parse_rules_str_located(&content, rules_path) else {
                continue; // parse errors are a different pass
            };
            let diags = e02(&rules);
            assert!(
                diags.is_empty(),
                "au-E02 false positive in corpus {scenario_name:?} file {rules_path:?}:\n{diags:#?}",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 8. op_str exact-token tests -- pin the PRECISE operator token in the
//    diagnostic message.
//
// The `assert_e02` helper uses `d.message.contains(op)`, which means
// `contains(">")` is satisfied by both `">"` and `">="`, and `contains("<")`
// is satisfied by both `"<"` and `"<="`.  Similarly `contains("&")` is
// satisfied by both `"&"` and `"&="`.  A mutation that swaps, e.g.,
// `CompareOp::Gt => ">"` for `CompareOp::Gt => ">="` in `op_str()` would pass
// all of the Section 2 tests above without being caught.
//
// The diagnostic message wraps the operator in backticks:
//   `au-E02: invalid operator `{op_str}` for field ...`
// so the substring `` `>` `` is PRESENT for Gt but NOT present when op_str
// returns `">="` (the substring would be `` `>=` `` instead).  These tests
// exploit that delimited form to kill the swap-mutations.
//
// Grounding: `operator_validity.rs` format!() at line 81 emits
//   `au-E02: invalid operator `{op_str}` for field `{field_name}` ...`
// The backtick delimiters are the invariant; these tests rely on them.
// ---------------------------------------------------------------------------

/// `op_str(Gt)` must emit exactly `">"`, not `">="`.
///
/// A mutation swapping `CompareOp::Gt => ">"` to `CompareOp::Gt => ">="` in
/// `op_str()` would change the diagnostic from containing `` `>` `` to
/// containing `` `>=` ``. The Section 2 tests that use `assert_e02(..., ">")` would
/// still pass (because `">=".contains(">")` is true), but this test kills it.
///
/// Grounding: libaudit.c supports all 8 operators for numeric/uid/gid fields;
/// `>` (Gt) and `>=` (Ge) are distinct opcodes with distinct string spellings.
#[test]
fn op_str_gt_is_strictly_greater_not_greater_equal() {
    let diags = lint("-a always,exit -S openat -F inode>100");
    assert_eq!(diags.len(), 1);
    let msg = &diags[0].message;
    // The backtick-delimited `>` must appear in the message.
    assert!(
        msg.contains("`>`"),
        "expected backtick-delimited `>` in message, got: {msg:?}"
    );
    // The backtick-delimited `>=` must NOT appear (that would be a wrong op).
    assert!(
        !msg.contains("`>=`"),
        "message must not contain `>=` when the op is strictly `>`: {msg:?}"
    );
}

/// `op_str(Lt)` must emit exactly `"<"`, not `"<="`.
///
/// A mutation swapping `CompareOp::Lt => "<"` to `CompareOp::Lt => "<="` would
/// change `` `<` `` to `` `<=` `` in the diagnostic.  The Section 2 tests use
/// `assert_e02(..., "<")` which still passes because `"<=".contains("<")` is true.
#[test]
fn op_str_lt_is_strictly_less_not_less_equal() {
    let diags = lint("-a always,exit -S execve -F exe</usr/bin");
    assert_eq!(diags.len(), 1);
    let msg = &diags[0].message;
    assert!(
        msg.contains("`<`"),
        "expected backtick-delimited `<` in message, got: {msg:?}"
    );
    assert!(
        !msg.contains("`<=`"),
        "message must not contain `<=` when the op is strictly `<`: {msg:?}"
    );
}

/// `op_str(BitAnd)` must emit exactly `"&"`, not `"&="`.
///
/// A mutation swapping `CompareOp::BitAnd => "&"` to `"&="` would change the
/// message from containing `` `&` `` to `` `&=` ``.  The Section 2 tests use
/// `assert_e02(..., "&")` which still passes because `"&=".contains("&")` is true.
#[test]
fn op_str_bitand_is_plain_not_bitand_eq() {
    let diags = lint("-a always,exit -S execve -F exe&0x1");
    assert_eq!(diags.len(), 1);
    let msg = &diags[0].message;
    assert!(
        msg.contains("`&`"),
        "expected backtick-delimited `&` in message, got: {msg:?}"
    );
    assert!(
        !msg.contains("`&=`"),
        "message must not contain `&=` when the op is plain `&`: {msg:?}"
    );
}

/// `op_str(Ge)` must emit exactly `">="`, not some other form (e.g. `">"`).
///
/// This is the symmetric counterpart to `op_str_gt_is_strictly_greater_not_greater_equal`.
/// A mutation swapping `CompareOp::Ge => ">="` to `">"`  would change `` `>=` ``
/// to `` `>` `` in the message, and this test kills it.
#[test]
fn op_str_ge_is_greater_equal_not_strictly_greater() {
    let diags = lint("-a always,exit -F arch>=b64 -S execve");
    assert_eq!(diags.len(), 1);
    let msg = &diags[0].message;
    assert!(
        msg.contains("`>=`"),
        "expected backtick-delimited `>=` in message, got: {msg:?}"
    );
}

/// `op_str(Le)` must emit exactly `"<="`, not `"<"`.
///
/// Symmetric counterpart: a mutation swapping `CompareOp::Le => "<="` to `"<"`
/// would change `` `<=` `` to `` `<` `` in the diagnostic.
#[test]
fn op_str_le_is_less_equal_not_strictly_less() {
    let diags = lint("-a always,exit -S openat -F inode<=999");
    assert_eq!(diags.len(), 1);
    let msg = &diags[0].message;
    assert!(
        msg.contains("`<=`"),
        "expected backtick-delimited `<=` in message, got: {msg:?}"
    );
}

/// `op_str(BitAndEq)` must emit exactly `"&="`, not `"&"`.
///
/// Symmetric counterpart: a mutation swapping `CompareOp::BitAndEq => "&="` to
/// `"&"` would change `` `&=` `` to `` `&` `` in the diagnostic.
#[test]
fn op_str_bitand_eq_is_not_plain_bitand() {
    let diags = lint("-a always,exit -S execve -F exe&=0x1");
    assert_eq!(diags.len(), 1);
    let msg = &diags[0].message;
    assert!(
        msg.contains("`&=`"),
        "expected backtick-delimited `&=` in message, got: {msg:?}"
    );
}

/// `op_str(Ne)` emits `"!="` -- pin it explicitly so a mutation swapping
/// `CompareOp::Ne => "!="` to any other form is killed.
#[test]
fn op_str_ne_exact_token_in_message() {
    let diags = lint("-a always,exit -S openat -F perm!=rwx");
    assert_eq!(diags.len(), 1);
    let msg = &diags[0].message;
    assert!(
        msg.contains("`!=`"),
        "expected backtick-delimited `!=` in message, got: {msg:?}"
    );
}

// ---------------------------------------------------------------------------
// 9. au-E05: KERNEL rejects bitmask ops (`&` / `&=`) beyond libaudit's
//    userspace validation -- issue #490.
//
// Sibling code to au-E02: au-E02 above models libaudit USERSPACE validation
// (`audit_rule_fieldpair_data`). This section grounds and pins the KERNEL's
// SEPARATE rule-insert validator, `audit_field_valid` in
// `kernel/auditfilter.c`, which rejects `Audit_bitmask` (`&`) /
// `Audit_bittest` (`&=`) for a field group libaudit's own parser has no
// opinion on. A rule such as `-F msgtype&0x100` therefore PARSES cleanly
// under `auditctl` (au-E02 correctly stays silent) but is REJECTED AT LOAD
// by the running kernel: a load-aborting false negative that au-E02 alone
// cannot catch. au-E02's own behavior is UNCHANGED by this addition: Section
// 3 above calls `e02()` directly (never the merged `lints::lint` dispatcher),
// so none of those `assert_clean` cases are affected by au-E05 existing.
//
// # Grounding (primary source, fetched directly at each pinned tag from
// `https://raw.githubusercontent.com/torvalds/linux/<tag>/kernel/auditfilter.c`)
//
// el8 (RHEL 8 kernel baseline, vanilla v4.18, `audit_field_valid` at
// auditfilter.c:336-435, the reject-bitmask switch arm at lines 361-388):
// 21 `AuditField` variants reject `&`/`&=`:
//   uid euid suid fsuid auid(AUDIT_LOGINUID) obj_uid
//   gid egid sgid fsgid obj_gid
//   pid pers msgtype ppid devmajor devminor exit success inode sessionid
// Everything else (arg0-3, subj_user/role/type/sen/clr, obj_user/role/type/
// lev_low/lev_high, watch/dir, filterkey) falls into the SAME switch's
// unconditional `break` arm (lines 389-406): every operator, including
// bitmask, is accepted. `AUDIT_SADDR_FAM` is not a recognized field constant
// in vanilla v4.18 at all (added upstream ~v5.4); see the SaddrFam note
// below.
//
// el9/el10 (RHEL 9/10 kernel baseline, v5.14 through at least v6.16 --
// `audit_field_valid` at auditfilter.c:323-437 (v5.14) / :327-441 (v6.6);
// the reject-bitmask arm is BYTE-IDENTICAL across v5.14, v6.6, v6.12, v6.16
// -- confirmed by direct diff of all four fetched sources, the only
// difference anywhere in the function being an unrelated
// AUDIT_FILTER_URING_EXIT guard added to the FIRST switch (the
// field-vs-listnr validity guard) at v6.6+, which does not touch this
// bitmask-reject field list):
// 24 `AuditField` variants reject `&`/`&=`:
//   uid euid suid fsuid auid obj_uid gid egid sgid fsgid obj_gid
//   pid msgtype ppid devmajor exit success inode sessionid
//   subj_sen subj_clr obj_lev_low obj_lev_high saddr_fam
// `pers` and `devminor` moved OUT of the reject arm and into a NEW,
// explicit "all ops are valid" arm alongside arg0-3 (v5.14
// auditfilter.c:350-357).
//
// # The 19-field version-STABLE intersection (`target == None`, the
// portable default -- fires regardless of `--target`, zero false positives
// AND zero false negatives on ANY of the examined kernel versions):
//   uid euid suid fsuid auid obj_uid gid egid sgid fsgid obj_gid
//   pid msgtype ppid devmajor exit success inode sessionid
//
// # EL8-ONLY additions (reject on el8, NOT on el9/el10): pers, devminor.
// # EL9/EL10-ONLY additions (reject on el9/el10, NOT on el8): subj_sen,
//   subj_clr, obj_lev_low, obj_lev_high, saddr_fam.
//
// # SaddrFam / el8 (DELIBERATE, DOCUMENTED gap -- orchestrator-locked):
// vanilla v4.18 has NO `AUDIT_SADDR_FAM` case at all (upstream added the
// constant/case ~v5.4); whether RHEL 8's backported/vendor kernel carries a
// backport of this specific case is UNVERIFIED against a real RHEL8 kernel
// tree. The el8 table in this test suite (and the implementation it drives)
// therefore OMITS saddr_fam: a false NEGATIVE here is acceptable, a false
// POSITIVE in a security linter is not. A follow-up issue tracks the
// empirical RHEL8 check; this is not guessed at here.
//
// # ARG0-3: unconditionally in the "all ops valid" arm at EVERY examined
// kernel version (el8 AND el9/el10 alike) -- the sharpest negative control:
// an impl that fires au-E05 for every field (a constant-true / "reject
// everything" regression) fails Section 9's arg-register tests at every
// target, including `None`.
//
// # Scope: bitmask operators ONLY (`&` Audit_bitmask / `&=` Audit_bittest).
// A SEPARATE, much larger kernel-vs-userspace divergence was also spotted
// during this grounding -- on el9/el10, `audit_field_valid` additionally
// restricts subj_user/subj_role/subj_type/obj_user/obj_role/obj_type/watch/
// dir/filterkey to `=`/`!=` only (v5.14 auditfilter.c:386-405), which
// libaudit's userspace parser does NOT restrict for these fields either.
// That is OUT OF SCOPE for au-E05 (issue #490's title and grounding request
// are bitmask-operator-specific) and is NOT modeled by any test below.
//
// # ORCHESTRATOR-LOCKED DECISION (NARROW, option (a)): au-E05 stays SILENT
// for a bitmask op on every field in that `=`/`!=`-only arm, at EVERY
// target, including `None`. Rationale, spelled out because it is
// non-obvious: that arm is a DIFFERENT kernel restriction (an operator
// allow-list, not a bitmask-specific reject), and modeling only its bitmask
// corner would be a half-measure -- `-F path>5` (a non-bitmask relational
// op) would STILL be a false negative even after that half-fix. Splitting
// the arm's fields by whether au-E02 ALREADY covers them (verified against
// `field_type()`, `src/lints/field_type.rs`):
//   - arch, fstype, perm, exe (`FieldType::Arch`/`FsType`/`Perm`/`StringEqNe`)
//     map to `true` in au-E02's operator-restriction table for a non-Eq/Ne
//     op -- au-E05 firing here too would be a DOUBLE-report of the same
//     load-abort, not a new finding.
//   - subj_user, subj_role, subj_type, obj_user, obj_role, obj_type, path,
//     dir (`FieldType::String`), key (`FieldType::Key`), and filetype
//     (`FieldType::Filetype`) map to `false` in au-E02 -- these TEN fields
//     are the genuine residual gap: today NEITHER au-E02 nor au-E05 catches
//     a relational/non-bitmask op rejected by this kernel arm on el9/el10.
//     A follow-up issue (filed by the orchestrator, out of scope here) will
//     model the WHOLE arm -- every kernel-disallowed op, not just bitmask --
//     as its own lint pass rather than bolting a half-measure onto au-E05.
// CORRECTION (round 3): an earlier draft of this comment claimed `filetype`
// "is NOT a member of this particular `=`/`!=`-only arm at all". That claim
// is TRUE only at the el8 (v4.18) kernel baseline -- v4.18 auditfilter.c:420
// handles `AUDIT_FILETYPE` with a VALUE check only
// (`if (f->val & ~S_IFMT) return -EINVAL;`), no operator guard of any kind.
// It is FALSE at el9/el10: v5.14 auditfilter.c places `case AUDIT_FILETYPE:`
// INSIDE the `/* only equal and not equal valid ops */` arm, alongside
// subj_user/subj_role/subj_type/obj_user/obj_role/obj_type/watch/dir/
// filterkey (byte-identical placement at v6.6/v6.12/v6.16). `filetype`
// therefore belongs in the TEN-field residual-gap list above, not as a
// separately-described "additional unrestricted field". No test assertion
// here was ever wrong -- au-E02 already maps `FieldType::Filetype => false`
// (`operator_validity.rs:76`), so `-F filetype>5` is kernel-rejected at
// el9/el10 and caught by NEITHER code today, exactly like the other nine --
// only this comment's prose was wrong, and the follow-up issue's scope must
// be drawn from the corrected TEN-field list, not the original nine.
// The 14-field negative-control set below (all clean for BITMASK ops --
// au-E05's only in-scope operator class -- at every target) is the union of
// the 4 au-E02-double-report fields (arch/fstype/perm/exe) and the TEN
// residual-gap fields above (subj_user, subj_role, subj_type, obj_user,
// obj_role, obj_type, path, dir, key, filetype). Section 9's negative-control
// test below (`e05_fields_outside_the_kernel_reject_table_...`) pins the
// CURRENT, deliberately-narrow contract: all 14 fields stay au-E05-CLEAN for
// bitmask ops at every target, and must NOT be "fixed" to fire without the
// follow-up issue doing the full-arm job properly.
// ---------------------------------------------------------------------------

/// Run `e05` on one or more inline rule strings against `target` and return
/// the diagnostics. Mirrors the `lint()` helper for `e02` above.
fn lint05(input: &str, target: Option<TargetVersion>) -> Vec<rulesteward_core::Diagnostic> {
    e05(&located(input), target)
}

/// Run `e05` and assert no au-E05 findings for `target` (clean pass).
fn assert_e05_clean(input: &str, target: Option<TargetVersion>) {
    let diags = lint05(input, target);
    assert!(
        diags.is_empty(),
        "expected no au-E05 for:\n  {input}\n  target={target:?}\ngot: {diags:#?}"
    );
}

/// Run `e05` and assert exactly one finding with code "au-E05" and
/// `Severity::Error`, naming `field` and `op` in the message. Also asserts
/// the message names the KERNEL specifically (case-insensitive): the whole
/// point of a sibling code (rather than folding this into au-E02) is that
/// operators can tell a KERNEL-rejected op from a USERSPACE-rejected one.
fn assert_e05(input: &str, target: Option<TargetVersion>, field: &str, op: &str) {
    let diags = lint05(input, target);
    assert_eq!(
        diags.len(),
        1,
        "expected exactly 1 au-E05 for:\n  {input}\n  target={target:?}\ngot: {diags:#?}"
    );
    let d = &diags[0];
    assert_eq!(d.severity, Severity::Error, "severity must be Error");
    assert_eq!(d.code, "au-E05", "code must be au-E05");
    // Backtick-delimited (round 3 fix): a plain `contains(field)` is a
    // substring check, so `uid` is satisfied by `euid`/`suid`/`fsuid`/
    // `auid`/`obj_uid`, and `gid` by `egid`/`sgid`/`fsgid`/`obj_gid`, and
    // `pid` by `ppid`. A wrong impl with a local field-name map that returns
    // the WRONG-but-superstring name (e.g. `Uid => "euid"`) would still pass
    // every plain-substring assertion. Mirrors the au-E02 Section 8
    // backtick-delimited op_str precedent, applied symmetrically to field.
    assert!(
        d.message.contains(&format!("`{field}`")),
        "message must name the field '{field}' backtick-delimited (not a \
         substring collision with a related field like euid/obj_uid/ppid): '{}'",
        d.message
    );
    assert!(
        d.message.contains(op),
        "message must name the operator '{op}': '{}'",
        d.message
    );
    assert!(
        d.message.to_lowercase().contains("kernel"),
        "au-E05 message must attribute the rejection to the KERNEL layer \
         (distinct from au-E02's auditctl/userspace wording): '{}'",
        d.message
    );
}

/// The 19-field version-STABLE intersection: (field name, sample rule)
/// pairs. See the Section 9 grounding doc comment above for the citation.
const STABLE_19: &[(&str, &str)] = &[
    ("uid", "-a always,exit -F uid&500"),
    ("euid", "-a always,exit -F euid&500"),
    ("suid", "-a always,exit -F suid&500"),
    ("fsuid", "-a always,exit -F fsuid&500"),
    ("auid", "-a always,exit -F auid&1000"),
    ("obj_uid", "-a always,exit -F obj_uid&500"),
    ("gid", "-a always,exit -F gid&500"),
    ("egid", "-a always,exit -F egid&500"),
    ("sgid", "-a always,exit -F sgid&500"),
    ("fsgid", "-a always,exit -F fsgid&500"),
    ("obj_gid", "-a always,exit -F obj_gid&500"),
    ("pid", "-a always,exit -F pid&100"),
    ("msgtype", "-a never,exclude -F msgtype&0x100"),
    ("ppid", "-a always,exit -F ppid&1"),
    ("devmajor", "-a always,exit -F devmajor&8"),
    ("exit", "-a always,exit -F exit&1"),
    ("success", "-a always,exit -F success&1"),
    ("inode", "-a always,exit -S openat -F inode&131"),
    ("sessionid", "-a always,exit -F sessionid&5"),
];

/// Every one of the 19 version-stable fields fires au-E05 for `&` under the
/// portable `target == None` default. This is the CENTRAL adversarial
/// property: `None` is NOT "fully silent like au-W06" -- it is the
/// conservative, always-on subset.
#[test]
fn e05_stable_19_fields_reject_bitand_when_target_is_none() {
    assert_eq!(
        STABLE_19.len(),
        19,
        "the version-stable intersection must have exactly 19 fields"
    );
    for (field, rule) in STABLE_19 {
        assert_e05(rule, None, field, "&");
    }
}

/// Same 19 fields, `&=` (`Audit_bittest`) instead of `&` (`Audit_bitmask`) --
/// both kernel-rejected bitmask forms, pinned separately per the au-E02
/// Section 8 precedent (`contains("&")` is satisfied by both `"&"` and
/// `"&="`, so a mutation collapsing `BitAndEq` handling into `BitAnd` would
/// slip past a `&`-only test suite).
#[test]
fn e05_stable_19_fields_reject_bitandeq_when_target_is_none() {
    assert_eq!(
        STABLE_19.len(),
        19,
        "the version-stable intersection must have exactly 19 fields"
    );
    for (field, rule) in STABLE_19 {
        let bitandeq_rule = rule.replacen('&', "&=", 1);
        assert_e05(&bitandeq_rule, None, field, "&=");
    }
}

/// The stable fields must ALSO fire when a specific `--target` is given, not
/// just under the portable `None` default. Kills an impl that (wrongly)
/// gates the ENTIRE au-E05 pass behind `target.is_some()` and forgets the
/// always-on stable check for `Some(t)`.
#[test]
fn e05_stable_fields_still_reject_under_every_specific_target_too() {
    let cases = [
        ("uid", "-a always,exit -F uid&500"),
        ("msgtype", "-a never,exclude -F msgtype&0x100"),
        ("inode", "-a always,exit -S openat -F inode&131"),
    ];
    for target in [
        TargetVersion::Rhel8,
        TargetVersion::Rhel9,
        TargetVersion::Rhel10,
    ] {
        for (field, rule) in &cases {
            assert_e05(rule, Some(target), field, "&");
        }
    }
}

/// El8-only additions: `pers` and `devminor` reject bitmask ops ONLY under
/// `Some(TargetVersion::Rhel8)`; el9/el10 moved both into the "all ops
/// valid" arm, and the portable `None` default (the 19-field stable set)
/// never included them.
///
/// Grounding: v4.18 auditfilter.c:376 lists `case AUDIT_PERS:` and
/// auditfilter.c:380 lists `case AUDIT_DEVMINOR:`, both inside the SAME
/// bitmask-reject arm as pid/msgtype/etc (lines 361-388; line 375 is
/// `case AUDIT_PID:`, not PERS -- corrected citation, round 3). v5.14
/// auditfilter.c:350-357 moves BOTH into a NEW arm explicitly commented
/// `/* all ops are valid */`.
#[test]
fn e05_pers_and_devminor_reject_bitand_only_under_rhel8() {
    let cases = [
        ("pers", "-a always,exit -F pers&1"),
        ("devminor", "-a always,exit -F devminor&0"),
    ];
    for (field, rule) in &cases {
        assert_e05(rule, Some(TargetVersion::Rhel8), field, "&");
        assert_e05_clean(rule, None);
        assert_e05_clean(rule, Some(TargetVersion::Rhel9));
        assert_e05_clean(rule, Some(TargetVersion::Rhel10));
    }
}

/// El9/el10-only additions (excluding `saddr_fam`, covered separately below):
/// `subj_sen`, `subj_clr`, `obj_lev_low`, `obj_lev_high` reject bitmask ops
/// ONLY under `Some(Rhel9)` / `Some(Rhel10)`; el8 groups all four in the
/// unconditional "all ops valid" arm (v4.18 auditfilter.c:393-402), and the
/// portable `None` default never included them.
///
/// Grounding: v5.14 auditfilter.c:377-381 (confirmed byte-identical at
/// v6.6/v6.12/v6.16) lists these 4 cases inside the bitmask-reject arm.
#[test]
fn e05_el9_el10_only_fields_reject_bitand_only_under_rhel9_and_rhel10() {
    let cases = [
        ("subj_sen", "-a always,exit -F subj_sen&1"),
        ("subj_clr", "-a always,exit -F subj_clr&1"),
        ("obj_lev_low", "-a always,exit -F obj_lev_low&1"),
        ("obj_lev_high", "-a always,exit -F obj_lev_high&1"),
    ];
    for (field, rule) in &cases {
        assert_e05(rule, Some(TargetVersion::Rhel9), field, "&");
        assert_e05(rule, Some(TargetVersion::Rhel10), field, "&");
        assert_e05_clean(rule, None);
        assert_e05_clean(rule, Some(TargetVersion::Rhel8));
    }
}

/// `saddr_fam`: rejects bitmask ops under `Some(Rhel9)` / `Some(Rhel10)`
/// (confirmed: v5.14 auditfilter.c:381 `case AUDIT_SADDR_FAM:` sits inside
/// the bitmask-reject arm, byte-identical at v6.6/v6.12/v6.16).
///
/// El8 is a DELIBERATE, DOCUMENTED gap, not an oversight: vanilla v4.18 has
/// NO `AUDIT_SADDR_FAM` case at all (the constant/case was added upstream
/// around v5.4); whether RHEL 8's backported kernel carries a backport of
/// this specific case is UNVERIFIED against a real RHEL8 kernel tree. Per
/// the orchestrator's locked decision, the el8 table OMITS `saddr_fam`
/// (conservative: a false NEGATIVE here is acceptable, a false POSITIVE in a
/// security linter is not). A follow-up issue tracks the empirical el8
/// check -- this test pins the current, deliberately-conservative contract;
/// it must NOT be "fixed" to fire on el8 without that empirical check.
#[test]
fn e05_saddr_fam_rejects_under_el9_el10_but_is_conservatively_omitted_on_el8() {
    let rule = "-a always,exit -F saddr_fam&2";
    assert_e05(rule, Some(TargetVersion::Rhel9), "saddr_fam", "&");
    assert_e05(rule, Some(TargetVersion::Rhel10), "saddr_fam", "&");
    // Conservative, documented omission (see doc comment above): el8 AND the
    // portable None default both stay clean for saddr_fam, even though a
    // REAL RHEL8 kernel backport MIGHT reject it -- unverified, not claimed.
    assert_e05_clean(rule, Some(TargetVersion::Rhel8));
    assert_e05_clean(rule, None);
}

/// arg0..arg3: unconditionally in the "all ops valid" arm at EVERY examined
/// kernel version (el8 AND el9/el10 alike). The sharpest negative control:
/// an impl that fires au-E05 for every field (a constant-true / "reject
/// everything" bug) fails this test at every target, including `None`.
///
/// Grounding: v4.18 auditfilter.c:389-406 (`case AUDIT_ARG0:` through
/// `AUDIT_ARG3:` fall to `break`, no op guard at all); v5.14
/// auditfilter.c:350-357 (`case AUDIT_ARG0:` through `AUDIT_ARG3:`
/// explicitly commented `/* all ops are valid */`), byte-identical at
/// v6.6/v6.12/v6.16.
#[test]
fn e05_arg_registers_never_reject_bitand_under_any_target() {
    let cases = [
        "-a always,exit -F a0&0xff",
        "-a always,exit -F a1&0xff",
        "-a always,exit -F a2&0xff",
        "-a always,exit -F a3&0xff",
    ];
    let targets: [Option<TargetVersion>; 4] = [
        None,
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
    ];
    for target in targets {
        for rule in &cases {
            assert_e05_clean(rule, target);
        }
    }
}

/// The 14 fields that sit OUTSIDE the kernel's bitmask-reject table
/// entirely, at EVERY examined kernel version, and are pinned by NOTHING
/// else in this suite: `path`, `dir`, `key`, `subj_user`, `subj_role`,
/// `subj_type`, `obj_user`, `obj_role`, `obj_type`, `exe`, `arch`, `perm`,
/// `filetype`, `fstype`. See the Section 9 grounding doc comment's
/// "ORCHESTRATOR-LOCKED DECISION (NARROW)" paragraph for the exact citation
/// and the au-E02-double-report-avoidance rationale.
///
/// This is the DEMONSTRATED-failure negative control: an impl that rejects
/// bitmask on "every field except arg0-3 (with `pers`/`devminor`/`subj_sen`/
/// `subj_clr`/`obj_lev_low`/`obj_lev_high`/`saddr_fam` gated by target)"
/// passes every OTHER Section 9 test above but ships real false positives --
/// `-F path&0x1`, `-F dir&0x1`, `-F subj_user&0x1`, `-F obj_type&0x1`,
/// `-F key&0x1` (among others) all firing under the portable `None` default,
/// which the el8 kernel (v4.18 auditfilter.c's unconditional `break` arm at
/// lines 389-406) genuinely accepts.
///
/// Both bitmask forms (`&` and `&=`) are checked, at all four targets, so
/// neither operator nor target can hide a false positive on any of these 14
/// fields.
#[test]
fn e05_fields_outside_the_kernel_reject_table_stay_clean_at_every_target() {
    let cases = [
        "-a always,exit -S openat -F path&0x1",
        "-a always,exit -S openat -F dir&0x1",
        "-a always,exit -S execve -F key&0x1",
        "-a always,exit -S execve -F subj_user&0x1",
        "-a always,exit -S execve -F subj_role&0x1",
        "-a always,exit -S execve -F subj_type&0x1",
        "-a always,exit -S openat -F obj_user&0x1",
        "-a always,exit -S openat -F obj_role&0x1",
        "-a always,exit -S openat -F obj_type&0x1",
        "-a always,exit -S execve -F exe&0x1",
        "-a always,exit -F arch&0xff -S execve",
        "-a always,exit -S openat -F perm&r",
        "-a always,exit -S openat -F filetype&0x1",
        "-a always,filesystem -F fstype&0x1",
    ];
    let targets: [Option<TargetVersion>; 4] = [
        None,
        Some(TargetVersion::Rhel8),
        Some(TargetVersion::Rhel9),
        Some(TargetVersion::Rhel10),
    ];
    for target in targets {
        for rule in &cases {
            assert_e05_clean(rule, target);
            let bitandeq_rule = rule.replacen('&', "&=", 1);
            assert_e05_clean(&bitandeq_rule, target);
        }
    }
}

/// Pin the PRECISE backtick-delimited operator token in the au-E05 message,
/// mirroring the au-E02 Section 8 precedent. `assert_e05`'s
/// `d.message.contains(op)` check is satisfied by both `"&"` and `"&="`
/// (`"&=".contains("&")` is true), so a mutation that returns `"&="` for
/// `CompareOp::BitAnd` would slip past every `assert_e05(..., "&")` call
/// above. Today that swap is caught only TRANSITIVELY, via Section 8's
/// `op_str_bitand_is_plain_not_bitand_eq` -- which pins au-E02's SHARED
/// `op_str()`. If au-E05 instead uses its own, LOCAL `op_str`-equivalent,
/// the transitive coverage does not apply and the swap goes uncaught. This
/// test pins it directly against au-E05's own diagnostic output, so au-E05
/// does not depend on reusing au-E02's helper to stay correct. (The reverse
/// swap -- `BitAndEq => "&"` -- is already caught: `d.message.contains("&=")`
/// in `e05_stable_19_fields_reject_bitandeq_when_target_is_none` would fail
/// outright, since `"&".contains("&=")` is false.)
#[test]
fn e05_bitand_message_is_backtick_delimited_plain_not_bitand_eq() {
    let diags = lint05("-a always,exit -F uid&500", None);
    assert_eq!(diags.len(), 1, "expected exactly 1 au-E05: {diags:#?}");
    let msg = &diags[0].message;
    assert!(
        msg.contains("`&`"),
        "expected backtick-delimited `&` in message, got: {msg:?}"
    );
    assert!(
        !msg.contains("`&=`"),
        "message must not contain `&=` when the op is plain `&`: {msg:?}"
    );
}

/// The kernel-side bitmask restriction applies ONLY to `&` (`Audit_bitmask`)
/// and `&=` (`Audit_bittest`); every OTHER operator on the same fields is
/// unrestricted at the kernel layer. An impl that (wrongly) fires au-E05 for
/// ANY operator on a listed field -- not just the two bitmask forms -- fails
/// this test.
///
/// Grounding: v5.14/v6.x auditfilter.c `if (f->op == Audit_bitmask ||
/// f->op == Audit_bittest) return -EINVAL;` -- an explicit two-value check,
/// not a blanket rejection of the field.
#[test]
fn e05_relational_and_equality_ops_never_fire_on_stable_fields() {
    let rules = [
        "-a always,exit -F uid=500",
        "-a always,exit -F uid!=500",
        "-a always,exit -F uid<500",
        "-a always,exit -F uid>500",
        "-a always,exit -F uid<=500",
        "-a always,exit -F uid>=500",
        "-a never,exclude -F msgtype=1300",
        "-a never,exclude -F msgtype!=1300",
        "-a never,exclude -F msgtype>1300",
        "-a always,exit -F pid<100",
        "-a always,exit -F pid>=100",
    ];
    for rule in rules {
        assert_e05_clean(rule, None);
        assert_e05_clean(rule, Some(TargetVersion::Rhel9));
    }
}

/// THE central issue #490 gap: `-F msgtype&0x100` PARSES cleanly under
/// libaudit userspace (au-E02 stays silent -- `FieldType::MsgType` has no
/// operator restriction, `field_type.rs` `MsgType` arm) but the KERNEL rejects
/// it at rule-LOAD time. au-E02 must remain silent (unchanged, userspace is
/// correctly modeled); au-E05 must be the ONLY code that catches this.
#[test]
fn e05_catches_the_e02_false_negative_on_userspace_unrestricted_stable_fields() {
    let cases = [
        ("-a always,exit -F uid&500", "uid"),
        ("-a never,exclude -F msgtype&0x100", "msgtype"),
        ("-a always,exit -F pid&100", "pid"),
        ("-a always,exit -F sessionid&5", "sessionid"),
    ];
    for (rule, field) in cases {
        let e02_diags = lint(rule);
        assert!(
            e02_diags.is_empty(),
            "au-E02 must stay silent for '{rule}' (userspace has no operator \
             restriction on this field): {e02_diags:#?}"
        );
        assert_e05(rule, None, field, "&");
    }
}

/// The documented OVERLAP case: `inode` is userspace-restricted to `=`/`!=`
/// (au-E02, `FieldType::NumericEqNe`, libaudit.c `EAU_OPEQNOTEQ`) AND
/// kernel-restricted against bitmask ops (au-E05, v4.18/v5.14+ both list
/// `AUDIT_INODE` in the bitmask-reject arm). `-F inode&131` is rejected by
/// BOTH layers, so a single rule legitimately carries BOTH codes.
#[test]
fn e05_and_e02_both_fire_on_inode_bitand_the_documented_overlap_case() {
    let rule = "-a always,exit -S openat -F inode&131";
    let e02_diags = lint(rule);
    assert_eq!(
        e02_diags.len(),
        1,
        "au-E02 must still fire for inode& (userspace EAU_OPEQNOTEQ, \
         unchanged by this addition): {e02_diags:#?}"
    );
    assert_eq!(e02_diags[0].code, "au-E02");
    assert_e05(rule, None, "inode", "&");
}

// ---------------------------------------------------------------------------
// 10. au-E05 diagnostic shape + multi-predicate behavior (mirrors the au-E02
//    Sections 5/6 precedent above).
// ---------------------------------------------------------------------------

/// Verify the full diagnostic shape for a known kernel-rejection case.
#[test]
fn e05_diagnostic_shape() {
    let file = Path::new("/etc/audit/rules.d/40-e05.rules");
    let input = "-a always,exit -F uid&500";
    let rules = parse_rules_str_located(input, file).expect("must parse");
    let diags = e05(&rules, None);

    assert_eq!(diags.len(), 1);
    let d = &diags[0];

    assert_eq!(
        d.severity,
        Severity::Error,
        "must be Error (the kernel rejects the rule load)"
    );
    assert_eq!(d.code, "au-E05");
    assert_eq!(d.file, file);
    assert_eq!(d.line, 1, "anchored at the rule's 1-based line number");
    assert_eq!(d.column, 1, "column 1 per auditd anchoring convention");
    assert_eq!(
        d.span,
        0..input.len(),
        "span must cover the whole raw rule line"
    );
    assert_eq!(
        d.source_id.as_deref(),
        Some(file.display().to_string().as_str()),
        "source_id must be the file path's display string"
    );
    assert!(
        d.message.contains("uid") && d.message.contains('&'),
        "message must name field 'uid' and operator '&': '{}'",
        d.message
    );
    assert!(
        d.message.to_lowercase().contains("kernel"),
        "message must attribute the rejection to the KERNEL layer \
         (distinct from au-E02's auditctl/userspace wording): '{}'",
        d.message
    );
}

/// Anchoring must point at the rule that actually FIRED, not always at rule
/// 1 / line 1 (round-3 fix).
///
/// Every other au-E05 fixture in this suite is a single rule on line 1, so
/// `d.line` / `d.span` / `d.file` are indistinguishable from constants there
/// -- an impl that hardcodes `line = 1` and anchors every finding at
/// `rules[0]`'s span would still pass every other test in this file (all
/// 79+ of them). This fixture is a 3-rule file where ONLY line 3 fires
/// (line 1 is the arg-register negative control, line 2 is a
/// negative-control field outside the kernel reject table); it pins BOTH
/// the line number AND that `span` slices back to the FIRING rule's exact
/// raw source text, not rule 1's -- so neither a wrong-rule-index bug nor a
/// byte-vs-char span bug can pass silently.
///
/// Precedent: sysctld PR #338 ("senior caught wrong-line") and PR #340
/// ("byte-vs-char span INVISIBLE to tests") are recorded repo incidents of
/// exactly this class of anchoring bug.
#[test]
fn e05_anchors_the_firing_rule_when_it_is_not_the_first_rule_in_the_file() {
    let file = Path::new("/etc/audit/rules.d/40-e05-multi.rules");
    let input = concat!(
        "-a always,exit -F a0&0xff\n",
        "-a always,exit -S openat -F path&0x1\n",
        "-a always,exit -F pid&100\n",
    );
    let rules = parse_rules_str_located(input, file).expect("fixture must parse");
    assert_eq!(rules.len(), 3, "fixture must have exactly 3 rules");

    let diags = e05(&rules, None);
    assert_eq!(
        diags.len(),
        1,
        "only line 3 (pid&100, a stable-19 field) is kernel-rejected; \
         line 1 (a0, arg-register negative control) and line 2 (path, \
         outside-the-reject-table negative control) must stay clean: \
         {diags:#?}"
    );

    let d = &diags[0];
    assert_eq!(
        d.line, 3,
        "must anchor at line 3 -- the FIRING rule -- not line 1"
    );

    let firing_line = "-a always,exit -F pid&100";
    let rule1_line = "-a always,exit -F a0&0xff";
    let sliced = &input[d.span.clone()];
    assert_eq!(
        sliced, firing_line,
        "span must slice back to the firing rule's exact raw source text \
         (a byte-vs-char span bug or a wrong-rule-index bug both fail this)"
    );
    assert_ne!(
        sliced, rule1_line,
        "span must not point at rule 1's text when rule 3 is the one that \
         fired -- the classic wrong-impl failure mode of anchoring every \
         finding at rules[0]"
    );
}

/// A rule with two kernel-rejected predicates emits exactly two au-E05
/// diagnostics.
#[test]
fn e05_two_kernel_rejected_predicates_produce_two_findings() {
    let input = "-a always,exit -F uid&500 -F pid&100";
    let diags = lint05(input, None);
    assert_eq!(
        diags.len(),
        2,
        "two kernel-rejected predicates must produce exactly 2 au-E05 \
         findings\ngot: {diags:#?}"
    );
    for d in &diags {
        assert_eq!(d.code, "au-E05");
        assert_eq!(d.severity, Severity::Error);
    }
    let msgs: Vec<&str> = diags.iter().map(|d| d.message.as_str()).collect();
    assert!(
        msgs.iter().any(|m| m.contains("uid")),
        "expected one finding naming uid: {msgs:?}"
    );
    assert!(
        msgs.iter().any(|m| m.contains("pid")),
        "expected one finding naming pid: {msgs:?}"
    );
}

/// A rule with one kernel-rejected and one kernel-accepted predicate emits
/// exactly one au-E05 (the arg0-3 negative control paired with a stable
/// field in the SAME rule).
#[test]
fn e05_one_rejected_one_accepted_predicate_produces_one_finding() {
    let input = "-a always,exit -F uid&500 -F a0&0xff";
    let diags = lint05(input, None);
    assert_eq!(
        diags.len(),
        1,
        "only the kernel-rejected predicate must fire: {diags:#?}"
    );
    assert!(diags[0].message.contains("uid"));
}

/// `-C` is already parser-restricted to `=`/`!=` (see `parse_field_compare`),
/// so it never reaches au-E05's `-F`-only scan; a `-C` predicate alongside a
/// genuinely kernel-rejected `-F` predicate must not add or remove findings.
#[test]
fn e05_c_field_compare_contributes_nothing_beyond_the_f_predicate() {
    let rules = located("-a always,exit -F uid&500 -C uid!=euid");
    let diags = e05(&rules, None);
    assert_eq!(
        diags.len(),
        1,
        "only the -F uid& predicate should fire; -C is untouched: {diags:#?}"
    );
}

// ---------------------------------------------------------------------------
// 11. Dispatcher wiring: `lints::lint` must route au-E05 findings, both for
//    the portable None default AND under an explicit --target (mirrors the
//    au-E04 T16 precedent in test_lints_field_filter.rs).
// ---------------------------------------------------------------------------

/// `lints::lint` must include au-E05 findings for a stable-19 field even
/// with `target = None` -- the 19-field stable set is NOT gated behind
/// `--target` (unlike au-W06, which stays fully silent under `None`).
#[test]
fn dispatcher_includes_e05_findings_for_stable_field_even_with_target_none() {
    let rules = located("-a always,exit -F uid&500");
    let all_diags = rulesteward_auditd::lints::lint(
        &rules,
        rulesteward_auditd::lints::LintOptions::default(),
        None,
    );
    let e05_diags: Vec<_> = all_diags.iter().filter(|d| d.code == "au-E05").collect();
    assert!(
        !e05_diags.is_empty(),
        "lints::lint must include au-E05 findings for uid& even with \
         target=None; got codes: {:?}",
        all_diags.iter().map(|d| &d.code).collect::<Vec<_>>()
    );
}

/// `lints::lint` must include au-E05 findings for a target-gated field
/// (`saddr_fam`) under an explicit `--target rhel9`.
#[test]
fn dispatcher_includes_e05_findings_for_target_gated_field_under_rhel9() {
    let rules = located("-a always,exit -F saddr_fam&2");
    let all_diags = rulesteward_auditd::lints::lint(
        &rules,
        rulesteward_auditd::lints::LintOptions::default(),
        Some(TargetVersion::Rhel9),
    );
    let e05_diags: Vec<_> = all_diags.iter().filter(|d| d.code == "au-E05").collect();
    assert!(
        !e05_diags.is_empty(),
        "lints::lint must include au-E05 findings for saddr_fam& under \
         --target rhel9; got codes: {:?}",
        all_diags.iter().map(|d| &d.code).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// 12. Clean-corpus regression: zero au-E05 findings across ALL corpus
//    scenarios under the portable (target=None) default -- every corpus
//    file was loaded on a real host, so any firing here (a bitmask op on a
//    kernel-rejected field that somehow made it past that host's OWN
//    kernel) would indicate a linter false positive.
// ---------------------------------------------------------------------------

#[test]
fn e05_zero_findings_across_all_corpus_scenarios_under_target_none() {
    use std::fs;

    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/auditd");

    let scenarios: Vec<_> = fs::read_dir(&corpus_root)
        .expect("corpus root must be readable")
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|ft| ft.is_dir()))
        .collect();

    assert!(
        !scenarios.is_empty(),
        "expected at least one corpus scenario under {corpus_root:?}"
    );

    // Round-3 fix: `let Ok(rules) = ... else { continue; }` below silently
    // skips any file that fails to parse, so a corpus where EVERY file fails
    // to parse would still report "0 findings" and pass vacuously. Count how
    // many files actually parsed and assert it is nonzero after the loop, so
    // a corpus-wide parse regression fails loudly here instead of masquerading
    // as a clean au-E05 pass.
    let mut parsed_count = 0usize;

    for entry in &scenarios {
        let scenario_name = entry.file_name();
        let scenario_dir = entry.path();

        let rules_files = collect_rules_files(&scenario_dir);
        assert!(
            !rules_files.is_empty(),
            "scenario {scenario_name:?} has no .rules files"
        );

        for rules_path in &rules_files {
            let content = fs::read_to_string(rules_path)
                .unwrap_or_else(|e| panic!("failed to read corpus file {rules_path:?}: {e}"));
            let Ok(rules) = parse_rules_str_located(&content, rules_path) else {
                continue; // parse errors are a different pass
            };
            parsed_count += 1;
            let diags = e05(&rules, None);
            assert!(
                diags.is_empty(),
                "au-E05 false positive in corpus {scenario_name:?} file {rules_path:?}:\n{diags:#?}",
            );
        }
    }

    assert!(
        parsed_count > 0,
        "no corpus file parsed successfully -- a corpus-wide parse failure \
         would otherwise pass this test vacuously (0 findings from 0 parsed \
         files looks identical to a genuine clean pass)"
    );
}

// ---------------------------------------------------------------------------

/// Collect all *.rules files under a scenario directory, recursing into
/// rules.d/ sub-directories.
fn collect_rules_files(dir: &Path) -> Vec<std::path::PathBuf> {
    use std::fs;
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_rules_files(&path));
            } else if path.extension().and_then(|s| s.to_str()) == Some("rules") {
                files.push(path);
            }
        }
    }
    files
}
