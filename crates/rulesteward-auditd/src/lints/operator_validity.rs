//! au-E02: comparison operator invalid for the field's type.
//!
//! Pipeline P3 (#193). `auditctl` REJECTS an invalid operator/field pairing at
//! load time (libaudit `audit_rule_fieldpair_data`), so a ruleset containing
//! one fails to load under `augenrules`: Error severity. The per-field
//! operator-validity matrix is grounded cell-by-cell in audit-userspace
//! commit 3bfa048 (`lib/fieldtab.h` + `lib/libaudit.c`), via the
//! [`super::field_type`] table.
//!
//! Scope: `-F` predicates only. `-C` is already parser-restricted to `=`/`!=`
//! (see `parse_field_compare`), so operator validity for `-C` is a parse
//! error, not a lint.

use rulesteward_core::{Diagnostic, Severity};

use crate::ast::{AuditRule, CompareOp, LocatedRule};
use crate::lints::anchored;
use crate::lints::field_type::{FieldType, field_type};

/// au-E02 operator-validity pass.
///
/// Walks every `-F` predicate in every Syscall rule. For each predicate, looks
/// up the field's type via [`field_type`] and checks whether the operator is
/// valid for that type. Emits one au-E02 per invalid pairing.
///
/// Grounding: `audit_rule_fieldpair_data` in libaudit.c at commit 3bfa048.
/// Only five field families have an explicit operator restriction:
///
/// | `FieldType`       | Allowed operators            | libaudit.c line |
/// |-------------------|------------------------------|-----------------|
/// | `StringEqNe`      | `=` and `!=` only            | 1825 (`EAU_OPEQNOTEQ`) |
/// | `Arch`            | `=` and `!=` only            | 1858 (`EAU_OPEQNOTEQ`) |
/// | `FsType`          | `=` and `!=` only            | 1941 (`EAU_OPEQNOTEQ`) |
/// | `NumericEqNe`     | `=` and `!=` only            | 1998 (`EAU_OPEQNOTEQ`) |
/// | `Perm`            | `=` only                     | 1892 (`EAU_OPEQ`) |
///
/// All other `FieldType` variants have no operator restriction and accept all 8
/// operators.
///
/// Body is pipeline P3's; the signature is Phase-0 frozen.
#[must_use]
pub fn e02(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    for located in rules {
        let AuditRule::Syscall { fields, .. } = &located.rule else {
            // Control rules and Watch rules carry no -F predicates.
            continue;
        };

        for filter in fields {
            let ft = field_type(&filter.field);
            let op = &filter.op;

            let invalid = match ft {
                // StringEqNe: exe -- libaudit.c:1825 (EAU_OPEQNOTEQ)
                // Arch:       arch -- libaudit.c:1858 (EAU_OPEQNOTEQ)
                // FsType:     fstype -- libaudit.c:1941 (EAU_OPEQNOTEQ)
                // NumericEqNe: inode -- libaudit.c:1998 (EAU_OPEQNOTEQ)
                FieldType::StringEqNe
                | FieldType::Arch
                | FieldType::FsType
                | FieldType::NumericEqNe => !matches!(op, CompareOp::Eq | CompareOp::Ne),
                // Perm: only = accepted -- libaudit.c:1892 (EAU_OPEQ)
                FieldType::Perm => !matches!(op, CompareOp::Eq),
                // All other types: no operator restriction in libaudit.c
                FieldType::Numeric
                | FieldType::NumericSigned
                | FieldType::Uid
                | FieldType::Gid
                | FieldType::String
                | FieldType::MsgType
                | FieldType::Filetype
                | FieldType::Key
                | FieldType::SaddrFam => false,
            };

            if invalid {
                let field_name = field_name_str(&filter.field);
                let op_str = op_str(op);
                let msg = format!(
                    "au-E02: invalid operator `{op_str}` for field `{field_name}` \
                     -- auditctl rejects this at load time (operator not allowed for this field type)"
                );
                diags.push(anchored(
                    Severity::Error,
                    "au-E02",
                    located.span.clone(),
                    msg,
                    located.file.clone(),
                    located.line,
                ));
            }
        }
    }

    diags
}

/// Map a [`CompareOp`] to its string form as written in rules files.
fn op_str(op: &CompareOp) -> &'static str {
    match op {
        CompareOp::Eq => "=",
        CompareOp::Ne => "!=",
        CompareOp::Lt => "<",
        CompareOp::Gt => ">",
        CompareOp::Le => "<=",
        CompareOp::Ge => ">=",
        CompareOp::BitAnd => "&",
        CompareOp::BitAndEq => "&=",
    }
}

/// Map an [`AuditField`] to its canonical name string for diagnostic messages.
fn field_name_str(field: &crate::ast::AuditField) -> &'static str {
    use crate::ast::AuditField;
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
