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
use crate::lints::TargetVersion;
use crate::lints::anchored;
use crate::lints::field_name::field_name;
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
                | FieldType::SessionId
                | FieldType::String
                | FieldType::MsgType
                | FieldType::Filetype
                | FieldType::Key
                | FieldType::SaddrFam => false,
            };

            if invalid {
                let field_name = field_name(&filter.field);
                let op_str = op_str(op);
                // Do NOT self-prefix the code: the renderer already prints the
                // `[au-E02]` tag, so a `au-E02:` here would double it. (Matches
                // every sibling pass, which emit a bare message.)
                let msg = format!(
                    "invalid operator `{op_str}` for field `{field_name}` \
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

/// au-E05: KERNEL rejects bitmask ops (`&`/`&=`) beyond libaudit's userspace
/// validation (issue #490).
///
/// Sibling code to au-E02: au-E02 models `audit_rule_fieldpair_data`
/// (libaudit USERSPACE, `auditctl`'s own parser); this pass models
/// `audit_field_valid` (the KERNEL's rule-insert validator,
/// `kernel/auditfilter.c`), which separately rejects `Audit_bitmask`
/// (`&`) / `Audit_bittest` (`&=`) for a field group libaudit's parser has no
/// opinion on. A rule like `-F msgtype&0x100` therefore PARSES under
/// `auditctl` (au-E02 stays silent -- correctly, per the userspace model) but
/// is REJECTED AT LOAD by the running kernel: a load-aborting false negative
/// that au-E02 alone cannot catch. au-E02's existing behavior and tests are
/// UNCHANGED by this addition.
///
/// STUB ONLY (test-author barrier, 9a-v0_8-wave1 lane-c-auditd-e05): the
/// frozen signature per the locked Option-B decision (`target:
/// Option<TargetVersion>`, mirroring `stig_required::w06`). The grounded
/// reject table -- a 19-field version-STABLE intersection fired for every
/// `target` including `None`, plus an el8-only extension under
/// `Some(TargetVersion::Rhel8)` and a distinct el9/el10-only extension under
/// `Some(TargetVersion::Rhel9) | Some(TargetVersion::Rhel10)` -- and the
/// dispatcher wiring into `lints::lint` (beside `e02`) are the IMPLEMENTER's
/// job, driven by the frozen RED tests in
/// `tests/test_lints_operator_validity.rs` (Section 9 onward: the grounding
/// doc comment there cites the exact kernel refs and per-target field lists,
/// including the deliberate conservative omission of `saddr_fam` from the
/// el8 table -- unverified against a real RHEL8 kernel tree).
#[must_use]
pub fn e05(_rules: &[LocatedRule], _target: Option<TargetVersion>) -> Vec<Diagnostic> {
    todo!(
        "au-E05 kernel-bitmask-rejection lint body -- issue #490; \
         see tests/test_lints_operator_validity.rs Section 9+ for the frozen \
         grounded reject table this must implement"
    )
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
