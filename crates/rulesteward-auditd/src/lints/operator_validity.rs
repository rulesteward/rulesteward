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

use crate::ast::{AuditField, AuditRule, CompareOp, LocatedRule};
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
/// Grounded reject table, keyed on [`AuditField`] (NOT [`FieldType`] -- au-E02's
/// `FieldType` groups are misaligned with the kernel's own groupings, e.g.
/// `Numeric` bundles `a0`-`a3` with `pid`/`ppid`, which the kernel treats
/// differently). Primary source: `kernel/auditfilter.c` `audit_field_valid`,
/// fetched directly at each pinned tag; see the grounding doc comment on
/// Section 9 of `tests/test_lints_operator_validity.rs` for the full citation.
///
/// Returns `true` when the running kernel at `target` rejects a bitmask
/// operator (`&`/`&=`) on `field` at rule-insert time.
///
/// - The 19-field version-STABLE intersection fires for every `target`,
///   including `None` (zero false positives AND zero false negatives at any
///   examined kernel version): `uid`/`euid`/`suid`/`fsuid`/`auid`/`obj_uid`,
///   `gid`/`egid`/`sgid`/`fsgid`/`obj_gid`, `pid`/`msgtype`/`ppid`/`devmajor`/
///   `exit`/`success`/`inode`/`sessionid`.
/// - `Some(Rhel8)` (vanilla v4.18) additionally rejects `pers` and
///   `devminor` -- both moved to an unconditional "all ops valid" arm at
///   el9/el10.
/// - `Some(Rhel9) | Some(Rhel10)` (v5.14 through at least v6.16, byte-
///   identical bitmask-reject arm) additionally rejects `subj_sen`,
///   `subj_clr`, `obj_lev_low`, `obj_lev_high`, and `saddr_fam`.
/// - `saddr_fam` is deliberately OMITTED from the el8 arm: vanilla v4.18 has
///   no `AUDIT_SADDR_FAM` case at all (added upstream ~v5.4), and RHEL 8's
///   backport status is unverified. A false negative here is acceptable; a
///   false positive in a security linter is not.
/// - `arg0`-`arg3` are unconditionally in the "all ops valid" arm at every
///   examined kernel version and never appear below.
/// - Fields the kernel restricts to `=`/`!=` only on el9/el10 (`arch`,
///   `fstype`, `perm`, `exe`, the `subj_user`/`subj_role`/`subj_type`/
///   `obj_user`/`obj_role`/`obj_type`/`path`/`dir`/`key`/`filetype` group) are
///   deliberately OUT OF SCOPE for au-E05 (issue #490 is bitmask-operator-
///   specific; that separate restriction is a distinct kernel-vs-userspace
///   gap tracked by a follow-up issue, not modeled here).
fn kernel_rejects_bitmask(field: &AuditField, target: Option<TargetVersion>) -> bool {
    match field {
        // 19-field version-STABLE intersection: rejected at every examined
        // kernel, including `target == None`.
        AuditField::Uid
        | AuditField::Euid
        | AuditField::Suid
        | AuditField::Fsuid
        | AuditField::Auid
        | AuditField::ObjUid
        | AuditField::Gid
        | AuditField::Egid
        | AuditField::Sgid
        | AuditField::Fsgid
        | AuditField::ObjGid
        | AuditField::Pid
        | AuditField::MsgType
        | AuditField::Ppid
        | AuditField::DevMajor
        | AuditField::Exit
        | AuditField::Success
        | AuditField::Inode
        | AuditField::SessionId => true,
        // el8 (v4.18) only -- both moved to an unconditional "all ops valid"
        // arm at el9/el10.
        AuditField::Pers | AuditField::DevMinor => is_el8(target),
        // el9/el10 (v5.14 through at least v6.16) only. `saddr_fam` is
        // deliberately absent from the el8 arm above: vanilla v4.18 has no
        // `AUDIT_SADDR_FAM` case at all (added upstream ~v5.4), and RHEL 8's
        // backport status is unverified.
        AuditField::SubjSen
        | AuditField::SubjClr
        | AuditField::ObjLevLow
        | AuditField::ObjLevHigh
        | AuditField::SaddrFam => is_el9_plus(target),
        // No examined kernel rejects a bitmask op on these. Explicit, not
        // `_`, so a 46th `AuditField` variant is a compile error here rather
        // than a silent false negative on an Error-tier, load-aborting lint.
        AuditField::A0
        | AuditField::A1
        | AuditField::A2
        | AuditField::A3
        | AuditField::Arch
        | AuditField::Dir
        | AuditField::Exe
        | AuditField::FieldCompare
        | AuditField::Filetype
        | AuditField::Fstype
        | AuditField::Key
        | AuditField::ObjRole
        | AuditField::ObjType
        | AuditField::ObjUser
        | AuditField::Path
        | AuditField::Perm
        | AuditField::SubjRole
        | AuditField::SubjType
        | AuditField::SubjUser => false,
    }
}

/// True only for the el8 kernel line (v4.18). Exhaustive over
/// [`TargetVersion`] by design: a future RHEL major must be classified here,
/// not silently defaulted.
fn is_el8(target: Option<TargetVersion>) -> bool {
    match target {
        Some(TargetVersion::Rhel8) => true,
        Some(TargetVersion::Rhel9 | TargetVersion::Rhel10) | None => false,
    }
}

/// True for the el9/el10 kernel line (v5.14 through at least v6.16).
/// Exhaustive over [`TargetVersion`] for the same reason as [`is_el8`].
fn is_el9_plus(target: Option<TargetVersion>) -> bool {
    match target {
        Some(TargetVersion::Rhel9 | TargetVersion::Rhel10) => true,
        Some(TargetVersion::Rhel8) | None => false,
    }
}

/// au-E05 pass body. Walks every `-F` predicate in every Syscall rule; for a
/// bitmask operator (`&`/`&=`) on a kernel-rejected field (per
/// [`kernel_rejects_bitmask`]), emits one au-E05 Error anchored at the
/// firing rule's own line and span. Mirrors `e02`'s walk shape and reuses
/// its `op_str`/`field_name` helpers (issue #458: do not reintroduce a
/// local copy of either).
#[must_use]
pub fn e05(rules: &[LocatedRule], target: Option<TargetVersion>) -> Vec<Diagnostic> {
    let mut diags = Vec::new();

    for located in rules {
        let AuditRule::Syscall { fields, .. } = &located.rule else {
            // Control rules and Watch rules carry no -F predicates.
            continue;
        };

        for filter in fields {
            let op = &filter.op;
            if !matches!(op, CompareOp::BitAnd | CompareOp::BitAndEq) {
                continue;
            }

            if kernel_rejects_bitmask(&filter.field, target) {
                let field_name = field_name(&filter.field);
                let op_str = op_str(op);
                // Do NOT self-prefix the code: the renderer already prints the
                // `[au-E05]` tag. Message must say "kernel" (case-insensitive),
                // distinct from au-E02's "auditctl"/userspace wording.
                let msg = format!(
                    "invalid operator `{op_str}` for field `{field_name}` \
                     -- the kernel rejects this bitmask operator for this field at rule-load time"
                );
                diags.push(anchored(
                    Severity::Error,
                    "au-E05",
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
