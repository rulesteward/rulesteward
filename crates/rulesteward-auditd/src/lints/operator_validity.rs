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

use rulesteward_core::Diagnostic;

use crate::ast::LocatedRule;

/// au-E02 operator-validity pass.
///
/// Body is pipeline P3's; the signature is Phase-0 frozen.
#[must_use]
pub fn e02(rules: &[LocatedRule]) -> Vec<Diagnostic> {
    let _ = rules;
    todo!("pipeline P3 (#193): au-E02 operator validity per field type")
}
