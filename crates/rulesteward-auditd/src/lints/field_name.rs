//! Canonical `-F` field-name strings for [`AuditField`] (#458).
//!
//! Both `operator_validity::e02` and `field_filter::e04` used to carry their
//! own byte-identical private `field_name_str` match, one per file. This
//! module unifies them into a single [`field_name`] free function so the
//! 45-arm map is defined exactly once (matching the sibling `field_type` /
//! `op_str` / `filter_list_name` / `field_restriction` free-fn convention in
//! this crate).
//!
//! Deliberately hosted here (`lints/field_name.rs`), NOT in `ast.rs`: the
//! global `.cargo/mutants.toml` `exclude_globs` excludes `**/ast.rs` from
//! mutation testing, while `crates/rulesteward-auditd/src/lints/**/*.rs` is in
//! `examine_globs`. Moving the map into `ast.rs` would silently drop it out of
//! the mutation gate (a vacuity regression); keeping it under `lints/` keeps
//! every arm mutation-covered.

use crate::ast::AuditField;

/// The canonical `-F` field name this variant serializes to in diagnostic
/// messages (e.g. `AuditField::Auid` -> `"auid"`), matching the name
/// `auditctl`/`augenrules` accepts on the left of `-F name=value`.
#[must_use]
pub(crate) fn field_name(field: &AuditField) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::field_name;
    use crate::ast::AuditField;

    /// Exhaustive pin: every one of the 45 `AuditField` variants maps to its
    /// exact expected `-F` field-name string. The table is asserted to be
    /// length 45 so a dropped row fails, and each expected string is checked
    /// against [`field_name`] so a swapped/blanked arm fails.
    #[test]
    fn name_covers_all_45_variants() {
        let cases: &[(AuditField, &str)] = &[
            (AuditField::A0, "a0"),
            (AuditField::A1, "a1"),
            (AuditField::A2, "a2"),
            (AuditField::A3, "a3"),
            (AuditField::Arch, "arch"),
            (AuditField::Auid, "auid"),
            (AuditField::DevMajor, "devmajor"),
            (AuditField::DevMinor, "devminor"),
            (AuditField::Dir, "dir"),
            (AuditField::Egid, "egid"),
            (AuditField::Euid, "euid"),
            (AuditField::Exe, "exe"),
            (AuditField::Exit, "exit"),
            (AuditField::FieldCompare, "field_compare"),
            (AuditField::Filetype, "filetype"),
            (AuditField::Fsgid, "fsgid"),
            (AuditField::Fstype, "fstype"),
            (AuditField::Fsuid, "fsuid"),
            (AuditField::Gid, "gid"),
            (AuditField::Inode, "inode"),
            (AuditField::Key, "key"),
            (AuditField::MsgType, "msgtype"),
            (AuditField::ObjGid, "obj_gid"),
            (AuditField::ObjLevHigh, "obj_lev_high"),
            (AuditField::ObjLevLow, "obj_lev_low"),
            (AuditField::ObjRole, "obj_role"),
            (AuditField::ObjType, "obj_type"),
            (AuditField::ObjUid, "obj_uid"),
            (AuditField::ObjUser, "obj_user"),
            (AuditField::Path, "path"),
            (AuditField::Perm, "perm"),
            (AuditField::Pers, "pers"),
            (AuditField::Pid, "pid"),
            (AuditField::Ppid, "ppid"),
            (AuditField::SaddrFam, "saddr_fam"),
            (AuditField::SessionId, "sessionid"),
            (AuditField::Sgid, "sgid"),
            (AuditField::SubjClr, "subj_clr"),
            (AuditField::SubjRole, "subj_role"),
            (AuditField::SubjSen, "subj_sen"),
            (AuditField::SubjType, "subj_type"),
            (AuditField::SubjUser, "subj_user"),
            (AuditField::Success, "success"),
            (AuditField::Suid, "suid"),
            (AuditField::Uid, "uid"),
        ];
        assert_eq!(cases.len(), 45, "must cover all 45 AuditField variants");
        for (field, expected) in cases {
            assert_eq!(
                field_name(field),
                *expected,
                "field_name({field:?}) mismatch"
            );
        }
    }
}
