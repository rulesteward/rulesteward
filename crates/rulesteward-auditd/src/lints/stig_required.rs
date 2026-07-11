//! au-W06: the ruleset is missing audit rules required by the applicable RHEL
//! STIG (issue #474). Version-aware: fires only under an explicit `--target`
//! (the portable default stays silent), mirroring the sysctld-W02 STIG
//! baseline pattern (#341).
//!
//! Phase-0 stub (session 7c): the entrypoint signature and the
//! [`TargetVersion`] enum are frozen here so the fan-out pipeline fills only
//! this file's body. The pinned per-RHEL-major required-rules tables are
//! derived from the DISA XCCDF benchmarks (RHEL 8 V2R4 / RHEL 9 V2R7 /
//! RHEL 10 V1R1) by `tools/auditd-stig-update`; matching is KEY-SENSITIVE
//! with a distinct present-but-key-differs message (locked decisions,
//! 2026-07-10).
//!
//! Session 7c-v0_6-wave3, P2: [`BaselineRule`], [`stig_baseline`], and
//! [`w06_with_baseline`] are the shipped shapes.
//! `RHEL8_REQUIRED`/`RHEL9_REQUIRED`/`RHEL10_REQUIRED` are the grounded
//! per-RHEL-major required-rules tables (61/67/75 rules.d lines respectively),
//! transcribed verbatim from `tools/auditd-stig-update derive`'s paste-ready
//! output and kept drift-tethered to the DISA XCCDF by that tool's `check`
//! gate (re-derive on a STIG bump; do not hand-edit). The matching algorithm
//! (`w06_with_baseline`'s body) is implemented per the grounded matcher spec
//! on that function's doc comment (sourced from the P2 grounding doc Part
//! C.5). [`w06_with_baseline`] is `pub` (not `pub(crate)`) specifically so the
//! frozen scenario tests in `tests/test_lints_stig_required.rs` (a separate
//! integration-test crate) can inject a small, appendix-cited test-local
//! baseline directly, independent of the shipped `RHEL*_REQUIRED` tables.

use rulesteward_core::Diagnostic;

use super::LintOptions;
use crate::ast::LocatedRule;

/// RHEL release whose STIG audit-rule baseline to check against. Clap-free
/// (the CLI maps its `--target` value-enum into this via a `From` impl);
/// mirrors `rulesteward_sysctld::TargetVersion` so each domain crate stays
/// clap-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetVersion {
    Rhel8,
    Rhel9,
    Rhel10,
}

/// au-W06 missing-required-STIG-rules pass. `target == None` (portable mode)
/// stays silent by contract; `Some(t)` dispatches to [`w06_with_baseline`]
/// against the shipped grounded table for `t` (via [`stig_baseline`]), which
/// reports every rule that release's STIG requires but this ruleset is missing
/// (or has present under a different key).
#[must_use]
pub fn w06(
    rules: &[LocatedRule],
    opts: LintOptions,
    target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    match target {
        None => Vec::new(),
        Some(t) => w06_with_baseline(rules, opts, baseline_for(t)),
    }
}

/// One STIG-required audit rule line: DISA's Group V-number, the RHEL STIG
/// control id (shown in au-W06 messages), and the canonical required
/// `rules.d` line text (auditd rules.d syntax; extraction source =
/// check-content, see `tools/auditd-stig-update/src/xccdf.rs`'s module doc).
/// `pub` (not `pub(crate)`) for two independent external consumers: (1)
/// `tools/auditd-stig-update`, which imports it for the drift `check`/`derive`
/// subcommands (mirrors `rulesteward_sysctld::baseline::StigEntry`), and (2)
/// the frozen scenario tests in `tests/test_lints_stig_required.rs`, which
/// build small test-local `&[BaselineRule]` slices to inject into
/// [`w06_with_baseline`] directly (see the module doc for why).
/// `Copy`: all fields are `&'static str`, so passing this type around never
/// needs a clone.
#[derive(Debug, Clone, Copy)]
pub struct BaselineRule {
    pub v_number: &'static str,
    pub stig_id: &'static str,
    pub line: &'static str,
}

/// The grounded per-RHEL-major required-rules tables: one `BaselineRule`
/// literal per derived rules.d line, transcribed verbatim from
/// `auditd-stig-update derive`'s paste-ready output and kept drift-tethered to
/// the DISA XCCDF by that tool's `check` gate (do not hand-edit; re-derive on a
/// STIG revision bump).
const RHEL8_REQUIRED: &[BaselineRule] = &[
    BaselineRule {
        v_number: "V-230386",
        stig_id: "RHEL-08-030000",
        line: "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv",
    },
    BaselineRule {
        v_number: "V-230386",
        stig_id: "RHEL-08-030000",
        line: "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
    },
    BaselineRule {
        v_number: "V-230386",
        stig_id: "RHEL-08-030000",
        line: "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv",
    },
    BaselineRule {
        v_number: "V-230386",
        stig_id: "RHEL-08-030000",
        line: "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv",
    },
    BaselineRule {
        v_number: "V-230404",
        stig_id: "RHEL-08-030130",
        line: "-w /etc/shadow -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-230405",
        stig_id: "RHEL-08-030140",
        line: "-w /etc/security/opasswd -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-230406",
        stig_id: "RHEL-08-030150",
        line: "-w /etc/passwd -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-230407",
        stig_id: "RHEL-08-030160",
        line: "-w /etc/gshadow -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-230408",
        stig_id: "RHEL-08-030170",
        line: "-w /etc/group -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-230409",
        stig_id: "RHEL-08-030171",
        line: "-w /etc/sudoers -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-230410",
        stig_id: "RHEL-08-030172",
        line: "-w /etc/sudoers.d/ -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-230412",
        stig_id: "RHEL-08-030190",
        line: "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change",
    },
    BaselineRule {
        v_number: "V-230413",
        stig_id: "RHEL-08-030200",
        line: "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230413",
        stig_id: "RHEL-08-030200",
        line: "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230413",
        stig_id: "RHEL-08-030200",
        line: "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230413",
        stig_id: "RHEL-08-030200",
        line: "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230418",
        stig_id: "RHEL-08-030250",
        line: "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage",
    },
    BaselineRule {
        v_number: "V-230419",
        stig_id: "RHEL-08-030260",
        line: "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230421",
        stig_id: "RHEL-08-030280",
        line: "-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh",
    },
    BaselineRule {
        v_number: "V-230422",
        stig_id: "RHEL-08-030290",
        line: "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd",
    },
    BaselineRule {
        v_number: "V-230423",
        stig_id: "RHEL-08-030300",
        line: "-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount",
    },
    BaselineRule {
        v_number: "V-230424",
        stig_id: "RHEL-08-030301",
        line: "-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount",
    },
    BaselineRule {
        v_number: "V-230425",
        stig_id: "RHEL-08-030302",
        line: "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount",
    },
    BaselineRule {
        v_number: "V-230425",
        stig_id: "RHEL-08-030302",
        line: "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k privileged-mount",
    },
    BaselineRule {
        v_number: "V-230426",
        stig_id: "RHEL-08-030310",
        line: "-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-230427",
        stig_id: "RHEL-08-030311",
        line: "-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-230428",
        stig_id: "RHEL-08-030312",
        line: "-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-230429",
        stig_id: "RHEL-08-030313",
        line: "-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-230430",
        stig_id: "RHEL-08-030314",
        line: "-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-230431",
        stig_id: "RHEL-08-030315",
        line: "-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-230432",
        stig_id: "RHEL-08-030316",
        line: "-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-230433",
        stig_id: "RHEL-08-030317",
        line: "-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-230434",
        stig_id: "RHEL-08-030320",
        line: "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh",
    },
    BaselineRule {
        v_number: "V-230435",
        stig_id: "RHEL-08-030330",
        line: "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230436",
        stig_id: "RHEL-08-030340",
        line: "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check",
    },
    BaselineRule {
        v_number: "V-230437",
        stig_id: "RHEL-08-030350",
        line: "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd",
    },
    BaselineRule {
        v_number: "V-230438",
        stig_id: "RHEL-08-030360",
        line: "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng",
    },
    BaselineRule {
        v_number: "V-230438",
        stig_id: "RHEL-08-030360",
        line: "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng",
    },
    BaselineRule {
        v_number: "V-230439",
        stig_id: "RHEL-08-030361",
        line: "-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete",
    },
    BaselineRule {
        v_number: "V-230439",
        stig_id: "RHEL-08-030361",
        line: "-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete",
    },
    BaselineRule {
        v_number: "V-230444",
        stig_id: "RHEL-08-030370",
        line: "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd",
    },
    BaselineRule {
        v_number: "V-230446",
        stig_id: "RHEL-08-030390",
        line: "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng",
    },
    BaselineRule {
        v_number: "V-230446",
        stig_id: "RHEL-08-030390",
        line: "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng",
    },
    BaselineRule {
        v_number: "V-230447",
        stig_id: "RHEL-08-030400",
        line: "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab",
    },
    BaselineRule {
        v_number: "V-230448",
        stig_id: "RHEL-08-030410",
        line: "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd",
    },
    BaselineRule {
        v_number: "V-230449",
        stig_id: "RHEL-08-030420",
        line: "-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access",
    },
    BaselineRule {
        v_number: "V-230449",
        stig_id: "RHEL-08-030420",
        line: "-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access",
    },
    BaselineRule {
        v_number: "V-230449",
        stig_id: "RHEL-08-030420",
        line: "-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access",
    },
    BaselineRule {
        v_number: "V-230449",
        stig_id: "RHEL-08-030420",
        line: "-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access",
    },
    BaselineRule {
        v_number: "V-230455",
        stig_id: "RHEL-08-030480",
        line: "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230455",
        stig_id: "RHEL-08-030480",
        line: "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230456",
        stig_id: "RHEL-08-030490",
        line: "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230456",
        stig_id: "RHEL-08-030490",
        line: "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230462",
        stig_id: "RHEL-08-030550",
        line: "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd",
    },
    BaselineRule {
        v_number: "V-230463",
        stig_id: "RHEL-08-030560",
        line: "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod",
    },
    BaselineRule {
        v_number: "V-230464",
        stig_id: "RHEL-08-030570",
        line: "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-230465",
        stig_id: "RHEL-08-030580",
        line: "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules",
    },
    BaselineRule {
        v_number: "V-230466",
        stig_id: "RHEL-08-030590",
        line: "-w /var/log/faillock -p wa -k logins",
    },
    BaselineRule {
        v_number: "V-230467",
        stig_id: "RHEL-08-030600",
        line: "-w /var/log/lastlog -p wa -k logins",
    },
    BaselineRule {
        v_number: "V-274877",
        stig_id: "RHEL-08-030655",
        line: "-w /etc/cron.d -p wa -k cronjobs",
    },
    BaselineRule {
        v_number: "V-274877",
        stig_id: "RHEL-08-030655",
        line: "-w /var/spool/cron -p wa -k cronjobs",
    },
];
const RHEL9_REQUIRED: &[BaselineRule] = &[
    BaselineRule {
        v_number: "V-258176",
        stig_id: "RHEL-09-654010",
        line: "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv",
    },
    BaselineRule {
        v_number: "V-258176",
        stig_id: "RHEL-09-654010",
        line: "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
    },
    BaselineRule {
        v_number: "V-258176",
        stig_id: "RHEL-09-654010",
        line: "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv",
    },
    BaselineRule {
        v_number: "V-258176",
        stig_id: "RHEL-09-654010",
        line: "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv",
    },
    BaselineRule {
        v_number: "V-258177",
        stig_id: "RHEL-09-654015",
        line: "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258177",
        stig_id: "RHEL-09-654015",
        line: "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258178",
        stig_id: "RHEL-09-654020",
        line: "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258178",
        stig_id: "RHEL-09-654020",
        line: "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258179",
        stig_id: "RHEL-09-654025",
        line: "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258179",
        stig_id: "RHEL-09-654025",
        line: "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258179",
        stig_id: "RHEL-09-654025",
        line: "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258179",
        stig_id: "RHEL-09-654025",
        line: "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid=0 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258180",
        stig_id: "RHEL-09-654030",
        line: "-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount",
    },
    BaselineRule {
        v_number: "V-258181",
        stig_id: "RHEL-09-654035",
        line: "-a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258182",
        stig_id: "RHEL-09-654040",
        line: "-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258183",
        stig_id: "RHEL-09-654045",
        line: "-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-258184",
        stig_id: "RHEL-09-654050",
        line: "-a always,exit -S all -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-258185",
        stig_id: "RHEL-09-654055",
        line: "-a always,exit -S all -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-258186",
        stig_id: "RHEL-09-654060",
        line: "-a always,exit -S all -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged",
    },
    BaselineRule {
        v_number: "V-258187",
        stig_id: "RHEL-09-654065",
        line: "-a always,exit -F arch=b32 -S unlink,rename,rmdir,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete",
    },
    BaselineRule {
        v_number: "V-258187",
        stig_id: "RHEL-09-654065",
        line: "-a always,exit -F arch=b64 -S rename,rmdir,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete",
    },
    BaselineRule {
        v_number: "V-258188",
        stig_id: "RHEL-09-654070",
        line: "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access",
    },
    BaselineRule {
        v_number: "V-258188",
        stig_id: "RHEL-09-654070",
        line: "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access",
    },
    BaselineRule {
        v_number: "V-258188",
        stig_id: "RHEL-09-654070",
        line: "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access",
    },
    BaselineRule {
        v_number: "V-258188",
        stig_id: "RHEL-09-654070",
        line: "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access",
    },
    BaselineRule {
        v_number: "V-258189",
        stig_id: "RHEL-09-654075",
        line: "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
    },
    BaselineRule {
        v_number: "V-258189",
        stig_id: "RHEL-09-654075",
        line: "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
    },
    BaselineRule {
        v_number: "V-258190",
        stig_id: "RHEL-09-654080",
        line: "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
    },
    BaselineRule {
        v_number: "V-258190",
        stig_id: "RHEL-09-654080",
        line: "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
    },
    BaselineRule {
        v_number: "V-258191",
        stig_id: "RHEL-09-654085",
        line: "-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage",
    },
    BaselineRule {
        v_number: "V-258192",
        stig_id: "RHEL-09-654090",
        line: "-a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd",
    },
    BaselineRule {
        v_number: "V-258193",
        stig_id: "RHEL-09-654095",
        line: "-a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-crontab",
    },
    BaselineRule {
        v_number: "V-258194",
        stig_id: "RHEL-09-654100",
        line: "-a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-gpasswd",
    },
    BaselineRule {
        v_number: "V-258195",
        stig_id: "RHEL-09-654105",
        line: "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=modules",
    },
    BaselineRule {
        v_number: "V-258196",
        stig_id: "RHEL-09-654110",
        line: "-a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd",
    },
    BaselineRule {
        v_number: "V-258197",
        stig_id: "RHEL-09-654115",
        line: "-a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-pam_timestamp_check",
    },
    BaselineRule {
        v_number: "V-258198",
        stig_id: "RHEL-09-654120",
        line: "-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-passwd",
    },
    BaselineRule {
        v_number: "V-258199",
        stig_id: "RHEL-09-654125",
        line: "-a always,exit -S all -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-258200",
        stig_id: "RHEL-09-654130",
        line: "-a always,exit -S all -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-258201",
        stig_id: "RHEL-09-654135",
        line: "-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh",
    },
    BaselineRule {
        v_number: "V-258202",
        stig_id: "RHEL-09-654140",
        line: "-a always,exit -S all -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh",
    },
    BaselineRule {
        v_number: "V-258203",
        stig_id: "RHEL-09-654145",
        line: "-a always,exit -S all -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-priv_change",
    },
    BaselineRule {
        v_number: "V-258204",
        stig_id: "RHEL-09-654150",
        line: "-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd",
    },
    BaselineRule {
        v_number: "V-258205",
        stig_id: "RHEL-09-654155",
        line: "-a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd",
    },
    BaselineRule {
        v_number: "V-258206",
        stig_id: "RHEL-09-654160",
        line: "-a always,exit -S all -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-258207",
        stig_id: "RHEL-09-654165",
        line: "-a always,exit -S all -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-258208",
        stig_id: "RHEL-09-654170",
        line: "-a always,exit -S all -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-258209",
        stig_id: "RHEL-09-654175",
        line: "-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod",
    },
    BaselineRule {
        v_number: "V-258210",
        stig_id: "RHEL-09-654180",
        line: "-a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount",
    },
    BaselineRule {
        v_number: "V-258211",
        stig_id: "RHEL-09-654185",
        line: "-a always,exit -S all -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-init",
    },
    BaselineRule {
        v_number: "V-258212",
        stig_id: "RHEL-09-654190",
        line: "-a always,exit -S all -F path=/usr/sbin/poweroff -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-poweroff",
    },
    BaselineRule {
        v_number: "V-258213",
        stig_id: "RHEL-09-654195",
        line: "-a always,exit -S all -F path=/usr/sbin/reboot -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-reboot",
    },
    BaselineRule {
        v_number: "V-258214",
        stig_id: "RHEL-09-654200",
        line: "-a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-shutdown",
    },
    BaselineRule {
        v_number: "V-258215",
        stig_id: "RHEL-09-654205",
        line: "-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=-1 -F key=privileged-umount",
    },
    BaselineRule {
        v_number: "V-258216",
        stig_id: "RHEL-09-654210",
        line: "-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount",
    },
    BaselineRule {
        v_number: "V-258216",
        stig_id: "RHEL-09-654210",
        line: "-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount",
    },
    BaselineRule {
        v_number: "V-258217",
        stig_id: "RHEL-09-654215",
        line: "-w /etc/sudoers -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-258218",
        stig_id: "RHEL-09-654220",
        line: "-w /etc/sudoers.d/ -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-258219",
        stig_id: "RHEL-09-654225",
        line: "-w /etc/group -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-258220",
        stig_id: "RHEL-09-654230",
        line: "-w /etc/gshadow -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-258221",
        stig_id: "RHEL-09-654235",
        line: "-w /etc/security/opasswd -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-258222",
        stig_id: "RHEL-09-654240",
        line: "-w /etc/passwd -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-258223",
        stig_id: "RHEL-09-654245",
        line: "-w /etc/shadow -p wa -k identity",
    },
    BaselineRule {
        v_number: "V-258224",
        stig_id: "RHEL-09-654250",
        line: "-w /var/log/faillock -p wa -k logins",
    },
    BaselineRule {
        v_number: "V-258225",
        stig_id: "RHEL-09-654255",
        line: "-w /var/log/lastlog -p wa -k logins",
    },
    BaselineRule {
        v_number: "V-279936",
        stig_id: "RHEL-09-654097",
        line: "-w /etc/cron.d -p wa -k cronjobs",
    },
    BaselineRule {
        v_number: "V-279936",
        stig_id: "RHEL-09-654097",
        line: "-w /var/spool/cron -p wa -k cronjobs",
    },
];
const RHEL10_REQUIRED: &[BaselineRule] = &[
    BaselineRule {
        v_number: "V-281116",
        stig_id: "RHEL-10-500300",
        line: "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv",
    },
    BaselineRule {
        v_number: "V-281116",
        stig_id: "RHEL-10-500300",
        line: "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv",
    },
    BaselineRule {
        v_number: "V-281116",
        stig_id: "RHEL-10-500300",
        line: "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv",
    },
    BaselineRule {
        v_number: "V-281116",
        stig_id: "RHEL-10-500300",
        line: "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv",
    },
    BaselineRule {
        v_number: "V-281117",
        stig_id: "RHEL-10-500310",
        line: "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-281117",
        stig_id: "RHEL-10-500310",
        line: "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-281117",
        stig_id: "RHEL-10-500310",
        line: "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod",
    },
    BaselineRule {
        v_number: "V-281117",
        stig_id: "RHEL-10-500310",
        line: "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod",
    },
    BaselineRule {
        v_number: "V-281118",
        stig_id: "RHEL-10-500320",
        line: "-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount",
    },
    BaselineRule {
        v_number: "V-281119",
        stig_id: "RHEL-10-500330",
        line: "-a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-281120",
        stig_id: "RHEL-10-500340",
        line: "-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-281121",
        stig_id: "RHEL-10-500350",
        line: "-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod",
    },
    BaselineRule {
        v_number: "V-281122",
        stig_id: "RHEL-10-500360",
        line: "-a always,exit -S all -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-281123",
        stig_id: "RHEL-10-500370",
        line: "-a always,exit -S all -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-281124",
        stig_id: "RHEL-10-500380",
        line: "-a always,exit -S all -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged",
    },
    BaselineRule {
        v_number: "V-281125",
        stig_id: "RHEL-10-500390",
        line: "-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access",
    },
    BaselineRule {
        v_number: "V-281125",
        stig_id: "RHEL-10-500390",
        line: "-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access",
    },
    BaselineRule {
        v_number: "V-281125",
        stig_id: "RHEL-10-500390",
        line: "-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access",
    },
    BaselineRule {
        v_number: "V-281125",
        stig_id: "RHEL-10-500390",
        line: "-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access",
    },
    BaselineRule {
        v_number: "V-281126",
        stig_id: "RHEL-10-500400",
        line: "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
    },
    BaselineRule {
        v_number: "V-281126",
        stig_id: "RHEL-10-500400",
        line: "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng",
    },
    BaselineRule {
        v_number: "V-281127",
        stig_id: "RHEL-10-500410",
        line: "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng",
    },
    BaselineRule {
        v_number: "V-281127",
        stig_id: "RHEL-10-500410",
        line: "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng",
    },
    BaselineRule {
        v_number: "V-281128",
        stig_id: "RHEL-10-500420",
        line: "-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage",
    },
    BaselineRule {
        v_number: "V-281129",
        stig_id: "RHEL-10-500430",
        line: "-a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd",
    },
    BaselineRule {
        v_number: "V-281130",
        stig_id: "RHEL-10-500440",
        line: "-a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-crontab",
    },
    BaselineRule {
        v_number: "V-281131",
        stig_id: "RHEL-10-500450",
        line: "-a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-gpasswd",
    },
    BaselineRule {
        v_number: "V-281132",
        stig_id: "RHEL-10-500460",
        line: "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=modules",
    },
    BaselineRule {
        v_number: "V-281133",
        stig_id: "RHEL-10-500470",
        line: "-a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd",
    },
    BaselineRule {
        v_number: "V-281134",
        stig_id: "RHEL-10-500480",
        line: "-a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-pam_timestamp_check",
    },
    BaselineRule {
        v_number: "V-281135",
        stig_id: "RHEL-10-500490",
        line: "-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-passwd",
    },
    BaselineRule {
        v_number: "V-281136",
        stig_id: "RHEL-10-500500",
        line: "-a always,exit -S all -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-281137",
        stig_id: "RHEL-10-500510",
        line: "-a always,exit -S all -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-281138",
        stig_id: "RHEL-10-500520",
        line: "-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh",
    },
    BaselineRule {
        v_number: "V-281139",
        stig_id: "RHEL-10-500530",
        line: "-a always,exit -S all -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh",
    },
    BaselineRule {
        v_number: "V-281140",
        stig_id: "RHEL-10-500540",
        line: "-a always,exit -S all -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-priv_change",
    },
    BaselineRule {
        v_number: "V-281141",
        stig_id: "RHEL-10-500550",
        line: "-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd",
    },
    BaselineRule {
        v_number: "V-281142",
        stig_id: "RHEL-10-500560",
        line: "-a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd",
    },
    BaselineRule {
        v_number: "V-281143",
        stig_id: "RHEL-10-500570",
        line: "-a always,exit -S all -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-281144",
        stig_id: "RHEL-10-500580",
        line: "-a always,exit -S all -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-281145",
        stig_id: "RHEL-10-500590",
        line: "-a always,exit -S all -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update",
    },
    BaselineRule {
        v_number: "V-281146",
        stig_id: "RHEL-10-500600",
        line: "-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod",
    },
    BaselineRule {
        v_number: "V-281147",
        stig_id: "RHEL-10-500610",
        line: "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k export",
    },
    BaselineRule {
        v_number: "V-281147",
        stig_id: "RHEL-10-500610",
        line: "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k export",
    },
    BaselineRule {
        v_number: "V-281148",
        stig_id: "RHEL-10-500620",
        line: "-a always,exit -S all -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-init",
    },
    BaselineRule {
        v_number: "V-281149",
        stig_id: "RHEL-10-500630",
        line: "-a always,exit -S all -F path=/usr/sbin/poweroff -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-poweroff",
    },
    BaselineRule {
        v_number: "V-281150",
        stig_id: "RHEL-10-500640",
        line: "-a always,exit -S all -F path=/usr/sbin/reboot -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-reboot",
    },
    BaselineRule {
        v_number: "V-281151",
        stig_id: "RHEL-10-500650",
        line: "-a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-shutdown",
    },
    BaselineRule {
        v_number: "V-281152",
        stig_id: "RHEL-10-500660",
        line: "-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=-1 -F key=privileged-umount",
    },
    BaselineRule {
        v_number: "V-281153",
        stig_id: "RHEL-10-500670",
        line: "-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount",
    },
    BaselineRule {
        v_number: "V-281153",
        stig_id: "RHEL-10-500670",
        line: "-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=-1 -F key=privileged-umount",
    },
    BaselineRule {
        v_number: "V-281154",
        stig_id: "RHEL-10-500680",
        line: "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F key=logins",
    },
    BaselineRule {
        v_number: "V-281154",
        stig_id: "RHEL-10-500680",
        line: "-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F key=logins",
    },
    BaselineRule {
        v_number: "V-281155",
        stig_id: "RHEL-10-500690",
        line: "-a always,exit -F arch=b32 -F path=/etc/sudoers.d/ -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281155",
        stig_id: "RHEL-10-500690",
        line: "-a always,exit -F arch=b64 -F path=/etc/sudoers.d/ -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281156",
        stig_id: "RHEL-10-500700",
        line: "-a always,exit -F arch=b32 -F path=/etc/group -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281156",
        stig_id: "RHEL-10-500700",
        line: "-a always,exit -F arch=b64 -F path=/etc/group -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281157",
        stig_id: "RHEL-10-500710",
        line: "-a always,exit -F arch=b32 -F path=/etc/gshadow -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281157",
        stig_id: "RHEL-10-500710",
        line: "-a always,exit -F arch=b64 -F path=/etc/gshadow -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281158",
        stig_id: "RHEL-10-500720",
        line: "-a always,exit -F arch=b32 -F path=/etc/security/opasswd -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281158",
        stig_id: "RHEL-10-500720",
        line: "-a always,exit -F arch=b64 -F path=/etc/security/opasswd -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281159",
        stig_id: "RHEL-10-500730",
        line: "-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281159",
        stig_id: "RHEL-10-500730",
        line: "-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281160",
        stig_id: "RHEL-10-500740",
        line: "-a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281160",
        stig_id: "RHEL-10-500740",
        line: "-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281161",
        stig_id: "RHEL-10-500750",
        line: "-a always,exit -F arch=b32 -F path=/var/log/faillock -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281161",
        stig_id: "RHEL-10-500750",
        line: "-a always,exit -F arch=b64 -F path=/var/log/faillock -F perm=wa -F key=identity",
    },
    BaselineRule {
        v_number: "V-281162",
        stig_id: "RHEL-10-500760",
        line: "-a always,exit -F arch=b32 -F path=/var/log/lastlog -F perm=wa -F key=logins",
    },
    BaselineRule {
        v_number: "V-281162",
        stig_id: "RHEL-10-500760",
        line: "-a always,exit -F arch=b64 -F path=/var/log/lastlog -F perm=wa -F key=logins",
    },
    BaselineRule {
        v_number: "V-281163",
        stig_id: "RHEL-10-500780",
        line: "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-281163",
        stig_id: "RHEL-10-500780",
        line: "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-281164",
        stig_id: "RHEL-10-500790",
        line: "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-281164",
        stig_id: "RHEL-10-500790",
        line: "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod",
    },
    BaselineRule {
        v_number: "V-281165",
        stig_id: "RHEL-10-500810",
        line: "-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,renameat2,unlinkat -F auid>=1000 -F auid!=unset -k delete",
    },
    BaselineRule {
        v_number: "V-281165",
        stig_id: "RHEL-10-500810",
        line: "-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,renameat2,unlinkat -F auid>=1000 -F auid!=unset -k delete",
    },
];

fn baseline_for(target: TargetVersion) -> &'static [BaselineRule] {
    match target {
        TargetVersion::Rhel8 => RHEL8_REQUIRED,
        TargetVersion::Rhel9 => RHEL9_REQUIRED,
        TargetVersion::Rhel10 => RHEL10_REQUIRED,
    }
}

/// The STIG baseline for `target` (the pub accessor for the drift test):
/// `tools/auditd-stig-update`'s `check`/`derive` subcommands import this to
/// diff the shipped table against a live/fixture-derived DISA XCCDF.
#[must_use]
pub fn stig_baseline(target: TargetVersion) -> &'static [BaselineRule] {
    baseline_for(target)
}

/// The au-W06 matcher, taking an EXPLICIT `baseline` slice (see the module doc
/// for why this is `pub` and separate from `w06`'s `target`-based signature).
/// An empty `baseline` short-circuits to `Vec::new()`, so a `--target` against
/// a (hypothetically) empty table is clean exit-0 plumbing; a non-empty
/// baseline (the shipped `RHEL*_REQUIRED` tables via [`w06`], or a test-local
/// injected one) runs the full matcher below.
///
/// # Grounded matcher spec (P2 grounding doc Part C.5)
///
/// For each `BaselineRule` in `baseline`:
/// 1. Parse `rule.line` via [`crate::parser`] (the SAME parser rules.d files
///    go through - `rulesteward_auditd::parser::parse_rules_str`, taking the
///    first parsed `AuditRule`) into the required `AuditRule`.
/// 2. Search `rules` (the full parsed ruleset) for a same-variant
///    (`Watch`-vs-`Watch` or `Syscall`-vs-`Syscall`) rule that matches on
///    EVERY axis:
///    - **Watch path:** plain string compare (or trailing-slash-normalized;
///      `is_dir` is NOT part of the comparison - grounding Part B.7.2).
///    - **Watch perms:** exact `PermBits` equality.
///    - **Key (both variants):** the UNIFIED key - `key.clone().or_else(||
///      fields.iter().find(|f| f.field == AuditField::Key).map(|f|
///      f.value.clone()))` on EACH side, then compare with `==`
///      (case-sensitive, trimmed) - this is the "`-k` == `-F key=`"
///      equivalence (locked decision), implemented as a lookup-time unify,
///      NOT a `canonical_value` fold.
///    - **`-F` fields (Syscall only), EXCLUDING any `AuditField::Key` entry**
///      (already consumed by the key-unify step): compare as a SET - same
///      size, and for every predicate a matching predicate on the other side
///      with the same `field`, same `op`, and
///      `canonical_value(field_type(field), value, opts) ==
///      canonical_value(field_type(field), other_value, opts)` (reuse
///      [`super::value::canonical_value`] directly; this is exactly the `I0`
///      branch of [`super::value::implies`], NOT `implies`/`disjoint`
///      themselves).
///    - **`-C` field-comparisons (Syscall only):** SET of `(left, op,
///      right)` triples, enum equality on all three (both operands are
///      field NAMES, never values, so no `canonical_value` step here).
///    - **`syscalls` (Syscall only):** SET of case-sensitive strings (NOT
///      ordered - grounding Part B.5.12/C.1 proves DISA's own text and a
///      live kernel round-trip both disagree on order).
///    - **`list`/`action`/`prepend` (Syscall only):** exact enum/bool
///      equality.
/// 3. Classify the verdict for this required line:
///    - **Satisfied:** a rule matches on every axis INCLUDING the key -> no
///      diagnostic.
///    - **Present-but-key-differs (the locked distinct finding):** a rule
///      matches every axis EXCEPT the key -> ONE `au-W06` `Warning`
///      diagnostic per such required line, with a message DISTINCT from the
///      missing case (name both the STIG id and that a same-shape rule with
///      a different key exists).
///    - **Missing:** no rule matches even excluding the key -> ONE `au-W06`
///      `Warning` diagnostic naming the STIG id and the missing line/watch.
/// 4. Anchor each diagnostic per the sysctld-W02 precedent
///    (`crates/rulesteward-sysctld/src/lints/baseline.rs`'s `w02_baseline`
///    doc comment): this is a MISSING-rule finding with no single offending
///    span in the user's ruleset, so anchor at the whole-ruleset/first-file
///    span (line 0, no `source_id`), not a specific existing rule's span.
#[must_use]
pub fn w06_with_baseline(
    rules: &[LocatedRule],
    opts: LintOptions,
    baseline: &[BaselineRule],
) -> Vec<Diagnostic> {
    if baseline.is_empty() {
        return Vec::new();
    }

    // No single offending span exists for a MISSING-rule finding (grounding
    // Part C.5, sysctld-W02 precedent): anchor at the first file in the
    // concatenated stream, mirroring that precedent's "anchor at the
    // whole-ruleset/first-file span" call. An empty `rules` slice (a ruleset
    // with zero parsed rules at all) has no file to anchor to; fall back to
    // an empty path rather than panicking.
    let anchor_file = rules.first().map(|r| r.file.clone()).unwrap_or_default();

    let candidates: Vec<&crate::ast::AuditRule> = rules.iter().map(|r| &r.rule).collect();

    let mut diags = Vec::new();
    for required in baseline {
        let required_rule = parse_single_rule(required.line).unwrap_or_else(|e| {
            panic!(
                "BaselineRule for {} ({}) has an unparseable line {:?}: {e}",
                required.stig_id, required.v_number, required.line
            )
        });

        let satisfied = candidates
            .iter()
            .any(|c| rules_match(&required_rule, c, opts, true));
        if satisfied {
            continue;
        }

        let key_differs = candidates
            .iter()
            .any(|c| rules_match(&required_rule, c, opts, false));

        let message = if key_differs {
            format!(
                "STIG-required audit rule {} ({}) is present but with a different key \
                 than required: `{}`",
                required.stig_id, required.v_number, required.line
            )
        } else {
            format!(
                "STIG-required audit rule {} ({}) is missing: `{}`",
                required.stig_id, required.v_number, required.line
            )
        };

        diags.push(Diagnostic::new(
            rulesteward_core::Severity::Warning,
            "au-W06",
            0..0,
            message,
            anchor_file.clone(),
            0,
            0,
        ));
    }
    diags
}

/// Parse one required `BaselineRule.line` via the SAME parser rules.d files go
/// through, taking the first (and only) parsed rule. Every real baseline entry
/// is a single auditd rules.d line (one `-w`/`-a`/`-A` per row - see
/// [`crate::derive`]'s module doc: `parse_requirements` emits one row per
/// extracted line), so exactly one rule is expected.
fn parse_single_rule(line: &str) -> Result<crate::ast::AuditRule, String> {
    crate::parser::parse_rules_str(line)
        .map_err(|errs| format!("{errs:?}"))?
        .into_iter()
        .next()
        .ok_or_else(|| "no rule parsed from an empty or comment-only line".to_string())
}

/// The unified "effective key" of a rule (grounding Part C.5): `-k` and
/// `-F key=` are the SAME `AUDIT_FILTERKEY` field (C.1), so a rule's key is
/// its `key` slot if set, else the value of an `-F key=` entry among its
/// `fields` (only `Syscall` rules can carry `-F key=`; the `Watch` grammar has
/// no `-F` branch at all - parser.rs has no such path for `-w` lines). Trimmed
/// for a robust, whitespace-insensitive compare.
fn effective_key(rule: &crate::ast::AuditRule) -> Option<&str> {
    use crate::ast::AuditRule;
    let raw = match rule {
        AuditRule::Watch { key, .. } => key.as_deref(),
        AuditRule::Syscall { key, fields, .. } => key.as_deref().or_else(|| {
            fields
                .iter()
                .find(|f| f.field == crate::ast::AuditField::Key)
                .map(|f| f.value.as_str())
        }),
        AuditRule::Control(_) => None,
    };
    raw.map(str::trim)
}

/// Whether `candidate` satisfies `required`. When `include_key` is `true` this
/// is the FULL match (the "Satisfied" verdict); when `false` the key axis is
/// excluded (used to distinguish "Missing" from "Present-but-key-differs").
/// Same-variant only (`Watch`-vs-`Watch` or `Syscall`-vs-`Syscall`): a
/// kernel-equivalent rule spelled in the OTHER variant's grammar never
/// satisfies a requirement (grounding Part C.2's documented non-goal).
fn rules_match(
    required: &crate::ast::AuditRule,
    candidate: &crate::ast::AuditRule,
    opts: LintOptions,
    include_key: bool,
) -> bool {
    use crate::ast::AuditRule;

    let axes_match = match (required, candidate) {
        (
            AuditRule::Watch {
                path: rp,
                perms: rpe,
                ..
            },
            AuditRule::Watch {
                path: cp,
                perms: cpe,
                ..
            },
        ) => normalize_watch_path(rp) == normalize_watch_path(cp) && rpe == cpe,
        (
            AuditRule::Syscall {
                list: rl,
                action: ra,
                syscalls: rs,
                fields: rf,
                field_compares: rfc,
                prepend: rpr,
                ..
            },
            AuditRule::Syscall {
                list: cl,
                action: ca,
                syscalls: cs,
                fields: cf,
                field_compares: cfc,
                prepend: cpr,
                ..
            },
        ) => {
            rl == cl
                && ra == ca
                && rpr == cpr
                && multiset_eq(rs, cs, |a, b| a == b)
                && multiset_eq(rfc, cfc, |a, b| a == b)
                && fields_match_excluding_key(rf, cf, opts)
        }
        _ => false,
    };

    axes_match && (!include_key || effective_key(required) == effective_key(candidate))
}

/// Trailing-slash-normalized watch path compare (grounding Part B.7.2):
/// check-content and fixtext disagree on a trailing `/` for the one multi-watch
/// requirement that has any slash at all, and `is_dir` is deliberately NOT part
/// of the comparison - stripping a trailing `/` before comparing is the
/// simpler, equivalent way to state "ignore `is_dir`".
fn normalize_watch_path(path: &str) -> &str {
    path.trim_end_matches('/')
}

/// Compare two rules' `-F` field-filter sets, EXCLUDING any `AuditField::Key`
/// entry on either side (the key axis is handled separately by
/// [`effective_key`] - a `-k`-spelled candidate vs a `-F key=`-spelled
/// requirement must not ALSO be compared here as a generic field, or it would
/// spuriously fail on "field set size mismatch" even when the key values
/// unify). A set (not ordered) compare per the locked field-order-insensitive
/// decision (grounding Part C.1).
fn fields_match_excluding_key(
    required: &[crate::ast::FieldFilter],
    candidate: &[crate::ast::FieldFilter],
    opts: LintOptions,
) -> bool {
    let rf: Vec<&crate::ast::FieldFilter> = required
        .iter()
        .filter(|f| f.field != crate::ast::AuditField::Key)
        .collect();
    let cf: Vec<&crate::ast::FieldFilter> = candidate
        .iter()
        .filter(|f| f.field != crate::ast::AuditField::Key)
        .collect();
    multiset_eq(&rf, &cf, |a, b| {
        a.field == b.field && a.op == b.op && {
            let ft = super::field_type::field_type(&a.field);
            super::value::canonical_value(ft, &a.value, opts)
                == super::value::canonical_value(ft, &b.value, opts)
        }
    })
}

/// Multiset equality: same length, and every element of `a` has a distinct
/// (not-yet-matched) equal element in `b` under `eq`. Used for the field/
/// syscall/field-compare SET comparisons (grounding Part C.1/C.5: none of
/// these are ordered).
fn multiset_eq<T>(a: &[T], b: &[T], eq: impl Fn(&T, &T) -> bool) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut used = vec![false; b.len()];
    for x in a {
        match b.iter().enumerate().position(|(i, y)| !used[i] && eq(x, y)) {
            Some(i) => used[i] = true,
            None => return false,
        }
    }
    true
}
