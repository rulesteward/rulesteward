//! au-W06: the ruleset is missing audit rules required by the applicable RHEL
//! STIG (issue #474). Version-aware: fires only under an explicit `--target`
//! (the portable default stays silent), mirroring the sysctld-W02 STIG
//! baseline pattern (#341).
//!
//! Phase-0 stub (session 7c): the entrypoint signature and the
//! [`TargetVersion`] enum are frozen here so the fan-out pipeline fills only
//! this file's body. The pinned per-RHEL-major required-rules tables are
//! derived from the DISA XCCDF benchmarks (RHEL 8 V2R8 / RHEL 9 V2R9 /
//! RHEL 10 V1R2) by `tools/auditd-stig-update`; matching is KEY-SENSITIVE
//! with a distinct present-but-key-differs message (locked decisions,
//! 2026-07-10).
//!
//! Session 7c-v0_6-wave3, P2: [`BaselineRule`], [`stig_baseline`], and
//! [`w06_with_baseline`] are the shipped shapes. USER RULING (`AskUserQuestion`,
//! 2026-07-17, session 9e-wave2c pipeline P2 round 2, #549 follow-up): a
//! path-watch STIG requirement is satisfied by EITHER kernel-equivalent form
//! (a classic `-w path -p perms -k key` watch, or its dual-arch
//! `-a always,exit -F arch=bXX -F path= -F perm= -k key` syscall pair), both
//! directions, all targets -- see [`rules_match`]'s doc comment for the full
//! grounding and the structural "pure path-watch shape" definition.
//! `RHEL8_REQUIRED`/`RHEL9_REQUIRED`/`RHEL10_REQUIRED` are the grounded
//! per-RHEL-major required-rules tables (63/81/77 rules.d lines respectively
//! as of the #549 RHEL9 V2R7->V2R9 pin bump, session 9e-wave2c pipeline P2;
//! originally 61/67/75), transcribed verbatim from
//! `tools/auditd-stig-update derive`'s paste-ready output and kept
//! drift-tethered to the DISA XCCDF by that tool's `check` gate (re-derive on
//! a STIG bump; do not hand-edit). The matching algorithm
//! (`w06_with_baseline`'s body) is implemented per the grounded matcher spec
//! on that function's doc comment (sourced from the P2 grounding doc Part
//! C.5). [`w06_with_baseline`] is `pub` (not `pub(crate)`) specifically so the
//! frozen scenario tests in `tests/test_lints_stig_required.rs` (a separate
//! integration-test crate) can inject a small, appendix-cited test-local
//! baseline directly, independent of the shipped `RHEL*_REQUIRED` tables.

use rulesteward_core::{ControlRef, Diagnostic, Framework};

use super::LintOptions;
use super::cis;
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
///
/// After `w06_with_baseline` returns, this outer wrapper attaches the
/// `Framework::Cis` refs (issue #528) that join each finding's `Stig` id
/// under `t` (via [`cis::cis_controls_for_stig`]), EXTENDING each
/// diagnostic's existing `controls` rather than replacing it (a finding keeps
/// its `Stig` ref and gains 0/1/many `Cis` refs alongside it). The CIS attach
/// lives HERE, not in `w06_with_baseline`, because that function's frozen
/// scenario tests (`tests/test_lints_stig_required.rs`) assert
/// `controls.len() == 1`.
#[must_use]
pub fn w06(
    rules: &[LocatedRule],
    opts: LintOptions,
    target: Option<TargetVersion>,
) -> Vec<Diagnostic> {
    match target {
        None => Vec::new(),
        Some(t) => {
            let mut diags = w06_with_baseline(rules, opts, baseline_for(t));
            for d in &mut diags {
                let stig_ids: Vec<String> = d
                    .controls
                    .iter()
                    .filter(|c| c.framework == Framework::Stig)
                    .map(|c| c.id.clone())
                    .collect();
                for stig_id in stig_ids {
                    d.controls.extend(cis::cis_controls_for_stig(t, &stig_id));
                }
            }
            diags
        }
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
    // Deepening (#523): SV-230402r1017208_rule, a bare Control-rule
    // requirement (the audit system must be set immutable). Fetched live
    // 2026-07-15 against the pinned DISA U_RHEL_8_STIG.zip (V2R4).
    BaselineRule {
        v_number: "V-230402",
        stig_id: "RHEL-08-030121",
        line: "-e 2",
    },
    // Deepening cont'd (#523, additive round 2): SV-230403r1017209_rule, a
    // bare Control-rule requirement (make the audit loginuid unchangeable
    // once set). Fetched live 2026-07-15 against the pinned DISA
    // U_RHEL_8_STIG.zip (V2R4).
    BaselineRule {
        v_number: "V-230403",
        stig_id: "RHEL-08-030122",
        line: "--loginuid-immutable",
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
    // #549 (session 9e-wave2c pipeline P2, 2026-07-17): DISA RHEL 9 STIG V2R9
    // (confirmed via U_RHEL_9_V2R9_STIG.zip) rewrote the 9 identity/login
    // rules below from single-line watch form (`-w PATH -p wa -k KEY`) into
    // dual-arch (b32/b64) syscall form, and added a brand-new required rule,
    // V-279936 (RHEL-09-654097), replacing the two old cron watch lines with
    // 4 new dual-arch execve/subj_type=crond_t syscall lines. Every line below
    // is pasted VERBATIM from `auditd-stig-update derive --product rhel9`
    // against the real V2R9 XCCDF (transcribed from check-content, not
    // fixtext); V-258225's b64 line carries a genuine double space before
    // `-F perm=wa` in DISA's own check-content text (not a transcription
    // error - see the pinned content test in
    // crates/rulesteward-auditd/tests/test_lints_stig_required.rs).
    BaselineRule {
        v_number: "V-258217",
        stig_id: "RHEL-09-654215",
        line: "-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258217",
        stig_id: "RHEL-09-654215",
        line: "-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258218",
        stig_id: "RHEL-09-654220",
        line: "-a always,exit -F arch=b32 -F path=/etc/sudoers.d -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258218",
        stig_id: "RHEL-09-654220",
        line: "-a always,exit -F arch=b64 -F path=/etc/sudoers.d -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258219",
        stig_id: "RHEL-09-654225",
        line: "-a always,exit -F arch=b32 -F path=/etc/group -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258219",
        stig_id: "RHEL-09-654225",
        line: "-a always,exit -F arch=b64 -F path=/etc/group -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258220",
        stig_id: "RHEL-09-654230",
        line: "-a always,exit -F arch=b32 -F path=/etc/gshadow -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258220",
        stig_id: "RHEL-09-654230",
        line: "-a always,exit -F arch=b64 -F path=/etc/gshadow -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258221",
        stig_id: "RHEL-09-654235",
        line: "-a always,exit -F arch=b32 -F path=/etc/security/opasswd -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258221",
        stig_id: "RHEL-09-654235",
        line: "-a always,exit -F arch=b64 -F path=/etc/security/opasswd -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258222",
        stig_id: "RHEL-09-654240",
        line: "-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258222",
        stig_id: "RHEL-09-654240",
        line: "-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258223",
        stig_id: "RHEL-09-654245",
        line: "-a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258223",
        stig_id: "RHEL-09-654245",
        line: "-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -k identity",
    },
    BaselineRule {
        v_number: "V-258224",
        stig_id: "RHEL-09-654250",
        line: "-a always,exit -F arch=b32 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins",
    },
    BaselineRule {
        v_number: "V-258224",
        stig_id: "RHEL-09-654250",
        line: "-a always,exit -F arch=b64 -F path=/var/log/faillock -F perm=wa -F auid>=1000 -F auid!=unset -k logins",
    },
    BaselineRule {
        v_number: "V-258225",
        stig_id: "RHEL-09-654255",
        line: "-a always,exit -F arch=b32 -F path=/var/log/lastlog -F perm=wa -F auid>=1000 -F auid!=unset -k logins",
    },
    BaselineRule {
        v_number: "V-258225",
        stig_id: "RHEL-09-654255",
        line: "-a always,exit -F arch=b64 -F path=/var/log/lastlog  -F perm=wa -F auid>=1000 -F auid!=unset -k logins",
    },
    BaselineRule {
        v_number: "V-279936",
        stig_id: "RHEL-09-654097",
        line: "-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec",
    },
    BaselineRule {
        v_number: "V-279936",
        stig_id: "RHEL-09-654097",
        line: "-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec",
    },
    BaselineRule {
        v_number: "V-279936",
        stig_id: "RHEL-09-654097",
        line: "-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec",
    },
    BaselineRule {
        v_number: "V-279936",
        stig_id: "RHEL-09-654097",
        line: "-a always,exit -F arch=b32 -S execve -F subj_type=crond_t -F auid>=1000 -F auid!=unset -k cron_exec",
    },
    // Deepening (#523): SV-258227r1014992_rule, a bare Control-rule
    // requirement (panic on critical audit failure). Fetched live
    // 2026-07-15 against the pinned DISA U_RHEL_9_STIG.zip (V2R7).
    BaselineRule {
        v_number: "V-258227",
        stig_id: "RHEL-09-654265",
        line: "-f 2",
    },
    // Deepening (#523): SV-258229r958434_rule, a bare Control-rule
    // requirement (the audit system must be set immutable).
    BaselineRule {
        v_number: "V-258229",
        stig_id: "RHEL-09-654275",
        line: "-e 2",
    },
    // Deepening cont'd (#523, additive round 2): SV-258228r991572_rule, a
    // bare Control-rule requirement (make the audit loginuid unchangeable
    // once set). Fetched live 2026-07-15 against the pinned DISA
    // U_RHEL_9_STIG.zip (V2R7).
    BaselineRule {
        v_number: "V-258228",
        stig_id: "RHEL-09-654270",
        line: "--loginuid-immutable",
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
    // Deepening (#523): SV-281103r1166261_rule, a bare Control-rule
    // requirement (panic on critical audit failure). Fetched live
    // 2026-07-15 against the pinned DISA U_RHEL_10_STIG.zip (V1R1).
    BaselineRule {
        v_number: "V-281103",
        stig_id: "RHEL-10-500035",
        line: "-f 2",
    },
    // Deepening (#523): SV-281365r1167245_rule, a bare Control-rule
    // requirement (the audit system must be set immutable).
    BaselineRule {
        v_number: "V-281365",
        stig_id: "RHEL-10-900100",
        line: "-e 2",
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
/// # Grounded matcher spec (P2 grounding doc Part C.5, PLUS the path-watch
/// # equivalence fold, USER RULING 2026-07-17 -- see [`rules_match`]'s doc
/// # comment for the full grounding)
///
/// For each `BaselineRule` in `baseline`:
/// 1. Parse `rule.line` via [`crate::parser`] (the SAME parser rules.d files
///    go through - `rulesteward_auditd::parser::parse_rules_str`, taking the
///    first parsed `AuditRule`) into the required `AuditRule`.
/// 2. Search `rules` (the full parsed ruleset) for a rule that matches on
///    EVERY axis. This is SAME-VARIANT (`Watch`-vs-`Watch` or
///    `Syscall`-vs-`Syscall`), PLUS the path-watch equivalence fold: a
///    `Watch`-vs-`Syscall` (or `Syscall`-vs-`Watch`) pair also matches when
///    the `Syscall` side is STRUCTURALLY a pure path-watch (empty `-S` list,
///    `always,exit`, no `-C`, and `-F` predicates limited to
///    `path`/`perm`/`arch`) and its `path`/`perm` equal the `Watch` side's
///    (arch is ignored on that side -- a watch has no arch axis, so it
///    matches a b32 row and a b64 row independently). See [`rules_match`]'s
///    doc comment for the axis definitions:
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

        diags.push(
            Diagnostic::new(
                rulesteward_core::Severity::Warning,
                "au-W06",
                0..0,
                message,
                anchor_file.clone(),
                0,
                0,
            )
            .with_controls(vec![
                ControlRef::new(Framework::Stig, required.stig_id).with_alias(required.v_number),
            ]),
        );
    }
    diags
}

/// Parse one required `BaselineRule.line` via the SAME parser rules.d files go
/// through, taking the first (and only) parsed rule. Every real baseline entry
/// is a single auditd rules.d line (one `-w`/`-a`/`-A` per row, or a bare
/// Control-rule line like `-e 2`/`-f 2`/`--loginuid-immutable` - see
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
///
/// Same-variant (`Watch`-vs-`Watch` or `Syscall`-vs-`Syscall`), PLUS the
/// path-watch equivalence fold (USER RULING via `AskUserQuestion`,
/// 2026-07-17, session 9e-wave2c pipeline P2 round 2, #549 follow-up): a
/// `Watch`-vs-`Syscall` pair (either order) ALSO matches when the `Syscall`
/// side is a pure path-watch SHAPE and its `path`/`perm` equal the `Watch`
/// side's. Grounding: DISA V2R9's own check-content runs `auditctl -l | grep
/// <path>` and PASSES against a plain watch line (V-258222's check-content,
/// verified against the downloaded V2R9 XCCDF); `auditctl(8)` documents
/// `-w path -p perms` as compiling to `-a always,exit -F path= -F perm=` per
/// architecture; `ComplianceAsCode`'s RHEL9 OVAL defaults to the watch style
/// (`audit_watches_style = 'legacy'`, `ssg/constants.py:468`); the kernel
/// folds a path-watch syscall rule back to `-w` in `auditctl -l`. So a
/// classic watch and its dual-arch syscall pair are the SAME kernel-level
/// audit configuration for a plain path+perm(+key) requirement -- this
/// supersedes grounding Part C.2's prior "different variant never satisfies"
/// non-goal for this specific shape only.
///
/// "Pure path-watch shape" (the structural test [`is_pure_path_watch_shaped`]
/// applies, on WHICHEVER side is `Syscall`): an EMPTY `-S` syscall list (`-w`
/// never names one), the `always,exit` list/action pair, no `-C`
/// field-comparisons, and `-F` predicates limited to `path`/`perm`/`arch`.
/// This is a STRUCTURAL check, never a per-V-number special case: a rule with
/// a non-empty `-S` list or any OTHER `-F` field (e.g. V-279936's
/// `-S execve -F subj_type=crond_t`) fails the shape test and stays
/// syscall-only, with no watch-equivalent form at all. `-F arch=` is IGNORED
/// on the `Syscall` side when comparing against a `Watch` (a watch has no
/// arch axis), so the SAME watch independently satisfies a b32 row and a b64
/// row of the same V-number (each is checked separately by the caller's
/// per-required-row loop). Path compares via [`normalize_watch_path`] (same
/// as the Watch-vs-Watch axis); perm compares via [`perm_bits_from_field_value`]
/// parsing the `-F perm=` string into `PermBits` for a genuinely
/// order-insensitive equality (mirroring the existing Watch-vs-Watch `rpe ==
/// cpe` rigor, not a raw string compare that `-p wa` vs `-p aw` could break).
/// Key handling is UNCHANGED: `effective_key` already works generically over
/// either variant, so the trailing `include_key` check below needs no new
/// logic once `axes_match` crosses variants.
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
        // Control-shaped requirements (STIG deepening, #523): "-e 2"
        // (immutable audit config), "-f 2" (panic on critical failure),
        // "--loginuid-immutable". `ControlRule` derives `PartialEq`, so exact
        // variant+value equality is the whole axis - no path/perms/key
        // concept applies to a Control rule (`effective_key` already returns
        // `None` for both sides, so the key-inclusion check below is a no-op
        // for this arm).
        (AuditRule::Control(rc), AuditRule::Control(cc)) => rc == cc,
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
        // Path-watch equivalence fold (USER RULING, 2026-07-17; see the doc
        // comment above): a Watch-shaped requirement, satisfied by a
        // structurally pure-path-watch Syscall candidate with matching
        // path/perm (arch ignored).
        (
            AuditRule::Watch {
                path: rp,
                perms: rpe,
                ..
            },
            AuditRule::Syscall {
                list: cl,
                action: ca,
                syscalls: cs,
                fields: cf,
                field_compares: cfc,
                ..
            },
        ) => {
            is_pure_path_watch_shaped(cl, ca, cs, cf, cfc)
                && watch_equivalent_axes_match(rp, rpe, cf)
        }
        // Reverse direction: a Syscall-shaped requirement (e.g. V-258222's
        // b32/b64 rows) satisfied by a classic Watch candidate, same shape
        // test applied to the REQUIRED side this time.
        (
            AuditRule::Syscall {
                list: rl,
                action: ra,
                syscalls: rs,
                fields: rf,
                field_compares: rfc,
                ..
            },
            AuditRule::Watch {
                path: cp,
                perms: cpe,
                ..
            },
        ) => {
            is_pure_path_watch_shaped(rl, ra, rs, rf, rfc)
                && watch_equivalent_axes_match(cp, cpe, rf)
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

/// Whether a `Syscall` rule's shape is STRUCTURALLY a "pure path-watch" -- the
/// shape a classic `-w path -p perms -k key` compiles down to at the kernel
/// level (see [`rules_match`]'s doc comment for the full grounding). This is
/// a purely structural test on the rule's own fields/syscalls/list/action, no
/// per-V-number special-casing: an EMPTY `-S` list, the `always,exit`
/// list/action pair, no `-C` field-comparisons, and every `-F` predicate one
/// of `path`/`perm`/`arch` (with at least one `path` predicate present, so an
/// empty field set does not vacuously pass). A rule with a non-empty `-S`
/// list or any OTHER `-F` field (e.g. V-279936's `-S execve -F
/// subj_type=crond_t`) fails this test and has no watch-equivalent form.
fn is_pure_path_watch_shaped(
    list: &crate::ast::FilterList,
    action: &crate::ast::Action,
    syscalls: &[String],
    fields: &[crate::ast::FieldFilter],
    field_compares: &[crate::ast::FieldComparison],
) -> bool {
    use crate::ast::{Action, AuditField, FilterList};

    *list == FilterList::Exit
        && *action == Action::Always
        && syscalls.is_empty()
        && field_compares.is_empty()
        && fields.iter().all(|f| {
            matches!(
                f.field,
                AuditField::Path | AuditField::Perm | AuditField::Arch
            )
        })
        && fields.iter().any(|f| f.field == AuditField::Path)
}

/// Compare a `Watch`'s `path`/`perms` against a (structurally pure-path-watch,
/// per [`is_pure_path_watch_shaped`]) `Syscall`'s `-F path=`/`-F perm=`
/// fields, for the path-watch equivalence fold. `-F arch=` is deliberately
/// never read here -- a watch has no arch axis, so the SAME watch candidate
/// independently satisfies a b32 required row and a b64 required row (the
/// caller's per-required-row loop checks each separately; see
/// [`rules_match`]'s doc comment). Returns `false` if the syscall side has no
/// `path` or `perm` predicate at all, or the perm value cannot parse as
/// permission-bit letters.
fn watch_equivalent_axes_match(
    watch_path: &str,
    watch_perms: &crate::ast::PermBits,
    syscall_fields: &[crate::ast::FieldFilter],
) -> bool {
    use crate::ast::AuditField;

    let syscall_path = syscall_fields
        .iter()
        .find(|f| f.field == AuditField::Path)
        .map(|f| f.value.as_str());
    let syscall_perm = syscall_fields
        .iter()
        .find(|f| f.field == AuditField::Perm)
        .map(|f| f.value.as_str());

    let (Some(sp), Some(sperm)) = (syscall_path, syscall_perm) else {
        return false;
    };

    normalize_watch_path(watch_path) == normalize_watch_path(sp)
        && perm_bits_from_field_value(sperm).as_ref() == Some(watch_perms)
}

/// Parse a `-F perm=` field VALUE (e.g. `"wa"`) into `PermBits`, mirroring
/// `parser::parse_perms`'s `r`/`w`/`x`/`a` letter grammar (the same one `-w
/// -p` uses) so a syscall rule's perm value compares against a `Watch`'s
/// `PermBits` order-insensitively -- the same rigor the existing
/// Watch-vs-Watch perms axis (`rpe == cpe`, genuine `PermBits` equality) has,
/// not a raw string compare that `-F perm=wa` vs `-F perm=aw` would wrongly
/// treat as different. Reimplemented locally (rather than exposing
/// `parser::parse_perms`) since this module's fix is scoped to this file; the
/// grammar itself is small and stable (4 letters, `permtab.h:28-31`). An
/// unrecognized character means the value cannot represent valid perm bits at
/// all, so it can never be perm-equivalent to a watch -- `None`, not a
/// partial/best-effort parse.
fn perm_bits_from_field_value(raw: &str) -> Option<crate::ast::PermBits> {
    let mut perms = crate::ast::PermBits::default();
    for ch in raw.trim().chars() {
        match ch {
            'r' => perms.read = true,
            'w' => perms.write = true,
            'x' => perms.exec = true,
            'a' => perms.attr = true,
            _ => return None,
        }
    }
    Some(perms)
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

/// Direct unit tests for [`is_pure_path_watch_shaped`]'s OWN return value,
/// NOT filtered through [`watch_equivalent_axes_match`] (which is the only
/// caller reachable from the public `w06`/`w06_with_baseline` API).
///
/// # Why this can't be pinned at the public-API level (mutation-gate report,
/// session 9e-wave2c pipeline P2 round 3)
///
/// `cargo mutants` flagged `:1609:42 - replace == with !=` (the
/// `fields.iter().any(|f| f.field == AuditField::Path)` guard) as a survivor.
/// It cannot be killed through `w06`/`w06_with_baseline`: EVERY caller of
/// [`is_pure_path_watch_shaped`] immediately follows it with
/// [`watch_equivalent_axes_match`], which independently re-derives path
/// presence via its OWN `.find(|f| f.field == AuditField::Path)` (and
/// likewise for `Perm`) and returns `false` whenever either is absent. Proof
/// by cases on the mutated `==`/`!=` divergence (only possible when `fields`
/// contains ALL-Path-no-other, or ALL-non-Path-no-Path): both divergent
/// shapes are missing either a Path or a Perm predicate, so
/// `watch_equivalent_axes_match` independently forces `false` regardless of
/// what `is_pure_path_watch_shaped` decided -- the observable `rules_match`
/// result is IDENTICAL under the mutant and the original for every reachable
/// input. Testing the private function directly (the standard Rust pattern
/// for a helper with no other observable surface) is the only way to pin the
/// "at least one Path predicate present" guard's own correctness -- it
/// exists to reject a vacuously-empty-of-Path field set per this function's
/// doc comment ("with at least one path predicate present, so an empty field
/// set does not vacuously pass").
#[cfg(test)]
mod pure_path_watch_shape_tests {
    use super::is_pure_path_watch_shaped;
    use crate::ast::{Action, AuditField, CompareOp, FieldFilter, FilterList};

    fn field(f: AuditField, value: &str) -> FieldFilter {
        FieldFilter {
            field: f,
            op: CompareOp::Eq,
            value: value.to_string(),
        }
    }

    #[test]
    fn perm_and_arch_without_any_path_predicate_is_not_path_watch_shaped() {
        // Every OTHER conjunct passes (always,exit / empty -S / empty -C /
        // every field is one of Path|Perm|Arch), but there is NO Path
        // predicate at all -- Perm and Arch alone must NOT count as
        // "path-watch shaped". Kills the `:1609:42 == -> !=` mutant
        // directly: the mutant's `any(|f| f.field != Path)` evaluates `true`
        // here (both Perm and Arch differ from Path), wrongly returning
        // `true` for a field set that names no path at all.
        let fields = vec![
            field(AuditField::Perm, "wa"),
            field(AuditField::Arch, "b32"),
        ];
        assert!(
            !is_pure_path_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "Perm+Arch with no Path predicate must not be path-watch shaped"
        );
    }

    #[test]
    fn path_perm_arch_is_path_watch_shaped() {
        // Positive control: the real V-258222/V-258223 dual-arch shape
        // (path + perm + arch, empty -S, empty -C) must pass. Without this,
        // an "always reject" impl would vacuously pass the negative test
        // above.
        let fields = vec![
            field(AuditField::Path, "/etc/passwd"),
            field(AuditField::Perm, "wa"),
            field(AuditField::Arch, "b32"),
        ];
        assert!(
            is_pure_path_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "path+perm+arch, empty -S, empty -C must be path-watch shaped"
        );
    }
}
