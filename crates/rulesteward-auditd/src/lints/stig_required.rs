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
//!
//! Session 9j lane 8, USER RULING (2026-07-24, issue #571): the SAME
//! equivalence, in parallel, for the OTHER field a `-w` watch compiles down
//! to: a directory-shaped STIG requirement is satisfied by EITHER a classic
//! `-w dir -p perms -k key` watch or its dual-arch
//! `-a always,exit -F arch=bXX -F dir= -F perm= -k key` syscall pair, both
//! directions, all targets. `-F dir=` (a recursive subtree watch) and
//! `-F path=` (a single-inode watch) are genuinely distinct kernel
//! constructs and are NEVER folded into each other, in either direction --
//! see [`rules_match`]'s doc comment for the full grounding, the "pure
//! dir-watch shape" definition, and why `is_dir` plays no part in either
//! fold (`ast.rs`'s `Watch::is_dir` doc comment).
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
///    `path`/`perm`/`arch`/`key`) and its `path`/`perm` equal the `Watch`
///    side's (arch is ignored on that side -- a watch has no arch axis, so
///    it matches a b32 row and a b64 row independently). PLUS, in parallel,
///    the dir-watch equivalence fold (issue #571): the SAME cross-variant
///    match when the `Syscall` side is instead STRUCTURALLY a pure dir-watch
///    (empty `-S` list, `always,exit`, no `-C`, `-F` predicates limited to
///    `dir`/`perm`/`arch`/`key`, EXACTLY ONE `dir` predicate present with the
///    `=` operator, and any `perm` predicate present also using `=` -- see
///    [`is_pure_dir_watch_shaped`]'s doc comment for the full grounding) and
///    its `dir`/`perm` equal the `Watch` side's. The path-shape and dir-shape
///    tests are mutually exclusive (a rule's field set cannot be
///    all-`path`-or-`perm`-or-`arch` AND all-`dir`-or-`perm`-or-`arch` unless
///    it has neither a `path` nor a `dir` predicate, which both shape tests
///    reject), and `-F dir=`/`-F path=` are never unified with each other or
///    with a `Watch`'s `path` slot in the generic field comparison -- each
///    cross-variant arm reads its OWN field kind only. See [`rules_match`]'s
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
///
/// Dir-watch equivalence fold (USER RULING, 2026-07-24, issue #571): a
/// SEPARATE, PARALLEL arm for the OTHER field a `-w` watch compiles down to.
/// `auditctl(8)`'s own EXAMPLES section shows this side by side with the
/// path case: "To recursively watch a directory for changes: `auditctl -w
/// /etc/ -p wa`" compiles to "`auditctl -a always,exit -F arch=b64 -F
/// dir=/etc/ -F perm=wa`" -- `-F dir=` places a RECURSIVE SUBTREE watch,
/// genuinely distinct from `-F path=`'s SINGLE-INODE watch. "Pure dir-watch
/// shape" (the structural test [`is_pure_dir_watch_shaped`], the Dir-flavored
/// twin of [`is_pure_path_watch_shaped`]) applies the SAME test with `dir`
/// swapped in for `path`, plus two guards the path twin does NOT yet have: an
/// EMPTY `-S` syscall list, the `always,exit` list/action pair, no `-C`
/// field-comparisons, `-F` predicates limited to `dir`/`perm`/`arch`/`key`,
/// EXACTLY ONE `dir` predicate present (using `=`), and any `perm` predicate
/// present also using `=` (see [`is_pure_dir_watch_shaped`]'s doc comment for
/// the full ATL-round grounding of the operator/multiplicity/key-membership
/// refinements).
///
/// NOT SYMMETRIC, deliberately, pending issue #600: the operator guard
/// (`=`-only) and the exactly-one-predicate guard were added to the DIR twin
/// only, because #571's scope was the dir-shape arm. The path twin still
/// accepts `-F path!=` / `-F perm!=` and more than one `-F path=`, none of
/// which can load on a real host (`-EAU_OPEQ`; `audit_to_watch` returns
/// `-EINVAL` when `krule->watch` is already set). That is over-crediting, so
/// do NOT read the path twin's laxness as intentional permissiveness -- it is
/// an untightened copy, tracked on #600. The
/// two shape tests are mutually exclusive (a field set that is
/// all-of-`{path,perm,arch,key}` cannot also be all-of-`{dir,perm,arch,key}`
/// unless it has neither a `path` nor a `dir` predicate, which both shape
/// tests' presence guards reject), so a rule is never credited by both arms
/// at once. `-F dir=`/`-F path=` are NEVER unified with each other, in either
/// direction: an EXPLICIT `-F path=` requirement is never satisfied by an
/// EXPLICIT `-F dir=` candidate or vice versa (both sides having declared a
/// different kernel construct outright, with no cross-variant ambiguity to
/// resolve) -- that discrimination falls out of the existing, UNMODIFIED
/// Syscall-vs-Syscall arm above (`AuditField::Path` and `AuditField::Dir` are
/// different enum variants, so [`fields_match_excluding_key`]'s per-field-type
/// set compare never merges them) and needs no change here. Dir compares via
/// [`normalize_watch_path`] (the SAME trailing-slash normalization the
/// path-fold and Watch-vs-Watch axis use -- DISA's own check-content is just
/// as inconsistent about trailing slashes on `-F` field values as it is on
/// `-w` lines); perm compares via [`perm_bits_from_field_value`], identically
/// to the path arm. `is_dir` plays NO part in this fold either (see
/// `ast.rs`'s `Watch::is_dir` doc comment): a static linter cannot `stat()`
/// the target host to resolve file-vs-directory, so the fold cannot and must
/// not gate on the trailing-slash spelling convention in either direction --
/// this is an accepted, deliberate over-credit (a `-F dir=` candidate can
/// satisfy a file-shaped `Watch` requirement) rather than a bug, since a
/// recursive subtree watch naming a regular file is a kernel-level no-op the
/// fold never needs to distinguish in practice.
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
        // path/perm (arch ignored). PLUS, in parallel, the dir-watch
        // equivalence fold (USER RULING, 2026-07-24, issue #571): the SAME
        // requirement satisfied instead by a structurally pure-dir-watch
        // Syscall candidate with matching dir/perm (arch ignored). The two
        // shape tests are mutually exclusive (see the doc comment above), so
        // at most one disjunct is ever true for a given candidate.
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
            (is_pure_path_watch_shaped(cl, ca, cs, cf, cfc)
                && watch_equivalent_axes_match(rp, rpe, cf))
                || (is_pure_dir_watch_shaped(cl, ca, cs, cf, cfc)
                    && dir_watch_equivalent_axes_match(rp, rpe, cf))
        }
        // Reverse direction: a Syscall-shaped requirement (e.g. V-258222's
        // b32/b64 rows, or a synthetic `-F dir=` requirement) satisfied by a
        // classic Watch candidate, same shape tests applied to the REQUIRED
        // side this time.
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
            (is_pure_path_watch_shaped(rl, ra, rs, rf, rfc)
                && watch_equivalent_axes_match(cp, cpe, rf))
                || (is_pure_dir_watch_shaped(rl, ra, rs, rf, rfc)
                    && dir_watch_equivalent_axes_match(cp, cpe, rf))
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
/// of `path`/`perm`/`arch`/`key` (with at least one `path` predicate present,
/// so an empty field set does not vacuously pass). A rule with a non-empty
/// `-S` list or any OTHER `-F` field (e.g. V-279936's `-S execve -F
/// subj_type=crond_t`) fails this test and has no watch-equivalent form.
/// `key` is allowed here despite never being named in the doc comment's
/// "path-watch shape" description above: it is NOT a location/perm axis at
/// all, so its presence must never disqualify the shape (fixed alongside the
/// dir-flavored twin's identical bug, issue #571 MISS-2b, ATL round, session
/// 9j lane 8) -- `-k KEY` and `-F key=KEY` are the SAME rule
/// (`auditctl`'s `setopt()` builds `-F key=%s` from `-k`'s argument before
/// calling `audit_rule_fieldpair_data`, lib/libaudit.c), and the key axis is
/// already handled separately by [`effective_key`]/[`fields_match_excluding_key`].
/// Measured regression this fixed: `RHEL10_REQUIRED`'s `/etc/sudoers.d` row
/// (V-281155/RHEL-10-500690, `stig_required.rs`, spelled `-F key=identity`)
/// wrongly reported a classic `-w /etc/sudoers.d/ -p wa -k identity` watch as
/// missing, while the byte-identical config satisfied RHEL8's `-k`-spelled
/// V-230410 -- the verdict flipped purely on DISA's spelling of the key
/// field, not any real ruleset difference.
fn is_pure_path_watch_shaped(
    list: &crate::ast::FilterList,
    action: &crate::ast::Action,
    syscalls: &[String],
    fields: &[crate::ast::FieldFilter],
    field_compares: &[crate::ast::FieldComparison],
) -> bool {
    use crate::ast::{Action, AuditField, CompareOp, FilterList};

    *list == FilterList::Exit
        && *action == Action::Always
        && syscalls.is_empty()
        && field_compares.is_empty()
        && fields.iter().all(|f| match f.field {
            // #600 (mirrors dir twin's MISS-1/MISS-3): `-F path=`/`-F perm=`
            // only ever LOAD with `=` -- `kernel/audit_watch.c`'s
            // `audit_to_watch` rejects any other operator on an AUDIT_WATCH
            // predicate, and `lib/libaudit.c`'s AUDIT_PERM case returns
            // -EAU_OPEQ for any op but `=`.
            AuditField::Path | AuditField::Perm => f.op == CompareOp::Eq,
            // `arch`'s own operator restriction is au-E02's job, not this
            // shape test's; `-F key=` unifies with `-k` via `effective_key`
            // (the key axis is handled separately), so its presence (with
            // any op) never disqualifies the shape either.
            AuditField::Arch | AuditField::Key => true,
            _ => false,
        })
        // #600 (mirrors dir twin's MISS-4): EXACTLY one Path predicate, not
        // "at least one" -- `audit_to_watch` returns -EINVAL once a rule's
        // watch pointer is already set, so a rule naming `-F path=` more
        // than once never loads either. `count() == 1` subsumes the old
        // presence check (`0 != 1`).
        && fields
            .iter()
            .filter(|f| f.field == AuditField::Path)
            .count()
            == 1
}

/// Whether a `Syscall` rule's shape is STRUCTURALLY a "pure dir-watch" -- the
/// Dir-flavored twin of [`is_pure_path_watch_shaped`] (issue #571, USER
/// RULING 2026-07-24): the shape a classic `-w dir -p perms -k key` compiles
/// down to at the kernel level for a RECURSIVE SUBTREE watch (see
/// [`rules_match`]'s doc comment for the full grounding). A purely structural
/// test, no per-V-number special-casing: an EMPTY `-S` list, the
/// `always,exit` list/action pair, no `-C` field-comparisons, every `-F`
/// predicate one of `dir`/`perm`/`arch`/`key`, EXACTLY ONE `dir` predicate
/// present (not "at least one" -- see the MISS-4 grounding below), and any
/// `dir`/`perm` predicate present using the `=` operator (see the MISS-1/
/// MISS-3 grounding below). A rule with a non-empty `-S` list or any OTHER
/// `-F` field fails this test and has no watch-equivalent form. Deliberately
/// implemented as its own function rather than a parameterized/generic
/// helper shared with [`is_pure_path_watch_shaped`]: `-F dir=` and `-F
/// path=` are different enum variants naming genuinely different kernel
/// constructs, and the two shape tests must never be unified into one
/// "location field" concept (see [`rules_match`]'s doc comment for why that
/// would be wrong).
///
/// Three fixes from the post-#571 Adversarial Testing Loop (session 9j lane
/// 8, all grounded in primary source and several verified empirically
/// against the host's installed audit-4.1.4 libaudit):
/// - **MISS-1/MISS-3 (operator blindness, fail-open):** the ORIGINAL version
///   of this test read only the field NAME, never the predicate's operator,
///   so `-F dir!=X`/`-F perm!=X` (or any of `< > <= >= & &=`) were wrongly
///   treated as dir-watch-shaped. But `kernel/audit_tree.c`'s
///   `audit_make_tree()` returns `-EINVAL` for any `AUDIT_DIR` predicate
///   whose op is not `Audit_equal`, and `lib/libaudit.c`'s `AUDIT_PERM` case
///   returns `-EAU_OPEQ` for any op but `=` (verified rc=-29 against the
///   installed audit-4.1.4 libaudit) -- a rule spelled with any other
///   operator on either field NEVER LOADS at the kernel level at all, so it
///   has no kernel-level meaning to be dir-watch-equivalent to. `arch`'s own
///   operator restriction (`=`/`!=` only) is a DIFFERENT lint's job (au-E02)
///   and irrelevant to whether the rule is dir-watch SHAPED.
/// - **MISS-2 (Key membership, false "missing"):** the ORIGINAL version did
///   not allow `AuditField::Key` in the field set at all, so a candidate
///   spelled `-F key=` instead of `-k` fell OUTSIDE the shape and reported a
///   false "missing" even though `-k`/`-F key=` are the SAME rule (see
///   [`is_pure_path_watch_shaped`]'s doc comment for the full grounding,
///   which this function shares).
/// - **MISS-4 (Dir multiplicity, order-dependent verdict):** the ORIGINAL
///   version accepted ANY NUMBER of `dir` predicates ("at least one"), so
///   [`dir_watch_equivalent_axes_match`]'s `.find()` silently picked whichever
///   `-F dir=` predicate happened to come FIRST, making the verdict flip
///   depending on field order. But `audit_make_tree()` returns `-EINVAL` once
///   a rule's `tree` pointer is already set -- one recursive-subtree watch
///   per rule is a hard kernel limit -- so a rule naming `-F dir=` MORE THAN
///   ONCE never loads either, regardless of which value comes first. Requiring
///   EXACTLY one Dir predicate here both fixes the false-accept and makes
///   `dir_watch_equivalent_axes_match`'s `.find()` deterministic (by the time
///   it runs, at most one Dir predicate can be present).
fn is_pure_dir_watch_shaped(
    list: &crate::ast::FilterList,
    action: &crate::ast::Action,
    syscalls: &[String],
    fields: &[crate::ast::FieldFilter],
    field_compares: &[crate::ast::FieldComparison],
) -> bool {
    use crate::ast::{Action, AuditField, CompareOp, FilterList};

    *list == FilterList::Exit
        && *action == Action::Always
        && syscalls.is_empty()
        && field_compares.is_empty()
        && fields.iter().all(|f| match f.field {
            // MISS-1/MISS-3: `-F dir=`/`-F perm=` only ever LOAD with `=`.
            AuditField::Dir | AuditField::Perm => f.op == CompareOp::Eq,
            // `arch`'s own operator restriction is au-E02's job, not this
            // shape test's; MISS-2: `-F key=` unifies with `-k` via
            // `effective_key` (the key axis is handled separately), so its
            // presence (with any op) never disqualifies the shape either.
            AuditField::Arch | AuditField::Key => true,
            _ => false,
        })
        // MISS-4: EXACTLY one Dir predicate, not "at least one".
        && fields.iter().filter(|f| f.field == AuditField::Dir).count() == 1
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

    let Some(sp) = syscall_fields
        .iter()
        .find(|f| f.field == AuditField::Path)
        .map(|f| f.value.as_str())
    else {
        return false;
    };

    let Some(sperm_bits) = perm_axis_bits(syscall_fields) else {
        return false;
    };

    normalize_watch_path(watch_path) == normalize_watch_path(sp) && sperm_bits == *watch_perms
}

/// Compare a `Watch`'s `path`/`perms` against a (structurally pure-dir-watch,
/// per [`is_pure_dir_watch_shaped`]) `Syscall`'s `-F dir=`/`-F perm=` fields,
/// for the dir-watch equivalence fold (issue #571). The Dir-flavored twin of
/// [`watch_equivalent_axes_match`]: `-F arch=` is deliberately never read
/// here -- a watch has no arch axis, so the SAME watch candidate
/// independently satisfies a b32 required row and a b64 required row (the
/// caller's per-required-row loop checks each separately; see
/// [`rules_match`]'s doc comment). Directory-value compares via
/// [`normalize_watch_path`] (the SAME trailing-slash normalization the path
/// arm uses -- DISA's own check-content is just as inconsistent about
/// trailing slashes on `-F` field values as it is on `-w` lines). Returns
/// `false` if the syscall side has no `dir` or `perm` predicate at all, or
/// the perm value cannot parse as permission-bit letters.
fn dir_watch_equivalent_axes_match(
    watch_path: &str,
    watch_perms: &crate::ast::PermBits,
    syscall_fields: &[crate::ast::FieldFilter],
) -> bool {
    use crate::ast::AuditField;

    let Some(sd) = syscall_fields
        .iter()
        .find(|f| f.field == AuditField::Dir)
        .map(|f| f.value.as_str())
    else {
        return false;
    };

    let Some(sperm_bits) = perm_axis_bits(syscall_fields) else {
        return false;
    };

    normalize_watch_path(watch_path) == normalize_watch_path(sd) && sperm_bits == *watch_perms
}

/// Fold a syscall rule's `-F perm=` predicate(s) into a single [`PermBits`]
/// value for the watch-equivalence axis compare, or `None` if they cannot
/// represent one. Multiple `Perm` predicates CONJOIN at the kernel level
/// (`kernel/auditsc.c`'s `audit_filter_rules` calls `audit_match_perm` once
/// PER `AUDIT_PERM` field and ANDs the per-field results via `if (!result)
/// return 0;`), and `audit_match_perm` is MONOTONE NON-DECREASING in its
/// `mask` argument: every branch reduces to `mask & <event-determined
/// constant>` (`AUDITSC_NATIVE`/`AUDITSC_COMPAT` return 1 on the first set
/// bit of `mask` that lands in the event's syscall class; `AUDITSC_OPEN`/
/// `AUDITSC_OPENAT2` return `mask & ACC_MODE(...)`; `AUDITSC_EXECVE` returns
/// `mask & AUDIT_PERM_EXEC`; `AUDITSC_SOCKETCALL` returns `(mask &
/// AUDIT_PERM_WRITE) && ...`). So for two masks `m1 subset-of m2`,
/// `match(m1)` implies `match(m2)` for every event, and a conjunction of
/// `-F perm=` predicates whose masks are pairwise SUBSET-COMPARABLE -- a
/// TOTAL ORDER, not merely "every predicate names the same value" -- reduces
/// to exactly its MINIMUM (smallest/strictest) element: for any comparable
/// pair `X subset-of Y`, `match(X) AND match(Y) == match(X)`, and induction
/// over the chain collapses the whole conjunction to its minimum.
///
/// Requiring bitwise EQUALITY of every predicate (this function's round-2
/// shape, commit d21c7aa) was an over-correction: it correctly stopped two
/// DIFFERENT predicates being credited by picking "whichever comes first"
/// (the original bug both call sites -- [`watch_equivalent_axes_match`] and
/// [`dir_watch_equivalent_axes_match`] -- shared; issue #601 ATL follow-up,
/// MISS-3), but "different" is not the same as "incomparable": it also
/// declined a genuinely-equivalent subset-comparable pair like `perm=wa` +
/// `perm=rwxa`, which collapses to `perm=wa` even though the two values
/// differ (round-4 regression fix, issue #601/#600 ATL).
///
/// Predicates that are NOT pairwise subset-comparable (e.g. `perm=rwa` +
/// `perm=wxa`: `r` only in the first, `x` only in the second) correctly
/// decline (`None`) rather than folding to their bitwise INTERSECTION.
/// Intersection is the WRONG fold for an incomparable pair: `perm=r AND
/// perm=w` is satisfiable on an `O_RDWR` open (`ACC_MODE` sets both the read
/// and write bits for that open), while `intersection({r}, {w})` is empty
/// and `match(empty)` is never true. Intersection and minimum only coincide
/// when the masks are already subset-comparable, which is exactly why no
/// SATISFIED-subset test can discriminate the two folds -- see the
/// `path_syscall_form_with_incomparable_perm_predicates_intersecting_to_the_
/// required_value_...` test for the incomparable-but-intersects-nonempty
/// case that does.
///
/// Returns `None` for zero `Perm` predicates (no axis to compare) or if any
/// predicate's value fails to parse as perm-bit letters.
fn perm_axis_bits(syscall_fields: &[crate::ast::FieldFilter]) -> Option<crate::ast::PermBits> {
    use crate::ast::AuditField;

    let perm_bits: Vec<crate::ast::PermBits> = syscall_fields
        .iter()
        .filter(|f| f.field == AuditField::Perm)
        .map(|f| perm_bits_from_field_value(f.value.as_str()))
        .collect::<Option<Vec<_>>>()?;

    // Confirm a genuine TOTAL ORDER: every pair, not merely traversal
    // neighbors, must be subset-comparable one way or the other. Two
    // predicates that are each comparable to a common third but not to each
    // other would still (per the doc comment above) collapse correctly, but
    // that is a stronger claim than "totally ordered by subset" and is not
    // the rule this fold implements -- decline rather than reach for it.
    for (i, a) in perm_bits.iter().enumerate() {
        for b in &perm_bits[i + 1..] {
            if !perm_bits_is_subset(a, b) && !perm_bits_is_subset(b, a) {
                return None;
            }
        }
    }

    let mut min_iter = perm_bits.iter();
    let mut min = min_iter.next()?.clone();
    for candidate in min_iter {
        if perm_bits_is_subset(candidate, &min) {
            min = candidate.clone();
        }
    }

    Some(min)
}

/// `a`'s permission bits are a subset of `b`'s: every bit set in `a` is also
/// set in `b`. The subset partial order [`perm_axis_bits`] folds a chain of
/// `-F perm=` predicates across.
fn perm_bits_is_subset(a: &crate::ast::PermBits, b: &crate::ast::PermBits) -> bool {
    (!a.read || b.read) && (!a.write || b.write) && (!a.exec || b.exec) && (!a.attr || b.attr)
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
/// partial/best-effort parse. Case-folded before matching (issue #571
/// MISS-5, ATL round, session 9j lane 8): `lib/libaudit.c` case-folds every
/// `-F perm=` character with `tolower((unsigned char)v[i])` before building
/// the bitmask, so `perm=WA` and `perm=wa` are the SAME rule at the kernel
/// level (verified on the installed audit-4.1.4 libaudit: both produce
/// `values[0] == 10`) -- rejecting uppercase letters as unparseable was a
/// false "missing" for any admin who wrote perm letters in caps.
fn perm_bits_from_field_value(raw: &str) -> Option<crate::ast::PermBits> {
    let mut perms = crate::ast::PermBits::default();
    for ch in raw.trim().chars() {
        match ch.to_ascii_lowercase() {
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
/// # Why this can't be pinned (fully) at the public-API level (mutation-gate
/// report, session 9e-wave2c pipeline P2 round 3; extended for issue #600)
///
/// `cargo mutants` originally flagged the field-presence guard as a
/// survivor: EVERY caller of [`is_pure_path_watch_shaped`] immediately
/// follows it with [`watch_equivalent_axes_match`], which independently
/// re-derives path presence via its OWN `.find(|f| f.field ==
/// AuditField::Path)` (and likewise for `Perm`) and returns `false`
/// whenever either is absent -- so the observable `rules_match` result is
/// IDENTICAL under a presence-only mutant and the original for every
/// reachable input.
///
/// Issue #600 replaced the original `fields.iter().any(|f| f.field ==
/// AuditField::Path)` guard with `fields.iter().filter(|f| f.field ==
/// AuditField::Path).count() == 1` (mirroring [`is_pure_dir_watch_shaped`]'s
/// MISS-4 fix -- `count() == 1` subsumes the old presence check: `0 != 1`)
/// and added an operator guard, `Path | Perm => f.op == CompareOp::Eq`
/// (mirroring MISS-1/MISS-3). The "at least one" half of `count() == 1`
/// stays unobservable through `w06` for the same reason as the deleted
/// `.any(..)` guard. The "exactly one, not more" half is only PARTLY
/// unobservable: a rule with two `-F path=` predicates IS distinguishable
/// through `w06` (see the sibling integration test
/// `path_syscall_form_with_two_path_predicates_does_not_satisfy_v230409_
/// regardless_of_field_order`), mirroring the note in
/// [`pure_dir_watch_shape_tests`]'s own docstring. Testing the private
/// function directly (the standard Rust pattern for a helper with no other
/// observable surface) remains the sharper, most localized pin for every
/// guard added here.
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

    fn field_with_op(f: AuditField, value: &str, op: CompareOp) -> FieldFilter {
        FieldFilter {
            field: f,
            op,
            value: value.to_string(),
        }
    }

    #[test]
    fn perm_and_arch_without_any_path_predicate_is_not_path_watch_shaped() {
        // Every OTHER conjunct passes (always,exit / empty -S / empty -C /
        // every field is one of Path|Perm|Arch, all using `=`), but there is
        // NO Path predicate at all -- Perm and Arch alone must NOT count as
        // "path-watch shaped". Pins the "at least one" half of the
        // `fields.iter().filter(|f| f.field ==
        // AuditField::Path).count() == 1` guard (issue #600): a mutant
        // widening `count() == 1` to `count() >= 0` (or deleting the
        // conjunct outright) would wrongly return `true` for a field set
        // that names no path at all.
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

    #[test]
    fn dir_field_alone_is_not_path_watch_shaped() {
        // Mirrors `path_field_alone_is_not_dir_watch_shaped` in the dir
        // twin's module: a Dir field is not in the {Path,Perm,Arch,Key}
        // allowed set, so a dir-only field list must never be path-watch
        // shaped.
        let fields = vec![field(AuditField::Dir, "/etc/sudoers.d")];
        assert!(
            !is_pure_path_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "a Dir-only field set must not be path-watch shaped"
        );
    }

    #[test]
    fn path_and_dir_together_is_not_path_watch_shaped() {
        // Test-adequacy strengthening mirroring
        // `dir_and_path_together_is_not_dir_watch_shaped`: a Dir-only field
        // set (see `dir_field_alone_is_not_path_watch_shaped` above) already
        // fails both the allowed-field-set conjunct and the "has exactly one
        // Path predicate" conjunct, so it alone cannot distinguish the real
        // allowed set (Path|Perm|Arch|Key) from an over-broad one
        // (Path|Dir|Perm|Arch). This test adds a Path predicate ALONGSIDE
        // the Dir predicate so the "has exactly one Path predicate" conjunct
        // is satisfied too, and only a correct allowed-field-set conjunct
        // can still reject it.
        let fields = vec![
            field(AuditField::Dir, "/etc/sudoers.d"),
            field(AuditField::Path, "/etc/sudoers.d"),
            field(AuditField::Perm, "wa"),
        ];
        assert!(
            !is_pure_path_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "a field set containing BOTH Path and Dir must not be path-watch \
             shaped -- Dir is not in the {{Path,Perm,Arch,Key}} allowed set"
        );
    }

    /// Every non-`Eq` `CompareOp` variant. `CompareOp` has 8 variants total
    /// (`Eq Ne Lt Gt Le Ge BitAnd BitAndEq`, `ast.rs`); a guard written as
    /// `op != CompareOp::Ne` (instead of `op == CompareOp::Eq`) would pass a
    /// `!=`-only test while wrongly accepting e.g. `>=` or `&=`. Looping
    /// over all seven here (rather than pinning `Ne` alone) closes that
    /// whole mutant class in one sweep, for BOTH `path_predicate_with_non_
    /// equal_operator_is_not_path_watch_shaped` and its Perm-side twin below.
    const NON_EQ_OPS: [CompareOp; 7] = [
        CompareOp::Ne,
        CompareOp::Lt,
        CompareOp::Gt,
        CompareOp::Le,
        CompareOp::Ge,
        CompareOp::BitAnd,
        CompareOp::BitAndEq,
    ];

    #[test]
    fn path_predicate_with_non_equal_operator_is_not_path_watch_shaped() {
        // #600 MISS-1 analog: `kernel/audit_watch.c`'s `audit_to_watch`
        // rejects any op but `=` on an AUDIT_WATCH (`path`) predicate at the
        // kernel level (mirroring AUDIT_DIR's -EINVAL) -- ALL non-`=` operators,
        // not just `!=` (see `NON_EQ_OPS`'s doc comment). This is the ONLY
        // net for the Path axis: `au-E02` deliberately leaves `-F path>=`/
        // `-F path&0x1`/etc. CLEAN
        // (`e02_path_relational_and_bitmask_all_clean`,
        // `tests/test_lints_operator_validity.rs:717`, grounded at
        // `libaudit.c:1804-1811` -- userspace has no operator check on
        // AUDIT_WATCH at all), so unlike Perm there is no downstream lint
        // to catch a mutant that only rejects `!=`.
        for op in NON_EQ_OPS {
            let fields = vec![
                field_with_op(AuditField::Path, "/etc/sudoers", op.clone()),
                field(AuditField::Perm, "wa"),
                field(AuditField::Arch, "b32"),
            ];
            assert!(
                !is_pure_path_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
                "a Path predicate using {op:?} must not be path-watch shaped"
            );
        }
    }

    #[test]
    fn perm_predicate_with_non_equal_operator_is_not_path_watch_shaped() {
        // #600 MISS-3 analog, the Perm side: `lib/libaudit.c`'s AUDIT_PERM
        // case returns -EAU_OPEQ for any op but `=` (verified rc=-29
        // against the installed audit-4.1.4 libaudit). ALL non-`=` operators
        // swept, same reasoning as the Path twin above.
        for op in NON_EQ_OPS {
            let fields = vec![
                field(AuditField::Path, "/etc/sudoers"),
                field_with_op(AuditField::Perm, "wa", op.clone()),
            ];
            assert!(
                !is_pure_path_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
                "a Perm predicate using {op:?} must not be path-watch shaped"
            );
        }
    }

    #[test]
    fn arch_and_key_with_non_equal_operators_are_still_path_watch_shaped() {
        // Pins the deliberate `Arch | Key => true` arm (any operator
        // allowed): arch's own operator restriction is au-E02's job, and
        // `-F key=` unifies with `-k` via `effective_key` regardless of
        // operator -- see the dir twin's identical arm and the module doc
        // comment on `is_pure_dir_watch_shaped`. A mutant tightening this
        // arm to require `=` would wrongly reject a well-formed rule.
        let fields = vec![
            field(AuditField::Path, "/etc/sudoers"),
            field(AuditField::Perm, "wa"),
            field_with_op(AuditField::Arch, "b32", CompareOp::Ne),
            field_with_op(AuditField::Key, "identity", CompareOp::Ne),
        ];
        assert!(
            is_pure_path_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "Arch/Key predicates with != must still be path-watch shaped: {fields:?}"
        );
    }

    #[test]
    fn two_path_predicates_is_not_path_watch_shaped() {
        // #600 MISS-4 analog: `audit_to_watch` returns -EINVAL once a
        // rule's watch pointer is already set -- one location watch per
        // rule is a hard kernel limit, so a rule naming -F path= twice
        // never loads either. Pins `count() == 1` against a `>= 1` mutant.
        let fields = vec![
            field(AuditField::Path, "/etc/sudoers"),
            field(AuditField::Path, "/tmp/nope"),
            field(AuditField::Perm, "wa"),
        ];
        assert!(
            !is_pure_path_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "two Path predicates must not be path-watch shaped"
        );
    }

    #[test]
    fn two_perm_predicates_is_still_path_watch_shaped() {
        // ATL round (issue #601 follow-up, MISS-3): unlike Path (kernel
        // `audit_to_watch` returns -EINVAL once a rule's watch pointer is
        // already set -- one location watch per rule is a hard limit), the
        // kernel has NO such limit on AUDIT_PERM predicates:
        // `kernel/auditsc.c`'s `audit_filter_rules` calls
        // `audit_match_perm(ctx, f->val)` once PER Perm field and ANDs the
        // results, so a rule naming `-F perm=` twice LOADS FINE at the
        // kernel level -- it just means something more restrictive than a
        // single `-p X` watch, not "never loads" the way two `-F path=`
        // predicates do. This shape test must therefore NOT reject a
        // multi-Perm field set the way it rejects a multi-Path one: doing
        // so would also wrongly reject an IDENTICAL duplicate (`perm=wa`
        // twice), which genuinely IS equivalent to a single `-p wa` watch
        // and must stay credited (see the integration-level positive
        // control `path_syscall_form_with_identical_duplicate_perm_
        // predicates_still_satisfies_v230409_sudoers`,
        // tests/test_lints_stig_required.rs). Whether two Perm predicates
        // are actually VALUE-equivalent to the required watch's perms is a
        // question for `watch_equivalent_axes_match`, not this shape test.
        let fields = vec![
            field(AuditField::Path, "/etc/sudoers"),
            field(AuditField::Perm, "wa"),
            field(AuditField::Perm, "r"),
        ];
        assert!(
            is_pure_path_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "two Perm predicates (even with DIFFERENT values) must still be \
             path-watch shaped -- the kernel loads multiple Perm predicates \
             fine, unlike Path; rejecting them here would also wrongly \
             reject an identical-duplicate perm pair"
        );
    }
}

/// Direct unit tests for [`is_pure_dir_watch_shaped`]'s OWN return value, the
/// Dir-flavored twin of [`pure_path_watch_shape_tests`] above (issue #571).
/// Not filtered through [`dir_watch_equivalent_axes_match`] for the SAME
/// reason `pure_path_watch_shape_tests`'s doc comment gives for the path arm:
/// every caller immediately follows this shape test with
/// `dir_watch_equivalent_axes_match`, which independently re-derives dir/perm
/// presence via its OWN `.find` calls and forces `false` whenever either is
/// absent -- so a mutant flipping the trailing guard's `==` to `!=` is
/// unobservable through `w06`/`w06_with_baseline` for the PRESENCE half.
/// Testing the private function directly pins the guard's own correctness.
///
/// Note the guard is `filter(|f| f.field == AuditField::Dir).count() == 1` --
/// EXACTLY one Dir predicate, not "at least one" (the MISS-4 refinement; an
/// earlier revision of this comment described the superseded `any(..)` form).
/// The count form is only PARTLY unobservable at the public API: a rule
/// carrying two `-F dir=` predicates IS distinguishable through `w06`, and
/// this module's sibling integration test covers that case. The direct unit
/// tests remain the sharper pin.
#[cfg(test)]
mod pure_dir_watch_shape_tests {
    use super::is_pure_dir_watch_shaped;
    use crate::ast::{Action, AuditField, CompareOp, FieldFilter, FilterList};

    fn field(f: AuditField, value: &str) -> FieldFilter {
        FieldFilter {
            field: f,
            op: CompareOp::Eq,
            value: value.to_string(),
        }
    }

    #[test]
    fn perm_and_arch_without_any_dir_predicate_is_not_dir_watch_shaped() {
        // Mirrors `perm_and_arch_without_any_path_predicate_is_not_path_watch_
        // shaped`: every OTHER conjunct passes, but there is NO Dir predicate
        // at all -- Perm and Arch alone must NOT count as "dir-watch shaped".
        let fields = vec![
            field(AuditField::Perm, "wa"),
            field(AuditField::Arch, "b32"),
        ];
        assert!(
            !is_pure_dir_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "Perm+Arch with no Dir predicate must not be dir-watch shaped"
        );
    }

    #[test]
    fn dir_perm_arch_is_dir_watch_shaped() {
        // Positive control, mirroring `path_perm_arch_is_path_watch_shaped`:
        // dir + perm + arch, empty -S, empty -C must pass. Without this, an
        // "always reject" impl would vacuously pass the negative test above.
        let fields = vec![
            field(AuditField::Dir, "/etc/sudoers.d"),
            field(AuditField::Perm, "wa"),
            field(AuditField::Arch, "b32"),
        ];
        assert!(
            is_pure_dir_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "dir+perm+arch, empty -S, empty -C must be dir-watch shaped"
        );
    }

    #[test]
    fn path_field_alone_is_not_dir_watch_shaped() {
        // Guards the "limited to dir/perm/arch" conjunct specifically for
        // the Dir arm: a Path field is not in the allowed set, so a
        // path-only field list must never be dir-watch shaped -- this is
        // the structural half of the anti-collapse boundary the integration
        // tests (`dir_syscall_form_does_not_satisfy_an_explicit_path_shaped_
        // requirement` / `dir_shaped_requirement_not_satisfied_by_an_
        // explicit_path_syscall`) pin at the public-API level.
        let fields = vec![field(AuditField::Path, "/etc/passwd")];
        assert!(
            !is_pure_dir_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "a Path-only field set must not be dir-watch shaped"
        );
    }

    #[test]
    fn dir_and_path_together_is_not_dir_watch_shaped() {
        // Test-adequacy strengthening (ATL round, issue #571, session 9j
        // lane 8): `path_field_alone_is_not_dir_watch_shaped` above pins a
        // Path-ONLY field set, which already fails BOTH the allowed-field-
        // set conjunct AND the "has a Dir predicate" conjunct -- so it
        // cannot distinguish this function's real allowed set
        // (Dir|Perm|Arch|Key) from a wrong, over-broad one
        // (Dir|Path|Perm|Arch): a mutant with that wider set still passes
        // it. This test adds a Dir predicate ALONGSIDE the Path predicate
        // so the "has a Dir predicate" conjunct is satisfied too, and only
        // a correct allowed-field-set conjunct can still reject it.
        let fields = vec![
            field(AuditField::Path, "/etc/sudoers.d"),
            field(AuditField::Dir, "/etc/sudoers.d"),
            field(AuditField::Perm, "wa"),
        ];
        assert!(
            !is_pure_dir_watch_shaped(&FilterList::Exit, &Action::Always, &[], &fields, &[]),
            "a field set containing BOTH Path and Dir must not be dir-watch \
             shaped -- Path is not in the {{Dir,Perm,Arch,Key}} allowed set"
        );
    }
}
