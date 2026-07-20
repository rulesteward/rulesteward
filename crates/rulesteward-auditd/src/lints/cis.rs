//! Per-product CIS Benchmark control table for the auditd backend (issue #528),
//! milestone 9f-v0_8-wave3-cis. Mirrors the `stig_required.rs`
//! [`BaselineRule`](super::stig_required::BaselineRule) /
//! [`stig_baseline`](super::stig_required::stig_baseline) shape: one row per
//! `ComplianceAsCode` audit rule, carrying the CIS control id and the one-line
//! `CaC` title, keyed per RHEL major via [`cis_baseline`].
//!
//! Ground truth: `tools/cis-update derive`'s output at the `CaC` pin
//! `519b5fe8` (see `tools/cis-update/cis-refs.toml`). Upstream
//! `ComplianceAsCode`/content is BSD-3-Clause; only CIS control ids and `CaC`
//! rule titles ever cross into this repo -- never CIS benchmark prose (license
//! discipline, #524/#510).
//!
//! The three per-product tables (`RHEL8_CIS`/`RHEL9_CIS`/`RHEL10_CIS`) are
//! filled verbatim from `cis-update derive`'s output
//! (`derive-rhel{8,9,10}-auditd.txt` at the pinned `CaC` commit), exactly as
//! the STIG `RHEL*_REQUIRED` tables were. The CIS->STIG join tables
//! (`RHEL{8,9,10}_CIS_JOIN`) are transcribed verbatim from `cis-update`'s
//! stig-refs output (`stig-refs-rhel{8,9,10}-auditd.txt`), joined via the
//! `CaC` rule name as the foreign key: a `(stig_id, control_id)` pair per row
//! whose `stig-refs` column is non-`-`, deduplicated so a control mapped by
//! several `CaC` rules under one STIG id appears once.

use rulesteward_core::{ControlRef, Framework};

use super::TargetVersion;

/// One CIS-mapped audit rule row: the `ComplianceAsCode` rule name (the stable
/// join key back to a `CaC` audit rule / an au-W06 requirement), its CIS
/// Benchmark control id (e.g. `"6.3.2.1"`), and the one-line `CaC` title shown
/// as a [`ControlRef`](rulesteward_core::ControlRef) `name`.
///
/// Mirrors [`super::stig_required::BaselineRule`]: `Copy`, all fields
/// `&'static str`. The control id is PRODUCT-SPECIFIC -- the same `cac_rule`
/// can carry a different `control_id` on a different RHEL major (e.g.
/// `audit_rules_immutable` is `6.3.3.21` on rhel8, `6.3.3.20` on rhel9,
/// `6.3.3.36` on rhel10), so callers MUST read the row from the target's own
/// table via [`cis_baseline`] and never assume an id is stable across products.
#[derive(Debug, Clone, Copy)]
pub struct CisControl {
    /// CIS Benchmark control id for this rule under the row's product (e.g.
    /// `"6.3.2.1"`).
    pub control_id: &'static str,
    /// `ComplianceAsCode` rule name (e.g.
    /// `"auditd_data_retention_max_log_file"`); the join key back to a `CaC`
    /// audit rule / au-W06 requirement.
    pub cac_rule: &'static str,
    /// The one-line `CaC` recommendation title (e.g. `"Ensure audit log storage
    /// size is configured (Automated)"`). `CaC` titles only; never benchmark
    /// prose.
    pub title: &'static str,
}

/// The grounded per-RHEL-major CIS control tables: one [`CisControl`] literal
/// per derived rule mapping, transcribed verbatim from `cis-update derive`'s
/// output and kept drift-tethered to `ComplianceAsCode` by that tool's `check`
/// gate (do not hand-edit; re-derive on a `CaC` pin bump).
#[rustfmt::skip]
const RHEL8_CIS: &[CisControl] = &[
    CisControl { control_id: "6.3.2.1", cac_rule: "auditd_data_retention_max_log_file", title: "Ensure audit log storage size is configured (Automated)" },
    CisControl { control_id: "6.3.2.2", cac_rule: "auditd_data_retention_max_log_file_action", title: "Ensure audit logs are not automatically deleted (Automated)" },
    CisControl { control_id: "6.3.2.3", cac_rule: "auditd_data_disk_error_action", title: "Ensure system is disabled when audit logs are full (Automated)" },
    CisControl { control_id: "6.3.2.3", cac_rule: "auditd_data_disk_full_action", title: "Ensure system is disabled when audit logs are full (Automated)" },
    CisControl { control_id: "6.3.2.4", cac_rule: "auditd_data_retention_admin_space_left_action", title: "Ensure system warns when audit logs are low on space (Automated)" },
    CisControl { control_id: "6.3.2.4", cac_rule: "auditd_data_retention_space_left_action", title: "Ensure system warns when audit logs are low on space (Automated)" },
    CisControl { control_id: "6.3.3.1", cac_rule: "audit_rules_sysadmin_actions", title: "Ensure changes to system administration scope (sudoers) is collected (Automated)" },
    CisControl { control_id: "6.3.3.2", cac_rule: "audit_rules_suid_auid_privilege_function", title: "Ensure actions as another user are always logged (Automated)" },
    CisControl { control_id: "6.3.3.3", cac_rule: "audit_sudo_log_events", title: "Ensure events that modify the sudo log file are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_adjtimex", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_settimeofday", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_clock_settime", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_watch_localtime", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.5", cac_rule: "audit_rules_networkconfig_modification", title: "Ensure events that modify the system's network environment are collected (Automated)" },
    CisControl { control_id: "6.3.3.5", cac_rule: "audit_rules_networkconfig_modification_network_scripts", title: "Ensure events that modify the system's network environment are collected (Automated)" },
    CisControl { control_id: "6.3.3.6", cac_rule: "audit_rules_privileged_commands", title: "Ensure use of privileged commands are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_creat", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_ftruncate", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_open", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_openat", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_truncate", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_group", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_passwd", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_gshadow", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_shadow", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_opasswd", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_nsswitch_conf", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_pam_conf", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_pamd", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_chmod", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fchmod", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fchmodat", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_chown", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fchown", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fchownat", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_lchown", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_setxattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_lsetxattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fsetxattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_removexattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_lremovexattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fremovexattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.10", cac_rule: "audit_rules_media_export", title: "Ensure successful file system mounts are collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_session_events_utmp", title: "Ensure session initiation information is collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_session_events_btmp", title: "Ensure session initiation information is collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_session_events_wtmp", title: "Ensure session initiation information is collected (Automated)" },
    CisControl { control_id: "6.3.3.12", cac_rule: "audit_rules_login_events_faillock", title: "Ensure login and logout events are collected (Automated)" },
    CisControl { control_id: "6.3.3.12", cac_rule: "audit_rules_login_events_lastlog", title: "Ensure login and logout events are collected (Automated)" },
    CisControl { control_id: "6.3.3.13", cac_rule: "audit_rules_file_deletion_events_rename", title: "Ensure file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.13", cac_rule: "audit_rules_file_deletion_events_renameat", title: "Ensure file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.13", cac_rule: "audit_rules_file_deletion_events_unlink", title: "Ensure file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.13", cac_rule: "audit_rules_file_deletion_events_unlinkat", title: "Ensure file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.14", cac_rule: "audit_rules_mac_modification", title: "Ensure events that modify the system's Mandatory Access Controls are collected (Automated)" },
    CisControl { control_id: "6.3.3.14", cac_rule: "audit_rules_mac_modification_usr_share", title: "Ensure events that modify the system's Mandatory Access Controls are collected (Automated)" },
    CisControl { control_id: "6.3.3.15", cac_rule: "audit_rules_execution_chcon", title: "Ensure successful and unsuccessful attempts to use the chcon command are recorded (Automated)" },
    CisControl { control_id: "6.3.3.16", cac_rule: "audit_rules_execution_setfacl", title: "Ensure successful and unsuccessful attempts to use the setfacl command are recorded (Automated)" },
    CisControl { control_id: "6.3.3.17", cac_rule: "audit_rules_execution_chacl", title: "Ensure successful and unsuccessful attempts to use the chacl command are recorded (Automated)" },
    CisControl { control_id: "6.3.3.18", cac_rule: "audit_rules_privileged_commands_usermod", title: "Ensure successful and unsuccessful attempts to use the usermod command are recorded (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_create", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_delete", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_finit", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_init", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_query", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_privileged_commands_kmod", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.20", cac_rule: "audit_rules_continue_loading", title: "Ensure the audit configuration is loaded regardless of errors (Automated)" },
    CisControl { control_id: "6.3.3.21", cac_rule: "audit_rules_immutable", title: "Ensure the audit configuration is immutable (Automated)" },
];

#[rustfmt::skip]
const RHEL9_CIS: &[CisControl] = &[
    CisControl { control_id: "6.3.2.1", cac_rule: "auditd_data_retention_max_log_file", title: "Ensure audit log storage size is configured (Automated)" },
    CisControl { control_id: "6.3.2.2", cac_rule: "auditd_data_retention_max_log_file_action", title: "Ensure audit logs are not automatically deleted (Automated)" },
    CisControl { control_id: "6.3.2.3", cac_rule: "auditd_data_disk_error_action", title: "Ensure system is disabled when audit logs are full (Automated)" },
    CisControl { control_id: "6.3.2.3", cac_rule: "auditd_data_disk_full_action", title: "Ensure system is disabled when audit logs are full (Automated)" },
    CisControl { control_id: "6.3.2.4", cac_rule: "auditd_data_retention_action_mail_acct", title: "Ensure system warns when audit logs are low on space (Automated)" },
    CisControl { control_id: "6.3.2.4", cac_rule: "auditd_data_retention_admin_space_left_action", title: "Ensure system warns when audit logs are low on space (Automated)" },
    CisControl { control_id: "6.3.2.4", cac_rule: "auditd_data_retention_space_left_action", title: "Ensure system warns when audit logs are low on space (Automated)" },
    CisControl { control_id: "6.3.3.1", cac_rule: "audit_rules_sysadmin_actions", title: "Ensure changes to system administration scope (sudoers) is collected (Automated)" },
    CisControl { control_id: "6.3.3.2", cac_rule: "audit_rules_suid_auid_privilege_function", title: "Ensure actions as another user are always logged (Automated)" },
    CisControl { control_id: "6.3.3.3", cac_rule: "audit_sudo_log_events", title: "Ensure events that modify the sudo log file are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_adjtimex", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_settimeofday", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_clock_settime", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_watch_localtime", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.5", cac_rule: "audit_rules_networkconfig_modification", title: "Ensure events that modify the system's network environment are collected (Automated)" },
    CisControl { control_id: "6.3.3.5", cac_rule: "audit_rules_networkconfig_modification_hostname_file", title: "Ensure events that modify the system's network environment are collected (Automated)" },
    CisControl { control_id: "6.3.3.5", cac_rule: "audit_rules_networkconfig_modification_network_scripts", title: "Ensure events that modify the system's network environment are collected (Automated)" },
    CisControl { control_id: "6.3.3.5", cac_rule: "audit_rules_networkconfig_modification_networkmanager", title: "Ensure events that modify the system's network environment are collected (Automated)" },
    CisControl { control_id: "6.3.3.6", cac_rule: "audit_rules_privileged_commands", title: "Ensure use of privileged commands are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_creat", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_ftruncate", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_open", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_openat", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_unsuccessful_file_modification_truncate", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_group", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_gshadow", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_opasswd", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_passwd", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_shadow", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_nsswitch_conf", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_pam_conf", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_usergroup_modification_pamd", title: "Ensure events that modify user/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_chmod", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_chown", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fchmod", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fchmodat", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fchown", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fchownat", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fremovexattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_fsetxattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_lchown", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_lremovexattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_lsetxattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_removexattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_dac_modification_setxattr", title: "Ensure discretionary access control permission modification events are collected (Automated)" },
    CisControl { control_id: "6.3.3.10", cac_rule: "audit_rules_media_export", title: "Ensure successful file system mounts are collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_session_events_utmp", title: "Ensure session initiation information is collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_session_events_btmp", title: "Ensure session initiation information is collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_session_events_wtmp", title: "Ensure session initiation information is collected (Automated)" },
    CisControl { control_id: "6.3.3.12", cac_rule: "audit_rules_login_events_faillock", title: "Ensure login and logout events are collected (Automated)" },
    CisControl { control_id: "6.3.3.12", cac_rule: "audit_rules_login_events_lastlog", title: "Ensure login and logout events are collected (Automated)" },
    CisControl { control_id: "6.3.3.13", cac_rule: "audit_rules_file_deletion_events_rename", title: "Ensure file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.13", cac_rule: "audit_rules_file_deletion_events_renameat", title: "Ensure file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.13", cac_rule: "audit_rules_file_deletion_events_unlink", title: "Ensure file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.13", cac_rule: "audit_rules_file_deletion_events_unlinkat", title: "Ensure file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.14", cac_rule: "audit_rules_mac_modification", title: "Ensure events that modify the system's Mandatory Access Controls are collected (Automated)" },
    CisControl { control_id: "6.3.3.14", cac_rule: "audit_rules_mac_modification_usr_share", title: "Ensure events that modify the system's Mandatory Access Controls are collected (Automated)" },
    CisControl { control_id: "6.3.3.15", cac_rule: "audit_rules_execution_chcon", title: "Ensure successful and unsuccessful attempts to use the chcon command are collected (Automated)" },
    CisControl { control_id: "6.3.3.16", cac_rule: "audit_rules_execution_setfacl", title: "Ensure successful and unsuccessful attempts to use the setfacl command are collected (Automated)" },
    CisControl { control_id: "6.3.3.17", cac_rule: "audit_rules_execution_chacl", title: "Ensure successful and unsuccessful attempts to use the chacl command are collected (Automated)" },
    CisControl { control_id: "6.3.3.18", cac_rule: "audit_rules_privileged_commands_usermod", title: "Ensure successful and unsuccessful attempts to use the usermod command are collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_create", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_delete", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_finit", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_init", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_kernel_module_loading_query", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_privileged_commands_kmod", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.20", cac_rule: "audit_rules_immutable", title: "Ensure the audit configuration is immutable (Automated)" },
];

#[rustfmt::skip]
const RHEL10_CIS: &[CisControl] = &[
    CisControl { control_id: "6.3.2.1", cac_rule: "auditd_data_retention_max_log_file", title: "Ensure audit log storage size is configured (Automated)" },
    CisControl { control_id: "6.3.2.2", cac_rule: "auditd_data_retention_max_log_file_action", title: "Ensure audit logs are not automatically deleted (Automated)" },
    CisControl { control_id: "6.3.2.3", cac_rule: "auditd_data_disk_error_action", title: "Ensure system is disabled when audit logs are full (Automated)" },
    CisControl { control_id: "6.3.2.3", cac_rule: "auditd_data_disk_full_action", title: "Ensure system is disabled when audit logs are full (Automated)" },
    CisControl { control_id: "6.3.2.4", cac_rule: "auditd_data_retention_action_mail_acct", title: "Ensure system warns when audit logs are low on space (Automated)" },
    CisControl { control_id: "6.3.2.4", cac_rule: "auditd_data_retention_admin_space_left_action", title: "Ensure system warns when audit logs are low on space (Automated)" },
    CisControl { control_id: "6.3.2.4", cac_rule: "auditd_data_retention_space_left_action", title: "Ensure system warns when audit logs are low on space (Automated)" },
    CisControl { control_id: "6.3.3.1", cac_rule: "audit_rules_sysadmin_actions", title: "Ensure modification of the /etc/sudoers file is collected (Automated)" },
    CisControl { control_id: "6.3.3.2", cac_rule: "audit_rules_suid_auid_privilege_function", title: "Ensure actions as another user are always logged (Automated)" },
    CisControl { control_id: "6.3.3.3", cac_rule: "audit_sudo_log_events", title: "Ensure events that modify the sudo log file are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_adjtimex", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_settimeofday", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_clock_settime", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.4", cac_rule: "audit_rules_time_watch_localtime", title: "Ensure events that modify date and time information are collected (Automated)" },
    CisControl { control_id: "6.3.3.5", cac_rule: "audit_rules_networkconfig_modification_setdomainname", title: "Ensure events that modify sethostname and setdomainname are collected (Automated)" },
    CisControl { control_id: "6.3.3.5", cac_rule: "audit_rules_networkconfig_modification_sethostname", title: "Ensure events that modify sethostname and setdomainname are collected (Automated)" },
    CisControl { control_id: "6.3.3.6", cac_rule: "audit_rules_networkconfig_modification_etc_issue", title: "Ensure events that modify /etc/issue and /etc/issue.net are collected (Automated)" },
    CisControl { control_id: "6.3.3.6", cac_rule: "audit_rules_networkconfig_modification_etc_issue_net", title: "Ensure events that modify /etc/issue and /etc/issue.net are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_networkconfig_modification_etc_hosts", title: "Ensure events that modify /etc/hosts and /etc/hostname are collected (Automated)" },
    CisControl { control_id: "6.3.3.7", cac_rule: "audit_rules_networkconfig_modification_hostname_file", title: "Ensure events that modify /etc/hosts and /etc/hostname are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_networkconfig_modification_etc_sysconfig_network", title: "Ensure events that modify /etc/sysconfig/network and /etc/NetworkManager/system-connections/ are collected (Automated)" },
    CisControl { control_id: "6.3.3.8", cac_rule: "audit_rules_networkconfig_modification_etc_networkmanager_system_connections", title: "Ensure events that modify /etc/sysconfig/network and /etc/NetworkManager/system-connections/ are collected (Automated)" },
    CisControl { control_id: "6.3.3.9", cac_rule: "audit_rules_networkconfig_modification_networkmanager", title: "Ensure events that modify /etc/NetworkManager directory are collected (Automated)" },
    CisControl { control_id: "6.3.3.10", cac_rule: "audit_rules_privileged_commands", title: "Ensure use of privileged commands are collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_unsuccessful_file_modification_creat", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_unsuccessful_file_modification_ftruncate", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_unsuccessful_file_modification_open", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_unsuccessful_file_modification_openat", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.11", cac_rule: "audit_rules_unsuccessful_file_modification_truncate", title: "Ensure unsuccessful file access attempts are collected (Automated)" },
    CisControl { control_id: "6.3.3.12", cac_rule: "audit_rules_usergroup_modification_group", title: "Ensure events that modify /etc/group information are collected (Automated)" },
    CisControl { control_id: "6.3.3.13", cac_rule: "audit_rules_usergroup_modification_passwd", title: "Ensure events that modify /etc/passwd information are collected (Automated)" },
    CisControl { control_id: "6.3.3.14", cac_rule: "audit_rules_usergroup_modification_gshadow", title: "Ensure events that modify /etc/shadow and /etc/gshadow are collected (Automated)" },
    CisControl { control_id: "6.3.3.14", cac_rule: "audit_rules_usergroup_modification_shadow", title: "Ensure events that modify /etc/shadow and /etc/gshadow are collected (Automated)" },
    CisControl { control_id: "6.3.3.15", cac_rule: "audit_rules_usergroup_modification_opasswd", title: "Ensure events that modify /etc/security/opasswd are collected (Automated)" },
    CisControl { control_id: "6.3.3.16", cac_rule: "audit_rules_usergroup_modification_nsswitch_conf", title: "Ensure events that modify /etc/nsswitch.conf file are collected (Automated)" },
    CisControl { control_id: "6.3.3.17", cac_rule: "audit_rules_usergroup_modification_pam_conf", title: "Ensure events that modify /etc/pam.conf and /etc/pam.d/ information are collected (Automated)" },
    CisControl { control_id: "6.3.3.17", cac_rule: "audit_rules_usergroup_modification_pamd", title: "Ensure events that modify /etc/pam.conf and /etc/pam.d/ information are collected (Automated)" },
    CisControl { control_id: "6.3.3.18", cac_rule: "audit_rules_dac_modification_chmod", title: "Ensure discretionary access control permission modification events chmod,fchmod,fchmodat,fchmodat2 are collected (Automated)" },
    CisControl { control_id: "6.3.3.18", cac_rule: "audit_rules_dac_modification_fchmod", title: "Ensure discretionary access control permission modification events chmod,fchmod,fchmodat,fchmodat2 are collected (Automated)" },
    CisControl { control_id: "6.3.3.18", cac_rule: "audit_rules_dac_modification_fchmodat", title: "Ensure discretionary access control permission modification events chmod,fchmod,fchmodat,fchmodat2 are collected (Automated)" },
    CisControl { control_id: "6.3.3.18", cac_rule: "audit_rules_dac_modification_fchmodat2", title: "Ensure discretionary access control permission modification events chmod,fchmod,fchmodat,fchmodat2 are collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_dac_modification_chown", title: "Ensure discretionary access control permission modification events chown,fchown,lchown,fchownat are collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_dac_modification_fchown", title: "Ensure discretionary access control permission modification events chown,fchown,lchown,fchownat are collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_dac_modification_fchownat", title: "Ensure discretionary access control permission modification events chown,fchown,lchown,fchownat are collected (Automated)" },
    CisControl { control_id: "6.3.3.19", cac_rule: "audit_rules_dac_modification_lchown", title: "Ensure discretionary access control permission modification events chown,fchown,lchown,fchownat are collected (Automated)" },
    CisControl { control_id: "6.3.3.20", cac_rule: "audit_rules_dac_modification_fremovexattr", title: "Ensure discretionary access control permission modification events setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr collected (Automated)" },
    CisControl { control_id: "6.3.3.20", cac_rule: "audit_rules_dac_modification_fsetxattr", title: "Ensure discretionary access control permission modification events setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr collected (Automated)" },
    CisControl { control_id: "6.3.3.20", cac_rule: "audit_rules_dac_modification_lremovexattr", title: "Ensure discretionary access control permission modification events setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr collected (Automated)" },
    CisControl { control_id: "6.3.3.20", cac_rule: "audit_rules_dac_modification_lsetxattr", title: "Ensure discretionary access control permission modification events setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr collected (Automated)" },
    CisControl { control_id: "6.3.3.20", cac_rule: "audit_rules_dac_modification_removexattr", title: "Ensure discretionary access control permission modification events setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr collected (Automated)" },
    CisControl { control_id: "6.3.3.20", cac_rule: "audit_rules_dac_modification_setxattr", title: "Ensure discretionary access control permission modification events setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr collected (Automated)" },
    CisControl { control_id: "6.3.3.21", cac_rule: "audit_rules_media_export", title: "Ensure successful file system mounts are collected (Automated)" },
    CisControl { control_id: "6.3.3.22", cac_rule: "audit_rules_session_events_utmp", title: "Ensure session initiation information is collected (Automated)" },
    CisControl { control_id: "6.3.3.22", cac_rule: "audit_rules_session_events_btmp", title: "Ensure session initiation information is collected (Automated)" },
    CisControl { control_id: "6.3.3.22", cac_rule: "audit_rules_session_events_wtmp", title: "Ensure session initiation information is collected (Automated)" },
    CisControl { control_id: "6.3.3.23", cac_rule: "audit_rules_login_events_faillock", title: "Ensure login and logout events are collected (Automated)" },
    CisControl { control_id: "6.3.3.23", cac_rule: "audit_rules_login_events_lastlog", title: "Ensure login and logout events are collected (Automated)" },
    CisControl { control_id: "6.3.3.24", cac_rule: "audit_rules_file_deletion_events_unlink", title: "Ensure unlink file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.24", cac_rule: "audit_rules_file_deletion_events_unlinkat", title: "Ensure unlink file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.25", cac_rule: "audit_rules_file_deletion_events_rename", title: "Ensure rename file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.25", cac_rule: "audit_rules_file_deletion_events_renameat", title: "Ensure rename file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.25", cac_rule: "audit_rules_file_deletion_events_renameat2", title: "Ensure rename file deletion events by users are collected (Automated)" },
    CisControl { control_id: "6.3.3.26", cac_rule: "audit_rules_mac_modification_etc_selinux", title: "Ensure events that modify the system's Mandatory Access Controls are collected (Automated)" },
    CisControl { control_id: "6.3.3.26", cac_rule: "audit_rules_mac_modification_usr_share", title: "Ensure events that modify the system's Mandatory Access Controls are collected (Automated)" },
    CisControl { control_id: "6.3.3.27", cac_rule: "audit_rules_execution_chcon", title: "Ensure successful and unsuccessful attempts to use the chcon command are collected (Automated)" },
    CisControl { control_id: "6.3.3.28", cac_rule: "audit_rules_execution_setfacl", title: "Ensure successful and unsuccessful attempts to use the setfacl command are collected (Automated)" },
    CisControl { control_id: "6.3.3.29", cac_rule: "audit_rules_execution_chacl", title: "Ensure successful and unsuccessful attempts to use the chacl command are collected (Automated)" },
    CisControl { control_id: "6.3.3.30", cac_rule: "audit_rules_privileged_commands_usermod", title: "Ensure successful and unsuccessful attempts to use the usermod command are collected (Automated)" },
    CisControl { control_id: "6.3.3.31", cac_rule: "audit_rules_privileged_commands_kmod", title: "Ensure kernel module loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.32", cac_rule: "audit_rules_kernel_module_loading_init", title: "Ensure kernel \"init_module\" and \"finit_module\" loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.32", cac_rule: "audit_rules_kernel_module_loading_finit", title: "Ensure kernel \"init_module\" and \"finit_module\" loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.33", cac_rule: "audit_rules_kernel_module_loading_delete", title: "Ensure kernel \"delete_module\" loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.34", cac_rule: "audit_rules_kernel_module_loading_query", title: "Ensure kernel \"query_module\" loading unloading and modification is collected (Automated)" },
    CisControl { control_id: "6.3.3.35", cac_rule: "audit_rules_continue_loading", title: "Ensure the audit configuration is loaded regardless of errors (Automated)" },
    CisControl { control_id: "6.3.3.36", cac_rule: "audit_rules_immutable", title: "Ensure the audit configuration is immutable (Automated)" },
];

/// The CIS control table for `target`. Mirrors
/// [`super::stig_required::stig_baseline`]: a pure per-product accessor over
/// the shipped grounded tables. The products DIVERGE (rhel10 is materially
/// larger and renumbers many controls), so the returned slice is
/// product-correct membership, not a shared superset.
#[must_use]
pub fn cis_baseline(target: TargetVersion) -> &'static [CisControl] {
    match target {
        TargetVersion::Rhel8 => RHEL8_CIS,
        TargetVersion::Rhel9 => RHEL9_CIS,
        TargetVersion::Rhel10 => RHEL10_CIS,
    }
}

/// The `Framework::Cis` control references that join `stig_id` under `target`,
/// ready to append to that STIG rule's au-W06 finding (issue #528). One
/// [`ControlRef`] per DISTINCT CIS control id that maps `stig_id` in the
/// product's `controls/stig_<p>.yml` (`cis-update`'s stig-refs join at the
/// pinned `CaC` commit), each carrying:
///
/// * `framework == Framework::Cis`,
/// * `id` = the CIS Benchmark control id (e.g. `"6.3.3.24"`), PRODUCT-SPECIFIC,
/// * `name = Some(<CaC title>)` -- the one-line `CaC` recommendation title
///   (via [`ControlRef::with_name`]); `CaC` titles only, never CIS prose,
/// * `alias == None` (CIS controls have no DISA Group/Vuln secondary id).
///
/// The result is DEDUPLICATED by control id and NEVER repeats one: several
/// `CaC` rules under one STIG id (e.g. `unlink`+`unlinkat` both under
/// `RHEL-10-500810`) collapse to their distinct CIS controls. It is
/// slice-shaped -- 0/1/many, not an `Option`: EMPTY when `stig_id` has no CIS
/// counterpart under `target` (a CIS-only `-` row, or a STIG id absent from
/// this product's join), and those findings stay STIG-only. One STIG id can
/// map several distinct CIS controls (`RHEL-10-500810` -> `6.3.3.24` +
/// `6.3.3.25`), so callers get 0, 1, or many refs.
///
/// Because the join is product-specific, callers MUST pass the target whose
/// au-W06 finding they are annotating; the same STIG id can join different CIS
/// ids (or none) on a different RHEL major.
///
/// Wired into [`super::stig_required::w06`] (the only entrypoint that carries
/// the `target`), which appends these refs onto each matching finding's
/// existing `Framework::Stig` ref rather than replacing it.
#[must_use]
pub fn cis_controls_for_stig(target: TargetVersion, stig_id: &str) -> Vec<ControlRef> {
    let table = cis_baseline(target);
    join_for(target)
        .iter()
        .filter(|(sid, _)| *sid == stig_id)
        .map(|(_, control_id)| {
            let title = match table.iter().find(|c| c.control_id == *control_id) {
                Some(c) => c.title,
                None => panic!("CIS join for {stig_id} references unknown control id {control_id}"),
            };
            ControlRef::new(Framework::Cis, *control_id).with_name(title)
        })
        .collect()
}

/// The per-product CIS<->STIG join: one `(stig_id, control_id)` pair per row
/// of `cis-update`'s stig-refs output whose STIG column is non-`-`,
/// transcribed verbatim from `stig-refs-rhel{8,9,10}-auditd.txt` and
/// deduplicated so several `CaC` rules mapping the same STIG id to the same
/// CIS control collapse to one pair (a STIG id mapping several DISTINCT CIS
/// controls, e.g. `RHEL-10-500810` -> `6.3.3.24` + `6.3.3.25`, keeps one pair
/// per distinct control).
#[rustfmt::skip]
const RHEL8_CIS_JOIN: &[(&str, &str)] = &[
    ("RHEL-08-030040", "6.3.2.3"),
    ("RHEL-08-030060", "6.3.2.3"),
    ("RHEL-08-030731", "6.3.2.4"),
    ("RHEL-08-030420", "6.3.3.7"),
    ("RHEL-08-030170", "6.3.3.8"),
    ("RHEL-08-030150", "6.3.3.8"),
    ("RHEL-08-030160", "6.3.3.8"),
    ("RHEL-08-030130", "6.3.3.8"),
    ("RHEL-08-030140", "6.3.3.8"),
    ("RHEL-08-030490", "6.3.3.9"),
    ("RHEL-08-030480", "6.3.3.9"),
    ("RHEL-08-030200", "6.3.3.9"),
    ("RHEL-08-030302", "6.3.3.10"),
    ("RHEL-08-030590", "6.3.3.12"),
    ("RHEL-08-030600", "6.3.3.12"),
    ("RHEL-08-030361", "6.3.3.13"),
    ("RHEL-08-030260", "6.3.3.15"),
    ("RHEL-08-030330", "6.3.3.16"),
    ("RHEL-08-030570", "6.3.3.17"),
    ("RHEL-08-030560", "6.3.3.18"),
    ("RHEL-08-030390", "6.3.3.19"),
    ("RHEL-08-030360", "6.3.3.19"),
    ("RHEL-08-030580", "6.3.3.19"),
    ("RHEL-08-030121", "6.3.3.21"),
];

#[rustfmt::skip]
const RHEL9_CIS_JOIN: &[(&str, &str)] = &[
    ("RHEL-09-653070", "6.3.2.4"),
    ("RHEL-09-653050", "6.3.2.4"),
    ("RHEL-09-653040", "6.3.2.4"),
    ("RHEL-09-654070", "6.3.3.7"),
    ("RHEL-09-654225", "6.3.3.8"),
    ("RHEL-09-654230", "6.3.3.8"),
    ("RHEL-09-654235", "6.3.3.8"),
    ("RHEL-09-654240", "6.3.3.8"),
    ("RHEL-09-654245", "6.3.3.8"),
    ("RHEL-09-654015", "6.3.3.9"),
    ("RHEL-09-654020", "6.3.3.9"),
    ("RHEL-09-654025", "6.3.3.9"),
    ("RHEL-09-654250", "6.3.3.12"),
    ("RHEL-09-654255", "6.3.3.12"),
    ("RHEL-09-654065", "6.3.3.13"),
    ("RHEL-09-654045", "6.3.3.15"),
    ("RHEL-09-654040", "6.3.3.16"),
    ("RHEL-09-654035", "6.3.3.17"),
    ("RHEL-09-654175", "6.3.3.18"),
    ("RHEL-09-654075", "6.3.3.19"),
    ("RHEL-09-654080", "6.3.3.19"),
    ("RHEL-09-654105", "6.3.3.19"),
    ("RHEL-09-654275", "6.3.3.20"),
];

#[rustfmt::skip]
const RHEL10_CIS_JOIN: &[(&str, &str)] = &[
    ("RHEL-10-500210", "6.3.2.4"),
    ("RHEL-10-500110", "6.3.2.4"),
    ("RHEL-10-500040", "6.3.2.4"),
    ("RHEL-10-500205", "6.3.2.4"),
    ("RHEL-10-500390", "6.3.3.11"),
    ("RHEL-10-500700", "6.3.3.12"),
    ("RHEL-10-500730", "6.3.3.13"),
    ("RHEL-10-500710", "6.3.3.14"),
    ("RHEL-10-500740", "6.3.3.14"),
    ("RHEL-10-500720", "6.3.3.15"),
    ("RHEL-10-500780", "6.3.3.18"),
    ("RHEL-10-500790", "6.3.3.19"),
    ("RHEL-10-500310", "6.3.3.20"),
    ("RHEL-10-500610", "6.3.3.21"),
    ("RHEL-10-500750", "6.3.3.23"),
    ("RHEL-10-500760", "6.3.3.23"),
    ("RHEL-10-500810", "6.3.3.24"),
    ("RHEL-10-500810", "6.3.3.25"),
    ("RHEL-10-500350", "6.3.3.27"),
    ("RHEL-10-500340", "6.3.3.28"),
    ("RHEL-10-500330", "6.3.3.29"),
    ("RHEL-10-500600", "6.3.3.30"),
    ("RHEL-10-500460", "6.3.3.31"),
    ("RHEL-10-500410", "6.3.3.32"),
    ("RHEL-10-500400", "6.3.3.33"),
    ("RHEL-10-900100", "6.3.3.36"),
];

/// The join table for `target` (the [`cis_controls_for_stig`] accessor).
fn join_for(target: TargetVersion) -> &'static [(&'static str, &'static str)] {
    match target {
        TargetVersion::Rhel8 => RHEL8_CIS_JOIN,
        TargetVersion::Rhel9 => RHEL9_CIS_JOIN,
        TargetVersion::Rhel10 => RHEL10_CIS_JOIN,
    }
}
