//! Parse the kernel `type=FANOTIFY` audit record (and its ausearch-grouped
//! companion records) into typed Rust structures.
//!
//! Grounding: f1 §3.2 / §3.4 / §5.2.
//!
//! Two kernel eras:
//! - **Era1** (`FAN_RESPONSE_INFO_NONE`): `fan_type=0`, no rule number.
//!   `fan_info` is the literal `0`.
//! - **Era2** (`FAN_RESPONSE_INFO_AUDIT_RULE`): `fan_type=1`, `fan_info` is
//!   the 1-based rule index printed in HEX (`%X`).
//!
//! `FanotifyRecord` captures the FANOTIFY line only.
//! `AuditEvent` groups the FANOTIFY record with companion SYSCALL/PATH/PROCTITLE
//! records that share the same `audit(TS:SERIAL)` stamp (f1 §3.4).
//!
//! Filled by pipeline P1 (issue #73).

use crate::ast::Perm;

// ---------------------------------------------------------------------------
// TrustVal
// ---------------------------------------------------------------------------

/// Trust value as encoded in the kernel FANOTIFY record.
///
/// The kernel encodes `{subj,obj}_trust` as 0 = not trusted, 1 = trusted,
/// 2 = unknown. Values outside {0,1,2} appear in old kernels (the real-world
/// example in f1 §3.2 has `subj_trust=3 obj_trust=5`); those are clamped to
/// `Unknown` (f1 §3.2: "modern kernels emit 0/1/2").
///
/// (f1 §3.2, `include/uapi/linux/fanotify.h` + kernel comment
///  `"{subj,obj}_trust values are {0,1,2}: no,yes,unknown"`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustVal {
    /// `subj_trust` / `obj_trust` = 0: path is NOT in the trust DB.
    No,
    /// `subj_trust` / `obj_trust` = 1: path IS in the trust DB.
    Yes,
    /// `subj_trust` / `obj_trust` = 2 (or any out-of-range value): status
    /// unknown / not provided.
    Unknown,
}

impl TrustVal {
    /// Decode a raw integer from the audit record into a `TrustVal`.
    ///
    /// Values outside {0, 1, 2} are clamped to `Unknown` (f1 §3.2).
    #[must_use]
    pub fn from_raw(_n: u32) -> Self {
        todo!("P1 #73 fills TrustVal::from_raw (0->No, 1->Yes, _->Unknown)")
    }

    /// Return the human-readable label used in `explain` output (f1 §4.2).
    #[must_use]
    pub fn label(self) -> &'static str {
        todo!("P1 #73 fills TrustVal::label (No->\"no\", Yes->\"yes\", Unknown->\"unknown\")")
    }
}

// ---------------------------------------------------------------------------
// FanotifyRecord
// ---------------------------------------------------------------------------

/// Parsed `type=FANOTIFY` audit record.
///
/// Layout fixed by `kernel/auditsc.c` `__audit_fanotify()` (f1 §3.2):
/// ```text
/// resp=%u fan_type=%u fan_info=%X subj_trust=%u obj_trust=%u
/// ```
/// The `audit(TS:SERIAL)` stamp is parsed but stored in the companion
/// `AuditEvent`, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanotifyRecord {
    /// `resp` field: `FAN_ALLOW` = 1, `FAN_DENY` = 2.
    pub resp: u32,
    /// `fan_type` field: 0 = `FAN_RESPONSE_INFO_NONE` (Era1, no rule number),
    ///  1 = `FAN_RESPONSE_INFO_AUDIT_RULE` (Era2, rule number present).
    pub fan_type: u32,
    /// `fan_info` field parsed from HEX (`%X` in the kernel printf).
    ///
    /// When `fan_type == 1` this is the 1-based fapolicyd rule index
    /// (f1 §3.3: `e->num + 1`). When `fan_type == 0` this is `0` (literal
    /// zero; no rule number available).
    ///
    /// CRITICAL: `fan_info` is hex. `fan_info=3137` in the record means
    /// `0x3137 = 12599` decimal, NOT 3137 decimal (f1 §3.2 worked example).
    pub fan_info: u32,
    /// `subj_trust`: trust status of the subject (process executable).
    pub subj_trust: TrustVal,
    /// `obj_trust`: trust status of the object (file being accessed).
    pub obj_trust: TrustVal,
}

impl FanotifyRecord {
    /// Return the 1-based rule number when the record carries one (Era2).
    ///
    /// Returns `None` for Era1 records (`fan_type == 0`).
    #[must_use]
    pub fn rule_number(&self) -> Option<u32> {
        todo!(
            "P1 #73 fills FanotifyRecord::rule_number (Some(fan_info) when fan_type==1, else None)"
        )
    }

    /// Return `true` if the kernel denied the access (`resp == 2`).
    #[must_use]
    pub fn is_deny(&self) -> bool {
        todo!("P1 #73 fills FanotifyRecord::is_deny (resp == 2)")
    }
}

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/// A grouped audit event: the FANOTIFY record plus companion SYSCALL/PATH
/// facts extracted from the same `audit(TS:SERIAL)` group (f1 §3.4).
///
/// `ausearch -m FANOTIFY` groups these automatically; the parser handles both
/// raw bare lines (FANOTIFY only) and ausearch-grouped blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// The FANOTIFY record (the primary record `explain` needs).
    pub fanotify: FanotifyRecord,
    /// PID of the accessing process (from SYSCALL `pid=`).
    pub pid: Option<i32>,
    /// Audit UID of the accessing process (from SYSCALL `auid=`).
    ///
    /// The sentinel `4294967295` (`u32::MAX`, `-1` as u32) means "not set";
    /// stored as `None`.
    pub auid: Option<u32>,
    /// Executable path of the accessing process (from SYSCALL `exe=`).
    pub exe: Option<String>,
    /// Object path being accessed (from PATH `name=`).
    pub path: Option<String>,
    /// Permission derived from the SYSCALL number (execve -> Execute, else Open).
    ///
    /// `None` when no SYSCALL record is present (bare FANOTIFY-only input).
    pub perm: Option<Perm>,
    /// The `audit(TS:SERIAL)` timestamp string, e.g. `"1600385147.372:590"`.
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// ParseError
// ---------------------------------------------------------------------------

/// Error returned when a record cannot be parsed.
///
/// Exit code 2 per f1 §4.2: "exit 2 on an unparseable record".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The input contained no recognizable `type=FANOTIFY` line.
    #[error("no FANOTIFY record found in input")]
    NoFanotifyRecord,
    /// A required field was missing or had an unparseable value.
    #[error("malformed FANOTIFY record: {0}")]
    MalformedRecord(String),
}

// ---------------------------------------------------------------------------
// Public parse API
// ---------------------------------------------------------------------------

/// Parse a single `type=FANOTIFY` line (bare, no companion records).
///
/// Accepts lines in the kernel `__audit_fanotify` format (f1 §3.2):
/// ```text
/// type=FANOTIFY msg=audit(<TS>:<SER>): resp=<u> fan_type=<u> fan_info=<HEX> subj_trust=<u> obj_trust=<u>
/// ```
///
/// Returns a `ParseError` if any required field is missing or malformed.
///
/// # Note on hex decoding
///
/// `fan_info` is parsed with `u32::from_str_radix(value, 16)` because the
/// kernel printf uses `%X` (uppercase hex). `fan_info=3137` in the record
/// decodes to `0x3137 = 12599` decimal (f1 §3.2 worked example).
pub fn parse_fanotify_record(_line: &str) -> Result<FanotifyRecord, ParseError> {
    todo!("P1 #73 fills fanotify record parser")
}

/// Parse an ausearch-grouped event block OR a bare `type=FANOTIFY` line into
/// an `AuditEvent`.
///
/// An ausearch block contains multiple `type=<X> msg=audit(<TS>:<SER>): ...`
/// lines sharing one `audit(TS:SERIAL)` stamp. The parser:
/// 1. Finds the `type=FANOTIFY` line and parses it via `parse_fanotify_record`.
/// 2. If a `type=SYSCALL` line is present (same serial), extracts `pid=`,
///    `auid=`, `exe=`, and infers `perm` from `syscall=` (59 = `execve` ->
///    `Perm::Execute`; all other syscalls -> `Perm::Open`).
/// 3. If a `type=PATH` line is present (same serial), extracts `name=` as the
///    object path.
/// 4. Records the `audit(TS:SERIAL)` timestamp from the FANOTIFY line.
///
/// A bare FANOTIFY line with no companions is also accepted; `pid`, `auid`,
/// `exe`, `path`, and `perm` will all be `None`.
///
/// Returns `ParseError::NoFanotifyRecord` if no FANOTIFY line is found.
/// Returns `ParseError::MalformedRecord` if the FANOTIFY line is present but
/// cannot be parsed.
pub fn parse_audit_event(_input: &str) -> Result<AuditEvent, ParseError> {
    todo!("P1 #73 fills audit event parser")
}
