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

use rulesteward_core::extract_audit_field;

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
    pub fn from_raw(n: u32) -> Self {
        match n {
            0 => TrustVal::No,
            1 => TrustVal::Yes,
            _ => TrustVal::Unknown,
        }
    }

    /// Return the human-readable label used in `explain` output (f1 §4.2).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            TrustVal::No => "no",
            TrustVal::Yes => "yes",
            TrustVal::Unknown => "unknown",
        }
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
        if self.fan_type == 1 {
            Some(self.fan_info)
        } else {
            None
        }
    }

    /// Return `true` if the kernel denied the access (`resp == 2`).
    #[must_use]
    pub fn is_deny(&self) -> bool {
        self.resp == 2
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
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract the `audit(TS:SERIAL)` timestamp from a `msg=audit(TS:SERIAL):` field.
fn extract_timestamp(line: &str) -> Option<&str> {
    let start = line.find("audit(")?;
    let inner = &line[start + "audit(".len()..];
    let end = inner.find(')')?;
    Some(&inner[..end])
}

/// Parse a `type=FANOTIFY` line into a `FanotifyRecord` and its timestamp.
///
/// Returns `(record, timestamp_str)` on success.
fn parse_fanotify_line(line: &str) -> Result<(FanotifyRecord, String), ParseError> {
    // Must be a FANOTIFY line.
    if !line.contains("type=FANOTIFY") {
        return Err(ParseError::NoFanotifyRecord);
    }

    let timestamp = extract_timestamp(line).unwrap_or("").to_string();

    let resp_str = extract_audit_field(line, "resp")
        .ok_or_else(|| ParseError::MalformedRecord("missing resp field".to_string()))?;
    let resp = resp_str
        .parse::<u32>()
        .map_err(|_| ParseError::MalformedRecord(format!("invalid resp value: {resp_str}")))?;

    let fan_type_str = extract_audit_field(line, "fan_type")
        .ok_or_else(|| ParseError::MalformedRecord("missing fan_type field".to_string()))?;
    let fan_type = fan_type_str.parse::<u32>().map_err(|_| {
        ParseError::MalformedRecord(format!("invalid fan_type value: {fan_type_str}"))
    })?;

    // fan_info is HEX (kernel printf uses %X); parse with base 16.
    let fan_info_str = extract_audit_field(line, "fan_info")
        .ok_or_else(|| ParseError::MalformedRecord("missing fan_info field".to_string()))?;
    let fan_info = u32::from_str_radix(fan_info_str, 16).map_err(|_| {
        ParseError::MalformedRecord(format!("invalid fan_info hex value: {fan_info_str}"))
    })?;

    let subj_trust_str = extract_audit_field(line, "subj_trust")
        .ok_or_else(|| ParseError::MalformedRecord("missing subj_trust field".to_string()))?;
    let subj_trust_raw = subj_trust_str.parse::<u32>().map_err(|_| {
        ParseError::MalformedRecord(format!("invalid subj_trust value: {subj_trust_str}"))
    })?;

    let obj_trust_str = extract_audit_field(line, "obj_trust")
        .ok_or_else(|| ParseError::MalformedRecord("missing obj_trust field".to_string()))?;
    let obj_trust_raw = obj_trust_str.parse::<u32>().map_err(|_| {
        ParseError::MalformedRecord(format!("invalid obj_trust value: {obj_trust_str}"))
    })?;

    Ok((
        FanotifyRecord {
            resp,
            fan_type,
            fan_info,
            subj_trust: TrustVal::from_raw(subj_trust_raw),
            obj_trust: TrustVal::from_raw(obj_trust_raw),
        },
        timestamp,
    ))
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
pub fn parse_fanotify_record(line: &str) -> Result<FanotifyRecord, ParseError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(ParseError::NoFanotifyRecord);
    }
    let (record, _ts) = parse_fanotify_line(trimmed)?;
    Ok(record)
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
pub fn parse_audit_event(input: &str) -> Result<AuditEvent, ParseError> {
    // Find the FANOTIFY line among the input lines (skip separator lines like "----").
    let mut fanotify_line: Option<&str> = None;
    let mut syscall_line: Option<&str> = None;
    let mut path_line: Option<&str> = None;

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "----" {
            continue;
        }
        if trimmed.contains("type=FANOTIFY") {
            fanotify_line = Some(trimmed);
        } else if trimmed.contains("type=SYSCALL") {
            syscall_line = Some(trimmed);
        } else if trimmed.contains("type=PATH") {
            path_line = Some(trimmed);
        }
        // PROCTITLE and CWD are ignored.
    }

    let fan_line = fanotify_line.ok_or(ParseError::NoFanotifyRecord)?;
    let (fanotify, timestamp) = parse_fanotify_line(fan_line)?;

    // Extract companion fields from SYSCALL record.
    let mut pid: Option<i32> = None;
    let mut auid: Option<u32> = None;
    let mut exe: Option<String> = None;
    let mut perm: Option<Perm> = None;

    if let Some(sc) = syscall_line {
        if let Some(pid_str) = extract_audit_field(sc, "pid") {
            pid = pid_str.parse::<i32>().ok();
        }
        if let Some(auid_str) = extract_audit_field(sc, "auid")
            && let Ok(raw) = auid_str.parse::<u32>()
        {
            // Sentinel u32::MAX means "not set" -> store as None.
            if raw != u32::MAX {
                auid = Some(raw);
            }
        }
        if let Some(exe_str) = extract_audit_field(sc, "exe") {
            exe = Some(exe_str.to_string());
        }
        if let Some(syscall_str) = extract_audit_field(sc, "syscall")
            && let Ok(syscall_num) = syscall_str.parse::<u32>()
        {
            // syscall 59 is execve on x86_64 -> Execute; all others -> Open.
            perm = Some(if syscall_num == 59 {
                Perm::Execute
            } else {
                Perm::Open
            });
        }
    }

    // Extract object path from PATH record.
    let path = path_line
        .and_then(|pl| extract_audit_field(pl, "name"))
        .map(String::from);

    Ok(AuditEvent {
        fanotify,
        pid,
        auid,
        exe,
        path,
        perm,
        timestamp,
    })
}
