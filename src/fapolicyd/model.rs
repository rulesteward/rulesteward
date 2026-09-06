//! The record model. DESIGN.md §4.

/// One side of a record, in emission order.
///
/// Deliberately a `Vec` of pairs and not a map: field names repeat within one side.
/// A `syslog_format` naming 21 subject fields makes the daemon emit
/// `rule=2 dec=deny_audit ... exe=... rule=2 dec=deny_audit ... rule=2` — the same
/// names twice in one record, captured in `rocky9-base-conf-validate.log`. A map
/// would silently drop the duplicates.
pub type Side = Vec<(Vec<u8>, Vec<u8>)>;

/// Values are bytes, never `String`: the escaper passes every byte >= 128 through raw,
/// so a non-UTF-8 path reaches us verbatim. Lossy conversion happens at display time
/// and nowhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub subject: Side,
    /// `None` when the record carried no bare ` : ` separator. That is a reachable
    /// configuration, not a parse failure: 21 subject-side names push the colon to
    /// field 22, which `parse_syslog_format` never looks at, so every record the
    /// daemon emits is subject-side only.
    pub object: Option<Side>,
}

/// First match wins. See the `Side` doc comment for why there can be more than one.
///
/// The value comes back UNESCAPED, because every caller wants the true bytes and
/// `exe=` is escaped exactly like `path=`. Unescaping once here is what stops a
/// second caller from forgetting to do it at all.
pub fn get(side: &Side, key: &[u8]) -> Option<Vec<u8>> {
    side.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| super::parse::unescape(v))
}

impl Record {
    pub fn subject_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        get(&self.subject, key)
    }

    pub fn object_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.object.as_ref().and_then(|o| get(o, key))
    }
}

/// One thing the run has to say, with the 1-based input line it came from. Host-level
/// diagnostics — the conf read, the uid/gid hazard, the corruption summary — belong to
/// the run and not to a line, so their `line` is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub line: Option<usize>,
    pub msg: String,
}

/// Object trust, from `obj ? (obj->val ? 1 : 0) : 9`.
///
/// `Unavailable` is emphatically not `Untrusted`: treating `9` as untrusted produces a
/// trust entry for a file whose trust state nobody knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Untrusted,
    Trusted,
    Unavailable,
    /// `trust` was not in `syslog_format` at all. The compiled default has no `trust`
    /// field; only the shipped conf adds it, so a host with a minimal conf lands here.
    Absent,
}

impl Trust {
    pub fn from_object(value: Option<&[u8]>) -> Trust {
        match value {
            None => Trust::Absent,
            Some(b"0") => Trust::Untrusted,
            Some(b"1") => Trust::Trusted,
            _ => Trust::Unavailable,
        }
    }
}

/// What the tool proposes for one denial. Emission is `emit`'s business.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Suggestion {
    /// Untrusted object: add it to the trust database and push the change to the
    /// running daemon. Both commands, always — `--file add` alone contacts no daemon.
    TrustFile { path: Vec<u8> },
    /// Trusted object, or one whose record carried no `trust=`: a rule scoped to this
    /// denial. DESIGN.md §7 "The rule v1 emits". `exe` is `None` when the record could
    /// not supply a usable one, which renders as `all` — no constraint on the subject.
    Rule {
        perm: Vec<u8>,
        exe: Option<Vec<u8>>,
        path: Vec<u8>,
    },
}
