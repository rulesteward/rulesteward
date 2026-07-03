//! The `Event` wire schema emitted by event-producing commands (v0.2 `collect`).
//! Stable from v0.1 (spec §12.3): a fleet collector aggregates by
//! `(rule_id x ftype x exe)`. `#[non_exhaustive]` lets the schema gain fields in
//! v0.2 without a breaking change; cross-crate callers must use [`Event::new`].
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Event {
    /// fapolicyd rule number that produced this decision (aggregation key).
    pub rule_id: u32,
    /// Decision keyword: `"allow"`, `"deny"`, `"allow_audit"`, etc.
    pub decision: String,
    /// Object file type / MIME (aggregation key).
    pub ftype: String,
    /// Subject executable path (aggregation key).
    pub exe: String,
    /// Object path the decision applied to.
    pub path: String,
    /// RFC 3339 timestamp, supplied by the producer (no time-crate dep here).
    pub timestamp: String,
}

impl Event {
    /// Construct an `Event`. Required because `#[non_exhaustive]` forbids
    /// struct-literal construction from other crates.
    #[must_use]
    pub fn new(
        rule_id: u32,
        decision: impl Into<String>,
        ftype: impl Into<String>,
        exe: impl Into<String>,
        path: impl Into<String>,
        timestamp: impl Into<String>,
    ) -> Self {
        Self {
            rule_id,
            decision: decision.into(),
            ftype: ftype.into(),
            exe: exe.into(),
            path: path.into(),
            timestamp: timestamp.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Event;

    #[test]
    fn event_serializes_to_expected_json_object() {
        let ev = Event::new(
            42,
            "deny",
            "application/x-executable",
            "/usr/bin/ssh",
            "/tmp/x",
            "2026-05-28T00:00:00Z",
        );
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(r#""rule_id":42"#));
        assert!(json.contains(r#""decision":"deny""#));
        assert!(json.contains(r#""ftype":"application/x-executable""#));
        assert!(json.contains(r#""exe":"/usr/bin/ssh""#));
        // `path` and `timestamp` are part of the stable v0.1 wire schema (spec
        // §12.3); assert their JSON names too so a silent `#[serde(rename)]` of
        // either field is caught (the round-trip test alone would not catch it).
        assert!(json.contains(r#""path":"/tmp/x""#));
        assert!(json.contains(r#""timestamp":"2026-05-28T00:00:00Z""#));
    }

    #[test]
    fn event_round_trips_through_json() {
        let ev = Event::new(
            1,
            "allow",
            "text/plain",
            "/bin/sh",
            "/etc/hosts",
            "2026-05-28T00:00:00Z",
        );
        let json = serde_json::to_string(&ev).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }
}
