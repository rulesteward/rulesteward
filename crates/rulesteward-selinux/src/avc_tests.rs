//! Tests for the AVC parser. Every test cites the grounding doc section it pins.
//!
//! Primary anchor: f4 §1.2 (real captured el9 AVC line).
//! Edge cases: f4 §1.1 kernel source (avc.c citations).

#[cfg(test)]
mod tests {
    use crate::avc::{Verdict, parse_avc};

    // -----------------------------------------------------------------------
    // PRIMARY ANCHOR TEST (f4 §1.2 - real captured el9 AVC line)
    // -----------------------------------------------------------------------

    /// f4 §1.2: the exact captured el9 line must parse to one `AvcDenial` with
    /// all fields populated exactly as the spec table maps them.
    #[test]
    fn test_anchor_el9_primary() {
        let line = "type=AVC msg=audit(1780438805.959:23844): avc:  denied  { read } for  pid=14601 comm=\"mycat\" name=\"data\" dev=\"vda4\" ino=109061505 scontext=system_u:system_r:logrotate_t:s0 tcontext=unconfined_u:object_r:shadow_t:s0 tclass=file permissive=0";

        let result = parse_avc(line).expect("anchor line must parse without error");
        assert_eq!(result.len(), 1, "anchor line yields exactly one AvcDenial");
        let d = &result[0];

        // verdict
        assert_eq!(d.verdict, Verdict::Denied, "verdict must be Denied");

        // perms (f4 §1.1 avc.c:670)
        assert_eq!(d.perms, vec!["read".to_string()]);

        // SELinux type fields
        assert_eq!(d.source_type, "logrotate_t");
        assert_eq!(d.target_type, "shadow_t");
        assert_eq!(d.tclass, "file");

        // permissive=0 -> Some(false) = truly enforcing (f4 §1.1 avc.c:721-722)
        assert_eq!(d.permissive, Some(false));

        // audit(EPOCH:SERIAL) decomposed
        assert_eq!(d.timestamp, Some(1_780_438_805.959));
        assert_eq!(d.serial, Some(23844));

        // optional companion fields from the AVC line itself
        assert_eq!(d.pid, Some(14601));
        assert_eq!(d.comm, Some("mycat".to_string()));
        assert_eq!(d.name, Some("data".to_string()));

        // raw context strings
        assert_eq!(d.scontext_raw, "system_u:system_r:logrotate_t:s0");
        assert_eq!(d.tcontext_raw, "unconfined_u:object_r:shadow_t:s0");
    }

    // -----------------------------------------------------------------------
    // COMPANION CORRELATION (f4 §1.3): two events, each enriched ONLY from its
    // own SYSCALL/PATH records (correct serial-keyed correlation).
    // -----------------------------------------------------------------------

    /// A multi-event `ausearch` block with two events carrying DISTINCT serials,
    /// each with its own `SYSCALL` (exe) and `PATH` (name). Each `AvcDenial` must
    /// be enriched ONLY from its OWN event's companions - never the other event's.
    /// A constant or corrupted correlation key would cross-enrich (event A picking
    /// up event B's exe), so this pins the serial-keyed correlation logic.
    #[test]
    fn test_ausearch_multi_event_correlation_is_per_event() {
        let block = "\
type=AVC msg=audit(1000.001:100): avc:  denied  { read } for  scontext=u:r:dom_a:s0 tcontext=u:object_r:tgt_a:s0 tclass=file permissive=0
type=SYSCALL msg=audit(1000.001:100): exe=\"/usr/bin/aaa\"
type=PATH msg=audit(1000.001:100): name=\"/etc/file_a\"
type=AVC msg=audit(2000.002:200): avc:  denied  { write } for  scontext=u:r:dom_b:s0 tcontext=u:object_r:tgt_b:s0 tclass=file permissive=0
type=SYSCALL msg=audit(2000.002:200): exe=\"/usr/bin/bbb\"
type=PATH msg=audit(2000.002:200): name=\"/etc/file_b\"";

        let denials = parse_avc(block).expect("multi-event block must parse");
        assert_eq!(
            denials.len(),
            2,
            "two type=AVC records yield two AvcDenials"
        );

        // Results are in AVC-line order: event A first, event B second.
        let a = &denials[0];
        let b = &denials[1];
        assert_eq!(a.source_type, "dom_a");
        assert_eq!(b.source_type, "dom_b");

        // Each AvcDenial is enriched ONLY from its own event's companion records.
        assert_eq!(
            a.exe.as_deref(),
            Some("/usr/bin/aaa"),
            "event A exe must come from event A's SYSCALL, not B's"
        );
        assert_eq!(
            a.path.as_deref(),
            Some("/etc/file_a"),
            "event A path must come from event A's PATH, not B's"
        );
        assert_eq!(b.exe.as_deref(), Some("/usr/bin/bbb"));
        assert_eq!(b.path.as_deref(), Some("/etc/file_b"));

        // Distinct numeric serials (the same parser now keys the correlation).
        assert_eq!(a.serial, Some(100));
        assert_eq!(b.serial, Some(200));
    }

    // -----------------------------------------------------------------------
    // EDGE CASE: double spaces (f4 §1.1 avc.c:659)
    // The kernel emits "avc:  denied  { ... } for  " with two spaces after
    // the colon AND two spaces between the verdict and the brace.
    // -----------------------------------------------------------------------

    #[test]
    fn test_double_spaces_tolerated() {
        // Minimal line with double spaces exactly as the kernel emits
        let line = "type=AVC msg=audit(1000000000.000:1): avc:  denied  { write } for  scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:etc_t:s0 tclass=file permissive=0";
        let result = parse_avc(line).expect("double-space line must parse");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].verdict, Verdict::Denied);
        assert_eq!(result[0].perms, vec!["write".to_string()]);
    }

    // -----------------------------------------------------------------------
    // EDGE CASE: granted verdict -> permissive is None (f4 §1.1 avc.c:721)
    // A granted/audited-allow record has no permissive= field.
    // -----------------------------------------------------------------------

    #[test]
    fn test_granted_verdict_permissive_none() {
        let line = "type=AVC msg=audit(1000000000.000:2): avc:  granted  { read } for  scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:httpd_sys_content_t:s0 tclass=file";
        let result = parse_avc(line).expect("granted line must parse");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].verdict, Verdict::Granted);
        assert_eq!(
            result[0].permissive, None,
            "granted records carry no permissive field"
        );
    }

    // -----------------------------------------------------------------------
    // EDGE CASE: multi-perm brace (f4 §1.1 avc.c:670-675)
    // "{ getattr read }" -> perms=["getattr","read"]
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_perm_brace() {
        let line = "type=AVC msg=audit(1000000000.000:3): avc:  denied  { getattr read } for  scontext=system_u:system_r:logrotate_t:s0 tcontext=unconfined_u:object_r:shadow_t:s0 tclass=file permissive=0";
        let result = parse_avc(line).expect("multi-perm line must parse");
        assert_eq!(result.len(), 1);
        let d = &result[0];
        assert_eq!(d.perms, vec!["getattr".to_string(), "read".to_string()]);
    }

    // -----------------------------------------------------------------------
    // EDGE CASE: raw 0x%x hex residual token inside braces (avc.c:677)
    // "{ read 0x4 }" -> perms=["read","0x4"] (preserved, not an error)
    // -----------------------------------------------------------------------

    #[test]
    fn test_hex_residual_perm_preserved() {
        let line = "type=AVC msg=audit(1000000000.000:4): avc:  denied  { read 0x4 } for  scontext=system_u:system_r:logrotate_t:s0 tcontext=unconfined_u:object_r:shadow_t:s0 tclass=file permissive=0";
        let result = parse_avc(line).expect("hex residual token in braces must not error");
        assert_eq!(result.len(), 1);
        let d = &result[0];
        assert!(
            d.perms.contains(&"read".to_string()),
            "named perm 'read' must be present"
        );
        assert!(
            d.perms.contains(&"0x4".to_string()),
            "hex residual token '0x4' must be preserved in perms"
        );
    }

    // -----------------------------------------------------------------------
    // EDGE CASE: ssid=/tsid= numeric fallback (avc.c:709,714)
    // When context cannot be resolved the kernel emits ssid=NNN / tsid=NNN.
    // Must not panic; scontext_raw = "ssid=NNN", tcontext_raw = "tsid=NNN",
    // source_type = "ssid=NNN", target_type = "tsid=NNN" (surface the raw sid).
    // -----------------------------------------------------------------------

    #[test]
    fn test_ssid_tsid_numeric_fallback_no_panic() {
        let line = "type=AVC msg=audit(1000000000.000:5): avc:  denied  { read } for  pid=100 comm=\"test\" ssid=42 tsid=99 tclass=file permissive=0";
        let result = parse_avc(line).expect("ssid/tsid fallback must parse without panic");
        assert_eq!(result.len(), 1);
        let d = &result[0];
        // We surface the sid values in the raw fields so callers can see them
        assert!(
            d.scontext_raw.contains("42"),
            "scontext_raw must contain the ssid value"
        );
        assert!(
            d.tcontext_raw.contains("99"),
            "tcontext_raw must contain the tsid value"
        );
        // source_type/target_type document the fallback
        assert!(
            !d.source_type.is_empty(),
            "source_type must not be empty on ssid fallback"
        );
        assert!(
            !d.target_type.is_empty(),
            "target_type must not be empty on tsid fallback"
        );
    }

    // -----------------------------------------------------------------------
    // EDGE CASE: no companion fields (bare minimal AVC)
    // "... for  scontext=... tcontext=... tclass=... permissive=0" with NO
    // pid/comm/name/dev/ino between "for " and "scontext=".
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_companion_fields() {
        let line = "type=AVC msg=audit(1000000000.000:6): avc:  denied  { read } for  scontext=system_u:system_r:logrotate_t:s0 tcontext=unconfined_u:object_r:shadow_t:s0 tclass=file permissive=0";
        let result = parse_avc(line).expect("bare AVC with no companion fields must parse");
        assert_eq!(result.len(), 1);
        let d = &result[0];
        assert_eq!(d.pid, None);
        assert_eq!(d.comm, None);
        assert_eq!(d.name, None);
        assert_eq!(d.source_type, "logrotate_t");
        assert_eq!(d.target_type, "shadow_t");
    }

    // -----------------------------------------------------------------------
    // EDGE CASE: extra unknown k=v keys between "for " and "scontext="
    // An unknown field must be silently ignored (tolerant parser).
    // -----------------------------------------------------------------------

    #[test]
    fn test_unknown_kv_ignored() {
        let line = "type=AVC msg=audit(1000000000.000:7): avc:  denied  { read } for  pid=200 comm=\"foo\" unknown_field=bar another=xyz scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:etc_t:s0 tclass=file permissive=1";
        let result = parse_avc(line).expect("unknown k=v fields must not error");
        assert_eq!(result.len(), 1);
        let d = &result[0];
        // permissive=1 -> Some(true) = permissive denial (did not actually block)
        assert_eq!(d.permissive, Some(true));
        assert_eq!(d.pid, Some(200));
    }

    // -----------------------------------------------------------------------
    // EDGE CASE: ausearch-grouped block (f4 §1.3)
    // A multi-line block where SYSCALL carries exe= and PATH carries name=,
    // sharing the same audit(TS:SERIAL) as the AVC line. The companion exe=
    // and path= (from PATH record's name=) must be pulled into AvcDenial.
    // -----------------------------------------------------------------------

    #[test]
    fn test_ausearch_grouped_block() {
        let block = concat!(
            "type=SYSCALL msg=audit(1780438805.959:23844): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=55a1b2c3d4e5 a2=0 a3=0 items=1 ppid=1 pid=14601 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=1 comm=\"mycat\" exe=\"/usr/bin/cat\" key=(null)\n",
            "type=PATH msg=audit(1780438805.959:23844): item=0 name=\"/etc/shadow\" inode=109061505 dev=fd:00 mode=0100000 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:shadow_t:s0 objtype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0\n",
            "type=AVC msg=audit(1780438805.959:23844): avc:  denied  { read } for  pid=14601 comm=\"mycat\" name=\"data\" dev=\"vda4\" ino=109061505 scontext=system_u:system_r:logrotate_t:s0 tcontext=unconfined_u:object_r:shadow_t:s0 tclass=file permissive=0"
        );

        let result = parse_avc(block).expect("ausearch block must parse");
        assert_eq!(result.len(), 1);
        let d = &result[0];
        // exe= enriched from SYSCALL companion record
        assert_eq!(
            d.exe,
            Some("/usr/bin/cat".to_string()),
            "exe must be enriched from SYSCALL companion"
        );
        // The AVC fields themselves must still be correct
        assert_eq!(d.source_type, "logrotate_t");
        assert_eq!(d.target_type, "shadow_t");
        assert_eq!(d.serial, Some(23844));
    }

    // -----------------------------------------------------------------------
    // EDGE CASE: permissive=1 (permissive denial - did NOT actually block)
    // f4 §1.1 avc.c:721-722: permissive=1 means the domain is permissive.
    // -----------------------------------------------------------------------

    #[test]
    fn test_permissive_denial() {
        let line = "type=AVC msg=audit(1000000000.000:8): avc:  denied  { write } for  scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:shadow_t:s0 tclass=file permissive=1";
        let result = parse_avc(line).expect("permissive=1 line must parse");
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].permissive,
            Some(true),
            "permissive=1 -> Some(true)"
        );
    }
}
