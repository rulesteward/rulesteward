//! Reading `syslog_format` out of fapolicyd.conf. DESIGN.md §6 step 1.
//!
//! Pure: the caller does the `fs::read` and hands the bytes here, so D1's config read
//! does not move the purity boundary.

/// Extract the `syslog_format` field list. Returns `None` when the key is absent — the
/// COMPILED default is `rule,dec,perm,auid,pid,exe,:,path,ftype`, which notably has no
/// `trust` field; only the shipped conf adds it.
pub fn syslog_format(conf: &[u8]) -> Option<Vec<String>> {
    for line in conf.split(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(line);
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "syslog_format" {
            continue;
        }
        let fields: Vec<String> = value
            .trim()
            .split(',')
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect();
        return (!fields.is_empty()).then_some(fields);
    }
    None
}

/// `format_value`'s uid/gid branch dereferences `subj` with no NULL check on Rocky
/// 9/10, which is a SIGSEGV; on Rocky 8 an empty gid set leaves the buffer
/// unterminated, so the field carries heap bytes that can include a space and break
/// field splitting. Either way the host is misconfigured and we say so.
pub fn hazardous_fields(fields: &[String]) -> Vec<&str> {
    fields
        .iter()
        .filter(|f| *f == "uid" || *f == "gid")
        .map(String::as_str)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_shipped_default() {
        let conf = b"# comment\npermissive = 0\nsyslog_format = rule,dec,perm,auid,pid,exe,:,path,ftype,trust\n";
        let f = syslog_format(conf).unwrap();
        assert_eq!(f.first().unwrap(), "rule");
        assert_eq!(f.last().unwrap(), "trust");
        assert!(f.contains(&":".to_string()));
    }

    #[test]
    fn absent_key_is_none_not_a_guess() {
        assert!(syslog_format(b"permissive = 0\n").is_none());
    }

    #[test]
    fn commented_out_key_does_not_count() {
        assert!(syslog_format(b"#syslog_format = dec,:,path\n").is_none());
    }

    #[test]
    fn flags_uid_and_gid_as_host_hazards() {
        let f = syslog_format(b"syslog_format = rule,dec,uid,gid,:,path\n").unwrap();
        assert_eq!(hazardous_fields(&f), vec!["uid", "gid"]);
    }
}
