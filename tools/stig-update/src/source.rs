//! The live fetch seam. [`fetch_xccdf`]/[`read_local`] (added #512, session
//! 9h-v0_8-wave4 Lane B) are the DISA zip fetch path this port's `check`/`derive`
//! subcommands now use - download a DISA STIG zip, unzip it, and read out the
//! `*Manual-xccdf.xml`, byte-identical logic to `tools/sshd-stig-update/src/source.rs`
//! / `tools/auditd-stig-update/src/source.rs` (a `curl` + `unzip` shell-out, isolated
//! here so the derivation core ([`crate::xccdf`]) stays offline-testable with
//! fixtures).
//!
//! The rest of this module (`curl`, `controls_optional`, `fetch_status`, `tree`,
//! `rule_fetcher`, `latest_release`, ...) is the CaC-era ComplianceAsCode fetch that
//! `main.rs`'s new DISA-sourced `check`/`derive` subcommands no longer call directly -
//! but it is NOT dead code: `tools/cis-update` (which path-deps this crate for its
//! own, still-`ComplianceAsCode`-sourced CIS derivation) calls `controls_optional`,
//! `tree`, `rule_fetcher`, and `latest_release` directly from its `main.rs`
//! (`cmd_check`/`cmd_derive`, for the `--latest`/`--stig-refs` paths), in addition to
//! `fetch_status` (via its own thin wrapper in `tools/cis-update/src/source.rs`).
//! Every function in this module stays `pub`/reachable per the #512 survival
//! constraint (verified live: `grep -rn stig_source:: tools/cis-update/src/main.rs`).
//! Any `check --latest` mentioned in the doc comments below refers to
//! `cis-update`'s OWN `--latest` flag - THIS crate's `check`/`derive` subcommands
//! dropped `--latest` entirely in #512 (DISA has no releases/latest API).

use std::path::{Path, PathBuf};
use std::process::Command;

const REPO: &str = "ComplianceAsCode/content";

/// Download the DISA STIG zip at `url`, unzip it, and return the contents of the
/// single `*Manual-xccdf.xml` inside. Uses a per-process temp dir under the system
/// temp directory.
pub fn fetch_xccdf(url: &str) -> Result<String, String> {
    let stem: String = url
        .rsplit('/')
        .next()
        .unwrap_or("stig")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let work = std::env::temp_dir().join(format!("stig-update-{}-{stem}", std::process::id()));
    // Fresh working dir.
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("create {}: {e}", work.display()))?;

    let zip = work.join("stig.zip");
    run(
        "curl",
        &[
            "-fsSL",
            "--max-time",
            "180",
            "-o",
            &zip.to_string_lossy(),
            url,
        ],
    )?;
    run(
        "unzip",
        &["-oq", &zip.to_string_lossy(), "-d", &work.to_string_lossy()],
    )?;

    let xccdf = find_xccdf(&work).ok_or_else(|| {
        format!("no *Manual-xccdf.xml found after unzipping {url} (is the pinned zip correct?)")
    })?;
    let body =
        std::fs::read_to_string(&xccdf).map_err(|e| format!("read {}: {e}", xccdf.display()))?;
    let _ = std::fs::remove_dir_all(&work);
    Ok(body)
}

/// Read a local XCCDF xml file (the offline `derive --file <path>` path).
pub fn read_local(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

/// Recursively find the first `*Manual-xccdf.xml` under `dir`.
fn find_xccdf(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with("Manual-xccdf.xml"))
        {
            return Some(path);
        }
    }
    subdirs.iter().find_map(|d| find_xccdf(d))
}

/// Run a command, mapping a spawn failure or non-zero exit to a readable error.
fn run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {cmd} (is it installed?): {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// `curl -fsSL <url>` -> body. Errors carry curl's stderr.
pub fn curl(url: &str) -> Result<String, String> {
    let out = Command::new("curl")
        .args(["-fsSL", url])
        .output()
        .map_err(|e| format!("spawn curl (is it installed?): {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("curl {url}: non-utf8 body: {e}"))
}

fn raw(reff: &str, path: &str) -> String {
    format!("https://raw.githubusercontent.com/{REPO}/{reff}/{path}")
}

/// Fetch a product's STIG controls file at `reff`, returning `None` when it does not
/// exist there (HTTP 404). A product can be absent at a given ref - e.g. `rhel10` is
/// on ComplianceAsCode master but not yet in a tagged release - so `cis-update`'s own
/// `check --latest` (see `tools/cis-update/src/main.rs::cmd_check`, which calls this
/// function directly for its `--stig-refs` CIS<->STIG join) treats `None` as
/// "not yet released; skip" rather than a hard error.
pub fn controls_optional(reff: &str, product: &str) -> Result<Option<String>, String> {
    let url = raw(
        reff,
        &format!("products/{product}/controls/stig_{product}.yml"),
    );
    let (code, body) = fetch_status(&url)?;
    match code {
        200 => Ok(Some(body)),
        404 => Ok(None),
        other => Err(format!("curl {url}: HTTP {other}")),
    }
}

/// `curl` that returns the HTTP status code alongside the body (so a 404 is
/// distinguishable from a transport failure). `-f` is intentionally NOT passed, so an
/// HTTP 404 still exits 0 and we read the code; `%{http_code}` is appended to stdout.
/// Public: `tools/cis-update` builds its own 404-as-`None` controls fetch on this
/// same seam (part of the shared lib surface #512 must keep alive).
pub fn fetch_status(url: &str) -> Result<(u16, String), String> {
    let out = Command::new("curl")
        .args(["-sSL", "--max-time", "60", "-w", "%{http_code}", url])
        .output()
        .map_err(|e| format!("spawn curl (is it installed?): {e}"))?;
    if !out.status.success() {
        // Transport failure (DNS, connection): curl exits non-zero, code is 000.
        return Err(format!(
            "curl {url} (transport): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let body =
        String::from_utf8(out.stdout).map_err(|e| format!("curl {url}: non-utf8 body: {e}"))?;
    parse_curl_status(&body).map_err(|e| format!("curl {url}: {e}"))
}

/// Split curl's `<body><http_code>` output - the 3-digit code is appended last.
fn parse_curl_status(body_with_code: &str) -> Result<(u16, String), String> {
    if body_with_code.len() < 3 {
        return Err("response too short to carry an HTTP status code".to_string());
    }
    let (text, code) = body_with_code.split_at(body_with_code.len() - 3);
    let code: u16 = code
        .parse()
        .map_err(|_| format!("trailing status code not a number: {code:?}"))?;
    Ok((code, text.to_string()))
}

/// Fetch the recursive git-tree (all paths) at `reff` once - used to locate each
/// rule's `rule.yml` + optional `_value.var` without guessing the guide directory.
///
/// GitHub caps this endpoint at ~100k entries / 7MB and sets `truncated: true`
/// on the response rather than erroring (see the GitHub REST API docs for
/// `GET /repos/{owner}/{repo}/git/trees/{sha}`). A truncated tree is missing an
/// unknown subset of paths, and a missing `rule.yml` path looks IDENTICAL to a
/// path that is genuinely absent - `find_path` would silently return `None` and
/// the derivation would proceed with an INCOMPLETE baseline. So this fails
/// closed rather than trusting a partial tree.
pub fn tree(reff: &str) -> Result<String, String> {
    let json = curl(&format!(
        "https://api.github.com/repos/{REPO}/git/trees/{reff}?recursive=1"
    ))?;
    reject_if_truncated(&json)?;
    Ok(json)
}

/// Reject a git-tree JSON body whose `truncated` field is `true`. The value is an
/// unquoted JSON boolean and GitHub may pretty-print the response (a space after the
/// colon) or not, so this tolerates both spacings - mirroring `find_path`'s
/// whitespace tolerance. A `truncated: false` value or an absent key (unlikely for
/// this endpoint, but not treated as a failure either way) is `Ok`.
///
/// The scan is ORDER-INDEPENDENT: it checks EVERY occurrence of the token
/// `"truncated"`, not just the first, so a benign earlier occurrence (e.g. a tree
/// entry whose path is literally `truncated`) cannot mask the genuine top-level
/// field that follows. It distinguishes the KEY `"truncated":` (the token followed
/// by a colon) from a path VALUE `"truncated"` (followed by `,`/`}`/`]`, never a
/// colon), so it is robust regardless of where the real field sits.
fn reject_if_truncated(tree_json: &str) -> Result<(), String> {
    for chunk in tree_json.split("\"truncated\"").skip(1) {
        // Only a KEY `"truncated"` is followed by a colon; a path VALUE is not.
        let Some(after_colon) = chunk.trim_start().strip_prefix(':') else {
            continue;
        };
        if after_colon.trim_start().starts_with("true") {
            return Err(
                "git-tree truncated (ComplianceAsCode exceeded the GitHub API tree cap); \
                 cannot derive a complete baseline - failing closed"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// The latest ComplianceAsCode release tag (for `cis-update`'s own `check --latest`
/// flag - see `tools/cis-update/src/main.rs::cmd_check`, which calls this function
/// directly; THIS crate's own `check` subcommand has no `--latest` flag as of #512).
pub fn latest_release() -> Result<String, String> {
    let json = curl(&format!(
        "https://api.github.com/repos/{REPO}/releases/latest"
    ))?;
    extract_json_string(&json, "tag_name")
        .ok_or_else(|| "no tag_name in releases/latest response".to_string())
}

/// A `get_rule` closure for [`crate::derive::derive_table`]: locate + fetch each
/// rule's `rule.yml` (+ its optional `_value.var`) from the pre-fetched `tree_json`.
pub fn rule_fetcher<'a>(
    reff: &'a str,
    tree_json: &'a str,
) -> impl Fn(&str) -> Result<(String, Option<String>), String> + 'a {
    move |rule_name: &str| {
        let rule_path = find_path(tree_json, &format!("/{rule_name}/rule.yml"))
            .ok_or_else(|| format!("rule.yml not found in git-tree for {rule_name}"))?;
        let rule_yaml = curl(&raw(reff, &rule_path))?;
        let var_yaml = match find_path(tree_json, &format!("/{rule_name}_value.var")) {
            Some(p) => Some(curl(&raw(reff, &p))?),
            None => None,
        };
        Ok((rule_yaml, var_yaml))
    }
}

/// Find a git-tree path ending in `suffix`. The tree JSON lists `"path": "..."`
/// entries; GitHub PRETTY-PRINTS the response (a space after the colon), so this
/// tolerates optional whitespace. The leading `/` in `suffix` anchors a path-segment
/// boundary so `sysctl_x` does not match `foo_sysctl_x`.
fn find_path(tree_json: &str, suffix: &str) -> Option<String> {
    for chunk in tree_json.split("\"path\"").skip(1) {
        let Some(after_colon) = chunk.trim_start().strip_prefix(':') else {
            continue;
        };
        let Some(value) = after_colon.trim_start().strip_prefix('"') else {
            continue;
        };
        let Some(end) = value.find('"') else { continue };
        if value[..end].ends_with(suffix) {
            return Some(value[..end].to_string());
        }
    }
    None
}

/// Extract a top-level `"key":"value"` string from a small JSON body (avoids a JSON
/// dependency for the one field we need from the releases API).
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let after_key = &json[json.find(&needle)? + needle.len()..];
    let after_colon = &after_key[after_key.find(':')? + 1..];
    let open = after_colon.find('"')? + 1;
    let close = after_colon[open..].find('"')? + open;
    Some(after_colon[open..close].to_string())
}

#[cfg(test)]
mod tests {
    use super::{extract_json_string, find_path, reject_if_truncated};

    #[test]
    fn find_path_anchors_on_segment_boundary() {
        let tree =
            r#"{"tree":[{"path":"a/foo_sysctl_x/rule.yml"},{"path":"b/sysctl_x/rule.yml"}]}"#;
        assert_eq!(
            find_path(tree, "/sysctl_x/rule.yml").as_deref(),
            Some("b/sysctl_x/rule.yml"),
            "must not match foo_sysctl_x"
        );
        assert_eq!(find_path(tree, "/missing/rule.yml"), None);
    }

    #[test]
    fn find_path_tolerates_pretty_printed_json() {
        // GitHub pretty-prints with a space after the colon: `"path": "..."`.
        let tree = "{\n  \"tree\": [\n    {\n      \"path\": \"g/sysctl_x/rule.yml\",\n      \"mode\": \"100644\"\n    }\n  ],\n  \"truncated\": false\n}";
        assert_eq!(
            find_path(tree, "/sysctl_x/rule.yml").as_deref(),
            Some("g/sysctl_x/rule.yml")
        );
    }

    #[test]
    fn reject_if_truncated_rejects_truncated_true_tolerating_spacing() {
        // Compact JSON: no space after the colon.
        let compact = r#"{"tree":[{"path":"a/rule.yml"}],"truncated":true}"#;
        let err = reject_if_truncated(compact).expect_err("truncated:true must be rejected");
        assert!(
            err.to_lowercase().contains("truncated"),
            "error must mention truncated: {err:?}"
        );

        // GitHub pretty-prints with a space after the colon: `"truncated": true`.
        let pretty = "{\n  \"tree\": [\n    {\n      \"path\": \"a/rule.yml\"\n    }\n  ],\n  \"truncated\": true\n}";
        let err = reject_if_truncated(pretty).expect_err("pretty truncated: true must be rejected");
        assert!(
            err.to_lowercase().contains("truncated"),
            "error must mention truncated: {err:?}"
        );
    }

    #[test]
    fn reject_if_truncated_accepts_false_in_both_spacings() {
        let compact = r#"{"tree":[{"path":"a/rule.yml"}],"truncated":false}"#;
        assert!(
            reject_if_truncated(compact).is_ok(),
            "truncated:false must be accepted"
        );

        let pretty = "{\n  \"tree\": [\n    {\n      \"path\": \"a/rule.yml\"\n    }\n  ],\n  \"truncated\": false\n}";
        assert!(
            reject_if_truncated(pretty).is_ok(),
            "truncated: false must be accepted"
        );
    }

    #[test]
    fn reject_if_truncated_accepts_key_absent() {
        let tree = r#"{"tree":[{"path":"a/rule.yml"}]}"#;
        assert!(
            reject_if_truncated(tree).is_ok(),
            "an absent truncated key must not be treated as truncated"
        );
    }

    #[test]
    fn reject_if_truncated_is_order_independent_earlier_path_named_truncated() {
        // A benign earlier occurrence of the token `truncated` (a tree entry whose
        // PATH is literally `truncated`) precedes the real top-level field. The scan
        // must not stop at the first occurrence and miss the genuine `truncated:true`
        // that follows - that would be a fail-OPEN in a guard whose whole job is to
        // fail closed.
        let tree = r#"{"tree":[{"path":"truncated","mode":"040000"}],"truncated":true}"#;
        let err = reject_if_truncated(tree)
            .expect_err("a real truncated:true after a path named `truncated` must be rejected");
        assert!(
            err.to_lowercase().contains("truncated"),
            "error must mention truncated: {err:?}"
        );
    }

    #[test]
    fn reject_if_truncated_no_false_positive_when_path_named_truncated_but_field_false() {
        // The mirror case: a path literally named `truncated` must NOT trip the guard
        // when the real field is `false`. The path VALUE is followed by `,`/`}`/`]`,
        // never `:`, so it is distinguishable from the KEY `"truncated":`.
        let tree = r#"{"tree":[{"path":"truncated","mode":"040000"}],"truncated":false}"#;
        assert!(
            reject_if_truncated(tree).is_ok(),
            "a path named `truncated` with the real field false must not false-positive"
        );
    }

    #[test]
    fn extract_tag_name() {
        let json = r#"{"url":"...","tag_name":"v0.1.76","name":"0.1.76"}"#;
        assert_eq!(
            extract_json_string(json, "tag_name").as_deref(),
            Some("v0.1.76")
        );
    }

    #[test]
    fn parse_curl_status_splits_body_and_code() {
        use super::parse_curl_status;
        // curl appends the 3-digit code with no newline.
        assert_eq!(
            parse_curl_status("controls: []\n200").unwrap(),
            (200, "controls: []\n".to_string())
        );
        // a 404 body (raw.githubusercontent's "404: Not Found") + code.
        let (code, _body) = parse_curl_status("404: Not Found404").unwrap();
        assert_eq!(code, 404);
        // transport failure: curl writes 000.
        assert_eq!(parse_curl_status("000").unwrap(), (0, String::new()));
        // too short / non-numeric tail -> error, not a panic.
        assert!(parse_curl_status("ab").is_err());
        assert!(parse_curl_status("bodyXYZ").is_err());
    }
}
