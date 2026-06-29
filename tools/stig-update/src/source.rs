//! The live ComplianceAsCode fetch (a `curl` shell-out) plus rule.yml / `_value.var`
//! path location from the repo git-tree. Isolated here behind a thin seam so the
//! derivation core ([`crate::derive`]) is tested offline with fixtures; this module
//! is exercised only by the live `check` / `derive` runs.

use std::process::Command;

const REPO: &str = "ComplianceAsCode/content";

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
/// on ComplianceAsCode master but not yet in a tagged release - so `check --latest`
/// treats `None` as "not yet released; skip" rather than a hard error.
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
fn fetch_status(url: &str) -> Result<(u16, String), String> {
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
pub fn tree(reff: &str) -> Result<String, String> {
    curl(&format!(
        "https://api.github.com/repos/{REPO}/git/trees/{reff}?recursive=1"
    ))
}

/// The latest ComplianceAsCode release tag (for `check --latest`).
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
    use super::{extract_json_string, find_path};

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
