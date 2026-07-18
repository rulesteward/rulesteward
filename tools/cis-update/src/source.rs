//! Live-fetch shim: only the CIS controls-file URL/fetch is new here - the
//! git-tree, rule fetcher, latest-release, and status-aware curl all come from
//! `stig_update::source` (the shared seam).

/// Raw URL of a product's CIS controls file at `reff`.
#[must_use]
pub fn controls_url(reff: &str, product: &str) -> String {
    format!(
        "https://raw.githubusercontent.com/ComplianceAsCode/content/{reff}/products/{product}/controls/cis_{product}.yml"
    )
}

/// Fetch a product's CIS controls file at `reff`, returning `None` when it does
/// not exist there (HTTP 404): a product can be absent at a given ref (e.g. not
/// yet in a tagged release), which `check --latest` treats as "skip", while a
/// pinned ref treats it as a misconfiguration.
pub fn controls_optional(reff: &str, product: &str) -> Result<Option<String>, String> {
    let url = controls_url(reff, product);
    let (code, body) = stig_update::source::fetch_status(&url)?;
    match code {
        200 => Ok(Some(body)),
        404 => Ok(None),
        other => Err(format!("curl {url}: HTTP {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::controls_url;

    #[test]
    fn controls_url_targets_the_product_scoped_cis_file() {
        assert_eq!(
            controls_url("519b5fe8ce338cfa25d53065bcb3759aafe8d36d", "rhel9"),
            "https://raw.githubusercontent.com/ComplianceAsCode/content/\
             519b5fe8ce338cfa25d53065bcb3759aafe8d36d/products/rhel9/controls/cis_rhel9.yml"
        );
    }
}
