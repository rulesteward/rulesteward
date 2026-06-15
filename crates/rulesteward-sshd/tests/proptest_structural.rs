//! Layer-2 property tests for the structural lints: whatever the input, the lint
//! dispatcher must never panic and must be deterministic. Generated configs mix
//! duplicate keywords, allow-repeat keywords, `Match` blocks, and `Include`
//! patterns so the e02/e03/e04 paths are all exercised on random shapes.

use std::path::Path;

use proptest::prelude::*;
use rulesteward_sshd::SshdLintContext;
use rulesteward_sshd::lints::{self, structural};
use rulesteward_sshd::parser::parse_config_str_located;

/// Build random `sshd_config`-shaped sources from a small token vocabulary.
fn config_strategy() -> impl Strategy<Value = String> {
    let line = prop::sample::select(vec![
        "PermitRootLogin no",
        "PermitRootLogin yes",
        "Port 22",
        "Port 2222",
        "X11Forwarding yes",
        "SetEnv FOO=1",
        "AcceptEnv LANG",
        "Ciphers aes256-ctr",
        "Banner /etc/issue.net",
        "Include /etc/ssh/sshd_config.d/*.conf",
        "Include relative.conf",
        "Match User bob",
        "Match All",
    ]);
    prop::collection::vec(line, 0..16)
        .prop_map(|lines| lines.into_iter().collect::<Vec<_>>().join("\n"))
}

proptest! {
    #[test]
    fn lint_never_panics_and_is_deterministic(src in config_strategy()) {
        let file = Path::new("/etc/ssh/sshd_config");
        if let Ok(blocks) = parse_config_str_located(&src, file) {
            let ctx = SshdLintContext::default();
            let first = lints::lint(&blocks, file, &ctx);
            let second = lints::lint(&blocks, file, &ctx);
            // Full equality (not just count): a determinism bug that reordered or
            // changed diagnostics while preserving the count would still be caught.
            prop_assert_eq!(first, second, "lint is deterministic");
        }
    }

    #[test]
    fn e04_only_flags_lines_inside_match_blocks(src in config_strategy()) {
        let file = Path::new("/etc/ssh/sshd_config");
        if let Ok(blocks) = parse_config_str_located(&src, file) {
            use rulesteward_sshd::ast::Block;
            let match_lines: std::collections::HashSet<usize> = blocks
                .iter()
                .filter_map(|b| match b {
                    Block::Match(m) => Some(m.body.iter().map(|d| d.line)),
                    Block::Global(_) => None,
                })
                .flatten()
                .collect();
            for diag in structural::e04(&blocks, file, &SshdLintContext::default()) {
                prop_assert!(
                    match_lines.contains(&diag.line),
                    "E04 may only flag directives inside a Match body"
                );
            }
        }
    }
}
