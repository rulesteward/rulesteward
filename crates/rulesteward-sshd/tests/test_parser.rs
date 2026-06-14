//! Parser unit tests for `rulesteward-sshd` (Phase 0).
//!
//! Grounded in `sshd_config(5)`: whole-line `#` comments, case-insensitive
//! keywords, double-quoted args (no escapes), positional `Match`-block scoping,
//! and accumulate-all-errors parsing. A wrong parser cannot pass these.

use std::path::Path;

use rulesteward_sshd::ast::{Block, Directive};
use rulesteward_sshd::parser::parse_config_str_located;

const CFG: &str = "/etc/ssh/sshd_config";

fn parse(input: &str) -> Vec<Block> {
    parse_config_str_located(input, Path::new(CFG)).expect("input should parse")
}

/// `blocks[0]` is always the global block. Return its directives.
fn global(blocks: &[Block]) -> &[Directive] {
    match blocks.first() {
        Some(Block::Global(d)) => d,
        other => panic!("blocks[0] must be Block::Global, got {other:?}"),
    }
}

// --- empties, comments, blanks ---------------------------------------------

#[test]
fn empty_input_is_one_empty_global_block() {
    let blocks = parse("");
    assert_eq!(blocks.len(), 1, "exactly the (empty) global block");
    assert!(global(&blocks).is_empty());
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let blocks = parse("# a comment\n\n   \n# another\nPermitRootLogin no\n");
    let g = global(&blocks);
    assert_eq!(g.len(), 1, "only the one real directive survives");
    assert_eq!(g[0].keyword, "PermitRootLogin");
}

#[test]
fn indented_comment_is_still_a_comment() {
    // A line whose first NON-BLANK char is `#` is a comment, even if indented.
    let blocks = parse("    # indented comment\nMaxAuthTries 4\n");
    let g = global(&blocks);
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].keyword, "MaxAuthTries");
}

#[test]
fn hash_is_only_a_comment_at_line_start_not_inline() {
    // sshd_config has NO inline comments: a `#` mid-line is a literal argument
    // character, not a comment introducer.
    let blocks = parse("Banner /etc/issue#net\n");
    let g = global(&blocks);
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].args, vec!["/etc/issue#net".to_string()]);
}

// --- directives: keyword + args, case, quotes ------------------------------

#[test]
fn directive_keeps_keyword_and_all_args_in_order() {
    let blocks = parse("Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n");
    let g = global(&blocks);
    assert_eq!(g[0].keyword, "Ciphers");
    assert_eq!(
        g[0].args,
        vec!["aes256-gcm@openssh.com,chacha20-poly1305@openssh.com".to_string()]
    );
}

#[test]
fn multiple_args_split_on_whitespace() {
    let blocks = parse("AllowUsers alice bob carol\n");
    let g = global(&blocks);
    assert_eq!(
        g[0].args,
        vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
    );
}

#[test]
fn keyword_is_preserved_verbatim_but_matches_case_insensitively() {
    let blocks = parse("permitrootlogin no\n");
    let g = global(&blocks);
    assert_eq!(g[0].keyword, "permitrootlogin", "raw spelling preserved");
    assert_eq!(
        g[0].keyword_lower(),
        "permitrootlogin",
        "PermitRootLogin / PERMITROOTLOGIN / permitrootlogin all share one canonical form"
    );
}

#[test]
fn directive_with_no_args_is_permitted_by_the_parser() {
    // Per-directive arity is a lint concern (needs the directive registry), not
    // the parser's: the parser accepts a bare keyword.
    let blocks = parse("X11Forwarding\n");
    let g = global(&blocks);
    assert_eq!(g[0].keyword, "X11Forwarding");
    assert!(g[0].args.is_empty());
}

#[test]
fn quoted_argument_preserves_internal_spaces_and_strips_quotes() {
    let blocks = parse("Banner \"/etc/issue net\"\n");
    let g = global(&blocks);
    assert_eq!(g[0].args, vec!["/etc/issue net".to_string()]);
}

#[test]
fn unterminated_quote_is_a_parse_error() {
    let err = parse_config_str_located("Banner \"/etc/issue\n", Path::new(CFG))
        .expect_err("an unterminated quote must fail to parse");
    assert_eq!(err.len(), 1);
    assert_eq!(err[0].line, 1);
    assert!(
        err[0].message.to_lowercase().contains("quote"),
        "message should name the quoting problem, got {:?}",
        err[0].message
    );
    assert_eq!(err[0].file, Path::new(CFG));
}

// --- `=` keyword/value delimiter (OpenSSH strdelim split_equals) ------------
// Verified against OpenSSH_10.2p1 `sshd -T`: `=` separates a name from its value
// (`MaxAuthTries=4` -> `maxauthtries 4`), but a `=` INSIDE an argument value is
// literal (`SetEnv FOO=bar` -> `setenv FOO=bar`).

#[test]
fn equals_separates_keyword_from_value_glued() {
    let blocks = parse("MaxAuthTries=4\n");
    let g = global(&blocks);
    assert_eq!(g[0].keyword, "MaxAuthTries");
    assert_eq!(g[0].args, vec!["4".to_string()]);
}

#[test]
fn equals_separates_keyword_from_value_spaced() {
    let blocks = parse("MaxAuthTries = 4\n");
    let g = global(&blocks);
    assert_eq!(g[0].keyword, "MaxAuthTries");
    assert_eq!(
        g[0].args,
        vec!["4".to_string()],
        "a spaced `=` is a delimiter, not a literal argument"
    );
}

#[test]
fn equals_inside_an_argument_value_stays_literal() {
    // SetEnv's value is KEY=VALUE; the `=` there is part of the value, not a
    // delimiter (OpenSSH reads such values whitespace-only). Splitting it would
    // corrupt every SetEnv/AcceptEnv-style directive.
    let blocks = parse("SetEnv FOO=bar\n");
    let g = global(&blocks);
    assert_eq!(g[0].keyword, "SetEnv");
    assert_eq!(g[0].args, vec!["FOO=bar".to_string()]);
}

#[test]
fn equals_keyword_separator_then_whitespace_args() {
    let blocks = parse("AllowUsers=alice bob\n");
    let g = global(&blocks);
    assert_eq!(g[0].keyword, "AllowUsers");
    assert_eq!(g[0].args, vec!["alice".to_string(), "bob".to_string()]);
}

#[test]
fn match_criterion_accepts_equals_form() {
    // `Match User=alice` is a valid config line (sshd -t exit 0): the `=`
    // separates the criterion keyword from its value. It must NOT be rejected.
    let blocks = parse("Match User=alice\n    X11Forwarding yes\n");
    let Block::Match(m) = &blocks[1] else {
        panic!("Match expected")
    };
    assert_eq!(m.criteria.len(), 1);
    assert_eq!(m.criteria[0].keyword, "User");
    assert_eq!(m.criteria[0].values, vec!["alice".to_string()]);
}

#[test]
fn match_criterion_equals_form_splits_comma_values() {
    let blocks = parse("Match User=alice,bob\n    X11Forwarding no\n");
    let Block::Match(m) = &blocks[1] else {
        panic!("Match expected")
    };
    assert_eq!(m.criteria[0].keyword, "User");
    assert_eq!(
        m.criteria[0].values,
        vec!["alice".to_string(), "bob".to_string()]
    );
}

// --- provenance: line + span -----------------------------------------------

#[test]
fn directive_carries_one_based_line_and_raw_line_byte_span() {
    let input = "PermitRootLogin no\nMaxAuthTries 4\n";
    let blocks = parse(input);
    let g = global(&blocks);
    assert_eq!(g[0].line, 1);
    assert_eq!(g[0].span, 0..18, "span of \"PermitRootLogin no\"");
    assert_eq!(&input[g[0].span.clone()], "PermitRootLogin no");
    assert_eq!(g[1].line, 2);
    assert_eq!(&input[g[1].span.clone()], "MaxAuthTries 4");
}

// --- Match-block scoping ----------------------------------------------------

#[test]
fn directives_before_first_match_are_global() {
    let blocks = parse("PermitRootLogin no\nMatch User alice\n    X11Forwarding yes\n");
    let g = global(&blocks);
    assert_eq!(g.len(), 1, "only PermitRootLogin is global");
    assert_eq!(g[0].keyword, "PermitRootLogin");
}

#[test]
fn directives_after_match_belong_to_the_match_block() {
    let blocks = parse("Match User alice\n    X11Forwarding yes\n    AllowTcpForwarding no\n");
    assert_eq!(blocks.len(), 2, "empty global + one match block");
    assert!(global(&blocks).is_empty());
    let Block::Match(m) = &blocks[1] else {
        panic!("blocks[1] must be a Match block");
    };
    assert_eq!(m.body.len(), 2);
    assert_eq!(m.body[0].keyword, "X11Forwarding");
    assert_eq!(m.body[1].keyword, "AllowTcpForwarding");
    assert_eq!(m.line, 1, "Match header is on line 1");
}

#[test]
fn two_match_blocks_partition_their_directives() {
    let blocks = parse(
        "Match User alice\n    X11Forwarding yes\nMatch Group sftp\n    ForceCommand internal-sftp\n",
    );
    assert_eq!(blocks.len(), 3, "empty global + two match blocks");
    let Block::Match(m1) = &blocks[1] else {
        panic!("blocks[1] is Match")
    };
    let Block::Match(m2) = &blocks[2] else {
        panic!("blocks[2] is Match")
    };
    assert_eq!(m1.body.len(), 1);
    assert_eq!(m1.body[0].keyword, "X11Forwarding");
    assert_eq!(m2.body.len(), 1);
    assert_eq!(m2.body[0].keyword, "ForceCommand");
}

// --- Match criteria ---------------------------------------------------------

#[test]
fn match_criterion_splits_comma_values() {
    let blocks = parse("Match User alice,bob,carol\n    X11Forwarding no\n");
    let Block::Match(m) = &blocks[1] else {
        panic!("Match expected")
    };
    assert_eq!(m.criteria.len(), 1);
    assert_eq!(m.criteria[0].keyword, "User");
    assert_eq!(
        m.criteria[0].values,
        vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
    );
}

#[test]
fn match_supports_multiple_criteria_pairs() {
    let blocks = parse("Match User alice Group wheel\n    X11Forwarding no\n");
    let Block::Match(m) = &blocks[1] else {
        panic!("Match expected")
    };
    assert_eq!(m.criteria.len(), 2);
    assert_eq!(m.criteria[0].keyword, "User");
    assert_eq!(m.criteria[0].values, vec!["alice".to_string()]);
    assert_eq!(m.criteria[1].keyword, "Group");
    assert_eq!(m.criteria[1].values, vec!["wheel".to_string()]);
}

#[test]
fn match_all_is_a_valueless_criterion() {
    let blocks = parse("Match All\n    Banner none\n");
    let Block::Match(m) = &blocks[1] else {
        panic!("Match expected")
    };
    assert_eq!(m.criteria.len(), 1);
    assert_eq!(m.criteria[0].keyword, "All");
    assert!(
        m.criteria[0].values.is_empty(),
        "All takes no value, got {:?}",
        m.criteria[0].values
    );
}

#[test]
fn match_with_no_criteria_is_a_parse_error() {
    let err = parse_config_str_located("Match\n    X11Forwarding no\n", Path::new(CFG))
        .expect_err("Match with no criteria must fail");
    assert_eq!(err[0].line, 1);
    assert!(
        err[0].message.to_lowercase().contains("match"),
        "message should mention Match, got {:?}",
        err[0].message
    );
}

#[test]
fn match_criterion_without_a_value_is_a_parse_error() {
    // `User` needs a value; `Match User` (no value) is malformed.
    let err = parse_config_str_located("Match User\n", Path::new(CFG))
        .expect_err("a value-taking criterion with no value must fail");
    assert_eq!(err[0].line, 1);
}

// --- Include captured as an ordinary directive ------------------------------

#[test]
fn include_is_captured_as_a_directive_resolution_deferred() {
    let blocks = parse("Include /etc/ssh/sshd_config.d/*.conf\n");
    let g = global(&blocks);
    assert_eq!(g[0].keyword, "Include");
    assert_eq!(g[0].args, vec!["/etc/ssh/sshd_config.d/*.conf".to_string()]);
}

// --- multi-error accumulation -----------------------------------------------

#[test]
fn all_parse_errors_are_accumulated_not_just_the_first() {
    let input = "Banner \"unterminated\nMatch\nPermitRootLogin no\n";
    let errs = parse_config_str_located(input, Path::new(CFG))
        .expect_err("two malformed lines must both report");
    assert_eq!(errs.len(), 2, "one error per bad line, got {errs:?}");
    assert_eq!(errs[0].line, 1, "unterminated quote on line 1");
    assert_eq!(errs[1].line, 2, "empty Match on line 2");
}
