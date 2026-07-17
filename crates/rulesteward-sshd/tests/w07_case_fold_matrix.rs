//! 54-cell case-fold property matrix for `sshd-W07` (#495).
//!
//! W07's cross-Match shadow analysis kept failing impl-blind adversarial
//! review along a NEW dimension each round (fold direction -> call-site
//! coverage -> axis coverage -> fold fidelity -> glob/multitype uniformity),
//! so this file closes the space exhaustively instead of patching one
//! survivor at a time: every cell of axis x pattern shape x block shape x
//! charset is generated from one template per family and checked against a
//! single two-fact oracle.
//!
//! # Grounding (settled by the frozen #495 suite in `src/lints/structural/w07.rs`)
//!
//! The daemon-truth citations live with the frozen fixtures (openssh-portable
//! tag `V_10_2_P1` + live `sshd -T -C` oracles, quoted there in full):
//!
//! - HOST folds BOTH sides, ASCII-only: `match.c:196-203` lowercases the
//!   incoming host and passes `dolower=1`; `match.c:141-146` then lowercases
//!   the config pattern byte-wise via `isupper`/`tolower`, so bytes >= 0x80
//!   (e.g. `\u{C9}`) never fold.
//! - USER does not fold: `servconf.c:1108-1115` -> `match.c:177-186`
//!   (`dolower=0`, `/* Case sensitive match */`).
//! - GROUP does not fold: `servconf.c:1127` -> `groupaccess.c:117-118` ->
//!   the same `dolower=0` comparison.
//!
//! # The oracle (kept deliberately tiny to avoid a tautology)
//!
//! No glob engine, no fold call, no mirror of the matcher. Two facts only:
//! [`axis_folds`] (one line, transcribed from the citations above) and
//! [`CasePair::erased_by_ascii_fold`] (a hard-coded per-token-pair constant,
//! NOT computed). Every template is constructed so that its two criterion
//! spellings denote the same population if and only if the daemon's fold
//! erases their case difference; each family's expected outcome is then a
//! pure function of that single bit ([`same_population`]).
//!
//! # Construction invariant (why one bit decides every cell)
//!
//! - Family A (overlap): the earlier pattern admits the later block's sole
//!   witness literal iff the case difference is erased. Shapes: literal vs
//!   literal; UPPER-glob vs lower-literal (pattern-side fold forced);
//!   lower-glob vs UPPER-literal (incoming-VALUE fold forced, because the
//!   only witness literal is uppercase).
//! - Family B (self-negation): `!lower,UPPER` positively admits nothing iff
//!   `UPPER` folds onto the vetoed `lower`; otherwise `UPPER` survives as a
//!   live positive that the earlier `*` block also admits.
//! - Family C (repeated instances): `{Axis} UPPER {Axis} lower` AND-s the
//!   two instances (`sshd_config(5)`), so a common witness exists iff the
//!   spellings fold together; otherwise the block matches nobody.
//!
//! Case-matched control probes (no fold involved) confirmed 2026-07-16 on
//! the pre-fix impl that every route these templates exercise (single-type
//! glob, multitype glob, repeated-instance, multitype literal) reports the
//! shadow, so a silent cell can only mean a fold gap, never unrelated
//! conservatism in those routes.
//!
//! Frozen like the rest of the #495 suite: strengthen-only, never weaken.

use std::path::Path;

use rulesteward_core::{Diagnostic, Severity};
use rulesteward_sshd::SshdLintContext;
use rulesteward_sshd::lints;
use rulesteward_sshd::parser::parse_config_str_located;

/// Match criterion axes the matrix sweeps. `Address`/`LocalAddress` are not
/// name axes (W07 routes them through CIDR logic, and `host||localaddress`
/// was proven unreachable at the #495 barrier), so the sweep is these three.
#[derive(Clone, Copy)]
enum Axis {
    User,
    Group,
    Host,
}

impl Axis {
    fn keyword(self) -> &'static str {
        match self {
            Axis::User => "User",
            Axis::Group => "Group",
            Axis::Host => "Host",
        }
    }
}

/// Transcribed daemon fact, not policy: only the host axis folds
/// (`match.c:196-203` passes `dolower=1`; user and group both reach the
/// `dolower=0` comparison at `match.c:177-186`).
fn axis_folds(axis: Axis) -> bool {
    matches!(axis, Axis::Host)
}

/// A cased token pair plus the one HARD-CODED fact the oracle consumes:
/// whether sshd's ASCII-only fold erases the case difference between the
/// `upper` and `lower` spellings (identically for the glob spellings).
struct CasePair {
    upper: &'static str,
    lower: &'static str,
    upper_glob: &'static str,
    lower_glob: &'static str,
    /// `true` for pure-ASCII case pairs; `false` when the cased letters are
    /// outside ASCII (`\u{C9}`/`\u{E9}`: byte-wise `tolower` in the C locale
    /// leaves bytes >= 0x80 untouched, live-oracle-confirmed in the frozen
    /// suite). Hard-coded on purpose: computing it here would re-implement
    /// the fold under test.
    erased_by_ascii_fold: bool,
}

const ASCII: CasePair = CasePair {
    upper: "WEB.CORP",
    lower: "web.corp",
    upper_glob: "WEB*",
    lower_glob: "web*",
    erased_by_ascii_fold: true,
};

/// Mixes cased ASCII (`CAF`/`caf`) with a non-ASCII cased letter, so a full
/// Unicode fold (`str::to_lowercase`, which maps `\u{C9}` -> `\u{E9}`) is
/// distinguished from the daemon's ASCII-only fold in every cell, not just
/// in a dedicated fidelity fixture.
const UNICODE: CasePair = CasePair {
    upper: "CAF\u{C9}.CORP",
    lower: "caf\u{E9}.corp",
    upper_glob: "CAF\u{C9}*",
    lower_glob: "caf\u{E9}*",
    erased_by_ascii_fold: false,
};

/// The single bit every expectation derives from: do the two spellings
/// denote one population under the daemon's fold?
fn same_population(axis: Axis, pair: &CasePair) -> bool {
    axis_folds(axis) && pair.erased_by_ascii_fold
}

/// Parse `src`, run the full lint dispatcher with the default (target=None)
/// context, and keep only `sshd-W07`: the public-API mirror of the inline
/// `w07_diags` helper the frozen suite uses.
fn w07_diags(src: &str) -> Vec<Diagnostic> {
    let file = Path::new("/etc/ssh/sshd_config");
    let blocks = parse_config_str_located(src, file).expect("matrix fixture parses");
    lints::lint(&blocks, file, &SshdLintContext::default())
        .into_iter()
        .filter(|d| d.code == "sshd-W07")
        .collect()
}

fn assert_cell(cell: &str, src: &str, expect_fire: bool) {
    let diags = w07_diags(src);
    if expect_fire {
        assert_eq!(
            diags.len(),
            1,
            "{cell}: one population + first-value-wins conflict -> exactly one W07\nfixture:\n{src}got: {diags:?}"
        );
        assert_eq!(diags[0].code, "sshd-W07", "{cell}");
        assert_eq!(diags[0].severity, Severity::Warning, "{cell}");
        assert_eq!(
            diags[0].line, 4,
            "{cell}: the LATER (shadowed) instance is flagged, not the winning first one\nfixture:\n{src}"
        );
    } else {
        assert!(
            diags.is_empty(),
            "{cell}: distinct populations (or an unsatisfiable block) -> W07 stays silent\nfixture:\n{src}got: {diags:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Family A: case-variant overlap. Does W07 treat two criteria differing only
// by case as one population? Fires iff `same_population`.
// ---------------------------------------------------------------------------

/// Which spelling carries the case difference in the A-template.
#[derive(Clone, Copy)]
enum Shape {
    /// upper literal earlier, lower literal later (both sides literal).
    LitLit,
    /// UPPER glob earlier, lower literal later (pattern-side fold forced).
    UpGlob,
    /// lower glob earlier, UPPER literal later (value-side fold forced:
    /// the only witness literal is uppercase).
    LoGlob,
}

fn family_a(cell: &str, axis: Axis, shape: Shape, multitype: bool, pair: &CasePair) {
    let (earlier, later) = match shape {
        Shape::LitLit => (pair.upper, pair.lower),
        Shape::UpGlob => (pair.upper_glob, pair.lower),
        Shape::LoGlob => (pair.lower_glob, pair.upper),
    };
    let mt = if multitype { " Address 10.0.0.0/8" } else { "" };
    let kw = axis.keyword();
    let src = format!(
        "Match {kw} {earlier}{mt}\n    X11Forwarding yes\nMatch {kw} {later}{mt}\n    X11Forwarding no\n"
    );
    assert_cell(cell, &src, same_population(axis, pair));
}

macro_rules! a_cell {
    ($name:ident, $axis:expr, $shape:expr, $multi:expr, $pair:expr) => {
        #[test]
        fn $name() {
            family_a(stringify!($name), $axis, $shape, $multi, &$pair);
        }
    };
}

a_cell!(
    a_user_litlit_single_ascii,
    Axis::User,
    Shape::LitLit,
    false,
    ASCII
);
a_cell!(
    a_user_litlit_single_unicode,
    Axis::User,
    Shape::LitLit,
    false,
    UNICODE
);
a_cell!(
    a_user_litlit_multi_ascii,
    Axis::User,
    Shape::LitLit,
    true,
    ASCII
);
a_cell!(
    a_user_litlit_multi_unicode,
    Axis::User,
    Shape::LitLit,
    true,
    UNICODE
);
a_cell!(
    a_user_upglob_single_ascii,
    Axis::User,
    Shape::UpGlob,
    false,
    ASCII
);
a_cell!(
    a_user_upglob_single_unicode,
    Axis::User,
    Shape::UpGlob,
    false,
    UNICODE
);
a_cell!(
    a_user_upglob_multi_ascii,
    Axis::User,
    Shape::UpGlob,
    true,
    ASCII
);
a_cell!(
    a_user_upglob_multi_unicode,
    Axis::User,
    Shape::UpGlob,
    true,
    UNICODE
);
a_cell!(
    a_user_loglob_single_ascii,
    Axis::User,
    Shape::LoGlob,
    false,
    ASCII
);
a_cell!(
    a_user_loglob_single_unicode,
    Axis::User,
    Shape::LoGlob,
    false,
    UNICODE
);
a_cell!(
    a_user_loglob_multi_ascii,
    Axis::User,
    Shape::LoGlob,
    true,
    ASCII
);
a_cell!(
    a_user_loglob_multi_unicode,
    Axis::User,
    Shape::LoGlob,
    true,
    UNICODE
);

a_cell!(
    a_group_litlit_single_ascii,
    Axis::Group,
    Shape::LitLit,
    false,
    ASCII
);
a_cell!(
    a_group_litlit_single_unicode,
    Axis::Group,
    Shape::LitLit,
    false,
    UNICODE
);
a_cell!(
    a_group_litlit_multi_ascii,
    Axis::Group,
    Shape::LitLit,
    true,
    ASCII
);
a_cell!(
    a_group_litlit_multi_unicode,
    Axis::Group,
    Shape::LitLit,
    true,
    UNICODE
);
a_cell!(
    a_group_upglob_single_ascii,
    Axis::Group,
    Shape::UpGlob,
    false,
    ASCII
);
a_cell!(
    a_group_upglob_single_unicode,
    Axis::Group,
    Shape::UpGlob,
    false,
    UNICODE
);
a_cell!(
    a_group_upglob_multi_ascii,
    Axis::Group,
    Shape::UpGlob,
    true,
    ASCII
);
a_cell!(
    a_group_upglob_multi_unicode,
    Axis::Group,
    Shape::UpGlob,
    true,
    UNICODE
);
a_cell!(
    a_group_loglob_single_ascii,
    Axis::Group,
    Shape::LoGlob,
    false,
    ASCII
);
a_cell!(
    a_group_loglob_single_unicode,
    Axis::Group,
    Shape::LoGlob,
    false,
    UNICODE
);
a_cell!(
    a_group_loglob_multi_ascii,
    Axis::Group,
    Shape::LoGlob,
    true,
    ASCII
);
a_cell!(
    a_group_loglob_multi_unicode,
    Axis::Group,
    Shape::LoGlob,
    true,
    UNICODE
);

a_cell!(
    a_host_litlit_single_ascii,
    Axis::Host,
    Shape::LitLit,
    false,
    ASCII
);
a_cell!(
    a_host_litlit_single_unicode,
    Axis::Host,
    Shape::LitLit,
    false,
    UNICODE
);
a_cell!(
    a_host_litlit_multi_ascii,
    Axis::Host,
    Shape::LitLit,
    true,
    ASCII
);
a_cell!(
    a_host_litlit_multi_unicode,
    Axis::Host,
    Shape::LitLit,
    true,
    UNICODE
);
a_cell!(
    a_host_upglob_single_ascii,
    Axis::Host,
    Shape::UpGlob,
    false,
    ASCII
);
a_cell!(
    a_host_upglob_single_unicode,
    Axis::Host,
    Shape::UpGlob,
    false,
    UNICODE
);
a_cell!(
    a_host_upglob_multi_ascii,
    Axis::Host,
    Shape::UpGlob,
    true,
    ASCII
);
a_cell!(
    a_host_upglob_multi_unicode,
    Axis::Host,
    Shape::UpGlob,
    true,
    UNICODE
);
a_cell!(
    a_host_loglob_single_ascii,
    Axis::Host,
    Shape::LoGlob,
    false,
    ASCII
);
a_cell!(
    a_host_loglob_single_unicode,
    Axis::Host,
    Shape::LoGlob,
    false,
    UNICODE
);
a_cell!(
    a_host_loglob_multi_ascii,
    Axis::Host,
    Shape::LoGlob,
    true,
    ASCII
);
a_cell!(
    a_host_loglob_multi_unicode,
    Axis::Host,
    Shape::LoGlob,
    true,
    UNICODE
);

// ---------------------------------------------------------------------------
// Family B: case-variant self-negation. A folded `!lower,UPPER` admits
// nobody and cannot be a shadow victim; unfolded, `UPPER` survives as a live
// positive that the earlier `*` block also admits. Silent iff
// `same_population`.
// ---------------------------------------------------------------------------

fn family_b(cell: &str, axis: Axis, multitype: bool, pair: &CasePair) {
    let mt = if multitype { " Address 10.0.0.0/8" } else { "" };
    let kw = axis.keyword();
    let src = format!(
        "Match {kw} *{mt}\n    X11Forwarding yes\nMatch {kw} !{lo},{up}{mt}\n    X11Forwarding no\n",
        lo = pair.lower,
        up = pair.upper,
    );
    assert_cell(cell, &src, !same_population(axis, pair));
}

macro_rules! b_cell {
    ($name:ident, $axis:expr, $multi:expr, $pair:expr) => {
        #[test]
        fn $name() {
            family_b(stringify!($name), $axis, $multi, &$pair);
        }
    };
}

b_cell!(b_user_single_ascii, Axis::User, false, ASCII);
b_cell!(b_user_single_unicode, Axis::User, false, UNICODE);
b_cell!(b_user_multi_ascii, Axis::User, true, ASCII);
b_cell!(b_user_multi_unicode, Axis::User, true, UNICODE);
b_cell!(b_group_single_ascii, Axis::Group, false, ASCII);
b_cell!(b_group_single_unicode, Axis::Group, false, UNICODE);
b_cell!(b_group_multi_ascii, Axis::Group, true, ASCII);
b_cell!(b_group_multi_unicode, Axis::Group, true, UNICODE);
b_cell!(b_host_single_ascii, Axis::Host, false, ASCII);
b_cell!(b_host_single_unicode, Axis::Host, false, UNICODE);
b_cell!(b_host_multi_ascii, Axis::Host, true, ASCII);
b_cell!(b_host_multi_unicode, Axis::Host, true, UNICODE);

// ---------------------------------------------------------------------------
// Family C: repeated-instance common witness. `{Axis} UPPER {Axis} lower`
// AND-s the two instances, so the block is satisfiable (and shadowed by the
// earlier `*`) iff the spellings fold together; otherwise it matches nobody.
// This is the only family that reaches the repeated-instance witness search
// with a counter-axis pair. Fires iff `same_population`.
// ---------------------------------------------------------------------------

fn family_c(cell: &str, axis: Axis, pair: &CasePair) {
    let kw = axis.keyword();
    let src = format!(
        "Match {kw} *\n    X11Forwarding yes\nMatch {kw} {up} {kw} {lo} Address 10.0.0.0/8\n    X11Forwarding no\n",
        up = pair.upper,
        lo = pair.lower,
    );
    assert_cell(cell, &src, same_population(axis, pair));
}

macro_rules! c_cell {
    ($name:ident, $axis:expr, $pair:expr) => {
        #[test]
        fn $name() {
            family_c(stringify!($name), $axis, &$pair);
        }
    };
}

c_cell!(c_user_ascii, Axis::User, ASCII);
c_cell!(c_user_unicode, Axis::User, UNICODE);
c_cell!(c_group_ascii, Axis::Group, ASCII);
c_cell!(c_group_unicode, Axis::Group, UNICODE);
c_cell!(c_host_ascii, Axis::Host, ASCII);
c_cell!(c_host_unicode, Axis::Host, UNICODE);
