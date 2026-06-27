//! Semantic lint passes over a parsed `sysctl.d`/`sysctl.conf` file.
//!
//! v1 ships two passes (issue #150):
//! * `sysctld-F01` - parse failure (a malformed line; emitted by the parser as it
//!   classifies each line, see [`crate::parser`]).
//! * `sysctld-W01` - last-wins conflict (the same key assigned different effective
//!   values, the earlier one overridden/dead).
//!
//! The `sysctld-` code catalog is frozen in Phase 0 ([`crate::catalog`]). Both
//! passes are driven from [`crate::parser`]: the assignment model and the
//! precedence-ordered last-wins reasoning live next to the tokenizer (one parse,
//! one pass over the assignments), so this module re-exports the public entry
//! points rather than re-implementing the dispatch. Single-file linting goes
//! through [`crate::parser::lint_str`]; a directory of drop-ins through
//! [`crate::parser::lint_dir`].

pub use crate::parser::{lint_dir, lint_str};
