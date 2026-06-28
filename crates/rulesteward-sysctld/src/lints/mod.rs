//! Semantic lint passes over a parsed `sysctl.d`/`sysctl.conf` file.
//!
//! Passes:
//! * `sysctld-F01` - parse failure (a malformed line; emitted by the parser as it
//!   classifies each line, see [`crate::parser`]).
//! * `sysctld-W01` - last-wins conflict (the same key assigned different effective
//!   values, the earlier one overridden/dead).
//! * `sysctld-W02` - the version-aware STIG kernel-hardening baseline check
//!   ([`baseline`], issue #335): a required key unset or set to an insecure value.
//!   Runs only when a `--target` baseline is selected.
//!
//! The `sysctld-` code catalog is frozen in Phase 0 ([`crate::catalog`]). The
//! F01/W01 passes are driven from [`crate::parser`]: the assignment model and the
//! precedence-ordered last-wins reasoning live next to the tokenizer (one parse,
//! one pass over the assignments), so this module re-exports the public entry
//! points rather than re-implementing the dispatch. W02 lives in [`baseline`] and
//! reuses the parser's effective-value map. Single-file linting goes through
//! [`crate::parser::lint_str`] / [`crate::parser::lint_str_with_target`]; a
//! directory of drop-ins through [`crate::parser::lint_dir`] /
//! [`crate::parser::lint_dir_with_target`].

pub mod baseline;

pub use crate::parser::{lint_dir, lint_dir_with_target, lint_str, lint_str_with_target};
pub use baseline::TargetVersion;
