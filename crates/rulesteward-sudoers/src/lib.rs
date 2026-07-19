//! `sudoers(5)` backend: parses a sudoers policy file (`/etc/sudoers`, the
//! `/etc/sudoers.d/` drop-ins) and runs security-baseline lint passes over it.
//!
//! # Scope (Phase 0, issue #329)
//! This is the FROZEN foundation the whole sudoers milestone builds on. What it
//! does TODAY:
//! * [`parser::parse`] - a hand-rolled TWO-STAGE parser: stage 1 joins physical
//!   lines on a trailing backslash into logical lines; stage 2 classifies each
//!   logical line into a [`ast::LineKind`] (blank / comment / `Defaults` / alias /
//!   include / user-spec / malformed), handling the sudoers `#` comment
//!   disambiguation exactly (a `#` is a comment UNLESS it begins a
//!   `#include`/`#includedir` directive or is a `#<digits>` UID subject). The
//!   parser is TOTAL: it always returns a [`ast::SudoersFile`], never `Err`;
//!   unparseable logical lines become [`ast::LineKind::Malformed`] so the good
//!   lines still lint.
//! * [`resolve::resolve_target`] - the include/dir resolution SEAM the CLI calls:
//!   a single file parses to one [`ast::SudoersFile`]; a directory parses each
//!   `*`-eligible drop-in (sorted, skipping `~`-suffixed and `.`-containing names)
//!   into a [`ast::SudoersFile`]. Directive-following of `@include`/`@includedir`
//!   and nested/relative resolution are deferred (#334).
//! * [`lints::lint`] - the dispatcher. Only `sudo-F01` (parse failure) EMITS in
//!   Phase 0: a Fatal for every [`ast::LineKind::Malformed`] logical line across
//!   all files. The `sudo-E01`/`W01`/`W02`/`W03`/`W04` passes are `Vec::new()`
//!   STUBS filled by the later parallel pipelines (#330-#333).
//!
//! The catalog ([`lints::catalog`]) lists the FULL `sudo-` taxonomy in sorted
//! order; freezing it up front means the lint passes emit only already-catalogued
//! codes and never edit that shared file. The AST ([`ast`]) is a RICH, frozen
//! surface so the leaf lints only EMIT diagnostics and never re-parse.

pub mod ast;
pub mod lints;
pub mod parser;
pub mod resolve;

pub use ast::SudoersFile;
pub use lints::{SudoersLintContext, TargetVersion, lint};
pub use parser::parse;
pub use resolve::resolve_target;
