//! Body of `rulesteward completions <shell>`. Emits a shell-completion
//! script to stdout for the user to redirect into the shell's
//! completion directory. Writes through `EpipeSwallowingWriter` so that
//! piping to a reader that closes early (e.g. `| head -5`) exits 0 instead
//! of panicking on `BrokenPipe` under static musl builds.

use clap::CommandFactory;
use clap_complete::{
    Generator, generate,
    shells::{Bash, Elvish, Fish, PowerShell, Zsh},
};
use std::fmt::Write as _;
use std::io;

use crate::cli::{Cli, CompletionShell, CompletionsArgs};
use crate::exit_code::EXIT_CLEAN;

/// A `clap_complete` backend that emits a `tcsh(1)` `complete` script.
///
/// `clap_complete` 4.x ships bash / zsh / fish / elvish / powershell backends
/// but NO tcsh backend, so we implement the public `Generator` trait ourselves
/// (the same trait the built-in shells implement). `generate(&self, cmd, buf)`
/// receives the fully-built clap [`clap::Command`] tree and walks it to produce
/// the script; nothing is hardcoded - subcommand and flag names come from clap.
///
/// # tcsh `complete` model
///
/// tcsh keys completion on the program name, not on a per-subcommand function
/// (unlike bash/zsh). The builtin syntax (see tcsh(1), "complete") is:
///
/// ```text
/// complete <command> <word>/<pattern>/<list>[:select]/ ...
/// ```
///
/// where each space-separated rule carries a SELECTOR type character:
///   * `p/N/(list)/`      - the Nth word on the line must be from `list`
///   * `n/word/(list)/`   - the word AFTER a literal `word` completes from `list`
///   * `c/prefix/(list)/`  - complete the current word given `prefix`
///
/// Because tcsh has no notion of "the previous TWO words", a single flat
/// `complete rulesteward` directive cannot perfectly disambiguate deeply
/// nested paths the way bash can. We emit a genuinely useful approximation:
///   * a `p/1/(...)/` rule listing the top-level subcommands,
///   * one `n/<subcommand>/(...)/` rule per command that has children or flags,
///     so that typing `rulesteward fapolicyd <TAB>` offers `fapolicyd`'s
///     children, and `rulesteward fapolicyd lint <TAB>` offers `lint`'s flags.
///
/// The `n/word/(...)/` rules are emitted for every command in the tree
/// (depth-first), keyed on each command's own name, so nested subcommands and
/// their flags are reachable.
pub(crate) struct Tcsh;

impl Generator for Tcsh {
    fn file_name(&self, name: &str) -> String {
        format!("{name}.tcsh")
    }

    fn generate(&self, cmd: &clap::Command, buf: &mut dyn io::Write) {
        // clap fills bin_name in via `generate`; fall back to the command name.
        let bin = cmd
            .get_bin_name()
            .unwrap_or_else(|| cmd.get_name())
            .to_owned();

        // Collect all `complete` rule tokens, then emit a single
        // `complete <bin> <rule> <rule> ...` directive (tcsh accepts many
        // rules in one `complete` invocation, one per line via `\` is also
        // valid; we use newline-and-continuation for readability).
        let mut rules: Vec<String> = Vec::new();

        // Rule 1: position-1 word is one of the top-level subcommands.
        let top_names = subcommand_names(cmd);
        if !top_names.is_empty() {
            rules.push(format!("'p/1/({})/'", top_names.join(" ")));
        }

        // Depth-first walk: for every (sub)command, emit an `n/<name>/(...)/`
        // rule whose list is that command's children + its own flags. This is
        // what makes `rulesteward fapolicyd <TAB>` and
        // `rulesteward fapolicyd lint <TAB>` useful.
        collect_next_word_rules(cmd, &mut rules);

        // Emit the directive. Use line continuations so a long rule set stays
        // readable in the generated file. tcsh treats a trailing `\` as a
        // continuation inside the builtin.
        let mut out = String::new();
        let _ = writeln!(out, "complete {bin} \\");
        for (i, rule) in rules.iter().enumerate() {
            // Every rule but the last gets a trailing ` \` line-continuation.
            if i + 1 == rules.len() {
                let _ = writeln!(out, "    {rule}");
            } else {
                let _ = writeln!(out, "    {rule} \\");
            }
        }

        // Best-effort write through the caller-supplied writer (the
        // EpipeSwallowingWriter in `run`); ignore the result so a closed pipe
        // does not propagate (the writer already swallows BrokenPipe, but the
        // built-in backends `.expect(...)`, so we mirror "do not panic" here).
        let _ = buf.write_all(out.as_bytes());
    }
}

/// Visible subcommand names of `cmd` (skips hidden commands and the
/// auto-generated `help` command, which clap reports via `get_subcommands`).
fn subcommand_names(cmd: &clap::Command) -> Vec<String> {
    cmd.get_subcommands()
        .filter(|sc| !sc.is_hide_set() && sc.get_name() != "help")
        .map(|sc| sc.get_name().to_owned())
        .collect()
}

/// Visible long flags of `cmd`, formatted as `--name` tokens.
fn long_flags(cmd: &clap::Command) -> Vec<String> {
    cmd.get_arguments()
        .filter(|a| !a.is_hide_set())
        .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
        .collect()
}

/// Depth-first: for `cmd` and every descendant, push an
/// `n/<name>/(children + flags)/` rule when there is anything to complete
/// after that word. Recurses into subcommands so nested levels are covered.
fn collect_next_word_rules(cmd: &clap::Command, rules: &mut Vec<String>) {
    for sub in cmd
        .get_subcommands()
        .filter(|sc| !sc.is_hide_set() && sc.get_name() != "help")
    {
        let mut list = subcommand_names(sub);
        list.extend(long_flags(sub));
        if !list.is_empty() {
            rules.push(format!("'n/{}/({})/'", sub.get_name(), list.join(" ")));
        }
        // Recurse so e.g. `fapolicyd`'s child `lint` also gets its own
        // `n/lint/(--format --file ...)/` rule.
        collect_next_word_rules(sub, rules);
    }
}

/// A writer that swallows `io::ErrorKind::BrokenPipe` errors and pretends
/// success, while propagating all other error kinds unchanged.
///
/// `clap_complete`'s shell backends call `.expect("failed to write completion
/// file")` on every write, so a `BrokenPipe` from a pipe consumer that closed
/// early (e.g. `| head -5`) panics with exit 101 under musl. Wrapping stdout
/// in this adapter makes those writes silently succeed instead.
///
/// NOTE on the partial-write contract: `write()` returns `Ok(buf.len())`
/// on `BrokenPipe` rather than `Ok(0)`. This is intentional for the
/// `clap_complete` use case: returning `Ok(0)` would make `write_all`
/// surface `Err(BrokenPipe)`, which the backends then `.expect(...)` on,
/// re-creating the panic this adapter exists to suppress. Reporting the
/// full `buf.len()` lets the generator complete its remaining `write!`
/// calls and exit normally. This struct is purpose-built for the
/// `clap_complete` consumer; do not generalize without revisiting this
/// trade-off.
pub(crate) struct EpipeSwallowingWriter<W: io::Write> {
    pub(crate) inner: W,
    pub(crate) pipe_closed: bool,
}

impl<W: io::Write> io::Write for EpipeSwallowingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.pipe_closed {
            return Ok(buf.len());
        }
        match self.inner.write(buf) {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                self.pipe_closed = true;
                Ok(buf.len())
            }
            other => other,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.pipe_closed {
            return Ok(());
        }
        match self.inner.flush() {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                self.pipe_closed = true;
                Ok(())
            }
            other => other,
        }
    }
}

pub fn run(args: &CompletionsArgs) -> anyhow::Result<i32> {
    let mut cmd = Cli::command();
    let bin_name = "rulesteward";
    let mut stdout = EpipeSwallowingWriter {
        inner: io::stdout().lock(),
        pipe_closed: false,
    };
    match args.shell {
        CompletionShell::Bash => generate(Bash, &mut cmd, bin_name, &mut stdout),
        CompletionShell::Zsh => generate(Zsh, &mut cmd, bin_name, &mut stdout),
        CompletionShell::Fish => generate(Fish, &mut cmd, bin_name, &mut stdout),
        CompletionShell::Elvish => generate(Elvish, &mut cmd, bin_name, &mut stdout),
        CompletionShell::PowerShell => generate(PowerShell, &mut cmd, bin_name, &mut stdout),
        CompletionShell::Tcsh => generate(Tcsh, &mut cmd, bin_name, &mut stdout),
    }
    Ok(EXIT_CLEAN)
}

#[cfg(test)]
mod tests {
    use super::EpipeSwallowingWriter;
    use std::io::{self, Write};

    // Helper: a writer that always returns the given error on write().
    struct AlwaysErrorWriter {
        kind: io::ErrorKind,
    }

    impl io::Write for AlwaysErrorWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(self.kind, "injected error"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(self.kind, "injected error"))
        }
    }

    // Helper: a writer that always returns BrokenPipe on flush() but writes ok.
    struct FlushErrorWriter;

    impl io::Write for FlushErrorWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected flush error",
            ))
        }
    }

    #[test]
    fn epipe_swallowing_writer_swallows_brokenpipe_on_write() {
        let inner = AlwaysErrorWriter {
            kind: io::ErrorKind::BrokenPipe,
        };
        let mut w = EpipeSwallowingWriter {
            inner,
            pipe_closed: false,
        };

        // First write: BrokenPipe from inner -> swallowed, returns Ok(len).
        let result = w.write(b"hello");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);

        // Second write: pipe_closed is now true -> short-circuit, returns Ok(len).
        let result2 = w.write(b"more");
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), 4);
    }

    #[test]
    fn epipe_swallowing_writer_propagates_non_brokenpipe_errors() {
        let inner = AlwaysErrorWriter {
            kind: io::ErrorKind::PermissionDenied,
        };
        let mut w = EpipeSwallowingWriter {
            inner,
            pipe_closed: false,
        };

        let result = w.write(b"x");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn epipe_swallowing_writer_swallows_brokenpipe_on_flush() {
        let inner = FlushErrorWriter;
        let mut w = EpipeSwallowingWriter {
            inner,
            pipe_closed: false,
        };

        let result = w.flush();
        assert!(result.is_ok());
    }

    #[test]
    fn epipe_swallowing_writer_passes_through_normal_writes() {
        let inner: Vec<u8> = Vec::new();
        let mut w = EpipeSwallowingWriter {
            inner,
            pipe_closed: false,
        };

        w.write_all(b"foo").unwrap();
        w.write_all(b"bar").unwrap();
        w.write_all(b"baz").unwrap();

        assert_eq!(&w.inner, b"foobarbaz");
    }
}
