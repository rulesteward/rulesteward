//! Body of `rulesteward completions <shell>`. Emits a shell-completion
//! script to stdout for the user to redirect into the shell's
//! completion directory. Writes through `EpipeSwallowingWriter` so that
//! piping to a reader that closes early (e.g. `| head -5`) exits 0 instead
//! of panicking on `BrokenPipe` under static musl builds.

use clap::CommandFactory;
use clap_complete::{
    generate,
    shells::{Bash, Elvish, Fish, PowerShell, Zsh},
};
use std::io;

use crate::cli::{Cli, CompletionShell, CompletionsArgs};
use crate::exit_code::EXIT_CLEAN;

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
