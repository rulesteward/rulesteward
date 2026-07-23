//! Shared config-file reading with special-file protection (#560).
//!
//! Every lint entry point calls `std::fs::read_to_string` directly on a
//! user-supplied path today. On a FIFO with no writer this blocks forever
//! (reproduced 2026-07-23 against main `142282b`: `fapolicyd lint --file
//! <fifo>` is still running past a 5s `timeout`); on a device node like
//! `/dev/zero` it reads unboundedly. [`read_to_string`] is the one shared,
//! regular-file-only replacement every backend routes through instead.
//!
//! # Contract
//!
//! - Opens `path`, then inspects the metadata of the **already-opened**
//!   file -- never a separate `stat`/`lstat` call on `path` -- so there is no
//!   TOCTOU window between the type check and the read (the brief's
//!   requirement: "the check is on the resolved file type (metadata of the
//!   opened file, not lstat), so no TOCTOU re-open pattern").
//! - A symlink TO a regular file is followed and read normally: opening a
//!   path already follows symlinks, and the type check reads the RESOLVED
//!   target's metadata, never `symlink_metadata`.
//! - Anything whose resolved type is not a regular file (FIFO, directory,
//!   socket, block/character device) is rejected with a clear `io::Error`
//!   (`io::ErrorKind::InvalidInput`) whose message names the file type found,
//!   e.g. `"refusing to read non-regular file (found FIFO)"`. The path
//!   itself is deliberately NOT embedded in the message: every caller
//!   already prepends its own `"<verb> <path>: <error>"` context (mirrors
//!   `std::io::Error`'s own convention of leaving path attribution to the
//!   caller, e.g. a plain "No such file or directory (os error 2)" never
//!   names the path either).
//! - On Unix, opening a FIFO for reading in the default BLOCKING mode
//!   already blocks indefinitely until a writer opens the other end -- this
//!   is the actual #560 hang, and it happens at `open()`, before any read.
//!   A metadata check alone, performed AFTER a blocking open, is therefore
//!   not sufficient. The implementation must open non-blocking (e.g.
//!   `std::os::unix::fs::OpenOptionsExt::custom_flags` with the platform
//!   `O_NONBLOCK` value -- a plain `i32`, no new crate dependency needed) so
//!   the open call itself cannot hang, check the resolved type, reject a
//!   non-regular file immediately, and only then perform a normal buffered
//!   read of an accepted regular file.
//!
//! Consumed via the full path (`rulesteward_core::fsread::read_to_string`);
//! `lib.rs` re-exports are consolidated at integration, not per-lane.

use std::io;
use std::path::Path;

/// Drop-in replacement for [`std::fs::read_to_string`] that rejects any
/// non-regular file (FIFO, directory, socket, block/character device)
/// instead of hanging or reading unbounded data. See the module docs above
/// for the full contract (TOCTOU-safe check, symlink-to-regular-file
/// support, non-blocking open on Unix, and the exact error shape).
///
/// # Errors
///
/// Returns the underlying `io::Error` if `path` cannot be opened (e.g. it
/// does not exist, or is not readable), or an `io::ErrorKind::InvalidInput`
/// error naming the file type if the resolved target is not a regular file.
pub fn read_to_string(path: &Path) -> io::Result<String> {
    todo!(
        "fsread::read_to_string({}): not yet implemented -- test-author \
         stub for #560, see the module docs for the required contract",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::read_to_string;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    /// A minimal RAII temp-directory guard. `rulesteward-core`'s
    /// `dev-dependencies` do not carry `tempfile` today (only `proptest` and
    /// `serde_json`), and lane-2's claimed-paths discipline (session 9i)
    /// covers `fsread.rs` itself but not this crate's `Cargo.toml`, so these
    /// tests build their own tiny std-only equivalent rather than adding a
    /// new dependency. Creates a uniquely-named directory under
    /// `std::env::temp_dir()` and removes it (recursively) on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "rulesteward-fsread-test-{tag}-{}-{n}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create temp test dir");
            Self(dir)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The happy path: a plain regular file reads back byte-for-byte, proving
    /// the special-file guard does not disturb ordinary reads.
    #[test]
    fn regular_file_reads_ok() {
        let dir = TempDir::new("regular");
        let f = dir.path().join("plain.txt");
        std::fs::write(&f, "hello rulesteward\n").expect("write");
        let got = read_to_string(&f).expect("a regular file must read OK");
        assert_eq!(got, "hello rulesteward\n");
    }

    /// A symlink POINTING AT a regular file must still work end-to-end (brief:
    /// "Symlinks to regular files must still work; the check is on the
    /// resolved file type ... not lstat"). A wrong impl that rejects every
    /// symlink outright (an `lstat`-based guard, or one that never follows
    /// the link at all) fails this.
    #[test]
    fn symlink_to_regular_file_reads_ok() {
        let dir = TempDir::new("symlink");
        let target = dir.path().join("real.txt");
        std::fs::write(&target, "via symlink\n").expect("write target");
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let got = read_to_string(&link).expect("a symlink to a regular file must read OK");
        assert_eq!(got, "via symlink\n");
    }

    /// A directory is rejected with a clear, TYPE-AWARE error -- NOT merely
    /// the raw OS "Is a directory" wording a naive `fs::read_to_string(path)`
    /// passthrough already surfaces via the read-time EISDIR (that wording
    /// contains neither phrase asserted below), so a trivial passthrough
    /// "implementation" that relies solely on the OS's own read error fails
    /// this assertion even though it happens to also return `Err` here.
    #[test]
    fn directory_is_rejected() {
        let dir = TempDir::new("directory");
        let err = read_to_string(dir.path()).expect_err("a directory must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("non-regular file"),
            "error must explicitly name the non-regular-file condition, got: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("directory"),
            "error must name the actual file type found (directory), got: {msg}"
        );
    }

    /// A character device (`/dev/null`) must be rejected, not silently
    /// "succeed" by falling through to a plain read. This kills a wrong
    /// "per-type-enumeration" implementation that only special-cases the two
    /// types most obviously exercised by #560's shell reproduction
    /// (directory, FIFO) and lets anything else -- including device nodes --
    /// fall through to an ordinary `std::fs::read_to_string`. Such an impl
    /// would happily return `Ok("")` here (`/dev/null` reads as an instant,
    /// silent EOF) and, worse, would still read `/dev/zero` UNBOUNDEDLY --
    /// the exact OOM half of #560's bug report ("on a device node it reads
    /// unboundedly"). Requires `/dev/null`, universal on the Linux
    /// distribution target.
    #[test]
    fn character_device_dev_null_is_rejected() {
        let path = std::path::Path::new("/dev/null");
        let err = read_to_string(path).expect_err("/dev/null must be rejected, not silently read");
        let msg = err.to_string();
        assert!(
            msg.contains("non-regular file") || msg.to_lowercase().contains("character device"),
            "error must name the non-regular-file / character-device condition, got: {msg}"
        );
    }

    /// #560's OOM half of the bug, driven directly: `/dev/zero` is a
    /// character device that reads UNBOUNDED zero bytes forever unless the
    /// special-file guard rejects it before ever attempting a normal read.
    /// Driven off a background thread with a bounded `recv_timeout`,
    /// mirroring `fifo_is_rejected_fast_no_hang` below, so a runaway-reading
    /// (wrong) implementation fails this ONE test instead of exhausting
    /// memory / wedging the whole suite.
    #[test]
    fn character_device_dev_zero_is_rejected_fast_no_unbounded_read() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = read_to_string(std::path::Path::new("/dev/zero"));
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(result) => {
                let err = result.expect_err("/dev/zero must be rejected, never read");
                let msg = err.to_string();
                assert!(
                    msg.contains("non-regular file")
                        || msg.to_lowercase().contains("character device"),
                    "error must name the non-regular-file / character-device condition, got: {msg}"
                );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!(
                    "read_to_string on /dev/zero did not return within 5s -- \
                     this IS the #560 OOM/hang bug (an unbounded read of a \
                     character device that returns infinite zero bytes); \
                     the special-file guard must reject the device before \
                     ever attempting a read"
                );
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!(
                    "worker thread ended without a result (the todo!() stub \
                     panics today -- expected RED until #560 is implemented)"
                );
            }
        }
    }

    /// A Unix domain socket must be rejected exactly like any other
    /// non-regular file. This kills a wrong implementation that guards only
    /// against directories, FIFOs, and device nodes but forgets sockets
    /// entirely (a real-world special file type any of the lint backends
    /// could be pointed at by mistake, e.g. a stray systemd-notify socket).
    #[test]
    fn unix_domain_socket_is_rejected() {
        let dir = TempDir::new("socket");
        let sock_path = dir.path().join("test.sock");
        let _listener =
            std::os::unix::net::UnixListener::bind(&sock_path).expect("bind unix socket");
        let err = read_to_string(&sock_path).expect_err("a unix domain socket must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("non-regular file"),
            "error must explicitly name the non-regular-file condition, got: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("socket"),
            "error must name the actual file type found (socket), got: {msg}"
        );
    }

    /// #560's actual bug: a FIFO with no writer must fail FAST, never block.
    /// Driven off a background thread with a bounded `recv_timeout` so a
    /// hanging (wrong) implementation fails this ONE test instead of wedging
    /// the whole suite. Today (test-author phase, no implementation yet) the
    /// `todo!()` stub panics immediately -- the sender is dropped without
    /// sending, so `recv_timeout` sees `Disconnected` right away, a clean and
    /// fast RED rather than a hang.
    #[test]
    fn fifo_is_rejected_fast_no_hang() {
        let dir = TempDir::new("fifo");
        let fifo = dir.path().join("special.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo(1) available on the Linux distribution target");
        assert!(status.success(), "mkfifo must succeed");

        let (tx, rx) = mpsc::channel();
        let fifo_for_thread = fifo.clone();
        std::thread::spawn(move || {
            let result = read_to_string(&fifo_for_thread);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(result) => {
                let err = result.expect_err("a FIFO with no writer must be rejected, not read");
                assert!(
                    err.to_string().to_lowercase().contains("fifo"),
                    "error must name the FIFO file type, got: {err}"
                );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!(
                    "read_to_string blocked for 5s+ on a FIFO with no writer -- \
                     this IS the #560 hang bug; the special-file guard must \
                     reject the FIFO before ever attempting a blocking \
                     open/read"
                );
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!(
                    "worker thread ended without a result (the todo!() stub \
                     panics today -- expected RED until #560 is implemented)"
                );
            }
        }
    }
}
