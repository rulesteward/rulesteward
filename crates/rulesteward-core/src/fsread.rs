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
//!
//! # `read_stream_to_string` (#583/#561 lane 3)
//!
//! [`read_to_string`] rejects EVERY FIFO, including one with a live writer on
//! the other end -- correct for a config-file target (a real config file is
//! never a pipe), but wrong for the small set of call sites that read a
//! STREAM-shaped input the operator legitimately pipes in (`fapolicyd explain
//! --record`, `report --file`/`--diff-against`, `simulate --workload`,
//! `selinux triage --record`/`--audit-log`, `auditd cost --from-log`).
//! Converting those six sites to `read_to_string` silently regressed pipe /
//! process-substitution / `/dev/stdin` support that worked one commit earlier
//! (`74dea9e`), while `simulate --workload -` kept a `-`-means-stdin escape
//! hatch the other five flags never had -- so the tool accepted a pipe under
//! one spelling and rejected it under another. [`read_stream_to_string`] is
//! the sibling those six call sites route through instead; it is strictly
//! MORE permissive than `read_to_string` (accepts everything `read_to_string`
//! accepts, plus a FIFO with a live writer), never less.
//!
//! Directory / socket / char device / block device stay rejected exactly as
//! before (same error shape, same [`describe_file_type`] wording). A FIFO is
//! special-cased:
//!
//! 1. Opened non-blocking (the same [`O_NONBLOCK`] this module already uses),
//!    so `open()` can never hang.
//! 2. `O_RDONLY|O_NONBLOCK` open SUCCEEDS on every FIFO on Linux, writer or
//!    not -- measured: a writerless FIFO's non-blocking open succeeds and the
//!    first read returns `b""` immediately (EOF), so the open call alone
//!    cannot distinguish "has a writer" from "does not". Emptiness of the
//!    full read IS the discriminator: a writerless FIFO read to EOF yields
//!    empty content with no hang; a writer-ful one yields its content. A FIFO
//!    whose full read is EMPTY is therefore rejected with the SAME
//!    `"refusing to read non-regular file (found FIFO)"` error
//!    `read_to_string` already produces for a writerless FIFO -- this is what
//!    keeps every existing writerless-FIFO regression test (six of them,
//!    across `explain`/`report`/`simulate`/`selinux triage`/`auditd cost`/
//!    `path_error_fifo.rs`) green while still accepting a live pipe.
//! 3. Before that read, `O_NONBLOCK` is CLEARED on the already-open fd via
//!    `fcntl(F_GETFL)`/`fcntl(F_SETFL)`. Measured: reading a 2 MB stream
//!    WITHOUT clearing the flag returns exactly 65536 bytes (one pipe buffer)
//!    then fails with `EAGAIN` -- silent truncation, not merely slow. The
//!    flag must be cleared for the buffered read to block normally until the
//!    writer is done, exactly like a blocking `open()` would have.
//!
//! Clearing `O_NONBLOCK` is a real syscall (`fcntl`), not a hardcodable
//! platform constant like `O_NONBLOCK`'s own value below -- so, unlike the
//! rest of this module, `read_stream_to_string`'s FIFO path pulls in the
//! `libc` crate for the `fcntl`/`F_GETFL`/`F_SETFL` FFI declarations. `libc`
//! is already a normal (non-dev) dependency of the shipped binary via
//! `heed -> lmdb-master-sys` (see the workspace `Cargo.toml`), so this adds no
//! new code to the musl static binary.

use std::fs::{FileType, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// `O_NONBLOCK`, Linux's value (`asm-generic/fcntl.h`, shared by every
/// architecture the `x86_64-unknown-linux-musl` distribution target and the
/// project's other Linux targets build for). Passed via
/// [`OpenOptionsExt::custom_flags`] so the `open()` call on a FIFO with no
/// writer returns immediately instead of blocking -- see the module docs
/// above for why a metadata check performed only AFTER a blocking open is
/// not sufficient. Hardcoded rather than using `libc::O_NONBLOCK` (the two
/// are numerically identical on Linux): a crate dependency is now pulled in
/// for `read_stream_to_string`'s `fcntl` SYSCALL below, which -- unlike this
/// single well-known platform CONSTANT -- cannot be hardcoded.
const O_NONBLOCK: i32 = 0o4000;

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
    // `O_NONBLOCK` on open() so a FIFO with no writer (and a bound
    // AF_UNIX socket, which fails at open() with ENXIO on Linux before this
    // even matters) cannot hang the process. A symlink is followed as
    // normal (no `O_NOFOLLOW`), so a symlink-to-regular-file opens the
    // resolved target transparently.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)?;

    // Inspect the metadata of the ALREADY-OPENED file descriptor -- never a
    // separate `stat`/`lstat` on `path` -- so there is no TOCTOU window
    // between this check and the read below (the module contract).
    let file_type = file.metadata()?.file_type();
    if !file_type.is_file() {
        return Err(non_regular_file_error(file_type));
    }

    // `O_NONBLOCK` has no effect on regular files (open(2): "this flag has
    // no effect for regular files and block devices"), so an ordinary
    // buffered read proceeds normally once the type check above accepts
    // the target.
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Like [`read_to_string`], but ALSO accepts a FIFO that has a live writer on
/// the other end -- restoring the pipe / process-substitution / `/dev/stdin`
/// support a plain `read_to_string` conversion removes for stream-shaped
/// inputs. See the module docs above for the full contract and the measured
/// "WHY" behind the empty-means-reject rule and the `O_NONBLOCK` clear.
///
/// Directory / socket / char device / block device are rejected exactly like
/// `read_to_string` (same error shape). A regular file reads exactly like
/// `read_to_string`. A FIFO is opened non-blocking (so `open()` can never
/// hang), has `O_NONBLOCK` cleared, and is read to EOF: a writerless FIFO
/// yields empty content and is rejected with the SAME
/// `"refusing to read non-regular file (found FIFO)"` error `read_to_string`
/// produces for it; a writer-ful FIFO yields its content and is accepted.
///
/// # Errors
///
/// Returns the underlying `io::Error` if `path` cannot be opened, or an
/// `io::ErrorKind::InvalidInput` error naming the file type if the resolved
/// target is not a regular file and (for a FIFO specifically) yielded no
/// content.
pub fn read_stream_to_string(path: &Path) -> io::Result<String> {
    // Same non-blocking open as `read_to_string`, for the same reason: the
    // `open()` call itself must never be able to hang, regardless of what
    // `path` resolves to.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)?;

    // Metadata of the ALREADY-OPENED fd, never a separate stat/lstat -- same
    // TOCTOU discipline as `read_to_string` (the module contract).
    let file_type = file.metadata()?.file_type();

    if file_type.is_fifo() {
        // A non-blocking open() on a FIFO succeeds unconditionally, writer or
        // not (measured; see module docs), so the type check alone cannot
        // tell them apart. Clear `O_NONBLOCK` so the read below blocks
        // normally to EOF (without this, a >64KB writer-ful stream silently
        // truncates at one pipe buffer and errors with EAGAIN -- also
        // measured; see module docs), then read fully. A writerless FIFO
        // reads back empty immediately (no hang: EOF is reported the moment
        // there is no writer), so EMPTY content is the discriminator that
        // keeps the writerless-FIFO rejection contract identical to
        // `read_to_string`'s.
        clear_nonblock(&file)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        return if contents.is_empty() {
            Err(non_regular_file_error(file_type))
        } else {
            Ok(contents)
        };
    }

    if !file_type.is_file() {
        return Err(non_regular_file_error(file_type));
    }

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Clear `O_NONBLOCK` on `file`'s fd via `fcntl(F_GETFL)` + `fcntl(F_SETFL)`,
/// so a subsequent buffered read on a FIFO blocks normally until EOF instead
/// of stopping after one pipe buffer with `EAGAIN`. See the module docs'
/// "WHY" section for the measured evidence this is required, not optional.
fn clear_nonblock(file: &std::fs::File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid, open file descriptor owned by `file` for the
    // entire duration of this call (nothing else closes or reassigns it
    // concurrently). `fcntl(F_GETFL)`/`fcntl(F_SETFL)` are plain POSIX
    // flag-query/flag-set operations that read/write only the kernel's
    // per-open-file-description status flags for this one fd -- they touch
    // no process memory beyond the returned/passed `c_int` flags.
    #[allow(unsafe_code)]
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same fd-ownership invariant as the `F_GETFL` call above.
    #[allow(unsafe_code)]
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !O_NONBLOCK) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Build the shared `InvalidInput` rejection error both [`read_to_string`]
/// and [`read_stream_to_string`] return for a non-regular (or, for the
/// latter, writerless-FIFO) target. The path itself is deliberately NOT
/// embedded (see the module docs' error-shape note).
fn non_regular_file_error(file_type: FileType) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "refusing to read non-regular file (found {})",
            describe_file_type(file_type)
        ),
    )
}

/// Name the resolved file type for the rejection message. Order matters only
/// in that each check is mutually exclusive on a real `FileType`.
fn describe_file_type(file_type: FileType) -> &'static str {
    if file_type.is_dir() {
        "directory"
    } else if file_type.is_fifo() {
        "FIFO"
    } else if file_type.is_socket() {
        "socket"
    } else if file_type.is_char_device() {
        "character device"
    } else if file_type.is_block_device() {
        "block device"
    } else if file_type.is_symlink() {
        // Unreachable in practice: `metadata()` (unlike `symlink_metadata()`)
        // always follows symlinks to the resolved target's type.
        "symlink"
    } else {
        "unknown non-regular file"
    }
}

#[cfg(test)]
mod tests {
    use super::{read_stream_to_string, read_to_string};
    use std::io::Write as _;
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

    /// A Unix domain socket must be rejected: opening a bound socket path
    /// for reading returns `Err` promptly, never `Ok`, never a hang. Note:
    /// on Linux, `open()` on a bound `AF_UNIX` socket fails with `ENXIO`
    /// BEFORE any fd-metadata check ever runs -- empirically confirmed
    /// against the canonical contract-following implementation (round 6
    /// adversarial review) -- so, unlike the directory/FIFO/character-device
    /// cases above, no TOCTOU-compliant impl (metadata-of-the-opened-fd,
    /// never a separate `stat`/`lstat`) CAN produce an error whose message
    /// names "socket" or "non-regular file" here: the OS itself refuses the
    /// open before the guard's own type check gets a chance to run. This
    /// test therefore pins only the real, impl-independent property (fails
    /// fast, never succeeds, never hangs) and deliberately does NOT assert
    /// on error wording for this one case. The general "no separate
    /// stat/lstat, check the opened fd's metadata" TOCTOU contract stays as
    /// documented in the module docs above, unchanged, and continues to be
    /// enforced by the post-GREEN impl-aware adversarial review rather than
    /// by a unit-level assertion here (it is inherently racy to pin
    /// deterministically at this level).
    #[test]
    fn unix_domain_socket_is_rejected() {
        let dir = TempDir::new("socket");
        let sock_path = dir.path().join("test.sock");
        let _listener =
            std::os::unix::net::UnixListener::bind(&sock_path).expect("bind unix socket");

        let (tx, rx) = mpsc::channel();
        let sock_for_thread = sock_path.clone();
        std::thread::spawn(move || {
            let result = read_to_string(&sock_for_thread);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(result) => {
                result.expect_err("a unix domain socket must be rejected, not read");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!(
                    "read_to_string on a bound unix domain socket did not \
                     return within 5s -- opening it must fail fast, never hang"
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

    // -------------------------------------------------------------------
    // read_stream_to_string (#583/#561 lane 3 -- adversarial review miss 1)
    // -------------------------------------------------------------------

    /// The happy path is unchanged from `read_to_string`: a regular file
    /// reads back byte-for-byte.
    #[test]
    fn read_stream_to_string_regular_file_reads_ok() {
        let dir = TempDir::new("stream-regular");
        let f = dir.path().join("plain.txt");
        std::fs::write(&f, "hello stream\n").expect("write");
        let got = read_stream_to_string(&f).expect("a regular file must read OK");
        assert_eq!(got, "hello stream\n");
    }

    /// A directory is rejected with the same type-aware error `read_to_string`
    /// produces -- `read_stream_to_string` is MORE permissive only for FIFOs,
    /// never for any other non-regular type.
    #[test]
    fn read_stream_to_string_directory_is_rejected() {
        let dir = TempDir::new("stream-directory");
        let err = read_stream_to_string(dir.path()).expect_err("a directory must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("non-regular file") && msg.to_lowercase().contains("directory"),
            "error must name the non-regular-file/directory condition, got: {msg}"
        );
    }

    /// A FIFO with NO writer must still be rejected -- this is the frozen
    /// contract every call site's e2e test pins (six sites, plus
    /// `path_error_fifo.rs`): a writerless FIFO must never silently succeed
    /// with empty content, and must never hang. Driven off a background
    /// thread with a bounded `recv_timeout`, mirroring
    /// `fifo_is_rejected_fast_no_hang` above.
    #[test]
    fn read_stream_to_string_writerless_fifo_is_rejected() {
        let dir = TempDir::new("stream-fifo-writerless");
        let fifo = dir.path().join("special.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo(1) available on the Linux distribution target");
        assert!(status.success(), "mkfifo must succeed");

        let (tx, rx) = mpsc::channel();
        let fifo_for_thread = fifo.clone();
        std::thread::spawn(move || {
            let result = read_stream_to_string(&fifo_for_thread);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(result) => {
                let err = result.expect_err(
                    "a writerless FIFO must be rejected, not silently accepted as empty",
                );
                assert!(
                    err.to_string().to_lowercase().contains("fifo"),
                    "error must name the FIFO file type, got: {err}"
                );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!(
                    "read_stream_to_string blocked for 5s+ on a writerless FIFO -- \
                     a read-to-EOF with no writer must return promptly (EOF, empty \
                     content), never hang"
                );
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("worker thread ended without a result");
            }
        }
    }

    /// A FIFO WITH a live writer must be accepted, with content read to EOF --
    /// the whole point of this function (restoring pipe / process-substitution
    /// support `read_to_string` removed for stream-shaped inputs). The writer
    /// thread's blocking `open(write-only)` call unblocks the moment the
    /// reader thread's non-blocking `open(read-only)` succeeds (a non-blocking
    /// read-open on a FIFO always succeeds immediately, writer or not -- see
    /// the module docs), so no explicit handshake is needed between the two
    /// threads. Driven off a background thread with a bounded `recv_timeout`,
    /// mirroring the writerless case above.
    #[test]
    fn read_stream_to_string_writer_ful_fifo_reads_ok() {
        const CONTENT: &str = "hello via a live pipe writer\n";

        let dir = TempDir::new("stream-fifo-writer");
        let fifo = dir.path().join("special.fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo(1) available on the Linux distribution target");
        assert!(status.success(), "mkfifo must succeed");

        let fifo_for_writer = fifo.clone();
        std::thread::spawn(move || {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo_for_writer)
                .expect("open fifo for write");
            f.write_all(CONTENT.as_bytes()).expect("write to fifo");
            // `f` drops here, closing the write end -> the reader sees EOF.
        });

        let (tx, rx) = mpsc::channel();
        let fifo_for_reader = fifo.clone();
        std::thread::spawn(move || {
            let result = read_stream_to_string(&fifo_for_reader);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(result) => {
                let got =
                    result.expect("a FIFO with a live writer must be accepted and read to EOF");
                assert_eq!(got, CONTENT);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!(
                    "read_stream_to_string on a writer-ful FIFO did not return within \
                     5s -- clearing O_NONBLOCK must let the read block normally to EOF"
                );
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("worker thread ended without a result");
            }
        }
    }
}
