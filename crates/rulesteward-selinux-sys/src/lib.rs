//! libsepol FFI shim for `RuleSteward` (#107).
//!
//! A minimal, in-process binding over the `SELinux` userspace library `libsepol`
//! (statically linked; #106) that replays an AVC `(scontext, tcontext, tclass,
//! perms)` access against a binary policy and returns libsepol's TE / CONS / RBAC
//! / BOUNDS reason bitmask - exactly what `audit2why` does
//! (`libselinux/src/audit2why.c`), but self-contained: no Python, no libselinux,
//! no shell-out. The product calls this in-process; `checkmodule` / `secilc` are
//! test-only (they build the known-answer fixtures).
//!
//! # The libsepol global-state model (why [`Policy`] owns handles + a lock)
//!
//! libsepol's service functions (`sepol_context_to_sid`,
//! `sepol_string_to_security_class`, `sepol_compute_av_reason_buffer`) operate on
//! a **process-global** policydb + sidtab, not on a handle you pass in
//! (`services.h`: "Set the policydb and sidtab structures to be used by the
//! service functions"). `sepol_load_policy` installs that global but CANNOT be
//! called twice in one process (the second call returns `EINVAL`). To categorize
//! denials against more than one policy in a single process (e.g. a test binary
//! that loads two fixtures, or a long-lived analysis run), we therefore:
//!
//! 1. read each policy into its OWN `policydb_t` via the handle API
//!    (`sepol_policydb_read`; no global touch) and build its OWN `sidtab_t`
//!    (`policydb_load_isids`), and
//! 2. re-POINT the global at those handles per replay
//!    (`sepol_set_policydb` + `sepol_set_sidtab`) - swapping, never re-loading -
//!    under a process-wide [`Mutex`] so concurrent replays (cargo runs tests in
//!    parallel threads) never observe a half-swapped global.
//!
//! This is the design the F4b spike + a throwaway probe proved end to end:
//! interleaving replays against two different policies in one process yields the
//! correct per-policy reason bits.
//!
//! # `unsafe`
//!
//! Every `extern "C"` call site is `unsafe`; the workspace lints `unsafe_code =
//! "deny"`, so each block carries a scoped `#[allow(unsafe_code)]` with a
//! `// SAFETY:` note (the same convention as the heed boundary in
//! `rulesteward-fapolicyd/src/trustdb.rs`). The unsafety is contained entirely in
//! this crate; the wrapping `rulesteward-selinux::categorize` layer is safe.

use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::path::Path;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// libsepol scalar types (flask_types.h)
// ---------------------------------------------------------------------------

/// `sepol_security_id_t` (`flask_types.h`): an interned SID.
type SecurityId = u32;
/// `sepol_security_class_t` (`flask_types.h`): an object-class index.
type SecurityClass = u16;
/// `sepol_access_vector_t` (`flask_types.h`): a permission bitmask.
type AccessVector = u32;

/// Reason bit: a missing TE allow (`SEPOL_COMPUTEAV_TE`, `services.h:49`).
pub const REASON_TE: u32 = 0x1;
/// Reason bit: a constraint (MLS / user / role `constrain`) blocked the access
/// (`SEPOL_COMPUTEAV_CONS`, `services.h:50`).
pub const REASON_CONS: u32 = 0x2;
/// Reason bit: an RBAC (`role_allow`) gap (`SEPOL_COMPUTEAV_RBAC`,
/// `services.h:51`). For a `process` role change the role-change `constrain`
/// fires first, so this is rarely the operative bit in practice (f4b 6.2).
pub const REASON_RBAC: u32 = 0x4;
/// Reason bit: a typebounds violation stripped the access
/// (`SEPOL_COMPUTEAV_BOUNDS`, `services.h:52`).
pub const REASON_BOUNDS: u32 = 0x8;

// ---------------------------------------------------------------------------
// Opaque libsepol handles + the one struct we must own by value
// ---------------------------------------------------------------------------

/// Opaque `sepol_policydb_t` (`policydb.h`). Its first field is `struct policydb
/// p`, so a `*mut SepolPolicydb` is also a valid raw `policydb_t *` for the
/// functions that take the raw type (`policydb_load_isids`, `sepol_set_policydb`).
#[repr(C)]
struct SepolPolicydb {
    _opaque: [u8; 0],
}

/// Opaque `sepol_policy_file_t` (`policydb.h`): the read source wrapper.
#[repr(C)]
struct SepolPolicyFile {
    _opaque: [u8; 0],
}

/// `sidtab_t` (`sidtab.h`): the SID table. We own one per [`Policy`] and pass it
/// by pointer to `policydb_load_isids` (to fill) and `sepol_set_sidtab` (to
/// install). The layout is the four public fields; we only ever zero-init it and
/// hand libsepol the pointer, so the exact field semantics do not matter to us -
/// only that the size + alignment match so libsepol writes within our allocation.
#[repr(C)]
struct Sidtab {
    htable: *mut c_void,
    nel: c_uint,
    next_sid: c_uint,
    shutdown: u8,
}

impl Default for Sidtab {
    fn default() -> Self {
        Sidtab {
            htable: std::ptr::null_mut(),
            nel: 0,
            next_sid: 0,
            shutdown: 0,
        }
    }
}

/// `struct sepol_av_decision` (`flask_types.h`): the compute out-param. We only
/// read nothing from it (the reason bitmask out-param is what we use), but it
/// must be a correctly-sized writable buffer libsepol fills.
#[repr(C)]
#[derive(Default)]
struct AvDecision {
    allowed: AccessVector,
    decided: AccessVector,
    auditallow: AccessVector,
    auditdeny: AccessVector,
    seqno: c_uint,
    flags: c_uint,
}

// ---------------------------------------------------------------------------
// extern "C" declarations (signatures cited to the bundled libsepol 3.10 headers)
// ---------------------------------------------------------------------------

// SAFETY: each signature is transcribed verbatim from the bundled libsepol 3.10
// header cited in its doc comment (services.h / policydb.h / debug.h) and from
// libc; the linked archive is that same libsepol 3.10 build (build.rs). The block
// only DECLARES the symbols - every CALL is in its own scoped `unsafe {}` below
// with its own `// SAFETY` note. `unsafe_code = "deny"` (workspace) flags the
// `unsafe extern` block itself, so this scoped allow mirrors the call-site allows.
#[allow(unsafe_code)]
unsafe extern "C" {
    /// `debug.h:11` - toggle libsepol's stderr diagnostic callback. We turn it
    /// OFF: a BADSCON (an undefined context) is an EXPECTED outcome we map to
    /// `ContextInvalid`, not an error to print.
    fn sepol_debug(on: c_int);

    /// `policydb.h:60` - allocate an empty `sepol_policydb_t`.
    fn sepol_policydb_create(p: *mut *mut SepolPolicydb) -> c_int;
    /// `policydb.h:61` - free a `sepol_policydb_t` (and its inner `policydb`).
    fn sepol_policydb_free(p: *mut SepolPolicydb);
    /// `policydb.h:22` - allocate a `sepol_policy_file_t`.
    fn sepol_policy_file_create(pf: *mut *mut SepolPolicyFile) -> c_int;
    /// `policydb.h:47` - point a policy-file wrapper at an open `FILE *`.
    fn sepol_policy_file_set_fp(pf: *mut SepolPolicyFile, fp: *mut c_void);
    /// `policydb.h:23` - free a `sepol_policy_file_t`.
    fn sepol_policy_file_free(pf: *mut SepolPolicyFile);
    /// `policydb.h:113` - read a binary policy from the policy file into the
    /// owned policydb. Does NOT touch the global.
    fn sepol_policydb_read(p: *mut SepolPolicydb, pf: *mut SepolPolicyFile) -> c_int;

    /// `policydb.h:667` - build the initial SID table `s` from policydb `p`.
    /// Takes the RAW `policydb_t *`; we pass our `SepolPolicydb` (first-field
    /// cast, see [`SepolPolicydb`]).
    fn policydb_load_isids(p: *mut SepolPolicydb, s: *mut Sidtab) -> c_int;

    /// `sidtab.h` - free a sidtab's internal hash table + entries (the allocation
    /// `policydb_load_isids` makes). Operates on a caller-owned `sidtab_t`: it
    /// frees the INTERNAL state, NOT the struct pointer itself (we own that via
    /// `Box`), so there is no double-free with the `Box` drop.
    fn sepol_sidtab_destroy(s: *mut Sidtab);

    /// `services.h:30` - install `p` as the global policydb the service functions
    /// use. Takes the raw `policydb_t *` (first-field cast).
    fn sepol_set_policydb(p: *mut SepolPolicydb) -> c_int;
    /// `services.h:31` - install `s` as the global sidtab.
    fn sepol_set_sidtab(s: *mut Sidtab) -> c_int;

    /// `services.h:158` - resolve a context string to a SID against the global
    /// policydb/sidtab. Returns < 0 (BADSCON) for a context the policy does not
    /// define.
    fn sepol_context_to_sid(
        scontext: *const c_char,
        scontext_len: usize,
        out_sid: *mut SecurityId,
    ) -> c_int;
    /// `services.h:95` - map a class name to its index against the global policy.
    fn sepol_string_to_security_class(
        class_name: *const c_char,
        tclass: *mut SecurityClass,
    ) -> c_int;
    /// `services.h:102` - map a permission name (valid for `tclass`) to its AV bit.
    fn sepol_string_to_av_perm(
        tclass: SecurityClass,
        perm_name: *const c_char,
        av: *mut AccessVector,
    ) -> c_int;
    /// `services.h:69` - the categorizer. Fills `reason` with the
    /// TE/CONS/RBAC/BOUNDS bit union; allocates `reason_buf` (a human constraint
    /// string) which the caller must `free`.
    fn sepol_compute_av_reason_buffer(
        ssid: SecurityId,
        tsid: SecurityId,
        tclass: SecurityClass,
        requested: AccessVector,
        avd: *mut AvDecision,
        reason: *mut c_uint,
        reason_buf: *mut *mut c_char,
        flags: c_uint,
    ) -> c_int;

    // libc, for the policy-file FILE* and the reason-buffer free.
    fn fopen(path: *const c_char, mode: *const c_char) -> *mut c_void;
    fn fclose(fp: *mut c_void) -> c_int;
    fn free(p: *mut c_void);
}

/// Process-wide lock serialising every global-policydb swap + replay.
///
/// libsepol's service functions share one global policydb/sidtab (see the module
/// docs). A replay re-points that global, so two replays must never overlap. This
/// lock makes the `set_policydb` -> `set_sidtab` -> resolve -> compute sequence
/// atomic across threads (cargo's parallel test threads, or any concurrent
/// caller). It is the soundness guarantee for the `unsafe` global manipulation.
static GLOBAL_REPLAY_LOCK: Mutex<()> = Mutex::new(());

/// Turn libsepol's stderr diagnostic callback off, exactly once.
fn silence_libsepol_debug() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: `sepol_debug` only sets an internal verbosity flag; no policy
        // state, no aliasing, no threading hazard (it is an idempotent flag set).
        #[allow(unsafe_code)]
        unsafe {
            sepol_debug(0);
        }
    });
}

/// An owned, loaded binary `SELinux` policy: its own libsepol policydb handle plus
/// its own SID table. Loading touches no global state; [`Policy::replay`]
/// installs these handles as the global under [`GLOBAL_REPLAY_LOCK`] for the
/// duration of one replay.
///
/// `Drop` frees the policydb handle AND the sidtab's internal hash table (via
/// `sepol_sidtab_destroy`): that htable is a separate libsepol allocation made by
/// `policydb_load_isids`, NOT released by freeing the policydb (#113). The sidtab
/// struct itself is `Box`ed (stable address across moves) and freed by the `Box`.
pub struct Policy {
    pdb: *mut SepolPolicydb,
    // Boxed so the pointer we hand libsepol (`sepol_set_sidtab`) stays valid even
    // if the `Policy` is moved.
    sidtab: Box<Sidtab>,
}

// SAFETY: `Policy` owns its libsepol handles exclusively; the only shared global
// state it touches (the libsepol policydb/sidtab globals) is guarded by
// `GLOBAL_REPLAY_LOCK` for the whole swap+replay critical section. The raw
// pointers are never handed out or aliased. So a `Policy` is safe to send to and
// share across threads.
#[allow(unsafe_code)]
unsafe impl Send for Policy {}
#[allow(unsafe_code)]
unsafe impl Sync for Policy {}

/// A hard libsepol failure while loading a policy file.
///
/// A BADSCON (undefined context at replay time) is deliberately NOT modelled here
/// - it is an expected outcome [`ReplayOutcome::BadContext`], not a load error.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The policy file could not be opened (`fopen` failed): missing / unreadable.
    #[error("cannot open policy file {path:?}")]
    Open {
        /// The path that could not be opened.
        path: String,
    },
    /// libsepol rejected the binary policy (`sepol_policydb_read` failed): wrong
    /// magic, truncated, or an unsupported policy version. The wrapped value is
    /// the libsepol return code.
    #[error("libsepol could not read binary policy {path:?} (rc={rc})")]
    Read {
        /// The path that failed to parse.
        path: String,
        /// libsepol's negative return code.
        rc: i32,
    },
    /// libsepol could not build the initial SID table for the loaded policy
    /// (`policydb_load_isids` failed). The wrapped value is the return code.
    #[error("libsepol could not initialise the SID table for {path:?} (rc={rc})")]
    Sidtab {
        /// The path whose SID table could not be built.
        path: String,
        /// libsepol's negative return code.
        rc: i32,
    },
    /// The path contained an interior NUL byte and could not be passed to `fopen`.
    #[error("policy path {path:?} contains an interior NUL byte")]
    PathNul {
        /// The offending path (lossily rendered).
        path: String,
    },
}

/// The outcome of replaying one access against a [`Policy`].
///
/// Distinguishes the THREE shapes the wrapping categorizer needs to map: a clean
/// reason bitmask, an undefined CONTEXT (the expected cross-host case ->
/// `ContextInvalid`), and a malformed class/permission or hard compute error (a
/// real [`ReplayError`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// The replay computed a reason bitmask (`SEPOL_COMPUTEAV_*` bits OR-ed).
    /// `0` means the access is actually allowed by the policy.
    Reason(u32),
    /// `sepol_context_to_sid` rejected the source or target context: the policy
    /// does not define that context (BADSCON / BADTCON). Maps to
    /// `ContextInvalid`, NOT an error (f4 section 8).
    BadContext,
}

/// A malformed-denial or hard-failure error from a replay (distinct from the
/// expected [`ReplayOutcome::BadContext`]).
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The `tclass` is not a class defined in the policy
    /// (`sepol_string_to_security_class` failed).
    #[error("object class {tclass:?} is not defined in the supplied policy")]
    UnknownClass {
        /// The unknown class token.
        tclass: String,
    },
    /// A permission is not valid for its `tclass` in the policy
    /// (`sepol_string_to_av_perm` failed).
    #[error("permission {perm:?} is not valid for class {tclass:?} in the supplied policy")]
    UnknownPermission {
        /// The offending permission token.
        perm: String,
        /// The class it was checked against.
        tclass: String,
    },
    /// `sepol_compute_av_reason_buffer` returned a hard error (negative rc).
    #[error("libsepol reason computation failed (rc={rc})")]
    Compute {
        /// libsepol's negative return code.
        rc: i32,
    },
    /// A replay input (context / class / permission) contained an interior NUL.
    #[error("replay input {what} contains an interior NUL byte")]
    InputNul {
        /// Which input carried the NUL.
        what: &'static str,
    },
}

impl Policy {
    /// Load a binary `SELinux` policy from `path` into owned libsepol handles.
    ///
    /// Reads via the handle API (`sepol_policydb_read`) and builds the SID table
    /// (`policydb_load_isids`); touches no global state. Loading is the expensive
    /// step, so callers load once and [`replay`](Policy::replay) many times.
    ///
    /// # Errors
    ///
    /// [`LoadError::Open`] (file missing / unreadable), [`LoadError::Read`]
    /// (not a valid binary policy), [`LoadError::Sidtab`] (SID table build
    /// failed), or [`LoadError::PathNul`] (path had an interior NUL).
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        silence_libsepol_debug();

        let path_str = path.display().to_string();
        let cpath = path_to_cstring(path).ok_or_else(|| LoadError::PathNul {
            path: path_str.clone(),
        })?;
        // "re" = read + O_CLOEXEC (do not leak the fd across an exec).
        let mode = CString::new("re").expect("static mode literal has no NUL");

        // SAFETY: `cpath`/`mode` are valid NUL-terminated C strings that outlive
        // the `fopen` call. A null return is the documented failure path we check.
        #[allow(unsafe_code)]
        let fp = unsafe { fopen(cpath.as_ptr(), mode.as_ptr()) };
        if fp.is_null() {
            return Err(LoadError::Open { path: path_str });
        }

        // From here on, on any error we must fclose(fp) and free the policydb.
        // SAFETY: all pointers below are either freshly created by libsepol
        // (checked non-null via rc) or the valid `fp` above; every allocation is
        // freed on every path (the early returns free what was created so far).
        #[allow(unsafe_code)]
        unsafe {
            let mut pdb: *mut SepolPolicydb = std::ptr::null_mut();
            if sepol_policydb_create(&raw mut pdb) != 0 || pdb.is_null() {
                fclose(fp);
                return Err(LoadError::Read {
                    path: path_str,
                    rc: -1,
                });
            }

            let mut pf: *mut SepolPolicyFile = std::ptr::null_mut();
            if sepol_policy_file_create(&raw mut pf) != 0 || pf.is_null() {
                sepol_policydb_free(pdb);
                fclose(fp);
                return Err(LoadError::Read {
                    path: path_str,
                    rc: -1,
                });
            }
            sepol_policy_file_set_fp(pf, fp);

            let rc = sepol_policydb_read(pdb, pf);
            sepol_policy_file_free(pf);
            fclose(fp);
            if rc != 0 {
                sepol_policydb_free(pdb);
                return Err(LoadError::Read { path: path_str, rc });
            }

            let mut sidtab = Box::new(Sidtab::default());
            let rc = policydb_load_isids(pdb, std::ptr::from_mut::<Sidtab>(sidtab.as_mut()));
            if rc != 0 {
                sepol_policydb_free(pdb);
                return Err(LoadError::Sidtab { path: path_str, rc });
            }

            Ok(Policy { pdb, sidtab })
        }
    }

    /// Replay one `(scontext, tcontext, tclass, perms)` access against this policy
    /// and return the libsepol reason outcome.
    ///
    /// Installs this policy's handles as the libsepol global under
    /// [`GLOBAL_REPLAY_LOCK`] for the duration of the call (swap, never re-load),
    /// resolves the contexts/class/permissions, then computes the reason bitmask.
    /// The `perms` are OR-ed into one requested access vector, mirroring
    /// `audit2why.c:358-376`.
    ///
    /// Returns [`ReplayOutcome::BadContext`] (NOT an error) when either context is
    /// undefined in the policy.
    ///
    /// # Errors
    ///
    /// [`ReplayError::UnknownClass`], [`ReplayError::UnknownPermission`],
    /// [`ReplayError::Compute`], or [`ReplayError::InputNul`].
    // `cscon` (Source CONtext) / `ctcon` (Target CONtext) are deliberately
    // parallel names mirroring the scontext/tcontext pair they wrap; the
    // similar-names lint is a false positive on this intentional symmetry.
    #[allow(clippy::similar_names)]
    pub fn replay(
        &self,
        scontext: &str,
        tcontext: &str,
        tclass: &str,
        perms: &[String],
    ) -> Result<ReplayOutcome, ReplayError> {
        let cscon =
            CString::new(scontext).map_err(|_| ReplayError::InputNul { what: "scontext" })?;
        let ctcon =
            CString::new(tcontext).map_err(|_| ReplayError::InputNul { what: "tcontext" })?;
        let cclass = CString::new(tclass).map_err(|_| ReplayError::InputNul { what: "tclass" })?;
        // Pre-build the permission C strings so the unsafe block does no allocation
        // that could fail mid-sequence.
        let cperms: Vec<CString> = perms
            .iter()
            .map(|p| CString::new(p.as_str()))
            .collect::<Result<_, _>>()
            .map_err(|_| ReplayError::InputNul { what: "perm" })?;

        // The whole global-swap + replay is one critical section.
        let _guard = GLOBAL_REPLAY_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // SAFETY: under GLOBAL_REPLAY_LOCK no other thread touches the libsepol
        // global; `self.pdb` and `self.sidtab` are valid for the lifetime of
        // `self` (Drop runs only when no `&self` exists). All C-string pointers
        // outlive the calls. `reason_buf` is freed on every path.
        #[allow(unsafe_code)]
        unsafe {
            // Re-point the global at this policy. A non-zero rc here would mean a
            // corrupt handle; treat as a compute error.
            if sepol_set_policydb(self.pdb) != 0 {
                return Err(ReplayError::Compute { rc: -1 });
            }
            if sepol_set_sidtab(std::ptr::from_ref::<Sidtab>(self.sidtab.as_ref()).cast_mut()) != 0
            {
                return Err(ReplayError::Compute { rc: -1 });
            }

            // +1 to include the NUL in the length, exactly as audit2why.c:345.
            let mut ssid: SecurityId = 0;
            if sepol_context_to_sid(cscon.as_ptr(), scontext.len() + 1, &raw mut ssid) < 0 {
                return Ok(ReplayOutcome::BadContext);
            }
            let mut tsid: SecurityId = 0;
            if sepol_context_to_sid(ctcon.as_ptr(), tcontext.len() + 1, &raw mut tsid) < 0 {
                return Ok(ReplayOutcome::BadContext);
            }

            let mut class_idx: SecurityClass = 0;
            if sepol_string_to_security_class(cclass.as_ptr(), &raw mut class_idx) < 0 {
                return Err(ReplayError::UnknownClass {
                    tclass: tclass.to_string(),
                });
            }

            let mut requested: AccessVector = 0;
            for (cperm, perm) in cperms.iter().zip(perms.iter()) {
                let mut bit: AccessVector = 0;
                if sepol_string_to_av_perm(class_idx, cperm.as_ptr(), &raw mut bit) < 0 {
                    return Err(ReplayError::UnknownPermission {
                        perm: perm.clone(),
                        tclass: tclass.to_string(),
                    });
                }
                requested |= bit;
            }

            let mut avd = AvDecision::default();
            let mut reason: c_uint = 0;
            let mut reason_buf: *mut c_char = std::ptr::null_mut();
            let rc = sepol_compute_av_reason_buffer(
                ssid,
                tsid,
                class_idx,
                requested,
                &raw mut avd,
                &raw mut reason,
                &raw mut reason_buf,
                0, // flags 0: only denied constraints in the buffer (audit2why.c:379)
            );
            if !reason_buf.is_null() {
                free(reason_buf.cast::<c_void>());
            }
            if rc < 0 {
                return Err(ReplayError::Compute { rc });
            }

            Ok(ReplayOutcome::Reason(reason))
        }
    }
}

impl Drop for Policy {
    fn drop(&mut self) {
        // SAFETY: Drop runs once. `self.sidtab` was filled by `policydb_load_isids`,
        // which allocated its internal htable; `sepol_sidtab_destroy` frees that
        // htable + entries WITHOUT freeing the `Sidtab` struct (the `Box` owns and
        // frees the struct after this), so there is no double-free (#113). `self.pdb`
        // was created by `sepol_policydb_create` and never freed elsewhere; freeing
        // it releases the policydb. We do NOT clear the libsepol globals: another
        // live `Policy` may currently own them, and they are borrowed pointers
        // (libsepol does not own them). Neither pointer is aliased here.
        #[allow(unsafe_code)]
        unsafe {
            sepol_sidtab_destroy(std::ptr::from_mut::<Sidtab>(self.sidtab.as_mut()));
            sepol_policydb_free(self.pdb);
        }
    }
}

/// Convert a filesystem path to a C string for `fopen`, or `None` on an interior
/// NUL. Uses the raw OS bytes so non-UTF-8 paths round-trip.
fn path_to_cstring(path: &Path) -> Option<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).ok()
}
