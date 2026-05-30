//! fapolicyd trust-DB reader (heed, read-only). Task-1 spike stub.
//!
//! This file currently exists only to force `heed` -> `lmdb-master-sys` -> `cc`
//! to compile and statically link the vendored liblmdb against musl (the Task-1
//! de-risk gate). Task 2 replaces this stub with the real
//! `open_trustdb_readonly` / `TrustDb` / `TrustDbError` reader.

/// Forces `lmdb-master-sys` to link by referencing a `heed` symbol from a `pub`
/// fn (so it is not dead-stripped). Replaced by `open_trustdb_readonly` in Task 2.
/// `EnvOpenOptions::new()` is the safe constructor; only `.open()` is `unsafe`.
#[must_use]
pub fn _heed_link_probe() -> bool {
    let _ = heed::EnvOpenOptions::new();
    true
}
