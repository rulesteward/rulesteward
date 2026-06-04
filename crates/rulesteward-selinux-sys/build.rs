//! Static-link the musl-built `libsepol.a` that lives alongside this crate (#106).
//!
//! The committed archive is libsepol 3.10 (`SELinux` userspace 3.10), built under
//! musl with CIL and the shared object disabled - libsepol alone, no PCRE2 / no
//! fts (the F4b spike proved libsepol links statically under
//! `x86_64-unknown-linux-musl` with no transitive native deps; `static-binary-proof.txt`).
//! It was produced with:
//!
//! ```sh
//! cd <selinux-3.10>/libsepol/src
//! make CC=musl-gcc DISABLE_CIL=y DISABLE_SHARED=y \
//!      CFLAGS="-I. -I../include -D_GNU_SOURCE -DHAVE_REALLOCARRAY -O2 -fno-semantic-interposition" \
//!      libsepol.a
//! ```
//!
//! The same archive links into BOTH the glibc host test build and the musl
//! release build: libsepol is plain C with no glibc-version ABI dependency on
//! the symbols this crate calls (verified by linking it into a glibc `cargo test`
//! binary in the F4b spike). So one committed `.a` serves every target.
//!
//! `links = "sepol"` in `Cargo.toml` makes Cargo enforce a single link of the
//! native `sepol` library across the dependency graph.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");

    // Search this crate's own directory for `libsepol.a`.
    println!("cargo:rustc-link-search=native={dir}");

    // `static=sepol` => rustc emits `-l static=sepol`, statically linking the
    // archive (no `libsepol.so` runtime dependency; the shipped binary stays a
    // single static artifact).
    println!("cargo:rustc-link-lib=static=sepol");

    // Rebuild if the archive is replaced (e.g. a libsepol version bump).
    println!("cargo:rerun-if-changed={dir}/libsepol.a");
}
