//! Build libsepol 3.10 from the in-tree vendored C source and statically link it
//! (#120). Replaces the previously committed prebuilt `libsepol.a`.
//!
//! # Feature-gated (the whole build is a no-op without `vendored`)
//!
//! This crate is a workspace member, so `cargo build/test/clippy --workspace`
//! compiles its rlib even when nothing enables the libsepol layer. An rlib links
//! no native libraries, so compiling the rlib does NOT need libsepol. We must
//! therefore NOT run the (relatively expensive) C build when nothing links
//! libsepol. The `vendored` Cargo feature gates it: build.rs returns early unless
//! `CARGO_FEATURE_VENDORED` is set. `rulesteward-selinux`'s
//! `authoritative-categorizer` feature is what turns `vendored` on, and it is
//! DEFAULT-ON since #135 (rulesteward-cli enables it by default), so:
//!   - default `--workspace` build: `vendored` is on via feature unification, so
//!     libsepol IS compiled and statically linked;
//!   - `--no-default-features` build (or this -sys crate's rlib compiled alone):
//!     `vendored` stays off, so `make` never runs and no libsepol is built -- the
//!     libsepol-free Apache-2.0 path the gate exists to keep cheap.
//!
//! The `vendored` gate is what lets the libsepol-free builds skip the C build
//! even though this crate is always compiled as a workspace member.
//!
//! # What it does (under the feature)
//!
//! libsepol's Makefile builds its objects + `libsepol.a` in place in `src/`. To
//! avoid mutating the vendored tree (and to stay inside Cargo's `OUT_DIR`
//! sandbox) we copy the vendored tree into `OUT_DIR` and run upstream's `make`
//! there, then point the linker at the produced archive.
//!
//! # Per-target (glibc host-test vs musl release)
//!
//! The build is per-target: a glibc host-test build uses the native `gcc` and
//! produces a glibc archive; the `x86_64-unknown-linux-musl` release build uses
//! `musl-gcc` and produces a musl archive. The single static musl binary is
//! preserved. The recipe + the pin live in `vendor/libsepol/README.txt`.
//!
//! `links = "sepol"` in `Cargo.toml` makes Cargo enforce a single link of the
//! native `sepol` library across the dependency graph.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Re-run if the build script itself changes. (Cargo also does this, but being
    // explicit keeps the intent clear alongside the vendored-tree trigger below.)
    println!("cargo:rerun-if-changed=build.rs");

    // GATE: only build libsepol when the `vendored` feature is active. Without it
    // this crate compiles as a plain rlib that links no native library (the
    // --no-default-features path). The module docs above explain why a DEFAULT
    // --workspace build DOES enable `vendored` (feature unification from the CLI
    // default), and so does build + link libsepol.
    if env::var_os("CARGO_FEATURE_VENDORED").is_none() {
        return;
    }

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let vendor = manifest.join("vendor/libsepol");

    // Copy the vendored tree into OUT_DIR (never mutate vendor/; the Makefile
    // builds in place). A fresh copy each time build.rs runs avoids stale objects
    // from a previous compiler/target.
    let build_root = out_dir.join("libsepol-build");
    if build_root.exists() {
        fs::remove_dir_all(&build_root).expect("clear previous libsepol build dir");
    }
    copy_dir(&vendor, &build_root);
    let build_src = build_root.join("src");

    // Pick the C compiler for the target, matching cc-crate / CI conventions:
    // `CC_<target_with_underscores>`, then `CC`, then a per-env default. The
    // musl release sets `CC_x86_64_unknown_linux_musl=musl-gcc` (see ci.yml /
    // release.yml); a glibc host build falls back to the env `CC` or `cc`.
    let target = env::var("TARGET").expect("TARGET");
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let cc = env::var(format!("CC_{}", target.replace('-', "_")))
        .or_else(|_| env::var("CC"))
        .unwrap_or_else(|_| {
            if target_env == "musl" {
                "musl-gcc".to_string()
            } else {
                "cc".to_string()
            }
        });

    // CFLAGS mirror the recipe in vendor/libsepol/README.txt. The Makefile's
    // `override CFLAGS += -I. -I../include -D_GNU_SOURCE` always appends the
    // include paths, and it auto-probes `-DHAVE_REALLOCARRAY` with this CC, so we
    // pass neither. Overriding CFLAGS drops upstream's default `-Werror` (a newer
    // host gcc must not warn-as-error on upstream C we do not control). The `%.o`
    // rule adds `-fPIC` itself; we keep it here too for the host glibc build.
    let cflags = [
        "-I.",
        "-I../include",
        "-D_GNU_SOURCE",
        "-O2",
        "-fno-semantic-interposition",
        "-fPIC",
    ]
    .join(" ");
    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "1".to_string());

    let status = Command::new("make")
        .current_dir(&build_src)
        .arg("libsepol.a")
        .arg(format!("CC={cc}"))
        .arg("DISABLE_CIL=y")
        .arg("DISABLE_SHARED=y")
        .arg(format!("CFLAGS={cflags}"))
        .arg(format!("-j{jobs}"))
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn `make` to build vendored libsepol ({e}). \
                 The `authoritative-categorizer` feature requires `make` and a C \
                 compiler ({cc}). Install them, or use the documented `cc`-crate \
                 fallback (vendor/libsepol/README.txt)."
            )
        });
    assert!(
        status.success(),
        "`make libsepol.a` (CC={cc}) failed building vendored libsepol from source"
    );

    let archive = build_src.join("libsepol.a");
    assert!(
        archive.is_file(),
        "make reported success but {} was not produced",
        archive.display()
    );

    // Static-link the freshly built archive. `static=sepol` => `-l static=sepol`,
    // so the shipped binary keeps no `libsepol.so` runtime dependency.
    println!("cargo:rustc-link-search=native={}", build_src.display());
    println!("cargo:rustc-link-lib=static=sepol");

    // Rebuild if any vendored input changes (directory-level is honored by Cargo)
    // or if the chosen compiler changes.
    println!("cargo:rerun-if-changed={}", vendor.display());
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CC_{}", target.replace('-', "_"));
}

/// Recursively copy `src` into `dst` (creating `dst`). std-only; the vendored tree
/// is plain text source, no symlinks or special files.
fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap_or_else(|e| panic!("create {}: {e}", dst.display()));
    for entry in fs::read_dir(src).unwrap_or_else(|e| panic!("read dir {}: {e}", src.display())) {
        let entry = entry.unwrap_or_else(|e| panic!("read entry in {}: {e}", src.display()));
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let file_type = entry
            .file_type()
            .unwrap_or_else(|e| panic!("stat {}: {e}", from.display()));
        if file_type.is_dir() {
            copy_dir(&from, &to);
        } else {
            fs::copy(&from, &to)
                .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", from.display(), to.display()));
        }
    }
}
