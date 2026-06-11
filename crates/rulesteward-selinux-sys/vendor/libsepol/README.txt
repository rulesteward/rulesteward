Vendored libsepol source (RuleSteward `rulesteward-selinux-sys`)
================================================================

What this is
------------
The pinned C source of libsepol, built from source by this crate's `build.rs`
into a static `libsepol.a` and statically linked when the `vendored` feature is
on. That feature is turned on by `rulesteward-selinux`'s
`authoritative-categorizer`, which is DEFAULT-ON since #135 -- so the default
RuleSteward build links libsepol, and `--no-default-features` is the
libsepol-free Apache-2.0 build. This replaces a previously committed prebuilt
`libsepol.a` binary blob: shipping the source instead makes
the build auditable, diffable, and reproducible, and satisfies the LGPL-2.1
source-availability obligation in-tree (no separate "relink source" deliverable
needed).

Version pin
-----------
libsepol 3.10 (SELinux userspace release 3.10).
  Upstream:   https://github.com/SELinuxProject/selinux  (tag: 3.10)
  Tarball:    https://github.com/SELinuxProject/selinux/releases/download/3.10/libsepol-3.10.tar.gz
  Tarball sha256: d555586797fa9f38344496d2a7ec1147b6caaf3fcc44c42d8d5173edd7a79a71
  VERSION file: see ./VERSION (contains "3.10")

This matches the version of the prebuilt `libsepol.a` it replaced (the F4b spike
archive was libsepol 3.10). To bump the pin: re-vendor from a new release tarball
(record its sha256 here), re-run the from-source build, and confirm the
known-answer tests in crates/rulesteward-selinux/tests/known_answer_categorize.rs
still pass under `--features authoritative-categorizer`.

License
-------
libsepol is LGPL-2.1. ./LICENSE is libsepol's upstream license text (verbatim).
The repo also carries LICENSES/LGPL-2.1.txt and a top-level NOTICE recording
that libsepol is a statically linked LGPL-2.1 component. Since #135 the
categorizer is DEFAULT-ON, so the default RuleSteward binary DOES statically
link libsepol and carries the LGPL-2.1 obligation (satisfied by LGPL-2.1.txt +
NOTICE + this in-tree source). The `--no-default-features` build links no
libsepol and carries no LGPL obligation.

Build recipe (what build.rs runs)
---------------------------------
build.rs copies this tree into OUT_DIR (libsepol's Makefile builds in place; the
vendored tree is never mutated) and runs, in the copied `src/`:

    make libsepol.a \
        CC=<per-target compiler> \
        DISABLE_CIL=y \
        DISABLE_SHARED=y \
        CFLAGS="-I. -I../include -D_GNU_SOURCE -O2 -fno-semantic-interposition -fPIC"

then emits:

    cargo:rustc-link-search=native=<copied src dir>
    cargo:rustc-link-lib=static=sepol

Notes on the recipe:
  - DISABLE_CIL=y excludes the CIL directory entirely (we do not vendor cil/).
  - DISABLE_SHARED=y builds only the static archive (no libsepol.so).
  - The `libsepol.a` target builds + archives the object files only; it never
    touches the .so / .pc / .map machinery, so libsepol.{map,pc}.in are not
    needed and are not vendored.
  - -DHAVE_REALLOCARRAY is NOT passed explicitly: libsepol's Makefile auto-probes
    it with the active CC (`override CFLAGS += -DHAVE_REALLOCARRAY` on success).
    musl and modern glibc both pass the probe.
  - The `%.o` Makefile rule appends -fPIC itself; passing it in CFLAGS too is
    harmless and keeps the host glibc build PIE-friendly.
  - The default upstream CFLAGS include -Werror; passing CFLAGS= overrides that.
    -Werror is intentionally dropped so a newer host gcc cannot warn-as-error on
    upstream C we do not control.

Per-target correctness
----------------------
The build is per-target: a glibc host-test build uses the native gcc and produces
a glibc archive; the x86_64-unknown-linux-musl release build uses musl-gcc and
produces a musl archive. build.rs selects the compiler from CARGO_CFG_TARGET_ENV
("musl" vs "gnu"). The single static musl release binary is preserved.

Task 0 (build-tool decision: make vs cc)
----------------------------------------
Probed against this exact 3.10 src/Makefile:
  - With DISABLE_CIL=y there is ZERO code generation. The only generated file in
    the Makefile is cil/src/cil_lexer.c (flex), gated entirely behind
    `ifneq ($(DISABLE_CIL),y)`.
  - src/flask.h is pre-generated and committed in the release tarball; no Makefile
    rule produces it at build time. (av_permissions.h / flask_internal.h are not
    present and not referenced by any src/*.c in 3.10.)
  - OBJS = $(patsubst %.c,%.o,$(sort $(wildcard *.c))) -> every src/*.c (45 of
    them); CIL is excluded at the directory level, never per-file.

Decision: lean upstream `make` is PRIMARY. It reuses upstream's blessed build,
auto-probes compiler features (e.g. HAVE_REALLOCARRAY) and auto-tracks the source
file list across version bumps, with zero reimplementation risk.

The Rust `cc` crate is the documented FALLBACK (use only if `make` ever proves
unworkable, e.g. under a future cross-target). Because there is no codegen and
CIL exclusion is directory-level, a cc build is straightforward:
    cc::Build::new()
        .include("src").include("include")
        .define("_GNU_SOURCE", None)
        .define("HAVE_REALLOCARRAY", None)   // cc has no autoprobe; safe on musl + glibc >= 2.29
        .flag("-fno-semantic-interposition").opt_level(2).warnings(false)
        .files(glob "src/*.c")               // CIL not vendored, so no exclusion needed
        .compile("sepol");
Switching to cc adds `cc` (+ `shlex`) to Cargo.lock (cargo-deny/audit surface) and
makes the HAVE_REALLOCARRAY / future feature-probe decisions a manual maintenance
item; that is why make remains primary. Bubble up before switching.

What was vendored / dropped from the upstream tarball
-----------------------------------------------------
Vendored (minimal subset needed to build libsepol.a):
  src/*.c           (45 source files)
  src/*.h           (18 private headers, incl. the pre-generated flask.h)
  src/Makefile      (upstream, verbatim - it IS the build recipe)
  include/sepol/**  (44 public + policydb headers; on the -I../include path)
  VERSION, LICENSE  (provenance + LGPL-2.1 text)

Dropped (not needed for the static archive):
  cil/                          (excluded by DISABLE_CIL=y)
  utils/  tests/  man/  fuzz/   (not part of the library build)
  src/libsepol.map.in           (only for the .so version script)
  src/libsepol.pc.in            (only for the pkg-config file)
  include/Makefile              (only installs headers)
  top-level + include Makefiles, all build artifacts (*.o, *.a)

Empirical build proof (this vendored tree, recipe above)
-------------------------------------------------------
  glibc (gcc):       libsepol.a ~892K, 45 objects, all called FFI symbols defined.
  musl  (musl-gcc):  libsepol.a  888K, 45 objects, all called FFI symbols defined.
The musl archive size matches the prebuilt blob it replaced (888K). The
authoritative correctness check is the known-answer test suite, which replays
real policies through the from-source archive.
