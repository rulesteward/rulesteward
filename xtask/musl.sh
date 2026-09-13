#!/usr/bin/env bash
# The x86_64-unknown-linux-musl release build, plus the assertion that what came
# out is actually static.
#
# No musl-tools install: rustc's self-contained musl links this tree, which is
# pure Rust plus clap. Verified with no .cargo/config.toml and no musl-gcc
# involved. If a C-linking dependency ever lands, this is where it shows up.
#
# The `ldd` check is the whole reason this is a script rather than one recipe
# line. A successful build says nothing about the link being self-contained, and
# a dynamically linked "static" binary is exactly the thing nobody notices until
# it runs on a host without the right glibc.

# shellcheck source=xtask/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TARGET=x86_64-unknown-linux-musl
cd "$REPO"

# Registry crates carry their absolute source path into panic locations, and
# `strip = true` removes debug info but not file!() strings. Map both roots to
# fixed names so CI and a local checkout produce the same bytes (#18).
#
# The host `cc` still drives the link, but `-fuse-ld=lld` with `-B` makes it pick
# the `ld.lld` the toolchain ships, so the linker is pinned by rust-toolchain.toml
# like rustc and the crt objects. Without it the host `ld` decides the section
# layout, and v0.2.0 measured 64 bytes and a `.plt.got` between EL10 and
# ubuntu-latest (#18). `-Clink-self-contained=+linker` is the same thing and is
# unstable in 1.98.0; switch when it stabilises.
sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | sed -n 's/^host: //p')"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$REPO=/src -Clink-arg=-fuse-ld=lld -Clink-arg=-B$sysroot/lib/rustlib/$host/bin/gcc-ld"

cargo build --release --target "$TARGET"

bin="target/$TARGET/release/rulesteward"
# ldd exits nonzero on some hosts for a static binary, so its status is not the
# answer and its output is. Captured rather than piped for the same reason.
out="$(ldd "$bin" 2>&1 || true)"
case "$out" in
    *"statically linked"*) log "$bin: statically linked" ;;
    *) die "$bin is not statically linked: $out" ;;
esac
# In the CI log this is the sum a local build at the same commit compares against (#18).
log "$(sha256sum "$bin")"
