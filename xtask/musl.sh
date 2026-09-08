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
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$REPO=/src"

cargo build --release --target "$TARGET"

bin="target/$TARGET/release/rulesteward"
# ldd exits nonzero on some hosts for a static binary, so its status is not the
# answer and its output is. Captured rather than piped for the same reason.
out="$(ldd "$bin" 2>&1 || true)"
case "$out" in
    *"statically linked"*) log "$bin: statically linked" ;;
    *) die "$bin is not statically linked: $out" ;;
esac
