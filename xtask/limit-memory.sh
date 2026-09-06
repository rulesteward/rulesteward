#!/usr/bin/env bash
# Cargo "runner" for mutant runs: caps the test binary's address space, then
# execs it. Set by xtask/mutants.sh through CARGO_TARGET_<host>_RUNNER, so
# `just test` and `cargo run` are never under it.
#
# Why: a mutant that stops a byte-walking loop advancing (`i += 1` to
# `i *= 1` in strip_ansi, and the same shape in unescape) keeps pushing to a
# Vec forever. On the 31 GB development box the 22 s test timeout fires first
# and records a timeout; on a 16 GB hosted runner the process exhausts memory
# in about a minute and the VM itself is killed -- measured as "the runner has
# received a shutdown signal" on shards 2 to 6 of every run, while 0, 1 and 7
# passed. Under this cap the allocation fails, Rust aborts, and the mutant is
# caught in seconds instead of taking the runner down.
#
# 1 GB is address space, not resident memory. The suite's real footprint is
# tens of megabytes, so the cap is far above use and far below the runner.
# Measured at a 4 GB cap: a runaway in a debug build grows at about 45 MB/s
# per process, so it reached the 60 s timeout first and recorded a timeout
# again, with 2.6 GB resident in one process and several such processes in
# flight (the cli tests each spawn the binary). At 1 GB the abort comes first.
# glibc reserves 64 MB of virtual per malloc arena and creates one per
# contending thread, so arenas are capped too; otherwise a 16-thread test
# harness could reserve most of the limit before allocating a byte.
export MALLOC_ARENA_MAX=2
ulimit -v 1048576
exec "$@"
