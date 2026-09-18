#!/usr/bin/env bash
# The release: one musl tarball, one RPM around the same binary, their checksums,
# then the GitHub release.
#
#   ./xtask/release.sh build          musl build, tar and rpm into dist/, write dist/SHA256SUMS
#   ./xtask/release.sh rpm            musl build and the RPM alone, for `just rpm`
#   ./xtask/release.sh stage <dir>    the binary, the man page, the completion and a SHA256SUM into <dir>
#   ./xtask/release.sh tarball <bin>  the tarball alone, around a binary built elsewhere
#   ./xtask/release.sh wrap <dir>     the RPM alone, around a staged <dir>, building nothing
#   ./xtask/release.sh publish        the sums, then gh release create for the tag being built
#
# `stage`, `tarball` and `wrap` are how the tag path splits `build` across three
# jobs: the musl job stages what it linked, a rockylinux:10 job wraps that file
# in the RPM and the release job tars the same file and publishes both. #59
# measured that only an EL rpm writes a package a local `just rpm` matches byte
# for byte, and the binary is downloaded rather than rebuilt to get there, so one
# file is in both artifacts by construction. `build` still does all of it in one
# process, which is what `just release` runs.
#
# cargo-dist is rejected: its value is a cross-platform matrix and installer
# generation, and this project has one target and one artifact.
#
# rpmbuild is deliberately not pinned in install-tools.sh. That file pins what
# decides the bytes of the binary; rpmbuild only wraps a binary it never touches
# (the spec turns off the brp chain that would).
#
# SHA256SUMS is integrity, not signing. It catches a truncated or corrupted
# download; it proves nothing about who built the file, because anyone who can
# replace the tarball can replace the sums beside it.

# shellcheck source=xtask/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

cd "$REPO"

TAG="${GITHUB_REF_NAME:-$(git describe --tags --always)}"
MUSL_BIN=target/x86_64-unknown-linux-musl/release/rulesteward

# build.rs writes the man page and the completion into the bin's OUT_DIR, whose
# hash cargo takes from the dependency graph. A dir from an earlier graph
# survives beside the current one, so exactly one match is demanded rather than
# the newest guessed.
generated_dir() {
    local pages=(target/x86_64-unknown-linux-musl/release/build/rulesteward-*/out/rulesteward.1)
    { [ "${#pages[@]}" -eq 1 ] && [ -e "${pages[0]}" ]; } \
        || die "expected one generated man page, found: ${pages[*]} (rm -rf target/x86_64-unknown-linux-musl/release/build/rulesteward-* and rerun)"
    dirname "${pages[0]}"
}

# What the musl job hands the two jobs after it: the binary it linked, the two
# files build.rs generated beside it, and the sum both of those jobs check the
# binary they received against.
stage() {
    local dir="$1" outdir
    outdir="$(generated_dir)"
    mkdir -p "$dir"
    cp "$MUSL_BIN" "$outdir/rulesteward.1" "$outdir/rulesteward.bash" "$dir/"
    (cd "$dir" && sha256sum rulesteward > SHA256SUM)
}

# The RPM around a binary and the two generated files. Both arguments default to
# what musl.sh and build.rs just wrote, so `just rpm` and `just release` pass
# neither; `wrap` passes a staged directory downloaded from the musl job.
rpm_pkg() {
    need rpmbuild
    local bin outdir
    bin="$(realpath "${1:-$MUSL_BIN}")"
    outdir="$(realpath "${2:-$(generated_dir)}")"
    # rpm forbids a hyphen in Version, and a pre-release tag like v0.3.0-rc1 has
    # one. `~` is rpm's own pre-release separator and sorts before the release.
    local ver="${TAG#v}"
    ver="${ver//-/\~}"
    mkdir -p dist
    # Committer date of HEAD: the tag commit on a tag run and on `just rpm` at the
    # tag. The spec clamps BUILDTIME and every file mtime to it.
    SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
    export SOURCE_DATE_EPOCH
    # _rpmfilename flattens rpm's default x86_64/ subdirectory so the package
    # lands beside the tarball. The %% keeps the macros unexpanded at define time.
    rpmbuild -bb \
        --define "_topdir $REPO/target/rpm" \
        --define "_rpmdir $REPO/dist" \
        --define "_rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
        --define "ver $ver" \
        --define "bin $bin" \
        --define "srcroot $REPO" \
        --define "outdir $outdir" \
        xtask/rulesteward.spec
    # No glob: a local dist/ accumulates artifacts from earlier tags, and the
    # check below has to read the package this run produced.
    local pkg="dist/rulesteward-$ver-1.x86_64.rpm"
    log "$(rpm -qp --qf 'BUILDTIME=%{BUILDTIME} BUILDHOST=%{BUILDHOST}\n' "$pkg"; rpm -qpl "$pkg")"
    # AutoReqProv is off, so the only dependencies left should be the rpmlib()
    # capability tags rpm always emits. Anything else means the binary stopped
    # being static or the package grew a script.
    local requires
    requires="$(rpm -qp --requires "$pkg" | grep -v '^rpmlib(' || true)"
    [ -z "$requires" ] || die "$pkg requires something beyond rpmlib: $requires"
}

# Pin every field tar and gzip would otherwise take from the filesystem or the
# clock: --mtime the member timestamp, --mode the member mode, --owner/--group/
# --numeric-owner the ownership, --sort=name the member order, gzip -n the header
# timestamp and name (#18). --mode is there because an artifact downloaded from
# the musl job comes back 0644 and the tarball must not say so; a local build,
# where the file is already 0755, produces the same bytes either way.
tarball() {
    local bin="${1:-$MUSL_BIN}"
    mkdir -p dist
    tar --mtime=@0 --mode=755 --owner=0 --group=0 --numeric-owner --sort=name \
        -C "$(dirname "$bin")" -cf - "$(basename "$bin")" \
        | gzip -n > "dist/rulesteward-$TAG-x86_64-unknown-linux-musl.tar.gz"
}

# Written here rather than only at the end of `build` because on the tag path the
# tarball and the RPM come from two different jobs and publish is the first place
# both files sit in one dist/.
sums() {
    (cd dist && sha256sum -- *.tar.gz *.rpm > SHA256SUMS)
}

build() {
    ./xtask/musl.sh
    tarball
    rpm_pkg
    sums
}

publish() {
    # No local fallback tag here on purpose: publish creates a public release, so
    # it runs only where a tag ref exists, which is the tag-triggered CI job.
    [ -n "${GITHUB_REF_NAME:-}" ] || die "GITHUB_REF_NAME is unset: publish runs on the tag CI job only"
    need gh
    sums
    gh release create "$GITHUB_REF_NAME" --generate-notes dist/*.tar.gz dist/*.rpm dist/SHA256SUMS
}

case "${1:-}" in
    build)   build ;;
    rpm)     ./xtask/musl.sh; rpm_pkg ;;
    stage)   stage "${2:?usage: release.sh stage <dir>}" ;;
    tarball) tarball "${2:?usage: release.sh tarball <binary>}" ;;
    wrap)    rpm_pkg "${2:?usage: release.sh wrap <dir>}/rulesteward" "$2" ;;
    publish) publish ;;
    *)       die "usage: release.sh build|rpm|stage <dir>|tarball <bin>|wrap <dir>|publish" ;;
esac
