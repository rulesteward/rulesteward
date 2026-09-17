#!/usr/bin/env bash
# The release: one musl tarball, one RPM around the same binary, their checksums,
# then the GitHub release.
#
#   ./xtask/release.sh build     musl build, tar and rpm into dist/, write dist/SHA256SUMS
#   ./xtask/release.sh rpm       musl build and the RPM alone, for `just rpm`
#   ./xtask/release.sh publish   gh release create for the tag being built
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

rpm_pkg() {
    need rpmbuild
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
        --define "srcroot $REPO" \
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

build() {
    ./xtask/musl.sh
    mkdir -p dist
    # Pin every field tar and gzip would otherwise take from the filesystem or
    # the clock: --mtime the member timestamp, --owner/--group/--numeric-owner
    # the ownership, --sort=name the member order, gzip -n the header timestamp
    # and name (#18).
    tar --mtime=@0 --owner=0 --group=0 --numeric-owner --sort=name \
        -C target/x86_64-unknown-linux-musl/release -cf - rulesteward \
        | gzip -n > "dist/rulesteward-$TAG-x86_64-unknown-linux-musl.tar.gz"
    rpm_pkg
    (cd dist && sha256sum -- *.tar.gz *.rpm > SHA256SUMS)
}

publish() {
    # No local fallback tag here on purpose: publish creates a public release, so
    # it runs only where a tag ref exists, which is the tag-triggered CI job.
    [ -n "${GITHUB_REF_NAME:-}" ] || die "GITHUB_REF_NAME is unset: publish runs on the tag CI job only"
    need gh
    gh release create "$GITHUB_REF_NAME" --generate-notes dist/*.tar.gz dist/*.rpm dist/SHA256SUMS
}

case "${1:-}" in
    build)   build ;;
    rpm)     ./xtask/musl.sh; rpm_pkg ;;
    publish) publish ;;
    *)       die "usage: release.sh build|rpm|publish" ;;
esac
