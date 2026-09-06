#!/usr/bin/env bash
# The release: one musl tarball and its checksum, then the GitHub release.
#
#   ./xtask/release.sh build     musl build, tar into dist/, write dist/SHA256SUMS
#   ./xtask/release.sh publish   gh release create for the tag being built
#
# cargo-dist is rejected: its value is a cross-platform matrix and installer
# generation, and this project has one target and one artifact.
#
# SHA256SUMS is integrity, not signing. It catches a truncated or corrupted
# download; it proves nothing about who built the file, because anyone who can
# replace the tarball can replace the sums beside it.

# shellcheck source=xtask/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

build() {
    ./xtask/musl.sh
    local tag="${GITHUB_REF_NAME:-$(git describe --tags --always)}"
    mkdir -p dist
    tar -czf "dist/rulesteward-$tag-x86_64-unknown-linux-musl.tar.gz" \
        -C target/x86_64-unknown-linux-musl/release rulesteward
    (cd dist && sha256sum -- *.tar.gz > SHA256SUMS)
}

publish() {
    # No local fallback tag here on purpose: publish creates a public release, so
    # it runs only where a tag ref exists, which is the tag-triggered CI job.
    [ -n "${GITHUB_REF_NAME:-}" ] || die "GITHUB_REF_NAME is unset: publish runs on the tag CI job only"
    need gh
    gh release create "$GITHUB_REF_NAME" --generate-notes dist/*.tar.gz dist/SHA256SUMS
}

cd "$REPO"
case "${1:-}" in
    build)   build ;;
    publish) publish ;;
    *)       die "usage: release.sh build|publish" ;;
esac
