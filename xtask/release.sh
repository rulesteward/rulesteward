#!/usr/bin/env bash
# The release: one musl tarball, one RPM around the same binary, their checksums,
# then the GitHub release.
#
#   ./xtask/release.sh build          musl build, tar and rpm into dist/, write dist/SHA256SUMS
#   ./xtask/release.sh rpm            musl build and the RPM alone, for `just rpm`
#   ./xtask/release.sh stage <dir>    the binary, the man page, the completion and a SHA256SUM into <dir>
#   ./xtask/release.sh tarball <bin>  the tarball alone, around a binary built elsewhere
#   ./xtask/release.sh wrap <dir>     the RPM alone, around a staged <dir>, building nothing
#   ./xtask/release.sh sign <dir>     the one RPM in <dir>, signed into <dir>/signed
#   ./xtask/release.sh publish        the sums, then gh release create for the tag being built
#   ./xtask/release.sh verify         every published artifact's attestation, read back
#
# `stage`, `tarball` and `wrap` are how the tag path splits `build` across three
# jobs: the musl job stages what it linked, a rockylinux:10 job wraps that file
# in the RPM and the release job tars the same file and publishes both. #59
# measured that only an EL rpm writes a package a local `just rpm` matches byte
# for byte, and the binary is downloaded rather than rebuilt to get there, so one
# file is in both artifacts by construction. `build` still does all of it in one
# process, which is what `just release` runs. `sign` is a fourth job between the
# wrap and the release rather than part of `wrap`, because it is the only job the
# signing key is released to and that job should do nothing else.
#
# cargo-dist is rejected: its value is a cross-platform matrix and installer
# generation, and this project has one target and one artifact.
#
# rpmbuild is deliberately not pinned in install-tools.sh. That file pins what
# decides the bytes of the binary; rpmbuild only wraps a binary it never touches
# (the spec turns off the brp chain that would).
#
# Three things reach a downloader, and only two of them are evidence. The RPM is
# GPG-signed by the `sign` job, and both assets carry build provenance that the
# attest step in the `release` job writes and `verify` reads back. SHA256SUMS is
# neither: it catches a truncated or corrupted download and nothing else, because
# anyone who can replace the tarball can replace the sums beside it.

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
    # check below has to read the package this run produced. The sha256 is logged
    # here so the rpm CI job and a local `just rpm` print the unsigned sum the
    # same way, which is the file the two are compared on.
    local pkg="dist/rulesteward-$ver-1.x86_64.rpm"
    log "$(rpm -qp --qf 'BUILDTIME=%{BUILDTIME} BUILDHOST=%{BUILDHOST}\n' "$pkg"; rpm -qpl "$pkg"; sha256sum "$pkg")"
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

# The GPG signature, written into a copy so the unsigned file survives beside it:
# a signature carries the time it was made and is not reproducible, so the sum a
# local `just rpm` is compared against stays the unsigned one. #104 measured that
# rpmsign touches nothing else -- %{PAYLOADDIGEST} and the file size are equal
# across a signature -- which is what the assertion below reads.
sign() {
    need rpmsign
    need gpg
    # No local fallback key, for the reason publish has no fallback tag: the
    # secret is released to one environment-scoped job and nowhere else.
    [ -n "${RPM_SIGNING_SUBKEY:-}" ] || die "RPM_SIGNING_SUBKEY is unset: sign runs on the tag CI job only"
    local dir="$1" unsigned signed
    # Exactly one package demanded rather than the newest guessed, as
    # generated_dir does: a dir with two rpms in it means the caller staged
    # something this function cannot reason about.
    local pkgs=("$dir"/*.rpm)
    { [ "${#pkgs[@]}" -eq 1 ] && [ -e "${pkgs[0]}" ]; } \
        || die "expected one rpm in $dir, found: ${pkgs[*]}"
    unsigned="${pkgs[0]}"
    signed="$dir/signed/$(basename "$unsigned")"
    # The keyring goes outside the workspace on purpose: upload-artifact reads
    # paths under it, and a keyring written into dist/ would be a file it could
    # publish. The trap removes it however this function returns.
    GNUPGHOME="$(mktemp -d)"
    export GNUPGHOME
    trap 'rm -rf "$GNUPGHOME"' EXIT
    # bash's own printf rather than a here-string or an argument, so the key is
    # in no process argv. gpg's import chatter goes to stderr, where every other
    # diagnostic in this tree goes; the variable itself is never echoed.
    printf '%s' "$RPM_SIGNING_SUBKEY" | gpg --batch --import
    mkdir -p "$dir/signed"
    cp "$unsigned" "$signed"
    # rpmsign execs /usr/bin/gpg and %_gpg_name is the only macro it needs; the
    # value is the signing UID exactly. stdin from /dev/null because there is no
    # tty in the container and the subkey has no passphrase, so nothing may block
    # on a prompt that will never be answered. The `Could not set GPG_TTY`
    # warning it prints is that, and is harmless.
    rpmsign --define "_gpg_name rulesteward release signing" --addsign "$signed" < /dev/null
    local before after
    before="$(rpm -qp --qf '%{PAYLOADDIGEST}' "$unsigned")"
    after="$(rpm -qp --qf '%{PAYLOADDIGEST}' "$signed")"
    [ "$before" = "$after" ] \
        || die "signing rewrote more than the signature header: unsigned PAYLOADDIGEST $before, signed $after"
    log "unsigned $(sha256sum "$unsigned")"
    log "signed   $(sha256sum "$signed")"
}

publish() {
    # No local fallback tag here on purpose: publish creates a public release, so
    # it runs only where a tag ref exists, which is the tag-triggered CI job.
    [ -n "${GITHUB_REF_NAME:-}" ] || die "GITHUB_REF_NAME is unset: publish runs on the tag CI job only"
    need gh
    sums
    # RPM-GPG-KEY-rulesteward rides along because `rpm --import` wants the key
    # before `rpm -K` on the package means anything, and a release page is where
    # a downloader who has neither already looks.
    gh release create "$GITHUB_REF_NAME" --generate-notes dist/*.tar.gz dist/*.rpm dist/SHA256SUMS RPM-GPG-KEY-rulesteward
}

# The attestation the attest step wrote, read back the way a downloader reads it:
# `gh attestation verify` hashes the local file and asks the repo's attestation
# store for a signed statement over that digest. A subject-path that missed one of
# the two artifacts, or a file rewritten after it was attested, fails here rather
# than on somebody's machine. Unlike SHA256SUMS this is not self-referential --
# whoever replaces the tarball cannot replace the signature over its digest.
verify() {
    # Same reasoning as publish's GITHUB_REF_NAME: the store being asked is a
    # repository's, so there is no sensible local fallback to guess.
    [ -n "${GITHUB_REPOSITORY:-}" ] || die "GITHUB_REPOSITORY is unset: verify runs on the tag CI job only"
    need gh
    # errexit stops the loop on the first failure, which is the wanted behaviour:
    # one unverifiable artifact fails the release job.
    for f in dist/*.tar.gz dist/*.rpm; do
        gh attestation verify "$f" --repo "$GITHUB_REPOSITORY"
    done
}

case "${1:-}" in
    build)   build ;;
    rpm)     ./xtask/musl.sh; rpm_pkg ;;
    stage)   stage "${2:?usage: release.sh stage <dir>}" ;;
    tarball) tarball "${2:?usage: release.sh tarball <binary>}" ;;
    wrap)    rpm_pkg "${2:?usage: release.sh wrap <dir>}/rulesteward" "$2" ;;
    sign)    sign "${2:?usage: release.sh sign <dir>}" ;;
    publish) publish ;;
    verify)  verify ;;
    *)       die "usage: release.sh build|rpm|stage <dir>|tarball <bin>|wrap <dir>|sign <dir>|publish|verify" ;;
esac
