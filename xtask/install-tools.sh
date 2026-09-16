#!/usr/bin/env bash
# Installs the pinned tool binaries this repo checks itself with into .tools/bin.
# Called directly and never through `just`, because it is what puts `just` on a
# runner that has none.
#
# **Pinned tarballs with committed digests, not marketplace actions.** An action
# at a mutable tag is somebody else's moving code running with the job's token,
# and `cargo binstall --only-signed` would refuse all four of these: none of them
# publish minisign metadata.
#
# **Always into .tools/bin, never /usr/local/bin and never $GITHUB_PATH.** A
# worktree owns its own copies, so nothing it runs depends on another checkout,
# and nothing here reads a CI platform's variables -- which is what keeps
# .github/ deletable. Callers spell the path: CI runs `./.tools/bin/just`, and
# the justfile prepends the directory to PATH for the recipes.

# shellcheck source=xtask/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# One row per tool: name, version, sha256 of the tarball, tarball URL. Bumping a
# tool is one row. Each project spells its own tag and target triple, so the URL
# is written out rather than templated; cargo-mutants is the gnu build because
# it is the only linux asset it publishes -- the other three are musl.
#
# just and cargo-deny digests are publisher checksums, taken from just's
# SHA256SUMS and from cargo-deny's per-asset .sha256 file at the pinned tag.
# Refreshing one means fetching that file again, not trusting a download.
#
# cargo-mutants and typos publish no checksums of any kind, so those two digests
# are SELF-COMPUTED: downloaded once, sha256sum'd, and committed here. That is
# weaker than a publisher digest -- it pins what was downloaded on one day rather
# than what the publisher says it shipped -- and still stronger than an
# unverified download on every run.
TOOLS=(
    "just          1.46.0 79966e6e353f535ee7d1c6221641bcc8e3381c55b0d0a6dc6e54b34f9db36eaa https://github.com/casey/just/releases/download/1.46.0/just-1.46.0-x86_64-unknown-linux-musl.tar.gz"
    "cargo-deny    0.20.2 9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz"
    "cargo-mutants 27.1.0 dfe6dc37d0342c891d2829b5a695aa57c2d0edecef7e7d0399a30cc6e206411e https://github.com/sourcefrog/cargo-mutants/releases/download/v27.1.0/cargo-mutants-x86_64-unknown-linux-gnu.tar.gz" # self-computed
    "typos         1.50.1 edf0545109aee6a22751d04ddecb97c45be47d3aa0409564fb895eeeace91b1e https://github.com/crate-ci/typos/releases/download/v1.50.1/typos-v1.50.1-x86_64-unknown-linux-musl.tar.gz" # self-computed
)

# Verified download into the scratch dir. The check is `sha256sum -c -` rather
# than a string compare, so a truncated download fails here instead of unpacking
# into something surprising.
fetch() {
    local want="$1" src="$2" dest="$3" file
    # Here rather than in main(): a box that already carries all four tools never
    # reaches this function and should not be refused for lacking curl.
    need curl
    file="$dest/$(basename "$src")"
    curl -fsSL --retry 3 -o "$file" "$src"
    echo "${want}  ${file}" | sha256sum -c - >/dev/null
    printf '%s\n' "$file"
}

install_one() {
    local tool="$1" version="$2" want="$3" src="$4" tmp file
    [ -x "$TOOLS_BIN/$tool" ] && { log "  $tool: already in .tools/bin"; return; }
    tmp="$TMP/$tool"; mkdir -p "$tmp"
    log "  $tool $version: downloading"
    file="$(fetch "$want" "$src" "$tmp")"
    tar -xzf "$file" -C "$tmp"
    # cargo-mutants unpacks a bare binary, typos and just unpack flat under ./,
    # cargo-deny nests under a versioned directory. `find -type f -name` covers
    # all three without hardcoding any of them.
    find "$tmp" -type f -name "$tool" -perm -u+x -exec mv {} "$TOOLS_BIN/$tool" \;
    [ -x "$TOOLS_BIN/$tool" ] || die "$tool: archive did not contain an executable named $tool"
}

main() {
    mkdir -p "$TOOLS_BIN"
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    local row
    log "installing tools into .tools/bin"
    for row in "${TOOLS[@]}"; do
        # Unquoted on purpose: the row is four space-separated words by construction.
        # shellcheck disable=SC2086
        install_one $row
    done
    log "done"
}

main "$@"
