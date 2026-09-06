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
#
# **.tools/bin converges to the list in main().** What is missing is installed,
# what is not on the list is pruned. A directory that only ever gains entries
# becomes whatever every past run left in it.

# shellcheck source=xtask/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

JUST_VERSION=1.46.0
CARGO_DENY_VERSION=0.20.2
CARGO_MUTANTS_VERSION=27.1.0
TYPOS_VERSION=1.50.1

# tool:version -> sha256 of the artifact url() names.
#
# just and cargo-deny are publisher checksums, taken from just's SHA256SUMS and
# from cargo-deny's per-asset .sha256 file at the pinned tag. Refreshing one
# means fetching that file again, not trusting a download.
#
# cargo-mutants and typos publish no checksums of any kind, so those two digests
# are SELF-COMPUTED: downloaded once, sha256sum'd, and committed here. That is
# weaker than a publisher digest -- it pins what was downloaded on one day rather
# than what the publisher says it shipped -- and still stronger than an
# unverified download on every run.
digest() {
    case "$1" in
        just:1.46.0)          echo 79966e6e353f535ee7d1c6221641bcc8e3381c55b0d0a6dc6e54b34f9db36eaa ;;
        cargo-deny:0.20.2)    echo 9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f ;;
        cargo-mutants:27.1.0) echo dfe6dc37d0342c891d2829b5a695aa57c2d0edecef7e7d0399a30cc6e206411e ;; # self-computed
        typos:1.50.1)         echo edf0545109aee6a22751d04ddecb97c45be47d3aa0409564fb895eeeace91b1e ;; # self-computed
        *) die "no pinned digest for $1 -- add it beside the others" ;;
    esac
}

# Each project spells its own tag and target triple; there is no pattern to
# factor out. cargo-mutants is the gnu build because it is the only linux asset
# it publishes -- the other three are musl.
url() {
    case "$1" in
        just)          echo "https://github.com/casey/just/releases/download/${2}/just-${2}-x86_64-unknown-linux-musl.tar.gz" ;;
        cargo-deny)    echo "https://github.com/EmbarkStudios/cargo-deny/releases/download/${2}/cargo-deny-${2}-x86_64-unknown-linux-musl.tar.gz" ;;
        cargo-mutants) echo "https://github.com/sourcefrog/cargo-mutants/releases/download/v${2}/cargo-mutants-x86_64-unknown-linux-gnu.tar.gz" ;;
        typos)         echo "https://github.com/crate-ci/typos/releases/download/v${2}/typos-v${2}-x86_64-unknown-linux-musl.tar.gz" ;;
    esac
}

# Verified download into the scratch dir. The check is `sha256sum -c -` rather
# than a string compare, so a truncated download fails here instead of unpacking
# into something surprising.
fetch() {
    local tool="$1" version="$2" dest="$3" want src file
    # Here rather than in main(): a box that already carries all four tools never
    # reaches this function and should not be refused for lacking curl.
    need curl
    want="$(digest "${tool}:${version}")"
    src="$(url "$tool" "$version")"
    [ -n "$src" ] || die "$tool: no download URL -- add a case arm to url()"
    file="$dest/$(basename "$src")"
    curl -fsSL --retry 3 -o "$file" "$src"
    echo "${want}  ${file}" | sha256sum -c - >/dev/null
    printf '%s\n' "$file"
}

# A regular, executable file -- not merely something with the execute bit, which
# every directory has.
installed() {
    [ -f "$TOOLS_BIN/$1" ] && [ -x "$TOOLS_BIN/$1" ]
}

install_one() {
    local tool="$1" version="$2" tmp file
    if installed "$tool"; then
        log "  $tool: already in .tools/bin"
        return
    fi
    tmp="$TMP/$tool"; mkdir -p "$tmp"
    log "  $tool $version: downloading"
    file="$(fetch "$tool" "$version" "$tmp")"
    tar -xzf "$file" -C "$tmp"
    # cargo-mutants unpacks a bare binary, typos and just unpack flat under ./,
    # cargo-deny nests under a versioned directory. `find -type f -name` covers
    # all three without hardcoding any of them.
    find "$tmp" -type f -name "$tool" -perm -u+x -exec mv {} "$TOOLS_BIN/$tool" \;
    installed "$tool" || die "$tool: archive did not contain an executable named $tool"
}

main() {
    mkdir -p "$TOOLS_BIN"
    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
    local entry name file listed=""
    # One list, read twice: once to install and once to decide what does not
    # belong. `tool:version` is the same key digest() takes, so the two spell a
    # pair the same way.
    local -a tools=(
        "just:$JUST_VERSION"
        "cargo-deny:$CARGO_DENY_VERSION"
        "cargo-mutants:$CARGO_MUTANTS_VERSION"
        "typos:$TYPOS_VERSION"
    )
    log "installing tools into .tools/bin"
    for entry in "${tools[@]}"; do
        install_one "${entry%%:*}" "${entry#*:}"
        listed="$listed ${entry%%:*}"
    done
    # Only regular files, so any directory under .tools/bin is out of scope by
    # construction.
    for file in "$TOOLS_BIN"/*; do
        [ -f "$file" ] || continue
        name="${file##*/}"
        case "$listed " in
            *" $name "*) continue ;;
        esac
        log "  prune: $name"
        rm -f "$file"
    done
    log "done"
}

main "$@"
