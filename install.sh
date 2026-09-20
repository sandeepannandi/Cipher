#!/bin/sh
# CipherAI installer.
#
# Explicit platform, version, and integrity behavior - no blind curl pipe:
# the release binary is verified against the SHA256SUMS.txt published with
# the release before anything is installed.
#
# Usage:
#   sh install.sh [--version vX.Y.Z] [--prefix DIR]
#   sh install.sh --resolve-target <os> <arch>   # print target triple, exit
#
# Options:
#   --version   Release tag to install (default: latest published release)
#   --prefix    Install directory (default: ~/.local/bin, or $CIPHER_AI_PREFIX)
set -eu

REPO="sandeepannandi/Cipher"
VERSION=""
PREFIX="${CIPHER_AI_PREFIX:-$HOME/.local/bin}"

die() { echo "install: $*" >&2; exit 1; }

# Map an uname-style OS/arch pair to a release target triple.
resolve_target() {
    case "$1" in
        Linux)
            case "$2" in
                x86_64|amd64)  echo "x86_64-unknown-linux-gnu" ;;
                aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
                *) return 1 ;;
            esac
            ;;
        Darwin)
            case "$2" in
                x86_64)        echo "x86_64-apple-darwin" ;;
                arm64|aarch64) echo "aarch64-apple-darwin" ;;
                *) return 1 ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            case "$2" in
                x86_64|amd64) echo "x86_64-pc-windows-msvc" ;;
                *) return 1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

# Test hook: print the triple for a given platform and exit.
if [ "${1:-}" = "--resolve-target" ]; then
    resolve_target "${2:-}" "${3:-}" || die "unsupported platform: ${2:-?} ${3:-?}"
    exit 0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --prefix)  PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

TARGET=$(resolve_target "$(uname -s)" "$(uname -m)") \
    || die "unsupported platform: $(uname -s) $(uname -m) - build from source (see README)"

case "$TARGET" in
    *windows*) EXT=".exe" ;;
    *)         EXT="" ;;
esac
ARTIFACT="cipher-ai-${TARGET}${EXT}"

fetch() { # fetch <url> - to stdout, via curl or wget
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1"
    else
        die "need curl or wget to download $1"
    fi
}

if [ -z "$VERSION" ]; then
    VERSION=$(fetch "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    [ -n "$VERSION" ] || die "could not resolve the latest release tag - pass --version vX.Y.Z"
fi

BASE="https://github.com/${REPO}/releases/download/${VERSION}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "install: cipher-ai ${VERSION} for ${TARGET}"
echo "install: downloading ${ARTIFACT} + SHA256SUMS.txt"
fetch "${BASE}/${ARTIFACT}" > "${TMP}/${ARTIFACT}" || die "download failed: ${BASE}/${ARTIFACT}"
fetch "${BASE}/SHA256SUMS.txt" > "${TMP}/SHA256SUMS.txt" || die "download failed: ${BASE}/SHA256SUMS.txt"

# Integrity: the release must carry a checksum line for this exact artifact,
# and the downloaded bytes must match it. Anything else is a hard failure.
grep " ${ARTIFACT}\$" "${TMP}/SHA256SUMS.txt" > "${TMP}/checksum.line" \
    || die "no checksum for ${ARTIFACT} in ${VERSION} SHA256SUMS.txt - refusing to install"
cd "$TMP"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c checksum.line >/dev/null || die "checksum mismatch for ${ARTIFACT} - refusing to install"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c checksum.line >/dev/null || die "checksum mismatch for ${ARTIFACT} - refusing to install"
else
    die "need sha256sum or shasum to verify ${ARTIFACT}"
fi
echo "install: checksum verified"

mkdir -p "$PREFIX"
cp "${TMP}/${ARTIFACT}" "${PREFIX}/cipher-ai${EXT}"
chmod +x "${PREFIX}/cipher-ai${EXT}"
echo "install: installed ${PREFIX}/cipher-ai${EXT}"
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) echo "install: add $PREFIX to your PATH" ;;
esac
"${PREFIX}/cipher-ai${EXT}" --version || true
echo "install: done - run 'cipher-ai setup' to configure an AI provider"
