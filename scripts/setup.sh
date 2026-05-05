#!/usr/bin/env bash
#
# remoteTool one-shot installer.
#
# Installs system build/runtime dependencies, builds a private patched
# copy of FreeRDP 3 (with channel plugins as loadable .so files), and
# builds the remoteTool binary. Idempotent: skips steps that are
# already done.
#
# Run from the repo root:
#   ./scripts/setup.sh
#
# Tested on Linux Mint 22 (Ubuntu 24.04 base). Requires sudo for apt
# and the FreeRDP install step; everything else runs as the invoking
# user.
#
# What it does:
#   1. apt-installs runtime + build deps (gtk, vte, libssh, freerdp
#      headers, cmake, X11 dev packages, ...).
#   2. Downloads FreeRDP 3.5.1 source to a build dir, applies the
#      patches under patches/, builds with channel plugins enabled,
#      installs to /opt/remotetool-freerdp (private prefix - does NOT
#      shadow the system FreeRDP).
#   3. Runs `make` in the repo root, producing build/remotetool.
#
# Why the FreeRDP rebuild:
#   Ubuntu/Mint's FreeRDP 3 package ships zero channel plugin .so
#   files, and FreeRDP 3 upstream itself only emits channels as object
#   files linked into xfreerdp - never as loadable .so plugins. We
#   patch the cmake to emit MODULE libraries and run them through a
#   linker --defsym to alias the entry symbols dlopen looks for.
#
# Re-running this script: safe. Detects existing FreeRDP install and
# skips the rebuild unless --force is passed.

set -euo pipefail

# ------------------------------------------------------------------ #
# Config
# ------------------------------------------------------------------ #

FREERDP_VERSION=3.5.1
FREERDP_PREFIX=/opt/remotetool-freerdp
FREERDP_TARBALL_URL="https://github.com/FreeRDP/FreeRDP/archive/refs/tags/${FREERDP_VERSION}.tar.gz"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH_DIR="${REPO_ROOT}/patches"
BUILD_DIR="${REPO_ROOT}/.freerdp-build"

# ------------------------------------------------------------------ #
# Args
# ------------------------------------------------------------------ #

FORCE=0
SKIP_DEPS=0
SKIP_FREERDP=0
SKIP_APP=0

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --force          Rebuild FreeRDP even if /opt/remotetool-freerdp exists.
  --skip-deps      Don't run apt install.
  --skip-freerdp   Don't (re)build FreeRDP.
  --skip-app       Don't build the remoteTool binary at the end.
  -h, --help       Show this help.
EOF
}

for arg in "$@"; do
    case "$arg" in
        --force)        FORCE=1 ;;
        --skip-deps)    SKIP_DEPS=1 ;;
        --skip-freerdp) SKIP_FREERDP=1 ;;
        --skip-app)     SKIP_APP=1 ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; usage; exit 1 ;;
    esac
done

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[setup]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[setup]\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

# ------------------------------------------------------------------ #
# Step 1: system packages
# ------------------------------------------------------------------ #

install_deps() {
    log "Installing system packages (sudo apt install)..."

    # Runtime + build deps for remoteTool itself plus build deps for
    # FreeRDP. Most of these come along with libgtk-3-dev / freerdp3-dev
    # already on a typical desktop install, but we pin them here for
    # fresh machines.
    local pkgs=(
        # remoteTool runtime + build
        build-essential
        pkg-config
        libgtk-3-dev
        libvte-2.91-dev
        libssh-dev
        # FreeRDP build prerequisites
        cmake
        libssl-dev
        libx11-dev
        libxcursor-dev
        libxext-dev
        libxinerama-dev
        libxrandr-dev
        libxv-dev
        libxrender-dev
        libxfixes-dev
        libxdamage-dev
        libxtst-dev
        libxkbfile-dev
        libxkbcommon-dev
        zlib1g-dev
        libkrb5-dev
        libpkcs11-helper1-dev
        libcjson-dev
        libusb-1.0-0-dev
        # The system FreeRDP3 dev package gives us many transitive
        # deps (uriparser, etc.) - cheaper to install than enumerate.
        freerdp3-dev
    )

    sudo apt update
    sudo apt install -y "${pkgs[@]}"
}

# ------------------------------------------------------------------ #
# Step 2: build private FreeRDP 3 with channel plugins
# ------------------------------------------------------------------ #

build_freerdp() {
    if [[ ${FORCE} -eq 0 && -f "${FREERDP_PREFIX}/lib/libfreerdp3.so.3" ]] \
       && [[ -f "${FREERDP_PREFIX}/lib/freerdp3/libdisp-client.so" ]]; then
        log "FreeRDP already installed at ${FREERDP_PREFIX} - skipping build (use --force to rebuild)."
        return
    fi

    log "Building FreeRDP ${FREERDP_VERSION} into ${FREERDP_PREFIX}..."

    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    local tarball="freerdp-${FREERDP_VERSION}.tar.gz"
    local srcdir="FreeRDP-${FREERDP_VERSION}"

    if [[ ! -f "${tarball}" ]]; then
        log "Downloading ${FREERDP_TARBALL_URL}..."
        require_cmd wget
        wget -q "${FREERDP_TARBALL_URL}" -O "${tarball}.partial"
        mv "${tarball}.partial" "${tarball}"
    fi

    if [[ ! -d "${srcdir}" ]]; then
        log "Extracting source..."
        tar xf "${tarball}"
    fi

    # Apply each patch under patches/ (idempotent: dry-run check first).
    log "Applying patches..."
    cd "${srcdir}"
    for p in "${PATCH_DIR}"/*.patch; do
        [[ -f "$p" ]] || continue
        local pname; pname="$(basename "$p")"
        # If already applied (forward dry-run rejects), skip.
        if patch -p1 --dry-run --silent < "$p" >/dev/null 2>&1; then
            log "  applying ${pname}"
            patch -p1 < "$p"
        elif patch -p1 -R --dry-run --silent < "$p" >/dev/null 2>&1; then
            log "  ${pname} already applied, skipping"
        else
            die "Patch ${pname} does not apply cleanly. Source tree may be wrong version."
        fi
    done
    cd ..

    log "Configuring CMake (${FREERDP_PREFIX})..."
    rm -rf build
    mkdir -p build
    cd build

    # Minimal client-only build: skip server/proxy/shadow, skip optional
    # codecs we don't need, skip the X11 xfreerdp client (we'd break it
    # by changing how channels are built anyway).
    cmake "../${srcdir}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="${FREERDP_PREFIX}" \
        -DWITH_ABSOLUTE_PLUGIN_LOAD_PATHS=ON \
        -DWITH_CLIENT_CHANNELS=ON \
        -DWITH_SERVER=OFF \
        -DWITH_SHADOW=OFF \
        -DWITH_PROXY=OFF \
        -DWITH_SAMPLE=OFF \
        -DWITH_PLATFORM_SERVER=OFF \
        -DWITH_CLIENT_INTERFACE=ON \
        -DWITH_CLIENT_SDL=OFF \
        -DWITH_CLIENT_COMMON=ON \
        -DWITH_X11=OFF \
        -DWITH_WAYLAND=OFF \
        -DBUILD_TESTING=OFF \
        -DWITH_MANPAGES=OFF \
        -DWITH_FFMPEG=OFF \
        -DWITH_SWSCALE=OFF \
        -DWITH_PULSE=OFF \
        -DWITH_OSS=OFF \
        -DWITH_ALSA=OFF \
        -DWITH_PCSC=OFF \
        -DWITH_CUPS=OFF \
        -DWITH_AAD=OFF \
        -DWITH_FUSE=OFF \
        -DWITH_WEBVIEW=OFF >/dev/null

    log "Compiling (this is the slow step)..."
    make -j"$(nproc)" >/dev/null

    log "Installing (sudo)..."
    sudo make install >/dev/null
    sudo ldconfig

    log "FreeRDP installed: $(ls "${FREERDP_PREFIX}/lib/freerdp3/" | wc -l) channel plugins."
}

# ------------------------------------------------------------------ #
# Step 3: build remoteTool
# ------------------------------------------------------------------ #

build_app() {
    log "Building remoteTool..."
    cd "${REPO_ROOT}"
    make clean
    make
    log "Done. Binary at ${REPO_ROOT}/build/remotetool"
    log "Run with: make run"
}

# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

main() {
    [[ $EUID -eq 0 ]] && die "Don't run as root. The script will sudo when it needs to."

    log "remoteTool setup starting..."
    log "  repo:    ${REPO_ROOT}"
    log "  freerdp: ${FREERDP_PREFIX} (version ${FREERDP_VERSION})"

    [[ ${SKIP_DEPS}    -eq 0 ]] && install_deps
    [[ ${SKIP_FREERDP} -eq 0 ]] && build_freerdp
    [[ ${SKIP_APP}     -eq 0 ]] && build_app

    log "All done."
}

main
