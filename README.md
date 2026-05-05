# remoteTool

NOTE: This is not intended to be used in production

A native Linux desktop client for connecting to remote systems over **SSH** and
**RDP**, with VMware-Workstation-style tabs.

- GTK 3 UI with tab-based session management
- SSH via libssh — full xterm emulation through VTE (colors, cursor, scrollback,
  vim/htop, mouse selection, dynamic PTY resize)
- RDP via FreeRDP 3 — keyboard, mouse, clipboard sync (CLIPRDR), and
  server-driven dynamic resolution change (DispDyn)
- Per-session worker thread; UI never blocks on the network

## Quick install

```bash
git clone <this-repo> remoteTool && cd remoteTool
./scripts/setup.sh
make run
```

`setup.sh` will:

1. `apt install` runtime + build dependencies
2. Download FreeRDP 3.5.1, apply the patches under [patches/](patches/), build
   it with channel plugins enabled, and install to `/opt/remotetool-freerdp`
   (a private prefix — does NOT shadow system FreeRDP)
3. Build `build/remotetool`

Re-running the script is safe: it skips steps that are already done. Pass
`--force` to rebuild FreeRDP; `--skip-freerdp` / `--skip-deps` / `--skip-app` to
target individual phases.

## Why does this need to rebuild FreeRDP?

Two issues that compound:

1. **Ubuntu/Mint's FreeRDP 3 package ships zero channel plugin `.so` files.**
   The library is there, the headers are there, but `/usr/lib/x86_64-linux-gnu/freerdp3/`
   doesn't exist — none of `libcliprdr-client.so`, `libdisp-client.so`,
   `libdrdynvc-client.so`, `librdpdr-client.so`, etc. Without those, no
   clipboard, no dynamic resolution, no anything channel-based.
2. **FreeRDP 3 upstream itself doesn't emit channels as loadable plugins.**
   The cmake builds them as `OBJECT` libraries that get statically linked into
   `xfreerdp` directly. The dlopen path that `libfreerdp-client3.so` uses for
   third-party clients (us) is legacy code from FreeRDP 2 — present but with
   no plugin files to load.

The patches under [patches/](patches/) flip channels to `MODULE` libraries (so
they emit `.so` files), add linker `--defsym` aliases so the entry symbols
match what the dlopen path expects, and export
`channel_client_quit_handler` (which several plugins reference but upstream
forgot to mark `FREERDP_API`).

We install into `/opt/remotetool-freerdp/` and `rpath` our binary at it, so
nothing else on the system — including system `xfreerdp3` — picks up the
patched build by accident.

## Manual install (if `setup.sh` doesn't fit your environment)

### System packages

```bash
sudo apt install -y \
  build-essential pkg-config \
  libgtk-3-dev libvte-2.91-dev libssh-dev \
  cmake libssl-dev libx11-dev libxcursor-dev libxext-dev \
  libxinerama-dev libxrandr-dev libxv-dev libxrender-dev \
  libxfixes-dev libxdamage-dev libxtst-dev libxkbfile-dev \
  libxkbcommon-dev zlib1g-dev libkrb5-dev libpkcs11-helper1-dev \
  libcjson-dev libusb-1.0-0-dev freerdp3-dev
```

### Build patched FreeRDP

```bash
mkdir -p .freerdp-build && cd .freerdp-build
wget https://github.com/FreeRDP/FreeRDP/archive/refs/tags/3.5.1.tar.gz \
  -O freerdp-3.5.1.tar.gz
tar xf freerdp-3.5.1.tar.gz
cd FreeRDP-3.5.1
for p in ../../patches/*.patch; do patch -p1 < "$p"; done
cd ..
mkdir -p build && cd build
cmake ../FreeRDP-3.5.1 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/opt/remotetool-freerdp \
  -DWITH_ABSOLUTE_PLUGIN_LOAD_PATHS=ON \
  -DWITH_CLIENT_CHANNELS=ON \
  -DWITH_SERVER=OFF -DWITH_SHADOW=OFF -DWITH_PROXY=OFF \
  -DWITH_SAMPLE=OFF -DWITH_PLATFORM_SERVER=OFF \
  -DWITH_X11=ON -DWITH_WAYLAND=OFF -DWITH_CLIENT_SDL=OFF \
  -DBUILD_TESTING=OFF -DWITH_MANPAGES=OFF \
  -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF \
  -DWITH_PULSE=OFF -DWITH_OSS=OFF -DWITH_ALSA=OFF \
  -DWITH_PCSC=OFF -DWITH_CUPS=OFF -DWITH_AAD=OFF \
  -DWITH_FUSE=OFF -DWITH_WEBVIEW=OFF
make -j$(nproc)
sudo make install
sudo ldconfig
```

`WITH_X11=ON` is required even though we don't ship `xfreerdp` itself — it's
what compiles the XKB keyboard scancode helpers into libfreerdp. Patch 03
disables the `xfreerdp` binary build (which would fail-link against our
MODULE-built channels). The repo-side Makefile already handles linking the
remoteTool app against `/opt/remotetool-freerdp`.

### Build remoteTool

```bash
make run
```

The Makefile points `pkg-config` and `rpath` at `/opt/remotetool-freerdp` so
nothing else on the system is affected.

## Project layout

```
include/
  core/              connection model, session lifecycle
  protocols/         protocol abstraction + per-back-end headers
  ui/                widget interfaces
src/
  core/              session marshalling between worker threads and GTK loop
  protocols/
    ssh/             libssh back-end (PTY, TOFU known_hosts, resize)
    rdp/             FreeRDP back-end (GDI framebuffer, DispDyn, cert TOFU,
                     CLIPRDR text)
  ui/
    main_window.c    branches on protocol to pick terminal vs RDP view
    terminal_view.c  VTE wrapper for SSH
    rdp_view.c       cairo-blit canvas + input forwarding for RDP
    connection_form.c  protocol-aware form
patches/             FreeRDP source patches (see "Why does this need..." above)
scripts/setup.sh     one-shot installer
```

## Architecture

Three layers, no upward dependencies:

1. **UI** (`src/ui/`) — GTK widgets. Knows about sessions, knows nothing about
   libssh or FreeRDP.
2. **Session core** (`src/core/`) — bridges protocol back-ends to the GTK main
   loop via a `GAsyncQueue` + idle source. Per-session worker thread.
3. **Protocol back-ends** (`src/protocols/`) — concrete protocol implementations
   behind a single vtable (`rt_protocol_ops_t`). The registry in
   `protocols/protocol.c` is the only file that touches both back-ends.

Adding a new protocol means: a `protocols/<name>/` module exposing one
`rt_<name>_get_ops()` entry point, plus one `case` in `rt_protocol_lookup()`.

## Connection profiles

Stored host-key fingerprints live at:

- `~/.config/remoteTool/known_hosts` — SSH (managed by libssh)
- `~/.config/remoteTool/rdp_known_hosts` — RDP (TOFU, our format:
  `host port fingerprint`)

Delete a line to re-trust a server whose key changed.

## Security defaults

- Passwords are never persisted; they're wiped (`explicit_bzero`) immediately
  after use.
- Both back-ends do trust-on-first-use cert verification by default. Bypass is
  available per-RDP-connection via the form (clearly marked **INSECURE**, lab
  use only).
- Legacy SSL is disabled by default and not exposed in the UI.
- Clipboard contents are never logged.

## Tested on

- Linux Mint 22.2 (Ubuntu 24.04 noble)
- GTK 3.24, VTE 0.76, libssh 0.10, FreeRDP 3.5.1

## Status

- **Phase 1 (MVP)**: GTK window, tabs, manual connection form ✓
- **Phase 2**: SSH + RDP through a shared protocol abstraction ✓
- **Phase 3**: RDP rendering, input forwarding, clipboard, scaling ✓
- **Phase 3.5**: DispDyn server-side resize, RDP cert TOFU ✓
- **Phase 4** (planned): saved profiles, secure credential storage
  (libsecret), reconnect logic, VNC
