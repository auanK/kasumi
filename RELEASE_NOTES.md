# Kasumi v0.30.2

## Fixed

- **Linux `.directory` Folder Icon Detection & Freedesktop Themes**:
  - Fixed `.directory` icon resolution on Linux to support relative paths, absolute paths, `file://` URIs, symlinked folders/theme icons, and Freedesktop icon theme names (e.g. `folder-music`, `folder-blue`) using active KDE/GTK icon theme settings and standard XDG search directories (`breeze`, `Papirus`, `Adwaita`, `hicolor`, `/usr/share/pixmaps`).
  - Prioritized `.directory` on Linux and `desktop.ini` on Windows with cross-fallback so folders synchronized between Windows and Linux always resolve their platform icon cleanly.
  - Added validated SVG icon support (`image/svg+xml` with strict active-content rejection and `Content-Security-Policy: sandbox; default-src 'none'`) for `.directory`, theme icons, and custom uploads.
- **Web UI Icon Picker, Live Preview & Linux Polish**:
  - Fixed folder auto-detection live preview (`?mode=auto` with `Cache-Control: private, no-cache`) so switching to *Auto from folder* previews `.directory` / `desktop.ini` immediately even when a preset or custom icon is currently saved.
  - Preserved the saved *Custom image* option in the dropdown while testing presets before saving, differentiated the `preset:folder` icon from `preset:default`, added MIME types + `.svg` to the file picker filter for case-sensitive Linux GTK/KDE portals, styled native `<select>` `<option>` popups for Linux dark themes, and updated `en` / `pt-BR` labels.
- **Profile Cloning with Custom Icons**:
  - Preserved `custom-icon.*` files atomically when cloning a profile so cloned profiles display their custom icon immediately.

## Compatibility

100% compatible with repositories, CLI commands, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.30.1` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the installer or portable archive for your platform (`kasumi-v0.30.2-windows-x86_64.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, or `.tar.gz`), verify it against `SHA256SUMS.txt` or `gh attestation verify`, check `kasumi --version` (or `kasumi version`), and run `kasumi web` to open the embedded Web UI.
