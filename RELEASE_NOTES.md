# Kasumi v0.30.0

## Highlights

- **Embedded Single-Binary Web UI (`kasumi web`)**:
  - Kasumi now embeds a full Vue 3 Web UI directly inside the `kasumi` executable and serves it on `http://127.0.0.1:3137/` when the daemon runs — preserving single-binary distribution across `.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, and `.tar.gz`.
  - Run `kasumi web` to start the daemon if needed and open the interface, or `kasumi web set-password` to configure your login password directly from the terminal (`en` and `pt-BR`).
- **Visual Workspace, File Previews, History & Maintenance**:
  - Manage profiles from the **Hub** and creation wizard (`rclone` remote discovery, OS vault checks, key storage controls, pause/resume/sync), inspect live daemon telemetry and logs in real time via Server-Sent Events (`/v1/events/stream`), browse local and remote trees with raster/text/media previews and byte-range streaming, inspect commit history and text diffs, restore files or snapshots, resolve conflicts visually, and run previewed `fsck`, `repack`, `gc`, and `.kasumiignore` checks.
- **Authenticated Browser HTTP API & Modular Daemon**:
  - Added `/v1/*` browser endpoints with Argon2id single-user session auth (`web-bootstrap.token` / `web-password.json`), DNS-rebinding `Host` validation, CSRF/Origin checks, progressive login backoff, and a complete OpenAPI 3.1 contract (`docs/api/openapi.yaml`).
  - Modularized the daemon scheduler/state/event engine, indexed local tree snapshots in `db.sqlite`, and split platform vault backends (`vault_linux.cpp`, `vault_windows.cpp`).
- **Desktop Installers & Upgrade Polish**:
  - Windows `.msi` now adds a Start Menu **Kasumi** shortcut, gracefully stops a running daemon during in-place upgrades or uninstalls, and offers an interactive finish option to start with Windows and open the Web UI.
  - Linux packages (`.deb`, `.rpm`, `.pkg.tar.zst`) include `/usr/share/applications/kasumi.desktop` (`Exec=/usr/bin/kasumi web`) and updated `PKGBUILD` Web UI build steps.

## Fixed

- **Cross-Process Windows Credential Manager Serialization**: Serialized Windows Credential Manager access across processes using the named mutex `Local\KasumiWindowsCredentialManager` (implemented with free-function guards) and expanded transient `ERROR_NOT_FOUND` retries in `read_vault`, eliminating races when concurrent daemon or CLI processes access credentials simultaneously.

## Compatibility

100% compatible with repositories, CLI commands, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.29.2` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the installer or portable archive for your platform (`kasumi-v0.30.0-windows-x86_64.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, or `.tar.gz`), verify it against `SHA256SUMS.txt` or `gh attestation verify`, check `kasumi --version` (or `kasumi version`), and run `kasumi web` to open the embedded Web UI.
