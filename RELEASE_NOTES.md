# Kasumi v0.30.1

## Highlights

- **Streamlined Username-Only Account Editing**:
  - Split Web UI account editing into separate **Change username** and **Change password** tabs (`en` and `pt-BR`).
  - Updating your username (`POST /v1/auth/username`) now requires only your current password and a second confirmation dialog — no new-password fields required, and your active session stays logged in.
- **Syncthing-Style Network & Tailscale Listener (`0.0.0.0` / `kasumi web listen`)**:
  - Configure Web UI network exposure directly from **System -> Service -> Web UI & network access** or via `kasumi web listen 0.0.0.0:3137` (`--allow-host`, `--skip-host-check`).
  - Non-loopback binds remain fail-closed until a Web UI password is configured, and binding `0.0.0.0` or `::` automatically accepts direct Tailscale (`100.x.y.z`) and LAN IP literals alongside `*.domain` wildcard patterns in `allowed_hosts`.
- **Long-Lived Persistent Web UI Sessions**:
  - Extended browser sessions to **7 days** of inactivity / **30 days** total (`Max-Age=2592000`) and persisted hashed session tokens in owner-only `web-sessions.json` (`0600`) across daemon restarts while still revoking all sessions on explicit logout or password change.

## Compatibility

100% compatible with repositories, CLI commands, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.30.0` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the installer or portable archive for your platform (`kasumi-v0.30.1-windows-x86_64.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, or `.tar.gz`), verify it against `SHA256SUMS.txt` or `gh attestation verify`, check `kasumi --version` (or `kasumi version`), and run `kasumi web` to open the embedded Web UI.
