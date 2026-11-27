# Kasumi v0.31.0

## Highlights

- **Live Maintenance Progress on the Hub**:
  - Active maintenance operations (`fsck`, `gc`, `repack`, `resolve-missing`, and marker removals) now display step progress and meters directly inside profile cards on the Hub, matching active syncs with a cleaner neutral header and continuous lavender side indicator.
- **Batch Abandoned Writer Cleanup & Live List Refresh**:
  - Added a **Remove all (`N`)** action in **Maintenance → Recovery** (backed by batch writer removal in the daemon API), and updated Recovery lists to refresh automatically right after writer or barrier removal completes so deleted markers cannot remain selectable.
- **Editable Explorer Address Bar in Files**:
  - Clicking the path bar (or pressing `Alt+D` / `Ctrl+L`) selects the entire path for desktop-style editing with `/` or `\` separator support, folder suggestions, direct file jumping on `Enter`, and `Escape` cancellation.
- **Consistent Login & Setup Screens**:
  - Unified the Web UI login and initial-setup pages with the app's persistent top bar and card header layout, translated the password visibility toggle, added smart input autofocus, and kept the primary sign-in button visually active.

## Compatibility

100% compatible with repositories, CLI commands, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.30.4` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the installer or portable archive for your platform (`kasumi-v0.31.0-windows-x86_64.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, or `.tar.gz`), verify it against `SHA256SUMS.txt` or `gh attestation verify`, check `kasumi --version` (or `kasumi version`), and run `kasumi web` to open the embedded Web UI.
