# Kasumi v0.31.2

## Highlights

- **Eliminated False "In Use by CLI" Status**:
  - Fixed concurrent background status checks colliding with each other on lock files, closed a brief race window when internal daemon tasks finish, and tracked conflict-resolution locks so idle or Web UI–managed profiles no longer flash as **In use by CLI**.
- **Collapsed Profile List on Hub Startup**:
  - Opening the Hub now starts with all profiles collapsed by default instead of automatically expanding the first profile, while preserving direct links and newly created profile focus.

## Compatibility

100% compatible with repositories, CLI commands, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.31.1` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the installer or portable archive for your platform (`kasumi-v0.31.2-windows-x86_64.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, or `.tar.gz`), verify it against `SHA256SUMS.txt` or `gh attestation verify`, check `kasumi --version` (or `kasumi version`), and run `kasumi web` to open the embedded Web UI.
