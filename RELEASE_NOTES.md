# Kasumi v0.31.1

## Highlights

- **Reliable Barrier & Writer Cleanup on Cancellation**:
  - Cancelling garbage collection or stopping the daemon now reliably removes remote maintenance barriers and abandoned writer markers (and publishes the cancelled activity record) instead of leaving profiles blocked with `GC active on destination`.
- **Faster Garbage Collection with Live Progress**:
  - Garbage collection now reuses the local encrypted commit cache instead of re-downloading all historical commits from the cloud, streams live commit-verification progress to the Hub and CLI, and stops cloud transfers cleanly if cancelled.
- **No Background Sync Collisions During Maintenance**:
  - Scheduled daemon syncs now wait while a maintenance job is running on the same profile instead of failing with misleading lock-busy errors.

## Compatibility

100% compatible with repositories, CLI commands, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.31.0` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the installer or portable archive for your platform (`kasumi-v0.31.1-windows-x86_64.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, or `.tar.gz`), verify it against `SHA256SUMS.txt` or `gh attestation verify`, check `kasumi --version` (or `kasumi version`), and run `kasumi web` to open the embedded Web UI.
