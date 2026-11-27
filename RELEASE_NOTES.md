# Kasumi v0.30.3

## Highlights

- **Faster History & Snapshot Loading on Cloud Remotes**:
  - Added a bounded two-tier cache for immutable, content-addressed commit objects: an in-memory LRU cache in the daemon plus a persistent encrypted-ciphertext cache under `cache/commits/` with integrity verification, automatic corruption self-healing, and live remote-existence enforcement.
  - Overlapped and parallelized local verification, decryption, and decoding of prefetched and disk-cached commits across worker threads.
  - Scoped non-auditing remote history operations (`RemoteCommits`, historical `RemoteTree`, `RemoteCommit`, `RemoteLog`, `RemoteStat`, `RemoteGet`, `RemoteRestore`, and download sessions) to list only `heads/`, `commits/`, and `epochs/` concurrently via `rclone_control_read_batch` instead of scanning all encrypted content blobs and packs.
- **Single-Observation Snapshot Diffs (`/v1/remote/{profile}/diff`)**:
  - Added `inspect_commit_pair()` so comparing two snapshots observes remote history once instead of twice.
- **Instant Cached Snapshot Modal in Files Explorer**:
  - Opening **Browse snapshots** in the **Files** tab now renders previously cached snapshots immediately while revalidating stale entries in the background, matching the **History** tab.

## Compatibility

100% compatible with repositories, CLI commands, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.30.2` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the installer or portable archive for your platform (`kasumi-v0.30.3-windows-x86_64.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, or `.tar.gz`), verify it against `SHA256SUMS.txt` or `gh attestation verify`, check `kasumi --version` (or `kasumi version`), and run `kasumi web` to open the embedded Web UI.
