# Kasumi v0.15.0

Kasumi now reports live progress in interactive terminals and measured transfer totals at the end of sync.

## Highlights

- `status` and `sync --dry-run` show local discovery, cache hits, and hashing alongside remote observation. `sync` and `resolve-missing` also show staging, transfers, verification, installation, and retries.
- Sync summaries show encrypted bytes and physical objects uploaded and downloaded, alongside the bytes saved through local chunk reuse and deduplication. Transfer rates and estimated time remaining appear when enough data is available.
- `fsck`, `gc`, remote inspection, and update downloads report progress during long operations. Redirected output keeps the familiar line-by-line format.
- rclone copies stay batched. Ctrl+C stops the active rclone job, and no-op sync keeps its existing content-probe behavior.

## Compatibility

- `v0.15.0` uses the same Protocol v3 vault format, flat commit layout, transaction journal v10, and profile configuration as `v0.14.2`. Follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).
