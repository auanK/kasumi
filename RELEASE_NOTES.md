# Kasumi v0.29.0

## Highlights

- **Cohesive Vertical CLI Layouts & UTC-Offset Timestamps**:
  - Standardized `kasumi` / `kasumi --full`, `kasumi list --full`, and `kasumi daemon status` / `daemon status --full` onto clean vertical profile blocks (`Name [State]` with aligned `Local:`, `Remote:`, `Last sync:`, and `Last change:` rows), removed the inconsistent green `ok` badge from profile menus, and unified all timestamps onto the same `YYYY-MM-DD HH:MM ±HH:MM` UTC-offset clock format used by `kasumi config` and `kasumi show`.
- **Clearer Command Discovery (`kasumi version`, `kasumi help`, Local vs. Remote Status)**:
  - Added subcommand forms `kasumi version` and `kasumi help [topic | --all]` alongside `--version`/`-v` and `--help`/`-h`.
  - Removed bare `kasumi status` as a local overview alias so local overview (`kasumi [--full]`) and remote preview (`kasumi status <profile>`) remain unambiguously separated.
- **Safer Manual Maintenance & Executable Metadata**:
  - Removed scheduled automatic GC execution from `kasumi daemon` (keeping manual `kasumi gc`, `repack`, and `fsck` unchanged, while still accepting and stripping legacy `gc_interval_hours` keys in existing `config.toml` files).
  - Updated the Windows executable description to reflect local paths, network shares, and `rclone`-compatible storage accurately.

## Fixed

- **30-Minute `fast_noop` Poll Stability**: Fixed `try_fast_remote_noop_poll()` / `finish_fast_noop()` not refreshing the warm SQLite metadata stamp after `state_storage::validate()` WAL read-write fallback, which previously forced every idle profile to alternate 1:1 between silent `fast_noop` polls and full sync scans every 10 minutes instead of verifying every 30 minutes.
- **`CopyLocal` Accounting in Sync Summaries**: Fixed `Action::CopyLocal` being skipped in `compute_sync_summary()`, which previously reported `up=0, down=0, rm=0, mv=0` / `no changes` when materializing duplicate-content files locally; syncs now record `copied` counts cleanly (`cp N`).
- **`rclone` Rate-Limit Resilience & Daemon Startup Pacing**: Classified HTTP `429` and rate-limit `403`/`5xx` responses (`rateLimitExceeded`, `userRateLimitExceeded`, `too many requests`, `quota exceeded`, throttling) as transient `BackendUnavailable` errors with bounded exponential-backoff read retries and daemon backoff, added default `3s` startup staggering and per-remote concurrency capping (`max_parallel_per_remote = 2`) in the daemon scheduler, and transitioned `active_stage` from `scanning` to `listing` while awaiting remote observation.

## Compatibility

100% compatible with repositories, `--json` contracts (with `copied` added to `SyncCompleted`), `config.toml` (ignoring legacy `gc_interval_hours`), and local/remote state created by `v0.19.x`–`v0.28.0` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the archive or package for your platform, extract it, verify the binary with `kasumi --version` (or `kasumi version`), or validate the release checksums via `SHA256SUMS.txt` (for example `kasumi-v0.29.0-linux-x86_64.tar.gz` or `kasumi-v0.29.0-windows-x86_64.zip`).
