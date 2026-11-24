# Kasumi v0.27.2

## Highlights

- **Warm `rclone` Shutdown & Idle Reliability**:
  - Fixed a Windows hang on `kasumi daemon stop` and warm-transport teardown by bounding `WaitForSingleObject` before `reproc::wait` and checking kernel child liveness.
  - Hardened idle RC health checks with stale keep-alive retry and automatic recovery after abrupt `rclone` exits on Windows and Linux.
- **Smooth Daemon UX Under Concurrent Local Edits**:
  - Editing files while a daemon sync is in flight now triggers transient backoff (preserving the warm transport) instead of tripping `NeedsAttention`, while true invariant/corruption checks remain fail-closed.
- **Windows Vault & Parallel I/O Hardening**:
  - Hardened Windows Credential Manager read/write and atomic file I/O retries under parallel load.
- **Faster CI & Release Pipelines**:
  - Added `KASUMI_ENABLE_IPO` (default `ON` for releases), removed redundant Debug CI jobs, and disabled IPO on CI test executables while keeping full LTO/LTCG on published release binaries.

## Compatibility

100% compatible with repositories and state created by `v0.19.x`–`v0.27.1` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`, and `config.toml`).

## Installation

Download the archive or package for your platform, extract it, verify the binary with `kasumi --version`, or validate the release checksums via `SHA256SUMS.txt` (for example `kasumi-v0.27.2-linux-x86_64.tar.gz` or `kasumi-v0.27.2-windows-x86_64.zip`).
