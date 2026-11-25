# Kasumi v0.29.2

## Fixed

- **Cloned Profiles Now Start Paused**: `clone_profile()` now initializes cloned profiles with `paused = true` (and notes this in the clone confirmation message), preventing a running `kasumi daemon` from watching or syncing the clone against the original profile's local folder and remote destination before paths are edited.
- **Immediate OS Vault Availability Check Before Credential Prompts**: Added `check_os_vault_available()` and validated OS vault availability immediately when selecting `vault` in `kasumi config` (`[n] New`, `[s] Storage`, `[k] Key`), `kasumi key`, and `kasumi profile create/storage`, failing fast on headless/server environments instead of prompting for Password and Salt first.
- **Windows Credential Manager Read & Delete Resilience**: Expanded transient `ERROR_NOT_FOUND` retry backoff in `read_vault()` (`10ms`–`80ms`, up to 4 retries) and added verify-on-delete retries in `delete_vault()` (`10ms`–`320ms`, up to 6 attempts confirming `ERROR_NOT_FOUND`) on Windows to prevent stale reads or surviving deleted entries under concurrent Credential Manager activity.

## Compatibility

100% compatible with repositories, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.29.1` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the archive or package for your platform, extract it, verify the binary with `kasumi --version` (or `kasumi version`), or validate the release checksums via `SHA256SUMS.txt` (for example `kasumi-v0.29.2-linux-x86_64.tar.gz` or `kasumi-v0.29.2-windows-x86_64.zip`).
