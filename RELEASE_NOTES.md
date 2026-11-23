# Kasumi v0.25.0

## Highlights

- **Historical Inspection & Recovery**:
  - Inspect file-level remote history with `kasumi remote log <profile> <path> [--full]`.
  - Inspect metadata and fetch files from any historical snapshot via `--commit <id>` on `kasumi remote stat` and `kasumi remote get`.
  - Restore files, prefixes, or full encrypted snapshots locally with `kasumi remote restore <profile> [<prefix>] <dst> [--commit <id>] [--dry-run]`.
- **Conflict Inspection & Resolution**:
  - List active conflict artifacts with `kasumi conflicts <profile>`.
  - Atomically resolve conflicts using `kasumi conflicts resolve <profile> <path> (--keep-canonical | --keep <artifact>) [--dry-run]`.
- **Non-Interactive Profile Management & Onboarding**:
  - Manage profiles and remote storage without prompts via `kasumi profile <create|edit|clone|storage|rename|delete>`.
  - Automatic `rclone listremotes` discovery hints and warnings in `kasumi config`.
- **Shell Completions & Automation Output**:
  - Generate completion scripts via `kasumi completion <bash|zsh|fish|powershell>`.
  - Expanded `--json` output across `profile`, `conflicts`, `conflicts resolve`, and `remote stat|get|log|restore`, plus `--quiet` and `--log-file` options.
- **Stability Fixes**:
  - Fixed concurrent KDE Wallet folder creation/deletion races and serialized intra-process Linux OS vault D-Bus/`libsecret` access in `src/runtime/vault.cpp`.
  - Fixed `run_rclone_readonly_cli` EOF handling in `src/transport/rclone/session.cpp` and a `std::string_view` lifetime bug in `src/cli/presenter.cpp`.

## Compatibility

100% compatible with repositories and state created by `v0.19.x`–`v0.24.0` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`, and `config.toml`).

## Installation

Download the archive or package for your platform, extract it, verify the binary with `kasumi --version`, or validate the release checksums via `SHA256SUMS.txt` (for example `kasumi-v0.25.0-linux-x86_64.tar.gz` or `kasumi-v0.25.0-windows-x86_64.zip`).
