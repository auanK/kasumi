# Kasumi v0.26.0

## Highlights

- **Continuous-Process `application` Foundation**:
  - Added per-operation `std::stop_token` cancellation (`ExecutionInput` / `InspectionInput` + rclone `RcClient` cancellation) and `MasterKeyBytes` in-memory credentials.
  - Added thread-scoped content concurrency (`--concurrency` > profile `transfer_concurrency` > `KASUMI_CONTENT_CONCURRENCY` > default `8`).
- **`config.toml` v1 & Transport Controls**:
  - Added `version = 1` schema versioning alongside per-profile `bandwidth_limit`, `transfer_concurrency`, and `rclone_config`, plus per-command `--bwlimit` and `--concurrency` flags across `sync`, `status`, `fsck`, `gc`, `repack`, and `remote ...`.
- **Empty-Local Safety Guards**:
  - Protected `sync` and `profile edit` against accidental missing or emptied local directories on populated vaults (`error.code = "empty_local_blocked"`, overridable with `--allow-empty-local`).
- **Remote Connection Test & CLI Completions**:
  - Validate connectivity and vault authentication read-only via `kasumi profile test <profile>` or atomically during creation with `kasumi profile create ... --verify`.
  - Non-interactive key automation with `kasumi key <profile> [--replace] [--json] [--quiet]`.
- **`.kasumiignore` Tooling & Diagnostics**:
  - Evaluate ignore rules with `kasumi ignore check <profile> <path...>`, scaffold templates with `kasumi ignore init <profile> [--preset default|dev|office|minimal] [--force] [--dry-run]`, and validate `.kasumiignore` syntax in `kasumi diagnostics`.

## Compatibility

100% compatible with repositories and state created by `v0.19.x`–`v0.25.0` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`, and unversioned `config.toml`).

## Installation

Download the archive or package for your platform, extract it, verify the binary with `kasumi --version`, or validate the release checksums via `SHA256SUMS.txt` (for example `kasumi-v0.26.0-linux-x86_64.tar.gz` or `kasumi-v0.26.0-windows-x86_64.zip`).
