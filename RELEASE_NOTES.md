# Kasumi v0.27.0

## Highlights

- **Multi-Profile Continuous Sync Daemon (`kasumi daemon`)**:
  - Run continuously in foreground or background (`kasumi daemon run [--foreground | --background]`) with warm `rclone rcd` transport sessions, validated in-memory SQLite observation state, native directory watching (`ReadDirectoryChangesW` / `inotify`) with debounce and self-mutation suppression, zero-walk remote fast polling, automatic `config.toml` reload, and opt-in scheduled cooperative GC (`gc_interval_hours`, default `0`).
  - Manage and inspect the daemon from any terminal with `kasumi daemon <status|sync|pause|resume|unlock|lock|reload|logs|stop|autostart>`, persistent rotating `daemon.log`, live daemon telemetry in `kasumi show` and `kasumi diagnostics`, and `"origin": "daemon" | "cli"` execution traceability.
- **RAM-Pinned Key Arena & Authenticated Loopback IPC**:
  - Active and unlocked `memory`-mode keys live in OS-locked non-swappable pages (`VirtualLock` on Windows; `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` on Linux) wiped with `crypto_wipe` on lock or shutdown.
  - Loopback-only (`127.0.0.1`) HTTP control IPC with constant-time `X-Kasumi-Daemon-Token` verification, browser-CSRF header rejection, and XChaCha20-Poly1305 sealed `/v1/unlock` payloads.
- **Data-Oriented Design Architecture**:
  - Replaced OOP classes across the production codebase with plain structs, SoA tables, and procedural free functions, continuously enforced by `kasumi_architecture_dag`.
- **Profile Automation & CLI Polish**:
  - Added per-profile `--watch`, `--sync-interval`, `--gc-interval`, and `--paused` controls in `config.toml` and `kasumi profile create|edit`, plus updated shell completions (`bash`, `zsh`, `fish`, `powershell`) and full English / Brazilian Portuguese i18n coverage.

## Compatibility

100% compatible with repositories and state created by `v0.19.x`–`v0.26.0` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`, and `config.toml`). Standalone one-shot CLI usage remains unchanged.

## Installation

Download the archive or package for your platform, extract it, verify the binary with `kasumi --version`, or validate the release checksums via `SHA256SUMS.txt` (for example `kasumi-v0.27.0-linux-x86_64.tar.gz` or `kasumi-v0.27.0-windows-x86_64.zip`).
