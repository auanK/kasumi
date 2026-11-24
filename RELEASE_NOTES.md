# Kasumi v0.28.0

## Highlights

- **Unified Overview Dashboard (`kasumi` / `kasumi status`)**:
  - Running bare `kasumi` (or `kasumi status` without a profile) now displays a single consolidated view of daemon state, autostart status, both the last local sync time and the HEAD commit's last change timestamp + author machine per profile, `[watch off]` / `[manual only]` indicators, conflict/error hints, or a 3-step quickstart when no profiles exist (`--full` expands metrics and paths).
- **One-Command Daily Workflow & Cross-Platform Live Logs**:
  - Added top-level `kasumi start [--autostart]`, `kasumi stop`, `kasumi pause <profile | --all>`, `kasumi resume <profile | --all>`, and per-profile watch/sync/GC schedule editing directly inside `kasumi config` (`[e] Edit`).
  - Added `kasumi logs [<profile>] [-f | --follow] [--lines <1..1000>] [--full]` (plus `-f` on `kasumi daemon logs`) for Windows and Linux live streaming, hiding repetitive `fast_noop`/`warm_transport_*` noise unless `--full` is passed and adding elapsed sync duration `(X.X s)` to completed sync events.
- **Progressive Disclosure (`--help` vs `--help --all`, `show`, `list`, `daemon status`)**:
  - `kasumi --help` now fits cleanly on one screen with `--help --all` revealing advanced/maintenance subcommands, while `show`, `list`, and `daemon status` surface clean summaries (including HEAD commit author in `show` and `watch off` indicators in `daemon status`) by default and full diagnostics with `--full`.

## Fixed

- **Linux Reboot OS-Vault Auto-Recovery**:
  - Fixed an issue where restarting a Linux desktop started `kasumi-daemon.service` before the keyring/KWallet unlocked and left `vault`-mode profiles in `state=locked`: the daemon now re-checks OS vault credentials periodically (`3s..30s`) outside the scheduler mutex, automatically falls back across Freedesktop Secret Service and KDE KWallet when querying in `auto` mode, and orders `kasumi-daemon.service` after `graphical-session.target`. Existing Linux users can run `kasumi start --autostart` once after upgrading to refresh their unit file.

## Compatibility

100% compatible with repositories, CLI commands, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.27.2` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the archive or package for your platform, extract it, verify the binary with `kasumi --version`, or validate the release checksums via `SHA256SUMS.txt` (for example `kasumi-v0.28.0-linux-x86_64.tar.gz` or `kasumi-v0.28.0-windows-x86_64.zip`).
