# Kasumi v0.24.0

This release hardens Garbage Collection concurrency and clock safety with a unique multi-barrier control layout, fail-closed remote-clock grace clamping, periodic mid-`Apply` exclusivity revalidation, and diagnostic marker metadata (`started_at`, `pid`, `machine`), alongside a refreshed README and documentation audit.

## Highlights

- **Multi-barrier GC control layout & settle window.** GC now publishes a unique per-run barrier under `<barriers-ns>/<32-hex-token>`, waits a `2000 ms` cooperative settle window in CLI runs, and verifies exclusivity without overwriting competing barriers, while maintaining full read and removal compatibility with legacy `v0.23.x` single barriers.
- **Fail-closed remote-clock `--min-age` clamping.** When `--min-age > 0` (default `6` hours / `5` commits), GC clamps its reference time to `min(local_now, remote_now)` derived from the barrier's remote `ModTime` and fails closed if remote time is unavailable, protecting freshly uploaded objects even under local clock skew.
- **Periodic mid-`Apply` exclusivity revalidation.** Long-running GC deletions now re-check writers, competing barriers, legacy barriers, and own barrier integrity every `16` batches (`128` objects) or `30s`, aborting unstarted batches cleanly with `NotAttempted` while preserving `confirmed_removed`.
- **Diagnostic marker metadata & targeted barrier recovery.** Writer and barrier control objects now include optional diagnostic `started_at`, `pid`, and `machine` metadata (never auto-expired by time), displayed by `kasumi remote writers <profile>` (text and `--json`). `kasumi gc remove-barrier <profile> [<barrier-id>] --confirm-abandoned` now supports selecting a specific barrier when multiple exist and also supports `--json`.
- **Documentation & README overhaul.** Reorganized `README.md` with comparison matrix, CLI output example, and installation/command tables, and synchronized architecture, usage, security, troubleshooting, and build docs across all 31 Markdown files.

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`, staying 100% compatible with `v0.19.x`–`v0.23.1` vaults and local databases (no re-sync required). See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.24.0/docs/best-practices.md#upgrading-kasumi).
- Upgrade in-place with the native installer for your platform (`kasumi-v0.24.0-windows-x86_64.msi`, `sudo pacman -U kasumi-v0.24.0-linux-x86_64.pkg.tar.zst`, `sudo apt install ./kasumi-v0.24.0-linux-x86_64.deb`, or `sudo dnf install --nogpgcheck ./kasumi-v0.24.0-linux-x86_64.rpm`), or extract the portable `.zip` / `.tar.gz` archive. Verify checksums (`SHA256SUMS.txt` / `.sha256`) and GitHub build provenance (`gh attestation verify`) before installing.
