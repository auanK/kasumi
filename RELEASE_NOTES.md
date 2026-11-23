# Kasumi v0.23.0

This release introduces safe, automatable multi-client garbage collection with a default 6-hour grace period (`--min-age`), expired commit pruning behind Epoch boundaries, read-only busy detection, and internal sync-engine modularization and stress testing.

## Highlights

- **Safe automatable GC (`--min-age`, default 6h).** `kasumi gc <profile>` now defers freshly uploaded orphan objects and unreachable commits using single-pass remote metadata (`list_metadata`) with fail-closed `ModTime` checks (and dual-clock `ModTime` + authenticated `created_at` checks for expired commits behind Epochs), protecting concurrent or slow uploads on other machines. Pass `--min-age 0` when immediate reclamation is explicitly desired.
- **Read-only busy detection (`remote_busy` / `[BUSY]`) and granular live progress.** Before creating a maintenance barrier, GC checks active writers and existing barriers read-only and exits cleanly with `error.code: "remote_busy"` (`--json`) and `[BUSY]` (`--log-file`). Live progress now shows sub-stages, commit counts, reclaimable/removed bytes, transfer rate, ETA, and deferred object counts, and skips the consistency probe when zero candidates exist.
- **Sync engine modularization and stress testing.** Decomposed `coordinator.cpp` into focused workspace/journal, upload, and download units (`coordinator_workspace.cpp`, `coordinator_uploads.cpp`, `coordinator_downloads.cpp`), expanded binary codec fuzzing across `KCOM`, `KPAK`, `KACT`, `Epoch`, `Transaction`, and AEAD (plus libFuzzer harnesses), and added randomized multi-client soak, transport fault-injection, and sync benchmark tests.

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`, staying 100% compatible with `v0.19.x`–`v0.22.0` vaults and local databases. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.23.0/docs/best-practices.md#upgrading-kasumi).
- Upgrade in-place with the native installer for your platform (`kasumi-windows-x86_64.msi`, `sudo pacman -U kasumi-linux-x86_64.pkg.tar.zst`, `sudo apt install ./kasumi-linux-x86_64.deb`, or `sudo dnf install --nogpgcheck ./kasumi-linux-x86_64.rpm`), or download the portable `.zip` / `.tar.gz` archive. Verify checksums (`SHA256SUMS.txt` / `.sha256`) and GitHub build provenance (`gh attestation verify`) before installing.
