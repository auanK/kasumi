# Kasumi v0.21.2

This patch release fixes misleading local status reporting when another Kasumi operation is actively running on a profile, distinguishing legitimate in-progress operations (`Running`) from actual local state corruption or lock errors (`Problem`).

## Highlights

- **`Running` state instead of false `Problem`.** While `sync`, `gc`, `fsck`, `repack`, or `resolve-missing` holds a valid exclusive profile lock, read-only inspection in `kasumi config`, `kasumi show <profile>`, and `kasumi diagnostics [<profile>]` now reports `Running` (with the active operation when recorded, e.g. `Running (gc)`) instead of `Problem` or triggering unhealthy diagnostics warnings. Genuine lock file corruption, symlinks, or permission failures still report `Problem`.
- **Operation context on `lock_busy` and `--json`.** Lock contention errors (`sync`, `status`, `fsck`, `gc`, `repack`, `kasumi key`, and `config` edits) now include `(running <op>)` when an `InProgress` local execution is recorded, and `kasumi show --json` / `kasumi diagnostics --json` expose `state: "running"`, `lock_active`, and `active_operation`.

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`, staying 100% compatible with `v0.19.x`–`v0.21.1` vaults and local databases. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.21.2/docs/best-practices.md#upgrading-kasumi).
- Download the archive for your platform (`kasumi-windows-x86_64.zip` or `kasumi-linux-x86_64.tar.gz`), verify its SHA-256 checksum and GitHub build provenance attestation (`gh attestation verify`), and replace the executable manually.
