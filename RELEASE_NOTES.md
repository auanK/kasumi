# Kasumi v0.19.0

This release adds end-to-end operational traceability across local state, authenticated commits, and shared remote maintenance records while preserving standard `sync` output and zero extra remote traffic during synchronization.

## Highlights

- **Persistent machine identity & `KCOM` v4 commit authorship.** Each installation persists a random internal `machine.id` alongside the automatically detected hostname (preserving historical names on renames). New `KCOM` v4 commits embed the publishing machine and origin operation (`sync`, `repack`, or `resolve-missing`) directly inside the encrypted, authenticated commit payload with zero extra remote objects.
- **Shared immutable maintenance records (`KACT` v1).** `fsck`, `gc`, `gc remove-writer`, and `gc remove-barrier` publish best-effort encrypted `KACT` v1 activity records under a dedicated keyed namespace. `kasumi gc` retains and prunes them alongside vault history retention while always keeping the newest successful record per `(machine_id, operation)` and failing closed on corrupt records.
- **Local execution tracking & offline inspection (`state.db` v2).** Local profiles record recent attempts, outcomes (including no-op and download-only syncs), accepted commit provenance, and cached maintenance snapshots. `kasumi show <profile> [--full]` works offline, `kasumi config` adds a concise last-sync column, `remote heads`/`commits`/`commit` show authorship and readable local timestamps, and `kasumi remote summary <profile> [--full]` displays live remote maintenance activity.

## Compatibility and installation

- **Pre-1.0 breaking format upgrade:** `v0.19.0` uses `KCOM` v4 commits and `state.db` schema v2 exclusively and rejects older vaults and v1 local databases without automatic migration. Complete any pending recovery on `v0.18.x`, back up your files and credentials, upgrade all clients together, and re-initialize vaults and local state. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.19.0/docs/best-practices.md#upgrading-kasumi).
- The built-in `kasumi update` command was removed in v0.17.0. For portable installations, download the archive for your platform, verify its SHA-256 checksum, and replace the executable. For managed installations, update through the package manager that installed Kasumi.
