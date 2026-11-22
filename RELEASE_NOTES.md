# Kasumi v0.20.0

This release hardens destructive maintenance commands (`gc --dry-run` and `resolve-missing` confirmation) and introduces machine-readable `--json` output with stable `error.code` identifiers and `--quiet` automation mode, without any protocol or storage format changes.

## Highlights

- **Garbage collection preview (`kasumi gc <profile> --dry-run`).** Inspects local transaction journals read-only, verifies barrier and writer preconditions, and reports candidate totals broken down into content objects, redundant commit variants, and expired `KACT` v1 activity records without establishing a remote barrier, deleting objects, or publishing activity records.
- **Confirmation guard for `resolve-missing`.** `kasumi resolve-missing <profile>` now lists eligible pending paths and prompts for explicit confirmation before publishing logical deletions. Use `--dry-run` to preview read-only, or `--confirm` for non-interactive automation after review.
- **Structured `--json` and `--quiet` automation.** Pass `--json` (`schema_version: 1`, empty `stderr`, language-independent fields regardless of `--lang`) on `list`, `show`, `status`, `sync`, `fsck`, `gc`, `repack`, `resolve-missing`, and `remote summary` with stable `error.code` values (including `lock_busy`, `partial_pending`, `confirmation_required`, and `transport_error`), or `--quiet` to suppress banners, live progress, duration lines, and non-error operational stdout.

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, and `state.db` schema v2 (`v0.19.x` vaults and databases open directly). Unattended scripts calling `kasumi resolve-missing <profile>` must add `--confirm`. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.20.0/docs/best-practices.md#upgrading-kasumi).
- Download the archive for your platform (`kasumi-windows-x86_64.zip` or `kasumi-linux-x86_64.tar.gz`), verify its SHA-256 checksum and GitHub build provenance attestation (`gh attestation verify`), and replace the executable manually.
