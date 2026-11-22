# Kasumi v0.21.0

This release focuses on operational resilience and diagnosability without any protocol or storage format changes, adding fast missing-object recovery (`sync --repair`), preflight disk-space and `rclone` version validation, a read-only local `diagnostics` command, and persistent `--log-file` output.

## Highlights

- **Fast missing-object recovery (`kasumi sync <profile> --repair`).** Uses a single physical remote listing across the effective `StorageManifest` (loose objects, `KPAK\x01` Micro-Packs, and FastCDC chunks) to detect missing remote objects and re-upload them from verified local files without downloading payloads or publishing a new Commit when only physical objects are restored (`data.repaired` in `--json`).
- **Preflight disk-space and toolchain guards.** Checks available free disk space on the profile local directory and staging parent before downloading payloads (`error.code: "insufficient_disk_space"`), and verifies `rclone >= v1.60.0` during daemon startup (`core/version`) and read-only probing.
- **Read-only local diagnostics (`kasumi diagnostics [<profile>] [--json] [--quiet]`).** Inspects OS, configuration files, free disk space, `rclone` availability/version, profile health, locks, pending journals, and key accessibility without accessing remote storage or exposing secrets.
- **Persistent CLI logs (`--log-file <path>`).** Appends clean ANSI-free UTF-8 execution summaries with UTC timestamps in text mode, or one valid JSON line per invocation (NDJSON) when combined with `--json`, validating paths upfront (`io_error` in JSON) and never creating files on `--help`.

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`, staying 100% compatible with `v0.19.x` and `v0.20.0` vaults and local databases. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.21.0/docs/best-practices.md#upgrading-kasumi).
- Download the archive for your platform (`kasumi-windows-x86_64.zip` or `kasumi-linux-x86_64.tar.gz`), verify its SHA-256 checksum and GitHub build provenance attestation (`gh attestation verify`), and replace the executable manually.
