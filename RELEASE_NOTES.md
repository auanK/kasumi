# Kasumi v0.19.1

This release removes the obsolete `--trust-existing-content` option from `kasumi sync --initial` so pre-existing remote content is always cryptographically verified before reuse.

## Highlights

- **Removed `--trust-existing-content`.** Eliminated the `--trust-existing-content` flag and its unverified content-ID trust bypass from CLI parsing, reconciliation, and initial sync bootstrap. With `KPAK\x01` Micro-Packs and FastCDC chunking managed through `StorageManifest`, loose object IDs without history cannot match packed or chunked layouts, and skipping AEAD payload verification risked silently recording corrupt remote objects. `kasumi sync --initial` continues to verify pre-existing loose remote objects through AEAD decryption and BLAKE3 checks before reusing them.

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4 and `state.db` schema v2 (`v0.19.0` vaults open directly). Automated scripts that previously passed `--trust-existing-content` must drop that flag. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.19.1/docs/best-practices.md#upgrading-kasumi).
- The built-in `kasumi update` command was removed in v0.17.0. For portable installations, download the archive for your platform, verify its SHA-256 checksum, and replace the executable. For managed installations, update through the package manager that installed Kasumi.
