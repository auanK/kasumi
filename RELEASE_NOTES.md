# Kasumi v0.17.3

This release speeds up change calculation on large syncs and reduces remote API overhead and temporary disk I/O during downloads.

## Highlights

- **Faster change calculation on large syncs.** When checking availability for 64 or more physical objects outside storage audits, Kasumi now uses a single remote listing instead of batched per-object `stat` checks (falling back to batched checks if listing fails). This removes thousands of redundant remote probes during `initial-sync` and large downloads.
- **Batch downloads no longer list the remote root.** rclone batch downloads now pass an explicit file list (`FilesFromRaw`) with `NoTraverse`, `NoCheckDest`, and `NoUpdateModTime`, avoiding repeated remote directory traversals on every download window.
- **FastCDC downloads skip plaintext chunk staging.** Kasumi now streams encrypted chunks straight from `chunk-dl` into the temporary destination file while verifying each chunk's size and BLAKE3 digest, removing the `chunk-plain` directory and cutting local disk I/O.
- **Audit and repair hardening.** Storage object audits always verify presence directly instead of reusing bulk listing results, and repair operation ordering now runs in linear time.

## Compatibility and installation

- Existing Protocol v3 vaults open directly with v0.17.3. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.17.3/docs/best-practices.md#upgrading-kasumi).
- The built-in `kasumi update` command was removed in v0.17.0. For portable installations, download the archive for your platform, verify its SHA-256 checksum, and replace the executable. For managed installations, update through the package manager that installed Kasumi.
