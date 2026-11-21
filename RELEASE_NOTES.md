# Kasumi v0.18.2

This release accelerates physical SHA-256 hashing on x86-64 CPUs with SHA-NI across Windows and Linux, and tunes remote content availability probing for small incremental syncs.

## Highlights

- **Hardware-accelerated SHA-256 via SHA-NI.** `sha256_update`, `sha256_finish`, and `hash_file` now use runtime-dispatched x86-64 SHA-NI instructions on both Windows and Linux, speeding up file encryption, Micro-Pack creation, and physical hashing while keeping automatic fallback on CPUs without SHA-NI.
- **Prioritize batched probes up to 255 objects.** Raised the bulk remote listing threshold from `64` to `256` physical objects and removed the `>= 8` chunked-object special case so small incremental syncs use `control_read_batch` or `presence` probes instead of listing the entire remote directory.

## Compatibility and installation

- Existing Protocol v3 vaults open directly with v0.18.2. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.18.2/docs/best-practices.md#upgrading-kasumi).
- The built-in `kasumi update` command was removed in v0.17.0. For portable installations, download the archive for your platform, verify its SHA-256 checksum, and replace the executable. For managed installations, update through the package manager that installed Kasumi.