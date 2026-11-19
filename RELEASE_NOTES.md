# Kasumi v0.17.4

This release fixes unnecessary remote and local database work during no-op syncs.

## Highlights

- **No-op syncs no longer trigger speculative writer registration on ignored-only directories.** During sync observation, Kasumi now projects the observed local tree against the persisted base tree before deciding whether a local change is proven. Workspaces containing non-ignored directories whose contents are entirely ignored no longer register and delete a remote writer marker on every no-op sync.
- **Consistent `file_cache` ordering avoids redundant SQLite writes.** Rows loaded from `file_cache` are now sorted with segment-wise `path_less` ordering to match the local scanner, eliminating false dirty-cache saves on no-op syncs when filenames and subdirectories share a prefix (for example `docs.md` and `docs/sub.md`).

## Compatibility and installation

- Existing Protocol v3 vaults open directly with v0.17.4. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.17.4/docs/best-practices.md#upgrading-kasumi).
- The built-in `kasumi update` command was removed in v0.17.0. For portable installations, download the archive for your platform, verify its SHA-256 checksum, and replace the executable. For managed installations, update through the package manager that installed Kasumi.
