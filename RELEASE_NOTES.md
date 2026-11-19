# Kasumi v0.17.0

This release makes interrupted synchronization easier to recover and improves integrity checks across rclone, SQLite, and local storage.

## Removed

- **The `kasumi update` command was removed**, along with the built-in updater and its private installer commands. For a portable installation, download the official archive, verify its SHA-256 checksum, and replace the executable manually. For a managed installation, update through the package manager that installed Kasumi.

## Synchronization and recovery

- Sync verifies remote payloads before reusing upload checkpoints and can replan a paused upload when local files or remote history change.
- Interrupted local copies and partially initialized journals recover cleanly. Destination conflicts clean up owned staging files, and missing-content resolution releases the writer marker on failure.
- GC, remote health, and inventory audits work after Epoch pruning. Advancing to a new Epoch clears pending materializations from the prior one.
- Diff and plan account for paths that change between files and directories, including three-way conflicts. Sync also accepts timestamps rounded to the destination filesystem's precision.
- Micro-Packs upload in bounded batches with checkpoints. Parallel extraction handles packs that share blobs, and a missing pack is reported as missing remote content.

## rclone and local storage

- Batch downloads verify every requested object and overwrite stale local copies even when size and modification time match. Removal batches account for response size, and oversized listings fail without a duplicate request.
- RC server failures and uncertain writes retain useful diagnostics. Cancellation requests that async copy jobs stop, checks the outcome, and lets the rclone process shut down.
- rclone lookup works from filesystem roots and home directories, Windows process exits are recognized correctly, and hash manifests use separate temporary workspaces.
- On Windows, copying a read-only source no longer makes the stored copy read-only. Local storage reports permission failures during enumeration.

## State, profiles, and platform

- SQLite initializes databases atomically, recovers interrupted WAL state, and prunes obsolete file-cache rows. It rejects redirected database files and sidecars. Crypto reads reject redirected inputs, bound Micro-Pack reads, and wipe plaintext buffers before reuse.
- Profiles reject duplicate names and support renames that only change capitalization. Linux profile setup can create a missing configuration directory. Windows Credential Manager retries transient failures, and Linux D-Bus disconnects are handled without terminating Kasumi.
- Windows console input and output handle UTF-8 and cancellation more reliably. Remote reports sanitize control characters. Windows file replacement, profile locking, and extended-path cleanup are more robust, and macOS uses native change timestamps and exclusive renames.

## Compatibility

- Existing Protocol v3 vaults use the same remote layout in v0.17.0. Review the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.17.0/docs/best-practices.md#upgrading-kasumi) before changing the executable on clients that share a vault.
