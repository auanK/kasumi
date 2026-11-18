# Kasumi v0.14.2

Patch release for Micro-Pack repair, FastCDC integrity and staging, garbage collection, and rclone shutdown.

## Highlights

- A required presence check that finds an absent Micro-Pack can trigger reconstruction of its original Pack ID from verified local files. A sync that already publishes a commit can replace the mapping when all required local sources are available.
- `fsck` verifies the whole-file BLAKE3 and size for FastCDC files using the committed chunk order.
- FastCDC downloads stream verified local slices directly into the staged file and remove downloaded chunks after their last use.
- GC counts distinct physical object IDs against its reachability limit, and remote content inspection deduplicates logical paths.
- After rclone acknowledges `core/quit`, Kasumi closes the RC pool and terminates its child process immediately.

## Compatibility

- `v0.14.2` uses the same Protocol v3 vault format, flat commit layout, transaction journal v10, and profile configuration as `v0.14.1`. Follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).
