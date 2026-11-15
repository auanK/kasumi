# Kasumi v0.10.0

Maintenance release focused on structural simplification, safer file handling, and transaction recovery.

## Highlights

- Consolidated duplicated code across Sync, history, storage, cryptography, and the CLI.
- Replaced runtime translation-catalog parsing with generated compile-time tables.
- Hardened local file access, credential-buffer cleanup, and rclone identifier filters.

## Removed

- Auxiliary Fsck checkpoints and the persistent remote-inspection history cache. Fsck still downloads and authenticates every referenced payload; remote inspection may fetch history again without its former cache.
- Standalone benchmark and provider-certification runners. Performance tracing was reduced.

## Compatibility

- Remote object formats, encryption schemes, and the SQLite schema remain unchanged from v0.9.4. The journal writer remains format 10; readers accept formats 9 and 10.
- Use the same release on all clients. Follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi), complete pending recovery, stop all clients, and retain independent backups before replacing binaries. `kasumi update` replaces only the executable and does not migrate data or guarantee compatibility across 0.x releases.
