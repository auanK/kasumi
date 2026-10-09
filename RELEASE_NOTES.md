# Kasumi v0.6.0

Feature and reliability release of Kasumi.

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

## Important Upgrade Notice

**Breaking change from v0.5.5:** v0.6.0 is incompatible with v0.5.5 local SQLite databases and unfinished transaction journals. Complete all synchronizations with v0.5.5, verify local and remote state, and back up the complete profile and synchronized files before upgrading. Preserve `key.bin` and `config.toml`. No automatic migration is provided. The new `kasumi update` command replaces only the executable; it does not migrate local data. Rebuilding the local database discards the previous accepted-history and Epoch rollback checkpoint. See the [v0.6.0 upgrade notes](https://github.com/auanK/kasumi/blob/v0.6.0/CHANGELOG.md#upgrade-notes) before proceeding.

## Added

- Synchronization records unavailable remote payloads as pending materializations and exits with code `2` when it completes partially.
- `fsck` verifies payloads with bounded parallel workers and provides progress reporting with authenticated checkpoints.
- Garbage collection reports progress through its maintenance stages.
- Added explicit quarantine maintenance commands, `gc purge-quarantine` and `gc repair-quarantine`, both requiring `--confirm-permanent-loss`. Purging can permanently delete content still referenced by history.
- `resolve-missing` provides an explicit way to publish logical deletions for eligible unrecoverable content.
- `kasumi update` updates official Windows and Linux x86_64 release binaries after SHA-256 verification and requests elevation when needed. It replaces only the executable; it does not migrate local state. See the [update instructions](https://github.com/auanK/kasumi/blob/v0.6.0/docs/configuration-and-usage.md#updating-kasumi).
- Windows supports extended-length paths beyond `MAX_PATH`.

## Changed

- Garbage collection can stage quarantine data with same-storage copies and batches copy, metadata publication, and source deletion operations.
- Remote history observation reads independent objects concurrently and reuses observed namespace data to reduce redundant listings.
- Read-only commands, including `status`, `sync --dry-run`, and remote inspection, no longer invoke transaction recovery.
- Remote providers without physical SHA-256 support use the verified client-side fallback path.

## Fixed

- Reconciliation preserves remote conflicts and modified descendants, including concurrent file/directory and multi-party conflicts.
- Commit creation is independent of remote head ordering, and merge-base selection follows ancestry in the commit DAG.
- Transaction recovery fails closed when remote publication is ambiguous or required rollback evidence is missing.
- Timestamp handling preserves nanosecond precision across platforms and handles unspecified modification times portably.
- Embedded localization catalogs compile with MSVC while preserving source content, including CRLF line endings.

## Downloads

- `kasumi-linux-x86_64.tar.gz`
- `kasumi-windows-x86_64.zip`
- `SHA256SUMS.txt`

Individual SHA-256 checksum files are also provided for each archive. On release, GitHub artifact attestations are generated for both archives and `SHA256SUMS.txt`.

See `CHANGELOG.md` for the complete v0.6.0 change summary.
