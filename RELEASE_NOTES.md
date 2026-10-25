# Kasumi v0.8.4

Release focused on initial vault enrollment, efficient orphan content bootstrapping, and stability fixes.

## Highlights

### Initial Vault Enrollment

`kasumi sync <profile> --initial` now supports joining an existing authenticated remote vault from an uninitialized client. The client verifies remote history and head markers before reconciling its local directory with the remote snapshot, failing closed if remote history is incomplete or invalid.

### Trusted Content Bootstrapping

For initial synchronization against remote storage containing pre-existing orphan Content objects, Kasumi introduces:

```bash
kasumi sync <profile> --initial --trust-existing-content
```

This flag avoids pre-verifying reused remote content and skips redundant uploads for matching Content objects, significantly reducing network operations during initial onboarding. Because remote Content payloads are not inspected prior to reuse, using this flag implies explicit trust in those existing objects; running `kasumi fsck` subsequently is recommended for offline integrity verification. Redundant remote presence queries are avoided by leveraging the initial storage listing.

### Stability and Concurrency Fixes

- **Database and State Validation:** SQLite detection rejects symlinks and invalid filesystem objects at the database path, while safely reusing empty databases left by interrupted initial runs.
- **Fail-Closed Concurrency:** Operations with `--trust-existing-content` fail closed if remote history is published concurrently during bootstrap.
- **History Authentication:** Remote history is strictly authenticated before the local database is initialized or updated.

## Compatibility

- **Remote Protocol:** The remote storage layout, ciphertext format, and authentication mechanisms remain fully unchanged.
- **Standard Sync:** Normal sync and no-op operations retain zero overhead.
