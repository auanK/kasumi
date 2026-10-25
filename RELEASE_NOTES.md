# Kasumi v0.8.4

Stabilization release of Kasumi focused on initial vault enrollment, robust
orphan content bootstrapping, concurrency protection, and local state validation.

## Highlights

### Initial vault enrollment (Scenario A2)

`kasumi sync <profile> --initial` now supports joining an existing authenticated
remote vault from an uninitialized client without failing with namespace errors.
The client observes accepted remote history, verifies head markers and epochs,
and reconciles its local tree against the remote snapshot. If remote history is
partial, unrecognized, or corrupted, the operation fails closed before creating
a local database.

### Trusted content bootstrapping (`--trust-existing-content`)

For initial sync against an empty remote history namespace containing pre-existing
Content objects (e.g. orphan objects left in cloud storage like Google Drive),
the `--trust-existing-content` flag allows bootstrapping without performing
speculative verification downloads.

- **Zero Verification GETs:** Content matching key-derived logical identifiers is trusted by presence without payload downloads.
- **Zero Redundant PUTs:** Uploads of pre-existing trusted content are elided.
- **Strict Concurrency Protection:** If remote history is published concurrently by another client before or during stabilization, the operation fails closed to prevent unverified content reuse or concurrent genesis publication.
- **Integrity Notice:** Reports the count of reused unverified objects and recommends running `kasumi fsck` for offline payload verification.

### Enrollment and bootstrap policy isolation

Enrollment into an existing vault no longer audits or downloads unreferenced
orphan content, preventing speculative GET overhead and preserving standard
deduplication behavior.

### Hardened local state validation

Local database inspection now uses `symlink_status` directly instead of following
symlinks. Symlinks (dangling or targeting valid databases) and non-regular files
at the database path are rejected. Empty, valid databases without accepted state
from interrupted initial runs are safely reused when no transaction recovery
evidence exists.

## Performance and Compatibility

- **No Remote Performance Regression:** Normal sync and no-op operations perform zero additional remote requests.
- **Protocol Compatibility:** Kasumi 0.8.4 introduces no changes to remote protocols, SQLite schemas, or ciphertext formats.
