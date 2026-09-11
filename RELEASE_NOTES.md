# Kasumi v0.5.3

Patch release of Kasumi.

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

## Highlights

- Fixed a `Composition Mismatch` occurring when remote storage contains files or directories matching `.kasumiignore` (such as `desktop.ini`, `node_modules/`, `*.tmp`). Ignore rules are now systematically enforced during diff computation and reconciliation, keeping local files untouched and purging excluded entries from the synchronized remote snapshot.
- Decoupled payload inspection and cryptographic auditing from garbage collection, allowing GC reachability to execute in constant time `O(1)` relative to file payloads without downloading content.
- Strengthened garbage collection distributed barriers with pre-destructive remote listing consistency checks prior to quarantine and purge.

## Downloads

- `kasumi-linux-x86_64.tar.gz`
- `kasumi-windows-x86_64.zip`
- `SHA256SUMS.txt`

Individual SHA-256 checksum files are also provided for each archive.

GitHub artifact attestations are generated for the release archives and
`SHA256SUMS.txt`.

See `CHANGELOG.md` for the complete v0.5.3 change summary.
