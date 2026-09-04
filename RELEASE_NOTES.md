# Kasumi v0.5.0

Initial public release of Kasumi.

Kasumi is a multi-master file synchronization tool for Linux and Windows that
synchronizes through shared storage without requiring a dedicated Kasumi
coordination server.

## Highlights

- Multi-master bidirectional synchronization
- Immutable DAG-based synchronization history
- Client-side authenticated encryption with XChaCha20-Poly1305
- Blinded remote object identifiers
- Local filesystem and rclone-compatible storage backends
- Encrypted transaction journal for interrupted-operation recovery
- Integrity verification with `kasumi fsck`
- History maintenance and garbage collection with `kasumi gc`
- Incremental file observation with persisted fingerprints and cached BLAKE3 hashes
- NTFS USN Change Journal integration on Windows
- Linux x86_64 and Windows x86_64 release binaries

## Downloads

- `kasumi-linux-x86_64.tar.gz`
- `kasumi-windows-x86_64.zip`
- `SHA256SUMS.txt`

Individual SHA-256 checksum files are also provided for each archive.

GitHub artifact attestations are generated for the release archives and
`SHA256SUMS.txt`.

See `CHANGELOG.md` for the complete v0.5.0 feature summary.
