# Kasumi v0.5.5

Patch release of Kasumi.

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

## Highlights

- Fixed a `Composition Mismatch` caused by modification-time drift on pre-existing equivalent files when publication is not required. Timestamps are now aligned during metadata restoration without triggering false-positive local divergence, while strictly preserving rejection of concurrent modifications.

## Downloads

- `kasumi-linux-x86_64.tar.gz`
- `kasumi-windows-x86_64.zip`
- `SHA256SUMS.txt`

Individual SHA-256 checksum files are also provided for each archive.

GitHub artifact attestations are generated for the release archives and
`SHA256SUMS.txt`.

See `CHANGELOG.md` for the complete v0.5.5 change summary.
