# Kasumi v0.6.1

Maintenance release of Kasumi.

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

## Fixed

- Fixed `rclone job/batch` read deadline timeouts during large content presence verification by splitting requests into bounded concurrent batches.

## Downloads

- `kasumi-linux-x86_64.tar.gz`
- `kasumi-windows-x86_64.zip`
- `SHA256SUMS.txt`

Individual SHA-256 checksum files are also provided for each archive. On release, GitHub artifact attestations are generated for both archives and `SHA256SUMS.txt`.

See `CHANGELOG.md` for the complete change summary.
