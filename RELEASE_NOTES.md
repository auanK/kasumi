# Kasumi v0.5.2

Patch release of Kasumi.

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

## Highlights

- Fixed a `Composition Mismatch` caused by modification-time drift on equivalent
  files, so unrelated changes can still be synchronized.
- Prevented the scanner from combining metadata and content from different file
  states when a file changes during hashing.
- Retried unstable local observations and safely aborted synchronization after
  repeated concurrent changes, without publishing partial state.
- Added regression coverage across Linux, MSYS2, and MSVC.

## Downloads

- `kasumi-linux-x86_64.tar.gz`
- `kasumi-windows-x86_64.zip`
- `SHA256SUMS.txt`

Individual SHA-256 checksum files are also provided for each archive.

GitHub artifact attestations are generated for the release archives and
`SHA256SUMS.txt`.

See `CHANGELOG.md` for the complete v0.5.2 change summary.
