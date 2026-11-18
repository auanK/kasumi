# Kasumi v0.16.0

Faster large-file planning, bounded FastCDC transfers, and verified upload resumption.

## Highlights

- FastCDC adapts to file size, with chunks up to 32 MiB. Kasumi computes the layouts for independent files in parallel and streams chunk encryption with an adaptive compression bypass.
- Sync uploads and downloads FastCDC chunks in windows of at most 64 chunks and 256 MiB of plaintext. Downloads reuse verified slices and check the whole-file BLAKE3 before installation.
- After an interrupted first upload, sync verifies and reuses chunks already stored on the remote. It uploads missing or unverified chunks.
- Windows workspace cleanup handles extended-length paths when protecting quarantine directories.

## Compatibility

- Existing Protocol v3 vaults open directly with `v0.16.0`, using the same flat commit layout, transaction journal v10, and profile configuration. Upgrade every client sharing a vault before publishing with `v0.16.0`. Clients on `v0.15.1` and earlier reject manifests containing FastCDC chunks larger than 4 MiB. Follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).
