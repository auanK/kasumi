# Kasumi v0.11.1

Performance maintenance release reducing remote round trips during rclone uploads, batch verification, and history reobservation.

## Highlights

- **Scoped batch verification & overlapped discovery:** Rclone batch SHA-256 verification restricts checks to the exact requested objects using `FilesFromRaw` and `NoTraverse`, and scoped HEAD discovery overlaps Epoch listing and read on batch-capable backends.
- **Reduced upload destination lookups:** Rclone uploads use `NoCheckDest` to skip redundant copy-layer destination queries while preserving post-upload physical verification.
- **Batched stabilization reobservation:** Within a command, stabilization reuses authenticated `Commit ID -> Ciphertext ID` addresses when HEAD markers and Epoch remain unchanged, rereading and re-authenticating ancestors in bounded batches without per-ancestor prefix listings.
- **CI test reliability:** The CLI process integration test avoids redundant Argon2id derivations during multi-profile setup so ASan/UBSan runs stay well within subprocess timeouts.

## Compatibility

- Remote formats, encryption schemes, and the SQLite schema remain unchanged from v0.11.0. The journal writer remains format 10; readers accept formats 9 and 10.
- Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi). `kasumi update` replaces only the executable and does not migrate data or guarantee cross-release compatibility.
