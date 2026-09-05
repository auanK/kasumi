# Changelog

## [0.5.1] - 2026-09-05

Patch release of Kasumi.

### Fixed

- Fixed Windows path handling issues that could cause incorrect filesystem path processing.
- Improved Unicode path handling on Windows.
- Improved cross-platform path normalization behavior.

## [0.5.0] - 2026-09-04

Initial public release of Kasumi.

### Added

- Multi-master bidirectional synchronization across multiple machines through shared storage without a dedicated Kasumi coordination server.
- Immutable history commits stored in a DAG, allowing concurrent publications to form branches that are reconciled deterministically without an exclusive global synchronization lock.
- Client-side authenticated encryption via XChaCha20-Poly1305 (Monocypher) with per-vault master keys.
- Blinded remote identifiers preventing original file paths and filenames from being used directly as remote object identifiers.
- Storage backends for local filesystems, network shares, and rclone-compatible remotes.
- Encrypted transaction journal for tracking and recovering interrupted synchronization operations.
- Epoch-based retention and maintenance protocol for history lifecycle and garbage-collection coordination.
- `kasumi fsck` for remote and history integrity verification, and `kasumi gc` for garbage collection with quarantine staging.
- Incremental file observation using persisted fingerprints, cached BLAKE3 hashes, and NTFS USN Change Journal integration on Windows.
- CLI commands for profile configuration, synchronization, inspection, maintenance, and dry-run simulation, with English and Portuguese localization and external JSON locale catalogs.
- Native builds for Linux and Windows.
- CMake install target for local installation.
