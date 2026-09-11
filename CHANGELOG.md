# Changelog

## [0.5.3] - 2026-09-10

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Fixed

- Fixed a `Composition Mismatch` when synchronizing profiles where remote storage contains entries matching `.kasumiignore` (such as `desktop.ini`, `node_modules/`, `*.tmp`). Reconciler and diff now systematically evaluate ignore patterns, preserving local files while purging excluded paths from the shared remote namespace.

### Changed

- Decoupled payload auditing from garbage collection reachability analysis, avoiding redundant payload downloads and significantly reducing GC duration. Cryptographic payload integrity verification is performed exclusively by `fsck`.
- Added pre-destructive remote listing verification before quarantine and purge in garbage collection to prevent races against concurrent modifications.

### Tests

- Added unit and end-to-end regression tests validating ignore pattern evaluation in 3-way reconciliation, remote cleanup of excluded entries, and composition consistency across Linux, MSYS2, and MSVC.
- Added unit, integration, and operational live benchmarks validating garbage collection reachability, quarantine staging, and retention policies.

## [0.5.2] - 2026-09-08

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Fixed

- Fixed a `Composition Mismatch` caused by modification-time drift on equivalent files. Shared rows are now synchronized with the current local tree before reconciliation, allowing unrelated changes to be published.
- Prevented hybrid scanner rows containing metadata from one file state and content from another when a file changes during hashing.
- Retried unstable local observations and safely aborted synchronization after repeated concurrent changes, without publishing partial state.

### Tests

- Added scanner, synchronization, and end-to-end regressions for concurrent file mutation and equivalent-file modification-time drift across Linux, MSYS2, and MSVC.

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
