# Changelog

## [0.9.1]

### Fixed

- Fixed downloads directly beneath a trailing-slash symlink synchronization root without permitting symlink traversal inside the synchronized tree.

## [0.9.0]

### Added

- Added profile cloning in `kasumi config`, reusing settings and the master key with a new empty SQLite database.
- Added local profile-state indicators in the configuration wizard without contacting remote storage or modifying persistent profile data.
- Added explicit recovery of abandoned maintenance barriers with `gc remove-barrier --confirm-abandoned`.

### Changed

- Standardized CLI argument validation, contextual help, elapsed-time reporting, and cancellation at safe operation boundaries.
- GC revalidates barrier ownership before deletion and reports acknowledged removals and uncertain effects separately.

### Fixed

- Reconciled histories with multiple best common ancestors, preserving independent changes, conflict variants, and later deletions within authenticated history limits.
- Serialized configuration mutations and corrected concurrent configuration reads, atomic replacement, permissions, and profile-lock handling on Windows.
- Hardened profile-clone rollback and interrupted Sync cleanup with filesystem identity and ownership checks.
- Preserved native Unicode command-line arguments on Windows independently of the system ANSI code page.

### Performance

- Reduced GC remote I/O by classifying orphan Content through authenticated reachability without payload auditing and applying candidate deletions in bounded batches.

## [0.8.4]

### Added

- Added support for `sync --initial` to enroll an uninitialized client into an existing authenticated remote vault.
- Added `--trust-existing-content` parameter for `sync --initial` to reuse orphan Content during bootstrap without verification downloads or redundant uploads.

### Fixed

- Hardened SQLite database validation by rejecting symlinks and non-regular files, while safely reusing empty databases left by interrupted initial operations.
- Validated remote history authentication before creating or updating the local SQLite database.
- Protected against concurrent modifications during bootstrap and enrollment, failing closed if remote history is observed concurrently.

### Performance

- Reduced redundant remote presence queries during trusted bootstrap by reusing the initial storage listing.
- Preserved zero network request overhead for normal sync and no-op operations.

## [0.8.3]

### Fixed

- Made file encryption and decryption transactional: output is written to isolated temporary files with private permissions and published atomically, preserving preexisting destinations when operations fail before publication.
- Protected against alias and destination corruption by rejecting empty paths, identical source/destination paths, directory/symlink targets, and hardlinked aliases of the input file.
- Fixed a double-close vulnerability in private file handling and strengthened RAII ownership of Windows handles and POSIX file descriptors.
- Made temporary file cleanup safe by validating physical `FileIdentity` before unlinking, preventing accidental removal of colliding or replaced files.

### Performance

- Sized encryption and decryption scratch buffers according to payload size up to chunk limits, reducing memory consumption and wipe work for small files.
- Optimized BLAKE3 file hashing with a 64 KiB buffer and RAII memory wiping via `BufferWipeGuard`.

## [0.8.2]

### Performance

- Sync checks remote Content availability only for its current work. No-op and small runs avoid a global presence scan; unrelated missing objects are not discovered or repaired automatically.

### Added

- Added the opt-in `kasumi sync <profile> --audit-inventory` command to report referenced, present, missing, and orphan Content across reachable history, plus unknown physical objects. A clean complete run returns `0`, findings or partial Sync return `2`, and audit failure returns `1`.

### Limitations

- The structural audit does not download or authenticate Content payloads, repair or delete objects, or provide an atomic snapshot. It rejects detected writers, barriers, and changes between its two physical listings. If audit fails after Sync publishes, that publication remains.

## [0.8.1]

### Fixed

- Stopped duplicate progress messages during `kasumi gc`.
- CLI rejects completion payloads that do not match their operation, preventing incorrect success messages.

## [0.8.0]

### Changed

- Replaced quarantine-based GC with direct removal of authenticated orphan Content and redundant CommitVariants, using one authenticated observation and a globally validated plan.
- GC applies sequential removals, reports partial and uncertain results, and preserves ownership checks during barrier cleanup.
- Sync checks required remote Content even on no-op runs and repairs missing objects from authenticated local bytes without publishing unnecessary history. Unavailable content remains pending instead of becoming a logical deletion.
- Added explicit `sync --initial` to initialize a missing local database only when local transaction evidence and current remote history are absent; compatible Content can be reused.
- Expanded maintenance, repair, and process-crash regressions and the release-critical gate; corrected Windows GCC/MSYS2 fixtures, crash-helper linkage, and crash-test signaling.

### Removed

- Quarantine and the `gc purge-quarantine`, `gc repair-quarantine`, and `remote quarantine` commands. GC deletions are permanent.

### Upgrade Notes

- Use the same release on all clients. See [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi) for compatibility and backup requirements.
- See [Release Notes](RELEASE_NOTES.md) for user-facing changes and the [provider certification scope](docs/provider-certification.md#requirements-and-limits) for current requirements and limitations.

## [0.7.0]

### Highlights

- Strengthened bidirectional Windows/Linux synchronization, concurrent-history observation, local mutation checks, and recovery of interrupted operations.
- Replaced full-record journal rewrites with an incremental authenticated journal and validated confirmed-session cache.
- Unified local scanning and persistent BLAKE3 hash reuse across Sync, Preview, and Status.

### Added

- Native metadata observation with Windows volume/full 128-bit file identity and Linux device/inode identity, explicit filesystem errors, and checked nanosecond timestamp conversion.
- Incremental journal snapshots and chained encrypted deltas, authenticated confirmation of the durable log prefix, and authenticated retirement for restart-safe cleanup. Incompatible, truncated, or contradictory confirmed state stops recovery and retains evidence.
- Journal preparation batching, confirmed Record/Tip caching with artifact and key checks, deterministic fault injection in separate test builds, and operational preparation/recovery benchmarks.
- Windows `longPathAware` manifests for the CLI and test executables, plus diagnostics identifying rejected internal staging paths and their lengths.

### Changed

- Windows and Linux use one scanner. Every observation enumerates the managed tree and reads metadata; hash reuse requires matching logical path, regular-file type, size, nanosecond mtime, and every native identity component.
- SQLite persists the uniform hash-cache representation without time-based expiration. `status` and `sync --dry-run` reuse eligible fingerprints read-only, hash cache misses or unreliable identities, and never save cache deltas. A differing authenticated ignore projection uses full hashing; a warm cache does not skip enumeration or remote observation.
- Existing profile configuration and SQLite state are validated before application operations open transport. Unknown profile fields, missing required values, and missing/corrupt/incompatible databases are rejected without migration, recreation, or accepted-base reset.
- Optimized ignore-rule matching and added regressions for anchored and wildcard patterns.
- Expanded Debug/Release CI to five toolchains: MSVC 2022, MSYS2 UCRT64 GCC, MSYS2 Clang64, Ubuntu GCC 14, and Ubuntu Clang 19; Windows MSYS2 jobs verify tool paths. Cleaned up test/benchmark namespaces and development-phase identifiers.
- Stable tags are no longer classified as prereleases solely for having major version zero; tags containing `-` are prereleases. Windows version resources derive from CMake's project version.
- Consolidated user guides, architecture, maintenance safety limits, and release documentation around the current implementation.
- Simplified Windows self-update permissions: replaced internal UAC helper elevation (`runas`, process ACL manipulation, nested helper processes) with a direct write-permission check. Non-elevated sessions fail fast with an explicit administrator requirement, while elevated or user-writable sessions install directly.

### Fixed

- Scoped history observation now verifies ancestry linkage across all loaded branches before trusting `cached_anchor`. Concurrent sibling HEADs invalidate the shortcut and trigger loading without that anchor, restoring the common ancestry needed for reconciliation. Includes the regression discovered during real Google Drive validation (`DEFECT-P36-01`).
- Destructive download, deletion, and conflict-rename targets are verified by content independently of cached hashes. A mismatch invalidates the cache row and triggers reconciliation; unexpected disappearance, non-regular replacement, or an occupied destination fails closed.
- Preserved cache invalidations and freshly reobserved fingerprints through finalization and across executions, including observations following confirmed local renames.
- Restored normal Linux local mutations and hardened verified staging, no-overwrite installation/rename, backup restoration, and rollback after interruptions. Detected pre-effect destination conflicts preserve completed peer effects for a fresh Sync; ambiguous recovery retains the journal and required backups.
- Hardened Commit/HEAD publication and recovery checks around confirmed local progress. Commit upload alone is not publication; exact marker/Commit/Epoch and accepted-state contradictions stop recovery rather than silently selecting rollback or success.
- Corrected Windows native timestamp reads, checked FILETIME conversion, 100-nanosecond timestamp equivalence, and timestamp preservation in synchronization and rollback backups.
- Corrected native metadata error handling and unsupported-identity fallback. Reworked the file-identity regression to avoid assuming that a filesystem cannot immediately reuse an identifier, and made the Windows sharing-violation retry regression deterministic.

### Removed

- Windows NTFS USN Change Journal scanning, observation checkpoints, directory-lineage machinery, and selective tree patching. The authenticated **transaction journal** remains in use.
- Obsolete fixed remote-layout readers/helpers, former custody-artifact replay/cleanup, and unused APIs/tests tied to those implementations. Unknown objects and unsupported custody artifacts are preserved rather than adopted or deleted.
- Windows self-update UAC elevation helper mode (`--kasumi-update-elevated`), `launch_elevated_windows`, and process query-access grants.

### Breaking Changes

- Kasumi provides **no backward compatibility between 0.x releases**. There is no automatic SQLite, journal, configuration, credential, or remote-format migration, no cross-version client interoperability contract, and no supported downgrade procedure.
- Current SQLite validation, fingerprint encoding, journal codec/envelopes, and key-derived remote layout must not be treated as an in-place upgrade path from older releases. The updater replaces only the executable. Preserve incompatible state and independent copies of files/credentials; do not delete `db.sqlite` or recovery evidence to force synchronization. See [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).

## [0.6.1]

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Fixed

- Fixed rclone job/batch timeouts during large content presence checks by splitting requests into bounded concurrent batches.

## [0.6.0]

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Highlights

- **Partial Materialization & Exit Code 2**: Gracefully handles missing remote payloads during synchronization by recording unresolved entries as pending materializations in local state and exiting with status code 2, allowing synchronization to proceed safely without failing the entire transaction.
- **Reconciliation & DAG Correctness**: Strictly selects merge bases by ancestry in the commit DAG, ensures state commits are independent of remote head ordering, preserves remote conflict copies in shared state when local changes win, and prevents data loss during concurrent file-and-directory branch collisions.
- **Fail-Closed Transaction Safety**: Strengthens recovery invariants to abort and fail closed if transaction journals encounter conflicting remote publications or missing rollback evidence, while keeping read-only commands strictly isolated from recovery side effects.
- **Concurrent Integrity Audits**: Parallelizes `kasumi fsck` payload validation with bounded workers controlled by `KASUMI_CONTENT_CONCURRENCY`, backed by crash-safe authenticated local checkpoint metadata and localized progress displays.
- **Garbage Collection Efficiency**: Adds verified same-storage copy for quarantine staging, batches metadata publications and purge operations through rclone, verifies maintenance barrier ownership via remote physical hash, and adds live staged progress tracking.
- **Storage Provider Certification**: Provider-neutral transport and application certification runner with ownership-safe cleanup.

### Added

- Added partial materialization support in `kasumi sync`: missing remote payloads are persisted in local state (`pending_materializations`), reported to the user, and signaled via exit code 2.
- Added parallel payload verification in `kasumi fsck` using bounded workers configured by `KASUMI_CONTENT_CONCURRENCY` (defaults to 8, capped at 16).
- Added crash-safe authenticated local checkpoint persistence (`fsck_checkpoint.bin.enc`) for tracking audit progress metadata across interruptions.
- Added real-time localized progress and summary metrics for `kasumi fsck` (reporting stages, verified object counts, percentage, and plaintext byte volume).
- Added staged, localized progress indicators for `kasumi gc`, reporting preparation, quarantine verification, analysis, application, and finalization stages.
- Added same-storage native copy support for quarantine staging during garbage collection, with automatic fallback to verified client-mediated copy.
- Added batched quarantine copy, batched metadata publication, and batched source deletion via rclone job/batch execution in garbage collection.
- Added explicit manual quarantine maintenance commands: `kasumi gc purge-quarantine <profile> --confirm-permanent-loss` and `kasumi gc repair-quarantine <profile> --confirm-permanent-loss`. These are intentionally separate from normal retention-aware garbage collection; purge can permanently remove content even when it is still needed.
- Added `kasumi resolve-missing <profile>` for explicitly accepting eligible missing remote content as deletions when the original payload cannot be restored. This changes logical history and should be used only after recovery options have been exhausted.
- Added support for Windows extended-length paths (`\\?\`) exceeding `MAX_PATH` (260 characters) across workspace and private profile paths.
- Added overlapped concurrent reading for independent remote history objects (markers, commits, epochs) during observation.
- Added comprehensive modular production architecture documentation covering runtime, data models, state storage, reconciliation, transactions, garbage collection, fsck, and transport.
- Added `kasumi update` for official Windows and Linux x86_64 releases. It verifies the package's SHA-256 checksum, replaces only the Kasumi executable, and requests elevated privileges when required. See [Updating Kasumi](docs/configuration-and-usage.md#updating-kasumi).

### Changed

- Reused the observed physical namespace snapshot during history loading and fsck to eliminate redundant remote listings.
- Enforced strict remote root path containment for all rclone storage operations.
- Classified unsupported remote physical hash types (such as backends lacking SHA-256) as optional capabilities rather than errors, utilizing verified client-side fallback paths.
- Disabled redundant destination modification time updates during rclone batch uploads.
- Isolated read-only commands (`status`, `sync --dry-run`, and remote inspection) from invoking transaction recovery.
- Standardized provider certification suites and test targets across all supported storage backends.

### Fixed

- Fixed conflict omission during reconciliation by preserving remote conflict files in shared state when local modifications take precedence.
- Fixed non-deterministic reconciliation by making state commits independent of remote logical head iteration order.
- Fixed concurrent file and directory branch resolution, preserving both entries when a file and a directory are created concurrently at the same path.
- Fixed multi-party conflict preservation across three concurrent modifications and preserved modified descendants during parent directory deletions.
- Fixed first-sync composition mismatches by evaluating `.kasumiignore` patterns against remote state before fresh-client reconciliation.
- Fixed merge-base resolution to select bases strictly by ancestry in the commit DAG, correctly handling unequal-height and ambiguous branching.
- Fixed history loading and inspection to strictly reject untrusted non-zero DAG roots.
- Fixed transaction recovery to fail closed on ambiguous publication states or missing rollback workspaces, preventing evidence loss.
- Fixed cross-platform timestamp precision by canonically preserving nanosecond-resolution modification times in history and local state.
- Fixed path status resolution on POSIX platforms by properly handling `ENOTDIR` errors during path traversals.
- Fixed causal error masking during `kasumi fsck` worker drain, ensuring the root hard failure is preserved and surfaced.
- Fixed portable handling of unspecified modification timestamps during file materialization.
- Fixed MSVC compilation of embedded localization catalogs by generating bounded C++ string fragments, with deterministic delimiter handling and byte-for-byte preservation of locale source content (including CRLF).

### Upgrade Notes

- **Breaking change — Local state compatibility:** v0.6.0 is incompatible with v0.5.5 local SQLite databases and unfinished transaction journals. Complete all synchronizations using v0.5.5 and verify local and remote state before upgrading. Back up the complete profile and synchronized files; preserve `key.bin` and `config.toml`. After verifying the existing state, rebuild the incompatible local database and synchronize again with v0.6.0. Rebuilding discards the previous local accepted-history and Epoch rollback checkpoint, so deployments that require preserving that checkpoint should not use this procedure. No automatic migration is provided. `kasumi update` replaces the executable only and does not migrate this state.
- **Automation Handling of Exit Code 2**: `kasumi sync` exits with status code 2 when synchronization completes partially with pending materializations (accepted metadata, but missing remote payloads). Automated workflows should treat exit code 2 as a non-fatal partial synchronization. Pending materializations can be downloaded or repaired by a later synchronization once the required payloads are available.
- **Fsck Checkpoint Metadata**: `kasumi fsck` creates authenticated local checkpoint and progress metadata (`fsck_checkpoint.bin.enc`) in the profile directory to track audit progress across interruptions. Checkpoint metadata does not allow referenced payloads to skip cryptographic verification: every referenced payload is still downloaded and authenticated during audit runs.
- **Manual Data-Loss Operations**: `gc purge-quarantine` intentionally bypasses normal quarantine retention/reachability safeguards and can permanently remove the only remaining copy of referenced encrypted content. `gc repair-quarantine` removes eligible orphaned quarantine metadata, not missing payloads. Both require `--confirm-permanent-loss` and must not be treated as routine GC. `resolve-missing` publishes logical deletions for eligible unresolved content. Read the operational documentation before using any of them.

## [0.5.5] - 2026-09-19

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Fixed

- Fixed a `Composition Mismatch` caused by modification-time drift on pre-existing equivalent files when publication is not required. Timestamps are now aligned during metadata restoration without triggering false-positive local divergence.

### Tests

- Added unit, integration, and end-to-end regression tests validating pre-existing equivalent file modification-time drift without publication, while preserving strict rejection of concurrent modifications.

## [0.5.4] - 2026-09-19

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Breaking Changes

- Overhauled remote history storage layout and protocol with privacy-preserving key-derived namespaces and canonical extensionless object identifiers. Backward compatibility with pre-0.5.4 remote layouts is not maintained and synchronization must be freshly re-initialized on all client machines.

### Added

- Isolated remote history objects (markers, commits, epochs, active writers, and maintenance barriers) within deterministic namespaces derived from the vault master key via HKDF/BLAKE3 to prevent unauthorized observation of commit graphs and activity cadences on shared storage.
- Added staged execution tracking (`Reconciling`, `Staging`, `Transferring`, `Finalizing`) and automated plan truncation for large file sets in `kasumi sync` and `kasumi status`.
- Added full English and Brazilian Portuguese (`pt-BR`) localization for remote health reports, marker validation, epoch verification, and orphan detection in `kasumi inspect`.

### Changed

- Eliminated plaintext file extensions (`.kcom`, `.head`, `.epoch`, `.writer`, `.probe`) across all remote storage operations in favor of canonical extensionless object naming.
- Standardized all internal error descriptions, assertion messages, and runtime diagnostic logging in English across the engine.
- Removed legacy directory fallback scans (`history/gc/v1/writers`), reducing round-trip remote listing overhead during garbage collection and epoch maintenance.

### Tests

- Added unit and integration test suites validating key-derived layout isolation, canonical object parsing, and concurrent GC barriers under partitioned namespaces.
- Updated all end-to-end sync, coordinator, and inspection tests, achieving a 100% pass rate across all 811 tests.

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
