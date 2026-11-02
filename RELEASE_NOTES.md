# Kasumi v0.9.4

Feature release introducing opt-in disposable ignored content via the `(?d)` modifier in `.kasumiignore`, transactionally removing eligible ignored files when previously managed directory trees are pruned.

## Highlights

### Disposable Ignored Files

Kasumi v0.9.4 introduces the optional `(?d)` modifier in `.kasumiignore` (such as `(?d)*.bak`). By default, all ignored files remain strictly protected and are never modified or removed. The `(?d)` modifier applies exclusively to regular files; directory rules cannot be made disposable, and patterns ending in `/` with `(?d)` are rejected during parsing.

When `(?d)` is specified on a pattern matching regular files, matching entries are classified as disposable. Disposable removal is not a general garbage collection sweep: it is strictly conditioned on the deletion of a previously managed directory tree authorized by reconciliation. If a directory tree contains protected ignored files, the subtree is preserved intact, preventing partial deletion, while nested subdirectories that are independently eligible remain candidate for removal.

Disposable content is never uploaded, materialized into Snapshots, or published to remote storage. `kasumi status <profile>` and `kasumi sync <profile> --dry-run` display planned `DeleteIgnoredLocalFile` operations and directory prunings without executing changes on disk.

### Transaction Safety and Recovery

Disposable removals are executed locally through the new `DeleteIgnoredLocalFile` action:

- **Pre-Removal Verification:** The file's native filesystem identity, size, and BLAKE3 hash are verified before any destructive operation, and an authenticated staging backup is established.
- **Fail-Closed Conflict Detection:** If a file disappears without evidence of removal by Kasumi, or if an external process modifies or replaces the target, Sync reports an explicit destination conflict.
- **Rollback and Interrupted Recovery:** Disposable removals participate in Kasumi's authenticated transaction journal. Interrupted operations can be recovered or rolled back when the required evidence remains valid. When safe recovery cannot be established, Kasumi fails closed and retains the necessary evidence instead of claiming successful recovery.
- **Platform Invariants and POSIX Boundary:** On Windows, private-file removal uses `SetFileInformationByHandle` with `FileDispositionInfo` after validating the file identity. On POSIX systems, identity verification and `unlink()` remain discrete system calls; therefore, POSIX execution cannot guarantee atomic isolation against hostile concurrent replacement within that narrow kernel window.

### Provider Certification Reliability

Test fixtures for operational provider certification have been hardened by allocating dedicated, isolated temporary workspaces per test instance (`kasumi::test::make_temp_workspace`). This eliminates timestamp-based file path collisions under concurrent CTest execution while maintaining strict byte-for-byte readback integrity verification.

## Compatibility

- **Transaction Journal:** The journal writer produces format 10. The reader accepts both formats 9 and 10. Journal format 8 is unsupported. Wire action IDs 0–10 are preserved, and `DeleteIgnoredLocalFile` is assigned wire ID 11.
- **Remote Storage and SQLite:** Remote object formats, encryption schemes, and SQLite database schemas remain unchanged.
- **General Compatibility:** Kasumi provides no general backward compatibility guarantee across disparate 0.x releases. All participating clients should run the same release. Follow the upgrade guidelines in [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi) before replacing binaries. `kasumi update` replaces the executable and does not perform data migration.
