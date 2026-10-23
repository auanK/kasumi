# Kasumi v0.8.0

## Highlights

- Direct garbage collection with one authenticated observation and a globally
  validated deletion plan.
- Required remote Content availability checks and authenticated repair during
  Sync, including otherwise no-op runs.
- Clearer partial-removal diagnostics and stronger crash-recovery coverage.

## Garbage Collection

GC acquires cooperative exclusivity per vault, authenticates history, builds
and validates a global deletion plan, removes candidates sequentially, and
finalizes maintenance. It collects orphan Content and redundant CommitVariants
while preserving required Content, HEAD-selected variants, valid alternatives
for reachable Commits, and Epochs.

Quarantine and its commands have been removed. Deletions are permanent: stop
Sync and other maintenance on every client before running `kasumi gc <profile>`.
On failure, GC reports acknowledged removals and any uncertain mutation, stops
deletion, and attempts barrier cleanup. A later run builds a fresh plan.

See [Garbage Collection](docs/architecture/garbage-collection.md) for the
protocol, failure handling, and backend requirements.

## Synchronization and Recovery

`kasumi sync <profile> --initial` can initialize a missing local database from
the existing profile configuration and vault key when no current remote history
or unfinished local transaction evidence exists. It publishes new history from
local files and can reuse compatible remote Content. It does not migrate old
databases, recover deleted history, or remove remote objects. Sync without the
flag continues to reject a missing database.

Sync checks the remote Content required by the reconciled tree and pending
work. Missing objects can be repaired from local bytes verified against the
expected hash and size, independently of the scanner's hash cache. Repair-only
work preserves logical history without publishing a new Commit or HEAD.

Without a valid repair source, Sync preserves logical files and pending
evidence and can return partial synchronization (exit code `2`). Transport
errors and inventory disagreement are not treated as missing Content.

Interrupted repairs use the authenticated transaction journal. Preserve journals
and backups when recovery fails; see [Transactions and Recovery](docs/architecture/transactions-and-recovery.md).
For referenced-payload integrity checks, use [Fsck](docs/architecture/fsck.md).

## Reliability and Testing

- Added regressions for cooperative GC/Sync admission, partial failures, and
  recovery after abrupt process termination.
- Corrected Windows GCC/MSYS2 test portability and crash-helper linkage.
- Fixed a crash-test signaling race and expanded the release-critical gate.
- Google Drive/rclone validation exercised up to 1,024 GC candidates with exact
  post-run physical reconciliation. Build identities, results, and measurement
  scope are recorded in [Provider Certification](docs/provider-certification.md).

## Upgrade Notes

Use the same release on all clients and follow
[Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi) before replacing
binaries. It covers backups, pending recovery, and the 0.x compatibility policy.
`kasumi update` replaces the executable only.

For installation, see [Getting Started](docs/getting-started.md) or
[Build and Test](docs/build-and-test.md).
