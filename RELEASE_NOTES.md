# Kasumi v0.9.0

Release focused on profile management, reconciliation of concurrent histories, CLI reliability, and more efficient garbage collection.

## Highlights

### Profile Management and Local State

Clone profiles through `kasumi config` to reuse settings and the master key with fresh SQLite state. The wizard shows local profile state without contacting remote storage, and configuration mutations are serialized across local processes.

### Concurrent History Reconciliation

Sync can now reconcile histories with multiple best common ancestors, combining independent edits and preserving conflict variants and later deletions. Previously rejected concurrent histories can converge when the required authenticated ancestry is available; the [history rules](docs/architecture/history-and-concurrency.md#selecting-the-merge-base) describe the limits.

### CLI and Recovery Reliability

The CLI standardizes argument validation and contextual help, reports elapsed time for executed operations, and observes cancellation at safe boundaries. Windows preserves native Unicode arguments and handles concurrent configuration access more reliably. Clone rollback and interrupted Sync cleanup verify ownership before removing temporary state.

### Garbage Collection

GC classifies orphan Content from authenticated reachability without payload auditing and removes candidates in bounded batches. Explicit abandoned-barrier recovery and clearer partial-removal diagnostics help operators recover interrupted maintenance. Stop Sync on every client before GC and follow the [operational contract](docs/architecture/garbage-collection.md#operational-contract).

## Compatibility

Kasumi provides no backward compatibility between 0.x releases or automatic migration of local and remote formats. Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi) before replacing binaries. `kasumi update` replaces only the executable.
