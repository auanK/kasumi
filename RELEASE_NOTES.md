# Kasumi v0.9.3

Patch release fixing directory synchronization when locally ignored content remains after remote deletions or renames.

## Highlights

### Ignored Content and Directory Reconciliation

Kasumi now preserves ignored files and the parent directories needed to contain them when managed content is deleted or moved remotely. These residual directories are excluded from the managed synchronization tree instead of blocking directory removal or being published back as new local directories.

The behavior also covers files that were previously synchronized and later became ignored. Ordinary empty directories remain synchronized, and ignored files are neither moved nor deleted automatically.

### Observation and Transaction Safety

Local scanning tracks transient physical evidence of ignored content without adding ignored entries to the synchronized Snapshot. Reconciliation and final validation use the managed projection consistently, while stabilization recalculates plans using updated observations.

Invalid metadata for managed regular files and unsupported non-regular entries remain explicit observation failures. Unexpected filesystem changes that invalidate a directory removal cause a conflict rather than silent deletion or success.

Interrupted transactions involving local moves and blocked directory removals retain the existing authenticated recovery behavior. Recovery and subsequent synchronization were validated against the affected v0.9.2 scenarios without requiring manual state cleanup.

## Compatibility

Remote object formats, the SQLite schema, and the transaction journal codec are unchanged. No new `.kasumiignore` syntax or automatic deletion of ignored content is introduced.

Kasumi provides no general backward compatibility guarantee between 0.x releases or automatic migration. Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi) before replacing binaries. `kasumi update` replaces only the executable.
