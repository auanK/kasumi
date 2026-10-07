# Remote Inspection

`kasumi remote ...` is a separate inspection dispatch, not one of the five `application::Operation` paths. Exact syntax is in [Configuration and Usage](../configuration-and-usage.md#remote-inspection). The family reports either an authenticated **logical** history/tree, a physical namespace/maintenance view, or both. A raw listing's existence and shape are not proof that its bytes authenticate.

## Common request path

1. The CLI parses one `InspectionOperation` and validates that its selector belongs to that operation (head, Commit, Epoch, Content ID, logical path, or destination). Invalid IDs, paths, and mismatched selectors fail before observation.
2. Inspection resolves the profile in read-only runtime mode, loads `key.bin` or verifies a supplied matching key, derives the keyed remote layout, opens the local/rclone transport, and creates a temporary workspace. It does **not** acquire the ordinary application profile lock or run Sync transaction recovery; another local process or remote writer can change what it sees.
3. The operation chooses its input view. Logical tree/history queries authenticate HEAD references, Commit variants, Snapshot/DAG, and Epoch continuity, using accepted SQLite frontier hints where applicable. Complete-history queries can load an authenticated private `inspection-history-v1.cache`; failed cache merge falls back to cold remote observation. Epoch queries load the authenticated chain directly. Physical queries start from the provider listing and then authenticate history/metadata only where their specific report requires it.
4. A typed report or error is returned. The temporary workspace, transport, and key are cleaned up. Complete-history queries may save the private history cache; read-only path protection may normalize local permissions. `remote get` additionally writes its explicit local destination. None of these operations publishes a Commit/HEAD/Epoch, runs GC, or accepts a new `StoredState` base.

These are point-in-time diagnostics, **not** a consistent remote snapshot against concurrent writers. Missing or invalid authenticated history, selector ambiguity, unsafe destination, unsupported transport result, or defensive history/listing limits fail rather than invent a usable tree. Physical-only listings intentionally make weaker claims. A pending Sync transaction remains pending until Sync, Fsck, or GC invokes recovery.

## Choose the view

| Question | Operation owner |
|---|---|
| Which heads, Commits, selected Snapshot, summary, or Epochs exist? | [History and Epoch Inspection](remote-history-inspection.md): `heads`, `tree`, `commits`, `commit`, `summary`, `epochs`, `epoch` |
| What is in the effective tree, and which content bytes authenticate? | [Content Inspection](remote-content-inspection.md): `stat`, `get`, `contents`, `contents --audit`, `content` |
| Which physical markers/objects, orphan candidates, quarantine entries, writers, or health reasons exist? | [Maintenance Inspection](remote-maintenance-inspection.md): `markers`, `objects`, `orphans`, `quarantine`, `writers`, `health` |

The [Remote Layout](remote-layout.md) defines keyed object names and Commit ID versus Ciphertext ID; [History and Concurrency](history-and-concurrency.md) explains logical heads and effective-tree resolution. For operations that **change** remote state, see [Synchronization](synchronization.md) and [Garbage Collection](garbage-collection.md).
