# Preview and Status

`kasumi sync <profile> --dry-run` and `kasumi status <profile>` are distinct CLI
intents but share the same read-only planner and return a plan report. `--full`
changes display truncation only. Neither command is a shortened Sync execution.

## Lifecycle

1. Runtime resolution validates the profile and retention, acquires the
   **local** exclusive profile lock, resolves the persisted or supplied matching
   master key, and opens the configured transport. See [Application and Runtime](application-and-runtime.md).
2. The planner **does not call normal transaction recovery**. It loads the accepted `StoredState` reconciliation base from SQLite and reads `.kasumiignore`; local observation and authenticated remote history observation run concurrently. Local observation creates a read-only session that reuses valid strong fingerprints from the persistent file-hash cache, falling back to full hashing for new, modified, or uncached files. Unlike Sync, this path operates strictly read-only: it does not commit file-hash cache deltas, register remote writers, or mutate SQLite state. Reconciliation can also download/authenticate a remote `.kasumiignore` to choose the effective projection. The remote observation can use the accepted Commit/Ciphertext ID and Epoch as frontier hints. See [Local Observation](local-observation.md) and [History and Concurrency](history-and-concurrency.md).
3. [Reconciliation](reconciliation.md) validates local/base/remote continuity and derives a candidate shared tree and ordered `SyncPlan`. The planner converts operations to action/path rows and counts, upload/download byte totals, conflict flag, target generation, and pending-materialization paths. It reports a plan; it does not stage, transfer, apply, stabilize, or publish it.
4. The transport closes, key/credential buffers are wiped at cleanup points, and the profile lock is released. No accepted `StoredState` commit, transaction journal, content upload, Commit, HEAD marker, or Epoch publication occurs.

Preview and Status do **not** run Sync's required-content availability preflight or repair. A physically absent Content object can therefore be invisible to an otherwise empty preview until normal Sync or an explicit remote audit observes it. A plan report is not proof that required payload bytes are physically available; use `remote contents --audit` or `fsck` when that distinction matters. See [Required Content Availability](synchronization.md#required-content-availability).

The synchronized tree is not intentionally mutated. Read-only resolution and private-path protection may still normalize local permissions; acquiring the lock can create/update its local lock file. The command reads `config.toml`, `key.bin` or an explicit key, SQLite state, the local tree, remote history, and any presence checks needed for history observation. It does not probe every required Content ID. A pending Sync transaction remains pending. It may affect what the plan can observe or make a later Sync recover first.

Every scan still enumerates the managed tree and reads metadata. Cached hash
reuse requires matching path, type, size, nanosecond mtime, and reliable native
identity; otherwise the file is hashed. A differing authenticated ignore
projection uses `FullHash`. Session cache changes remain in memory and are
discarded on return. Preview/Status do not perform Sync's independent destructive
target checks because they apply no mutations. The accepted history anchor is a
separate optimization: [all observed branches must link to it](history-and-concurrency.md#cached-anchors-and-scoped-observation),
or loading retries without that anchor before resolution.

Invalid profile/key/transport, an inaccessible or invalid local tree, malformed accepted state, missing remote history for a persisted base, authentication/continuity failure, or reconciliation error is returned at preparation, observing, or calculating stage rather than repaired by the planner. The report is a **point-in-time observation**, not a reservation: local or remote state can change before a later Sync, which reobserves and may choose a different plan. `status` is a direct status query; `sync --dry-run` previews the actions that a Sync would currently plan. They share computation, not a guarantee of identical future effects. See [Synchronization](synchronization.md) for the executing path.
