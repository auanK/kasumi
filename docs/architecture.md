# Architecture Map

The [0.32 vault protocol](architecture/protocol-0.32.md) defines the interoperability and safety contract shared by Sync, recovery, and maintenance.

Kasumi is a C++23 client that synchronizes local directories through a passive shared object store. Clients authenticate and reconcile history locally; the provider stores encrypted payloads and protocol objects. Each machine has its own profile and accepted SQLite state. The shared vault is identified by its key and authenticated genesis Epoch. Concurrent clients can publish immutable Commit branches without a global sync lock. A later client resolves the branches and may publish a merge Commit.

```text
CLI/profile → local observation + authenticated remote history + StoredState
             → remote DAG resolution → reconciliation → SyncPlan
             → reobservation → staged execution → verified Commit and HEAD when publishing
             → genesis Epoch on bootstrap, or checkpoint validation on established history
             → SQLite accepted state and cleanup
```

## Follow an Operation

| Question | Owner |
|---|---|
| What do `config` and `profile ...` do to profiles, keys, and private paths? | [Profile Management](architecture/profile-management.md), [Configuration and Usage](configuration-and-usage.md) |
| How does an operation resolve runtime, lock, credentials, and transport? | [Application and Runtime](architecture/application-and-runtime.md) |
| What is a Snapshot, NodeRow, or Merkle hash? | [Data Model](architecture/data-model.md) |
| What do SQLite, StoredState, caches, checkpoints, keys, and locks own? | [Local Persistent State](architecture/local-state.md) |
| How does each tree scan validate metadata and reuse persisted file hashes? | [Local Observation](architecture/local-observation.md) |
| How do local/base/remote form a candidate tree and SyncPlan? | [Reconciliation](architecture/reconciliation.md) |
| What does `sync --dry-run`/Preview or `status` observe and report? | [Preview and Status](architecture/planning-and-status.md) |
| How does `sync` stabilize, execute, and publish? | [Synchronization](architecture/synchronization.md) |
| What do transaction phases mean, and how does interruption recovery decide? | [Transactions and Recovery](architecture/transactions-and-recovery.md) |
| Which journal bytes are confirmed, cached, replayed, or retired? | [Incremental Transaction Journal](architecture/transaction-journal.md) |
| How does `fsck` audit structure and every referenced payload? | [Fsck](architecture/fsck.md) |
| How does `repack` consolidate Micro-Packs without downloading or deleting remote objects? | [Micro-Pack Repack](architecture/repack.md) |
| How does GC authorize direct deletion and preserve partial results? | [Garbage Collection](architecture/garbage-collection.md) |
| How are Commit DAGs, logical heads, merge bases, Epochs, and retention resolved? | [History and Concurrency](architecture/history-and-concurrency.md) |
| What is the actual remote namespace and publication order? | [Remote Layout and Publication](architecture/remote-layout.md) |
| What must a backend implement, and how are optional capabilities verified? | [Transport](architecture/transport.md) |
| What does each `remote ...` family inspect? | [Remote Inspection](architecture/remote-inspection.md) → [History/Epoch](architecture/remote-history-inspection.md), [Content](architecture/remote-content-inspection.md), [Physical/Maintenance](architecture/remote-maintenance-inspection.md) |
| What can the provider see, and what does `key.bin` protect? | [Security](security.md) |

## Effects at a Glance

| Request | Local effects | Remote effects |
|---|---|---|
| `config` list/create/edit/rename/delete, `profile <create\|edit\|clone\|storage\|rename\|delete>`, `key` | Reads or changes `config.toml`, private profile paths, and persisted keys in the OS vault or `key.bin`; delete preserves the synchronized directory | None (`profile create --verify` checks the candidate connection before publishing the name) |
| `profile test <profile>` | Validates credentials and opens transport read-only without changing local SQLite state | Lists/observes vault readiness (`empty_ready_for_init` or authenticated HEAD/Epoch probe) read-only |
| `ignore check`, `ignore init` | `ignore check` evaluates `.kasumiignore` rules read-only; `ignore init` writes (or previews with `--dry-run`) `.kasumiignore` in `local_dir` | None |
| `list`, `show`, `diagnostics`, `conflicts [<profile>]`, `web`, `completion` | `list`/`show`/`diagnostics`/`conflicts <profile>` inspect `config.toml`, `.kasumiignore` syntax, local/SQLite traceability, or `.kasumiconflict_*` artifacts read-only without contacting remote storage or exposing secrets; `web` launches/opens the daemon's embedded Web UI (or configures `web-password.json` via `web set-password`); `completion` prints shell completion scripts | None |
| `conflicts resolve` | Under `profile-<name>.lock` (skipped for `--dry-run`): optionally promotes the chosen `.kasumiconflict_*` file atomically over the canonical path, and retains the other artifacts in an excluded local recovery directory | None |
| Preview (`sync --dry-run`), Status | Reads local/SQLite state; profile lock and permission normalization are possible | Observation only; no recovery or publication |
| Sync | May change synchronized files, file-hash cache, transaction journal, and accepted `StoredState` | May upload content and publish/prune history; registers a writer for active work |
| Resolve Missing | `--dry-run`: read-only preview of pending paths. `--confirm` (or confirmed prompt): preceding recovery, logical deletion updates in `StoredState` | `--dry-run`: observation only. Confirmed run: registers writer and publishes a `KCOM` Commit/HEAD marking unresolved paths deleted |
| Fsck | Workspace; preceding recovery can change local state | Audit reads plus best-effort `KACT` v1 activity record publication; preceding transaction recovery may publish Sync changes |
| Repack | `--dry-run`: read-only observation (refuses pending journal). Real run: preceding recovery if applicable, file-hash cache delta, and updated `StoredState` + `StorageManifest`; zero synchronized-file mutations | `--dry-run`: observation only. Real run: registers writer, uploads consolidated `KPAK\x01` packs, publishes tree-preserving Commit/HEAD, prunes superseded HEAD markers; zero remote deletions |
| GC | `--dry-run`: read-only observation (refuses pending journal). Real run: workspace; preceding recovery can change local state | `--dry-run`: observation only. Real run: direct deletion of eligible orphan Content, redundant CommitVariants, expired unreachable Commits behind Epochs, and pruned `KACT` activities under cooperative multi-barrier controls and a globally validated plan, plus `KACT` v1 activity publication; preceding recovery may publish |
| `remote ...` | Temporary workspace; `remote get` writes its chosen destination and `remote restore` materializes a snapshot/subtree into a verified empty directory | Inspection reads only; no normal transaction recovery |

Read the linked owners for exact invariants. The [README](../README.md) is a short entry point.
