# Architecture Map

Kasumi is a C++23 client that synchronizes local directories through a passive shared object store. Clients authenticate and reconcile history locally; the provider stores encrypted payloads and protocol objects. Each machine has its own profile and accepted SQLite state. The shared vault is identified by its key and authenticated genesis Epoch. Concurrent clients can publish immutable Commit branches without a global sync lock. A later client resolves the branches and may publish a merge Commit.

```text
CLI/profile → local observation + authenticated remote history + StoredState
             → remote DAG resolution → reconciliation → SyncPlan
             → reobservation → staged execution → Commit/HEAD/Epoch publication
             → SQLite accepted state and cleanup
```

## Follow an Operation

| Question | Owner |
|---|---|
| What does `config` do to profiles, keys, and private paths? | [Profile Management](architecture/profile-management.md), [Configuration and Usage](configuration-and-usage.md) |
| How does an operation resolve runtime, lock, credentials, and transport? | [Application and Runtime](architecture/application-and-runtime.md) |
| What is a Snapshot, NodeRow, or Merkle hash? | [Data Model](architecture/data-model.md) |
| What do SQLite, StoredState, caches, checkpoints, keys, and locks own? | [Local Persistent State](architecture/local-state.md) |
| How is disk observed, and when are hashes or journal checkpoints reused? | [Local Observation](architecture/local-observation.md) |
| How do local/base/remote form a candidate tree and SyncPlan? | [Reconciliation](architecture/reconciliation.md) |
| What does `sync --dry-run`/Preview or `status` observe and report? | [Preview and Status](architecture/planning-and-status.md) |
| How does `sync` stabilize, execute, and publish? | [Synchronization](architecture/synchronization.md) |
| What do transaction phases mean, and how does interruption recovery decide? | [Transactions and Recovery](architecture/transactions-and-recovery.md) |
| How does `fsck` audit structure and every referenced payload? | [Fsck](architecture/fsck.md) |
| When can `gc` quarantine, restore, or purge safely? | [Garbage Collection](architecture/garbage-collection.md) |
| How are Commit DAGs, logical heads, merge bases, Epochs, and retention resolved? | [History and Concurrency](architecture/history-and-concurrency.md) |
| What is the actual remote namespace and publication order? | [Remote Layout and Publication](architecture/remote-layout.md) |
| What must a backend implement, and how are optional capabilities verified? | [Transport](architecture/transport.md) |
| What does each `remote ...` family inspect? | [Remote Inspection](architecture/remote-inspection.md) → [History/Epoch](architecture/remote-history-inspection.md), [Content](architecture/remote-content-inspection.md), [Physical/Maintenance](architecture/remote-maintenance-inspection.md) |
| What can the provider see, and what does `key.bin` protect? | [Security](security.md) |

## Effects at a Glance

| Request | Local effects | Remote effects |
|---|---|---|
| `config` list/create/edit/rename/delete | Reads or changes `config.toml` and private profile paths; delete preserves the synchronized directory | None |
| Preview (`sync --dry-run`), Status | Reads local/SQLite state; profile lock and permission normalization are possible | Observation only; no recovery or publication |
| Sync | May change synchronized files, cache/checkpoint, transaction journal, and accepted `StoredState` | May upload content and publish/prune history; registers a writer for active work |
| Fsck | Checkpoint/workspace; preceding recovery can change local state | Audit reads only, **except** effects of preceding transaction recovery |
| GC | Workspace; preceding recovery can change local state | Barrier/probe even in analysis-only mode; online restore, quarantine, source removal, and purge when safe |
| `remote ...` | Temporary workspace and possible private history cache; `remote get` writes its chosen destination | Inspection reads only; no normal transaction recovery |

Read the linked owners for exact invariants. The [README](../README.md) is a short entry point, and [Provider Certification](provider-certification.md) records externally established backend certification results.
