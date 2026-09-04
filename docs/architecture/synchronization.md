# Synchronization and Reconciliation

A `kasumi sync` run observes the local tree, the locally accepted base, and the effective remote tree. Three-way reconciliation computes a `SyncPlan`, which is re-observed before execution and then tracked through the transaction journal:

```text
Local Tree
    +
Accepted Base Tree
    +
Effective Remote Tree
    ↓
Three-Way Reconciliation
    ↓
SyncPlan
    ↓
Re-observation & Stabilization
    ↓
Transactional Journal
    ↓
Publication and/or Local Materialization
```

## The Reconciliation Base

Upon accepting any publication, a client persists its `StoredState` into local SQLite storage. The Merkle tree of this state is the **reconciliation base**: the last shared state accepted and persisted locally.

Consider a base state `V1`. If the local tree remains `V1` while the remote tree has advanced to `V2`:

```text
Base:   V1
Local:  V1
Remote: V2
=> Remote-only modification (remote changed relative to the base while local remained unchanged)
```

Because the local state matches the base, the client simply materializes `V2` locally.

If the local tree has changed to `V3` while the remote tree has advanced to `V2`:

```text
Base:   V1
Local:  V3
Remote: V2
=> Concurrent modification
```

Comparing each side with the base distinguishes which side changed relative to the accepted state and allows the reconciler to derive the required operations. Directly comparing local and remote trees without a base would only indicate differences without showing which side diverged.

## Two Decoupled Resolution Phases

When concurrent publications exist in the history DAG, synchronization executes two decoupled resolution steps:

1. **Remote DAG Resolution**: Reconciles multiple remote logical heads into an **effective remote tree**.
2. **Three-Way Reconciliation**: Combines the local tree, base tree, and effective remote tree into a **candidate shared tree**.

```text
Remote HEADs ── DAG Resolution ──> Effective Remote Tree

Local Tree ────────────┐
Base Tree ─────────────┼── 3-Way Reconciliation ──> Candidate Shared Tree
Effective Remote Tree ─┘
```

Remote DAG resolution derives the effective remote tree, preserves conflict variants, or fails if the history cannot be resolved (such as an ambiguous merge base or structural validation failure).

`StorageState` represents the validated remote view delivered to reconciliation, encapsulating logical heads, reachable commits, generation counters, authenticated Epoch information, the effective tree, and history conflict state.

## Three-Way Reconciliation Logic

Reconciliation categorizes each path across the three inputs:

* **Local-only changes**: Produce remote-side upload and publication work.
* **Remote-only changes**: Produce local materialization work.
* **Changes on independent paths**: Represented in the candidate tree without generating conflict artifacts.
* **Incompatible local/remote states**: Generate conflict-preservation operations.
* **Deletions**: Interpreted relative to the base.

If a file was deleted remotely while modified locally, the local content is retained and uploaded. If a file was modified remotely while deleted locally, the remote content is retained and materialized.

When both local and remote files have been modified concurrently since the base, observed filesystem modification timestamps (`mtime`) decide which version retains the canonical path:
* The local file keeps the canonical path only when its observed `mtime` is strictly greater than the remote `mtime`; the remote variant is downloaded as `<path>.kasumiconflict_remote`.
* Otherwise (including equal timestamps), the remote file keeps the canonical path, and the local file is renamed to `<path>.kasumiconflict_local` and uploaded.

## The SyncPlan

Comparing trees produces a `SyncPlan`: a strictly ordered sequence of operations targeting a specific generation. Decoupling calculation from execution allows:
1. Re-observing computed inputs before mutation execution;
2. Validating path security and plan invariants;
3. Recording the plan and operation progress in the transaction journal;
4. Inspecting persisted phases during recovery after an interruption.

## Canonical Operation Ordering

Plan actions execute in a strict dependency order:

1. `RenameLocal`
2. `Upload`
3. `CreateLocalDirectory`
4. `CreateRemoteDirectory`
5. `Download`
6. `DeleteLocal`
7. `DeleteLocalDirectory`
8. `DeleteRemote`
9. `DeleteRemoteDirectory`

Local directory creation proceeds top-down (parents before children). Directory deletion proceeds bottom-up (children before parents).

## Active Writers and Re-Observation

A sync run that performs active synchronization work registers an ephemeral `writer` marker in remote storage. Active work includes publication, storage repair, local mutation, or committing an accepted state locally. Multiple writer registrations can coexist: writer registration checks for the presence of a GC barrier, and a present barrier blocks admission of new writers. Writer markers coordinate with garbage collection and do not act as an exclusive global synchronization lock between clients.

Before mutation execution, Kasumi re-observes the inputs used by the plan. If an input observation changed during plan generation, reconciliation is recalculated. Stabilization is attempted up to three times; repeated changes result in a `ConcurrentModification` error.

After mutation execution, Kasumi re-scans the local directory. New local paths created during execution and outside the candidate shared tree are left on disk and excluded from the current publication tree validation; they can be observed by a later synchronization cycle. Changes to expected paths, however, result in a `CompositionMismatch` error and trigger rollback.

## Transactional Execution

Synchronization execution records transaction phases and operation progress so an interrupted run can be inspected and recovered on the next execution:
* `transaction.bin.enc` stores the authenticated and encrypted journal record (plan, phase, and progress).
* `.transactions/<id>` stores temporary pre-mutation backups and staging files.
* Local mutation preparation records backup and staging information used when rollback is required.

```text
Plan Generated
  → Persist Encrypted Journal
  → Prepare Staging & Backups
  → Execute Network Transfers & Local Mutations
  → Verify Materialized Local Snapshot
  → Publish Commit Object & HEAD Marker
  → Persist StoredState to SQLite
  → Clean Journal & Workspaces
```

## Publication

When the shared state has evolved, the client prepares and publishes a new Commit whose tree is derived from the validated post-execution state. In normal synchronization with existing history, its parents are the sorted logical heads from the stabilized observation, and its height is the maximum observed height + 1. During initial bootstrap, the commit has zero parents and height 0.

Stabilization does not create an exclusive lock against remote publications. Another client may publish concurrently before or during publication, which can introduce an additional logical head. Logical heads observed by later synchronization runs are resolved through the history DAG.

```text
Confirmed Content Payload
  → Confirmed Commit Payload
  → Publish & Confirm HEAD Marker
  → Publish Epoch (if horizon advanced)
  → Persist Local SQLite StoredState
  → Prune Ancestral HEAD Markers
  → Finalize Transaction
```

## Failure Recovery Strategy

Every sync run checks for an existing transaction journal before planning new operations:

1. **Pre-publication transactions**: A transaction can be resumed when its resumption checks succeed; otherwise, rollback uses the transaction workspace to restore local mutations to their pre-transaction filesystem state. The previously persisted `StoredState` remains unadvanced.
2. **Publication-phase transactions**: When a transaction reached publication phases, recovery inspects remote publication state.
3. **Roll-forward**: If the referenced commit object is reachable remotely and its HEAD marker is valid, recovery rolls forward the remaining commit, Epoch, database, and cleanup phases.
4. **Recovery conflict**: If the journal records publication but the expected remote commit or HEAD marker is invalid or mismatched, recovery reports a recovery conflict (`RecoveryConflict`) rather than assuming success.
5. **Indeterminate state**: If remote publication state cannot be determined (such as due to network or transport failures during verification), recovery returns an indeterminate error (`RecoveryIndeterminate`) instead of guessing.
6. **Local-only transactions**: Local recovery uses journal and database state to determine whether to complete or roll back.

Recovery decisions are based on persisted transaction phases together with observed local and remote state. Indeterminate or conflicting publication states are reported as recovery errors instead of being silently accepted.
