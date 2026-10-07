# Transactions and Recovery

Sync durably records a transaction before applying its [SyncPlan](synchronization.md). The encrypted, authenticated `transaction.bin.enc` is recovery authority for **this in-progress Sync**, not a remote transaction or a replacement for the accepted [StoredState](local-state.md). Its record pins the observed local base Commit ID/height, remote generation and head or parent IDs, old/new pending-materialization paths, immutable plan, per-operation progress, whether publication is required, and later Commit/Ciphertext/HEAD/Epoch references. `.transactions/<id>` holds staging and pre-mutation backups. [Remote Layout and Publication](remote-layout.md) owns object identities and verification methods.

```text
old StoredState + durable journal → staged/applied plan → verified Commit
    → verified HEAD marker (externally visible) → optional verified Epoch
    → new StoredState in SQLite → marker/workspace/journal cleanup
```

## Durable phases

The phase is the **last saved checkpoint**, not proof that a following filesystem or network call never started. Recovery inspects real state whenever a crash could fall between an effect and the next journal write. `publication_required=false` skips the Commit/HEAD/Epoch rows entirely.

| Persisted phase | Durable facts and uncertainty | Recovery decision / next safe action |
|---|---|---|
| `Started` | Journal pins the base, plan, and pending intent; the workspace and operation preparation may be incomplete. Old `StoredState` remains accepted. | Check per-operation progress and required backups. Before publication, normally roll back; only the narrowly resumable publication-upload case below can continue. |
| `FilesStaged` | Operations/preconditions and necessary backups were prepared, but transfers and local mutations may already have begun while this phase remained saved. Some remote content may be uploaded. | Use operation checkpoints and backups to roll back local effects, or return a resumable transaction only under the exact pinned-input conditions below. Do not infer all plan effects from the phase name. |
| `LocalChangesApplied` | Plan transfers/mutations finished and were checkpointed; final local reobservation and publication-tree validation may still be pending. For local-only work, SQLite might advance before the next phase save. | Re-establish exact inputs and continue only through the narrow publishing resume route, otherwise roll back pre-publication local effects; check SQLite's actual state for local-only recovery. |
| `CommitPrepared` | Canonical Commit ID and parents are recorded. Speculative upload may have left a physical Commit object, but no HEAD was intentionally published yet. | A bare Commit object is **not** an accepted publication. Resume only under pinned-input rules; otherwise roll back local mutations, leaving any harmless remote orphan for later GC. |
| `CommitUploaded` | Commit ID, Ciphertext ID, and marker identity are durable; the Commit object may be present/verified, but the marker might have been published just before a crash. | Inspect the **exact HeadReference**: absent/invalid marker before `HeadPublished` permits rollback; valid marker requires authenticated Commit verification and roll-forward; unreadable visibility is indeterminate. |
| `CommitVerified` | Commit bytes passed publication verification, but HEAD publication is not yet journaled and could have started. | Same exact-marker inspection as `CommitUploaded`; never treat Commit verification alone as public acceptance. |
| `HeadPublished` | Marker PUT completed or a valid marker was observed after an ambiguous PUT; its later verification checkpoint may be missing. | Reinspect marker and authenticate its referenced Commit. A valid marker is the externally visible publication boundary and must roll forward. Missing/invalid marker conflicts with this phase; uncertain visibility is indeterminate. |
| `HeadVerified` | Exact physical marker was verified. Local SQLite may still hold the old base. | Reauthenticate the published Commit/reference and roll forward through Epoch, SQLite, and cleanup; do not silently roll back visible history. |
| `EpochPrepared` | For genesis, canonical Epoch intent is recorded but remote publication is not confirmed. | With valid HEAD, prepare/verify or publish the genesis Epoch before accepting SQLite. A pruning Epoch recorded as prepared without a durable upload checkpoint is a recovery conflict. |
| `EpochUploaded` | Genesis or pruning Epoch may be on remote storage; verification/chain acceptance may be incomplete. | Authenticate the exact Epoch and continuity; genesis can be retried/verified. Missing or divergent pruning Epoch is a conflict, and unreadable remote state remains indeterminate. |
| `EpochVerified` | The required new Epoch was authenticated, but SQLite may still be old or its write may have completed before this phase advanced. | Compare SQLite with old or intended target, reject a third state or Epoch regression, then commit/confirm the new accepted base. |
| `DatabaseCommitted` | New `StoredState` is intended to be durable; marker pruning and local cleanup may still be pending. | Recheck SQLite against authenticated Commit and pending intent, prune eligible ancestral markers for publishing Sync, then continue cleanup. No rollback of accepted publication. |
| `CleanupCompleted` | Marker processing is checkpointed; the workspace or journal file may still exist. | Remove the transaction workspace **before** clearing the journal. A cleanup failure keeps the journal for another cleanup attempt. |

Normal publication verifies the encrypted Commit object **before** publishing HEAD. A Commit upload or successful PUT response alone cannot establish that HEAD is visible. After `HeadPublished`, recovery requires a valid exact marker and authenticated reachable Commit with the recorded parents and Ciphertext ID. It resolves intended pending-materialization paths against that Commit and checks old/target SQLite state before accepting the new base. Transport uncertainty yields `RecoveryIndeterminate`; a contradictory marker, Commit, Epoch, or SQLite state yields `RecoveryConflict`. Remote operations are inspected/verified rather than assumed successful or blindly repeated.

## Per-operation state and branching

| `OperationState` | Meaning for resume and rollback |
|---|---|
| `Pending` | No preparation is durably accepted; revalidate paths/preconditions before acting. |
| `Prepared` | Preconditions were checked, but no effect is accepted yet. Reuse only after validating any required staged evidence. |
| `BackupCreated` | Rollback state is preserved (or prior absence is recorded) **before** a local mutation may occur. File backups are checked against the prior logical hash. If a required workspace/backup is missing or invalid, recovery fails instead of overwriting an unknown file. |
| `Applied` | This operation's effect was checkpointed. Recovery skips or verifies completed work, and reverse-order rollback restores local effects from backups where required. Remote upload completion is recorded only after verification, not merely a PUT response. |

For **pre-publication publishing** transactions (`Started` through `CommitPrepared`), the old `StoredState` remains authoritative. Most are rolled back. A publishing transaction can be returned to Sync as resumable only with its workspace, already applied uploads but **no** applied local mutation, a journal not older than 24 hours, unchanged upload-source sizes, and remote heads equal to its pinned parent set. Sync then reobserves/reconciles and accepts the journal only if publication flag, local/remote generations, base ID, old/new pending paths, and plan operations still match. Otherwise rollback preserves the old accepted base. Uploaded content or Commit ciphertext may remain remotely as unreachable objects.

A **local-only** transaction (`publication_required=false`) pins exactly one observed remote logical head and publishes no new Commit/HEAD/Epoch. Normal Sync validates the materialized tree against that head before saving SQLite. Recovery may resume unfinished storage-repair uploads and local operations, but it only accepts a target already durably committed in SQLite; if SQLite still matches the old base it rolls back, and if it matches neither old nor target it fails as a conflict. Pending materializations remain explicit logical files awaiting safe local materialization or repair, not silent deletions.

At the start of Sync, Fsck, or GC, recovery discards an abandoned temporary journal file, loads and authenticates the final journal, and cleans orphan transaction workspaces only when no active journal exists. Invalid/authentication-failed journals or unsafe/missing required backups stop recovery. Remote-writing recovery re-registers a writer and respects the GC barrier; failure to gain admission stops rather than bypasses GC. After verified rollback or roll-forward, workspace deletion and journal removal are durable cleanup steps; a failed step is reported for the next attempt. Preview, Status, and `remote ...` do **not** enter this recovery path.
