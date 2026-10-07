# Synchronization

`kasumi sync <profile>` prepares the [runtime](application-and-runtime.md), recovers a pending [transaction](transactions-and-recovery.md), then collects local disk, accepted `StoredState`, and authenticated remote history. Local scan and remote observation can overlap. Remote history resolution produces an effective remote tree; [reconciliation](reconciliation.md) creates a candidate shared tree, an ordered `SyncPlan`, and flags for physical repair, local mutation, publication, or accepted-state commit.

Sync registers a remote writer when active work is needed, including publication, repair, local mutation, or state commit. Writer markers admit multiple clients concurrently while blocking [GC](garbage-collection.md) from starting destructive maintenance. If initial history is absent, sync initializes the remote transport before publication. A true no-op may update the local file cache and observation checkpoint without creating a new Commit.

## Stabilize Before Effects

The coordinator probes required content availability, re-reconciles, stages plan inputs, reobserves remote and local state, and compares the observations. If inputs changed, it recalculates and retries up to three times; repeated movement yields `ConcurrentModification`. A remote publication after this window is still possible: immutable Commit/HEAD objects preserve both branches for later resolution. Missing download payloads discovered during execution trigger bounded replan attempts; repeated disappearance also fails instead of applying an unsafe stale plan. [Local Observation](local-observation.md) owns scan/cache and checkpoint rules.

## Execute and Validate

The transaction journal records the validated plan and per-operation progress. Staging preserves previous local content before mutation. Content uploads are encrypted, content downloads authenticated and verified, and logical remote actions update the intended tree. Work follows the plan's dependency phases, with bounded transfer concurrency and optional transport batches. A missing remote payload may be repaired from a compatible local file; otherwise the accepted logical file can remain pending materialization. See [Reconciliation](reconciliation.md#reconciliation-and-syncplan) for the plan and pending-file model.

After applying effects, sync restores required timestamps, scans disk again, and builds the **publication tree** from observed materialized rows plus pending remote rows. New unrelated local paths that appeared during execution stay on disk for a later run. Changes to expected rows fail validation and roll back local mutations. A local-only run validates against its pinned remote head and commits that accepted state to SQLite without publishing a Commit.

If publication is required, sync prepares a canonical Commit whose parents are the sorted logical heads from the stabilized observation (none for bootstrap). The encrypted Commit variant is uploaded or safely reused and verified before a physical HEAD marker is uploaded and verified. A genesis Epoch follows bootstrap; later authenticated Epochs may advance a safe retention frontier. Only after those remote checks does SQLite accept the new `StoredState`; observed ancestral markers are then pruned and the journal/workspace cleaned. [Remote Layout and Publication](remote-layout.md) defines identities, ordering, and physical verification. Publication can overlap local transfer work, but the marker remains behind Commit verification and final local-tree validation.

## Other Operations

`sync --dry-run` is [Preview](planning-and-status.md), not this execution path; `status` shares its planner. [Fsck](fsck.md) and [Garbage Collection](garbage-collection.md) run transaction recovery before their own distinct maintenance lifecycles.
