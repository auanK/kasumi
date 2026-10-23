# Synchronization

`kasumi sync <profile>` prepares the [runtime](application-and-runtime.md), recovers a pending [transaction](transactions-and-recovery.md), then collects local disk, accepted `StoredState`, and authenticated remote history. Local scan and remote observation can overlap. Remote history resolution produces an effective remote tree; [reconciliation](reconciliation.md) creates a candidate shared tree, an ordered `SyncPlan`, and flags for physical repair, local mutation, publication, or accepted-state commit.

## Initial Sync

`kasumi sync <profile> --initial` is an explicit exception for a missing local
database. Under the profile lock it rejects SQLite sidecars and transaction
evidence, resolves the existing vault key, initializes and lists the transport,
and rejects any object in the key-derived current history namespace. It then
creates the current database schema and runs the same Sync path, which publishes
new history from local files and can reuse compatible root Content. It never
overwrites a database, migrates old state, or deletes remote objects; a failed
listing is an error. Without this flag, Sync behavior is unchanged.

## Required Content Availability

Every normal Sync, including an otherwise empty no-op run, derives a deduplicated set of Content IDs required by the effective reconciled remote tree, Download operations, and pending materialization/storage rows that still match the effective tree. A stable local file is therefore still a repair source even when this run would otherwise upload nothing. The explicit pending-deletion authority used by `resolve-missing` keeps its own scope; Sync never expands it into a logical deletion.

The probe uses `control_read_batch` when the transport exposes it and falls back to individual `presence` checks. A transport or cancellation failure is an error, never evidence of absence. When a complete physical content inventory is already available, Sync cross-checks LIST and PRESENCE in both directions and fails closed on disagreement; LIST omission alone never proves that a required object is missing. Missing IDs are returned to reconciliation, which deduplicates repair uploads by plaintext hash. The upload path requires a regular non-symlink local source and verifies its bytes against the expected logical hash and size, independently of cached fingerprints. A mismatch fails before PUT and preserves accepted logical state and recovery evidence. If no compatible source exists, Sync preserves the logical rows, accepted Commit/HEAD, expected Content IDs, local state, and pending evidence, records pending paths, and returns a partial result (exit status `2`). It never infers a logical deletion or invokes `resolve-missing` automatically.

Scoped remote observation may use the accepted Commit as a `cached_anchor` only
after proving ancestry linkage for all loaded branches. A concurrent sibling
head need not descend from that anchor, even if its marker remains visible;
loading then retries without the cached anchor to recover the common ancestry.
The resulting authenticated multi-head history is reconciled and can produce a
multi-parent merge Commit. See [History and Concurrency](history-and-concurrency.md#cached-anchors-and-scoped-observation).

Sync registers a remote writer when active work is needed, including publication, repair, local mutation, or state commit. Writer markers admit multiple clients concurrently while blocking [GC](garbage-collection.md) from starting destructive maintenance. A repair-only run is admitted through the same registration path; an active GC barrier stops it before effects. If initial history is absent, sync initializes the remote transport before publication. A true no-op still performs the required-content probe and may update the local file-hash cache without creating a new Commit.

## Stabilize Before Effects

The coordinator starts from the caller's required-content probe and reconciliation, verifies destructive local file targets independently of cached hashes, stages plan inputs, reobserves remote and local state, probes the required Content again, re-reconciles, and compares the observations. A content mismatch updates the observed row, invalidates its cache entry, and triggers reconciliation before effects. Unexpected disappearance, replacement by a non-regular entry, or an occupied rename/download destination stops the operation. If inputs changed, stabilization retries within a three-attempt bound; repeated movement yields `ConcurrentModification`. A remote publication after this window is still possible: immutable Commit/HEAD objects preserve both branches for later resolution. Missing download payloads discovered during execution trigger bounded replan attempts; repeated disappearance also fails instead of applying an unsafe stale plan. [Local Observation](local-observation.md) owns scan and cache rules.

## Execute and Validate

The transaction journal records the validated plan and per-operation progress. Staging preserves previous local content before mutation. Content uploads are encrypted, downloaded plaintext is authenticated and hash-checked before installation, and logical remote actions update the intended tree. Existing Download destinations are atomically replaced; absent destinations use installation that fails if another entry appeared. `DeleteLocal` and `RenameLocal` use the prepared content/type checks, with rename installation refusing an occupied destination. Work follows the plan's dependency phases, with bounded transfer concurrency and optional transport batches. Repair-only work publishes no Commit or HEAD and uses the local-only journal/recovery contract. See [Reconciliation](reconciliation.md#reconciliation-and-syncplan) for the plan and pending-file model and [Transactions and Recovery](transactions-and-recovery.md#per-operation-state-and-branching) for repair recovery.

The final local validation and the filesystem syscall are separate operations. External writers can still change the destination in that interval or write through an open handle after a rename; that race can overwrite, remove, or move their edit. If a destination conflict is detected before that operation has an effect, the transaction is cleared while completed peer effects remain on disk, and Sync returns `ConcurrentModification`; the next Sync reobserves and replans rather than replaying the old plan. Other failures use the established rollback/resume path; if recovery becomes ambiguous, its journal and backups remain. See [Transactions and Recovery](transactions-and-recovery.md#local-mutation-contract-and-external-writers).

After applying effects, sync restores required timestamps, scans disk again, and builds the **publication tree** from observed materialized rows plus pending remote rows. New unrelated local paths that appeared during execution stay on disk for a later run. Changes to expected rows fail validation and roll back local mutations. A local-only run validates against its pinned remote head and commits that accepted state to SQLite without publishing a Commit.

If publication is required, sync prepares a canonical Commit whose parents are the sorted logical heads from the stabilized observation (none for bootstrap). The encrypted Commit variant is uploaded or safely reused and verified before a physical HEAD marker is uploaded and verified. A genesis Epoch follows bootstrap; later authenticated Epochs may advance a safe retention frontier. Only after those remote checks does SQLite accept the new `StoredState`; observed ancestral markers are then pruned and the journal/workspace cleaned. [Remote Layout and Publication](remote-layout.md) defines identities, ordering, and physical verification. Publication can overlap local transfer work, but the marker remains behind Commit verification and final local-tree validation.

## Other Operations

`sync --dry-run` is [Preview](planning-and-status.md), not this execution path; `status` shares its planner. [Fsck](fsck.md) and [Garbage Collection](garbage-collection.md) run transaction recovery before their own distinct maintenance lifecycles.
