# Garbage Collection

> **Phase GC-R2.1 status:** the quarantine subsystem is gone and the
> direct-deletion collector is implemented and connected to
> `Operation::GarbageCollect`. It removes one authenticated candidate at a
> time, revalidates current history and ownership before each deletion, counts
> only confirmed removals, and preserves partial-failure diagnostics. This
> remains best-effort maintenance, not a distributed lock or fencing
> mechanism. Fsck, Sync, transport operations, writers, barriers, probes, and
> maintenance inspection share the same operational limits described below.

## What was removed

The entire quarantine lifecycle is gone: quarantine inventory, staging,
authenticated metadata, retention, restoration, expiration/purge, repair,
inspection, CLI commands (`gc purge-quarantine`, `gc repair-quarantine`,
`remote quarantine`), translations, exclusive tests, live GC runners, smoke
tests, and GC benchmarks. The remote layout no longer derives quarantine
paths, and `RemoteObjectCategory::RetentionMetadata` no longer exists.

Legacy objects that happen to live under an old quarantine path are **not**
interpreted as deletion candidates and are not migrated, restored, or
deleted by this phase. They are ordinary unknown remote objects unless a
future explicit design assigns them another meaning. A raw `remote objects`
listing is not a deletion list.

## Components and connection point

- `Operation::GarbageCollect` dispatches through
  `run_garbage_collect(OperationContext&)`, implemented in
  `src/application/use_cases/maintenance.cpp`.
- `GarbageCollectStage` (`Preparing`, `Analyzing`, `Applying`, `Finalizing`),
  `GarbageCollectProgress`, `GarbageCollectCompleted`
  (`candidate_objects`, `analysis_only`, `removed_objects`), and
  `GarbageCollectFailure` describe progress, successful counts, and partial
  failure context.
- `src/application/integrity/garbage_collection.cpp` contains the stable
  observation, candidate selection, revalidation, direct removal, and barrier
  cleanup implementation.
- Barrier establishment/ownership checks, writer admission, writer-marker
  observations, and the provider-visibility probe remain separate protocol
  components.
- Reachability, Commit variant selection, Epoch anchors, historical retention
  (`min_history_depth` and `min_history_age_hours`), content availability,
  and transport batch/physical-hash capabilities remain the reachability
  authority used by GC.
- The GC collector lifecycle is unchanged by GC-R3. Normal Sync now checks
  required Content availability on every run, including no-ops, and may repair
  a missing required object from an authenticated local source. That repair is
  still gated by writer admission and the GC barrier; it cannot upload while
  the barrier blocks writers. Fsck, incremental observation, and the
  `gc remove-writer` maintenance operation remain separate.

## Admission and analysis contract

The direct-deletion collector preserves the following order:

1. `application::execute` resolves the profile/key, validates retention,
   takes the **local** profile lock, and opens the [transport](transport.md).
   As with Fsck, pending [Sync transaction recovery](transactions-and-recovery.md)
   runs **before** GC and can finish local or remote Sync effects or stop the
   operation on uncertainty.
2. GC publishes a verified, token-owned remote **barrier**. New Sync writers
   register their own visible writer marker and reject admission if the
   barrier is present. GC lists writer markers twice and re-verifies its own
   barrier between checks. Any observed active or abandoned marker, malformed
   control state, or observed loss of barrier ownership blocks collection
   rather than guessing liveness.
3. GC publishes a temporary provider-visibility probe, requires its presence
   in two listings, removes it, and requires its absence in two listings. If
   safe online mutation cannot be established, the collector must return
   `analysis_only` after one validated reachability/candidate snapshot and
   perform no deletion. Barrier/probe creation and cleanup may already have
   touched the remote. Probe errors fail rather than imply safety.
4. The collector takes **two complete observations** of the physical
   namespace plus authenticated HEAD/Commit/Epoch reachability and content
   inventory. The observations must agree on logical heads, reachable
   Commits, required ciphertext variants, reachable content, candidates, and
   physical identifiers. A final listing must match before any destructive
   phase. Change, malformed history, unknown identifiers, missing required
   content, or an unsafe transport result stops collection.

The reachability walk retains current logical heads and the history required
by authenticated Epoch anchors/retention; a reachable Commit needs its marked
Ciphertext ID or a valid required variant, not every redundant variant.
Candidate selection excludes retained content and required variants.
Unknown/protected objects are **not** inferred safe to delete, and Epoch
objects are not deletion candidates.

## Destructive phase

The former quarantine staging, metadata verification, retention, restoration,
and purge steps no longer exist. The direct-deletion collector issues one
REMOVE for one candidate at a time and applies these checks immediately before
that mutation:

- the physical namespace still matches the observed namespace and no writer
  marker is active;
- a Commit variant is still a valid, redundant variant of a current reachable
  Commit, or a Content object is still an authenticated, unreferenced payload
  under a freshly authenticated current-history inventory;
- the candidate identifier is still present and belongs to the authorized
  candidate kind;
- the maintenance barrier is still owned by this run; and
- cancellation has not been requested.

After REMOVE, a PRESENCE check must report `Absent` before the removal is
counted. An ambiguous DELETE is never retried automatically; its mutation
state remains `Uncertain` and the object is not added to `removed_objects`. A
failure that definitely did not mutate the object remains `NotAttempted`.
Every post-Apply failure carries the candidate total,
confirmed removals, failed identifier when one exists, operation stage,
transport error category/message/native code when available, mutation state
(`NotAttempted`, `Confirmed`, or `Uncertain`), and barrier cleanup status.

Barrier cleanup has a single owner. A normal result path attempts release at
most once, a failed or ambiguous release is not retried during destruction,
a foreign or replaced barrier is never removed, and primary and cleanup
errors are both preserved. Destructive GC leaves unknown objects, legacy
quarantine objects, and control objects untouched. It has no local
transaction journal for remote deletions: a later run must re-observe remote
state rather than trust an earlier partial result.

## Unreachable commits remain out of scope

The collector does not collect whole unreachable Commits. Commit objects that
are not reachable from current logical heads, Epoch anchors, or retention are
preserved, together with their variants, even when they are no longer
referenced. The only Commit-variant deletions are redundant valid variants of
a currently reachable Commit whose marked variant is already required.

Collecting unreachable Commits would require a separate authenticated policy
for their trees and content; inferring that policy from a raw listing is
unsafe. `GarbageCollectionTest.UnreachableCommitVariantsArePreserved` fixes
this boundary, and the same boundary applies to the `GC → Fsck → GC`
regression: the second run must report zero candidates and zero removals.

## Operational contract

**Warning — concurrent destructive maintenance is unsupported.** Run only
one destructive maintenance operation per remote vault at a time, across all
machines. Manual writer-marker removal must not overlap with another
maintenance operation. Pause scheduled and interactive Sync on every client
before destructive maintenance and keep it paused until maintenance finishes.
That includes no-op Sync runs: they now probe required Content and may repair a
missing object even when local files are unchanged. Writer admission rejects a
repair while the barrier is visible, but the barrier is not a distributed lock.
The local profile lock covers only processes using that profile on one
machine. The remote barrier is a best-effort coordination mechanism built
from ordinary storage operations. It can reduce the chance of overlap, but it
is not a distributed lock or fencing mechanism; two maintenance commands can
replace the shared barrier, and an ownership check can become stale before
the next mutation.

The required `PUT`, `GET`, `LIST`, `PRESENCE`, and `REMOVE` operation names do
not by themselves promise strong consistency. Destructive collection assumes
the backend exposes completed changes to the listings and presence checks
used by the protocol. The runtime probe tests visibility of its own newly
published probe; passing it does not prove that every older object or writer
marker is visible, nor certify provider-wide consistency. Confirm the
backend's consistency guarantees independently before relying on
destructive GC.

An `analysis_only` result means no candidate removal occurred; it is not a
selectable mode or proof that a backend which passed the probe is safe.

### Maintenance procedure for retained operations

1. Stop Sync schedulers and active Sync processes on all clients using the
   vault.
2. Confirm that no other maintenance operation is active on another client.
3. Inspect `kasumi remote health <profile>` and
   `kasumi remote writers <profile>`. Identify any marker's owner before
   considering removal.
4. Confirm that the configured backend meets the consistency assumptions
   above; the runtime probe alone is not provider certification.
5. Run one maintenance command and inspect its result. Treat conflicts and
   ambiguous transport errors as reasons to investigate before retrying.
6. Preserve markers and control objects while resolving uncertainty. Do not
   delete protocol objects directly through the provider.
7. Resume normal Sync activity after maintenance has completed and its
   results have been inspected.

## Manual writer removal

`kasumi gc remove-writer <profile> <writer-id>` is a separate manual recovery
operation. Take the exact identifier from `kasumi remote writers <profile>`;
Kasumi verifies the keyed writer namespace and removes only that marker. It
refuses removal when a maintenance barrier is present, but this check does
not provide distributed exclusion. Kasumi cannot determine safely whether the
associated process is still active, so the operator must verify that no Sync
or maintenance operation is running before proceeding. It neither removes
barriers nor runs Sync or GC.

## Inspecting before maintenance

Prefer `kasumi remote health <profile>`, `kasumi remote writers <profile>`,
`kasumi remote orphans <profile>`, and `kasumi fsck <profile>` to understand
the state before maintenance. The `remote quarantine` command has been
removed. Do not remove other remote protocol objects through the storage
backend.
