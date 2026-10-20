# Garbage Collection

> **Phase GC-R1 status:** the quarantine subsystem has been removed. The
> public `GarbageCollect` operation, its progress/result types, the CLI
> dispatch, and the stable reachability analysis helpers remain, but the old
> GC orchestration (`run_garbage_collect`) has no definition. Until the new
> direct-deletion collector is implemented and the dispatch is reconnected,
> this path does not link and no GC command can run. Fsck, Sync, transport
> operations, writers, barriers, probes, and maintenance inspection are
> unaffected. This document describes the retained design contract and the
> reconnection boundary; it does not claim that destructive collection is
> currently available.

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

## Retained pieces and the reconnection point

The following remain in place and must be preserved when GC is reconnected:

- `Operation::GarbageCollect` and its dispatch case in
  `src/application/execute.cpp`.
- `GarbageCollectStage` (`Preparing`, `Analyzing`, `Applying`, `Finalizing`),
  `GarbageCollectProgress`, and `GarbageCollectCompleted`
  (`candidate_objects`, `analysis_only`).
- The GC analysis infrastructure in `maintenance.cpp`:
  `GarbageCollectionSnapshot`, the snapshot trace names,
  `collect_garbage_collection_snapshot`, `same_reachable_state`, and the
  validation helpers used to compare stable observations.
- Barrier establishment/ownership checks, writer admission, writer-marker
  observations, and the provider-visibility probe.
- Reachability, Commit variant selection, Epoch anchors, historical retention
  (`min_history_depth` and `min_history_age_hours`), content availability,
  and transport batch/physical-hash capabilities.
- Fsck, Sync and incremental observation, and the `gc remove-writer`
  maintenance operation.

The single known broken reconnection point is intentional:
`src/application/execute.cpp` declares and dispatches
`run_garbage_collect(OperationContext&)`, but no translation unit defines it.
There is no stub, compatibility alias, or fake implementation. A build that
links the GC dispatch will therefore fail at link time until the new
collector is implemented or the call is deliberately reconnected to it.

## Admission and analysis contract

When the direct-deletion collector is reconnected, it is expected to preserve
the following order:

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

## Destructive phase (not currently connected)

The former quarantine staging, metadata verification, retention, restoration,
and purge steps no longer exist. The replacement direct-deletion design must
delete only candidates that survive both stable observations and continue to
satisfy retention and barrier ownership at the point of removal. It must:

- recheck barrier ownership before each destructive batch;
- use bounded batches and report partial outcomes without blindly replaying
  ambiguous failures;
- leave unknown objects, legacy quarantine objects, and control objects
  untouched;
- return counts for candidates and whether the run was analysis-only; and
- have no local transaction journal for remote deletions. A later run must
  re-observe remote state rather than trust an earlier partial result.

Until that implementation exists, no destructive GC phase can run.

## Operational contract

**Warning — concurrent destructive maintenance is unsupported.** Run only
one destructive maintenance operation per remote vault at a time, across all
machines. Manual writer-marker removal must not overlap with another
maintenance operation. Pause scheduled and interactive Sync on every client
before destructive maintenance and keep it paused until maintenance finishes.
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
backend's consistency guarantees independently before reconnecting
destructive GC.

An `analysis_only` result, when the collector is connected, means no
candidate removal occurred; it is not a selectable mode or proof that a
backend which passed the probe is safe.

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
