# Garbage Collection

> **Phase GC-R5.3 status:** the collector acquires cooperative exclusivity,
> performs **one authenticated observation**, builds and validates a complete
> global deletion plan, executes one sequential `REMOVE` per planned candidate,
> and releases the maintenance barrier. Apply performs no history
> reconstruction, candidate `GET`, candidate `LIST`, or candidate `PRESENCE`
> call. A successful `REMOVE` is counted as acknowledged by the transport; the
> collector does not read the object back to prove physical absence. Exclusivity
> is cooperative, not a distributed transaction.

## Components and connection point

- `Operation::GarbageCollect` dispatches through
  `run_garbage_collect(OperationContext&)` in
  `src/application/use_cases/maintenance.cpp`.
- `GarbageCollectStage` (`Preparing`, `Analyzing`, `Applying`, `Finalizing`),
  `GarbageCollectProgress`, `GarbageCollectCompleted`, and
  `GarbageCollectFailure` describe progress, counts, and partial failure
  context.
- `src/application/integrity/garbage_collection.cpp` implements exclusivity
  acquisition, the single authenticated observation, global plan construction
  and validation, sequential deletion, and barrier cleanup.
- Barrier establishment/ownership checks, writer admission, writer-marker
  observation, and the provider-visibility probe remain separate protocol
  components in `history_storage/maintenance_protocol.cpp`.
- Reachability, Commit variant selection, Epoch anchors, historical retention
  (`min_history_depth` and `min_history_age_hours`), content reachability, and
  transport capabilities remain the authority used by GC.

## Admission and analysis contract

The collector preserves this order:

1. `application::execute` resolves the profile/key, validates retention, takes
   the **local** profile lock, and opens the transport. Pending
   [Sync transaction recovery](transactions-and-recovery.md) runs before GC.
2. GC publishes a verified, token-owned remote **barrier**. Cooperative Sync
   writers register a visible writer marker and are denied admission while the
   barrier is present. GC rejects any active or abandoned writer marker before
   analysis.
3. GC publishes a temporary provider-visibility probe, requires it to be
   visible in listings, removes it, and requires its absence. Probe errors fail
   closed. The probe is a transport precondition, not a second history
   observation.
4. After these preconditions, GC performs **one complete authenticated
   observation**: physical listing, HEAD/Commit/Epoch reachability, commit
   variants, content references, and orphan-content payload classification.
   Malformed history, unknown objects, missing required content, invalid
   control state, or transport errors stop collection before mutation.
5. GC builds the complete deletion plan and validates the plan as a set before
   the first `REMOVE`. If online mutation cannot be established, the collector
   returns `analysis_only` and performs no candidate deletion.

The single observation is authoritative for the rest of the run. The collector
does not perform a second full reconstruction merely to repeat the first.

## Global deletion plan

The plan is an in-memory `std::vector` of candidates plus a sorted set of
protected object identifiers. It is never persisted and is discarded at the end
of the run. Candidate kinds are:

- `CommitVariant`: a valid variant of a current reachable Commit that is not a
  required variant.
- `Content`: an authenticated, unreferenced payload that is physically present
  and valid.

The protected set includes:

- every variant selected by a valid HEAD marker (all HEAD-selected ciphertext
  variants are preserved);
- at least one valid variant for every reachable, unmarked Commit, including
  unmarked parents and Epoch-anchored Commits;
- every reachable Content object;
- valid Epoch objects and retained orphan Epoch objects;
- all protocol/control objects by construction.

Before the first DELETE the collector verifies:

```text
DELETE_SET ∩ PROTECTED_SET = ∅
```

It also verifies that candidates are sorted and unique, that every candidate is
a classified Content or valid reachable Commit variant, that no control object
is a candidate, that every reachable Commit retains at least one valid variant
outside the deletion set, and that every HEAD-selected variant is outside the
deletion set. Removing all variants of a Commit with multiple individually
redundant variants is rejected before mutation.

Unreachable Commit variants remain out of scope: the collector does not delete
whole unreachable Commits. Unknown, invalid, or ambiguously classified objects
are not inferred safe to delete. Epoch objects are never candidates.

## Destructive phase

Apply iterates the frozen plan in deterministic order and issues exactly one
`REMOVE` per candidate:

```text
for candidate in deletion_plan:
    result = transport.remove(candidate)

    if result is successful:
        increment acknowledged_removals
        continue

    preserve failure diagnostic
    stop applying further candidates
```

There is no per-candidate history reconstruction, candidate `GET`, candidate
`LIST`, candidate `PRESENCE`, barrier-ownership recheck, writer recheck,
read-back, retry, batching, quarantine, or persistent authorization cache.

A `Removed` or `AlreadyAbsent` result is transport-acknowledged completion and
is counted in `removed_objects` / `confirmed_removed`. Those public names now
mean **REMOVE operations acknowledged by the API**, not an independent physical
audit. No presence check follows the delete to prove absence.

On a failed `REMOVE`, the collector preserves the transport error category,
message, and native code; keeps the count of previously acknowledged removals;
classifies the attempt (`NotAttempted` for a definite non-mutation, `Uncertain`
for an ambiguous result); stops further deletion without retry; releases the
barrier through the normal cleanup path; and returns the partial diagnostic.
A later GC run starts from a new observation and does not reuse the old plan.

Barrier cleanup remains special. It verifies ownership, attempts release at most
once, never removes a foreign or replaced barrier, preserves primary and
cleanup errors separately, and does not declare a healthy finish when release
is ambiguous. The destructor never opens a second release path.

## Concurrency contract and removed guarantees

Exclusivity is **cooperative**:

- one authorized GC per vault;
- the local profile lock;
- the remote maintenance barrier;
- writer registration and the initial writer check;
- barrier ownership verification on acquisition and cleanup;
- the provider-visibility probe.

The protocol has no distributed CAS or fencing token. A non-cooperative agent
can mutate the vault after the observation; such a change may invalidate the
plan and is outside the cooperative contract. The collector does not claim to
detect arbitrary external mutation during Apply, and it does not add repeated
checks that shrink the race window without establishing atomicity.

The previous implementation reconstructed and reauthenticated history before
each candidate, compared two full observations, listed the namespace per
candidate, checked writers and barrier ownership per candidate, and performed a
post-`REMOVE` presence check. These guarantees are deliberately removed from
Apply because they duplicated the observation and did not create atomicity.
Cooperative writer admission and barrier ownership at acquisition/cleanup remain
mandatory; tests cover them directly. Residual risk: a non-cooperative writer
or provider change during Apply can make a planned deletion unsafe or leave an
object unexpectedly absent.

## Tracing

Tracing keeps the existing phase timings and history counters and adds:

```text
gc.analysis_get_calls
gc.analysis_list_calls
gc.analysis_presence_calls

gc.apply_get_calls
gc.apply_list_calls
gc.apply_presence_calls

gc.candidate_remove_attempts
gc.candidate_remove_acknowledged
gc.history_reconstructions
```

The structural target is `gc.apply_get_calls = 0`,
`gc.apply_list_calls = 0`, and `gc.apply_presence_calls = 0`; per-candidate
maintenance reads must not reappear. Analysis `GET` counts depend on the number
of distinct commit variants, markers, Epochs, and audited orphan payloads, not
on the number of deletion candidates multiplied by full-history
reconstruction. Barrier/probe control operations remain separate from candidate
traffic.

## Operational contract

**Warning — concurrent destructive maintenance is unsupported.** Run only one
destructive maintenance operation per remote vault at a time, across all
machines. Manual writer-marker removal must not overlap with another maintenance
operation. Pause scheduled and interactive Sync on every client before
destructive maintenance and keep it paused until maintenance finishes. This
includes no-op Sync runs: they probe required Content and may repair a missing
object. Writer admission rejects a repair while the barrier is visible, but the
barrier is not a distributed lock.

The local profile lock covers only processes using that profile on one machine.
The remote barrier is best-effort coordination built from ordinary storage
operations. It reduces the chance of overlap but is not a distributed lock or
fencing mechanism. The collector assumes that cooperative writers honor the
barrier and that the backend exposes completed changes to the listings and
presence checks used by the protocol. Passing the runtime probe does not prove
provider-wide consistency or protect against non-cooperative mutation.

An `analysis_only` result means no candidate removal occurred. It is not a
selectable mode and not proof that a backend which passed the probe is safe.

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
7. Resume normal Sync activity after maintenance has completed and its results
   have been inspected.

## Manual writer removal

`kasumi gc remove-writer <profile> <writer-id>` is a separate manual recovery
operation. Take the exact identifier from `kasumi remote writers <profile>`;
Kasumi verifies the keyed writer namespace and removes only that marker. It
refuses removal when a maintenance barrier is present, but this check does not
provide distributed exclusion. Kasumi cannot determine safely whether the
associated process is still active, so the operator must verify that no Sync or
maintenance operation is running before proceeding. It neither removes barriers
nor runs Sync or GC.

## Inspecting before maintenance

Prefer `kasumi remote health <profile>`, `kasumi remote writers <profile>`,
`kasumi remote orphans <profile>`, and `kasumi fsck <profile>` to understand the
state before maintenance. The `remote quarantine` command has been removed. Do
not remove other remote protocol objects through the storage backend.
