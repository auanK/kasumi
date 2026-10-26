# Garbage Collection

GC acquires cooperative exclusivity per vault, observes authenticated history
once, validates a global deletion plan, removes candidates sequentially, and
releases the maintenance barrier.

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
   control state, or transport errors stop collection before candidate deletion.
5. GC builds the complete deletion plan and validates the plan as a set before
   the first `REMOVE`. If online mutation cannot be established, the collector
   returns `analysis_only` and performs no candidate deletion.

## Global deletion plan

The plan is an in-memory candidate list and a sorted set of protected object
identifiers. It is discarded at the end of the run. Eligible candidates are:

| Candidate | Eligibility |
|---|---|
| Orphan Content | Physically present Content not referenced by protected reachable history, with its payload authenticated before deletion is authorized |
| Redundant CommitVariant | Valid ciphertext of a reachable Commit that is not a required variant |

The observation authenticates history and classifies deletion eligibility.
GC authenticates orphan candidate bytes; [Fsck](fsck.md) audits every payload
referenced by the effective remote tree.

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

Apply consumes the frozen plan without per-candidate observation, writer or
barrier checks, batching, or readback. It performs no candidate `GET`, `LIST`,
or `PRESENCE` calls.

A `Removed` or `AlreadyAbsent` result increments `removed_objects` /
`confirmed_removed`: these count **REMOVE operations acknowledged by the API**,
not independently verified physical absence.

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

## Tracing

Performance tracing records phase timings, history counters, and candidate traffic:

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

Apply counters for `GET`, `LIST`, and `PRESENCE` stay at zero. Analysis reads
depend on distinct history objects and orphan payloads, rather than a full
reconstruction per candidate. Barrier/probe operations are separate from
candidate traffic.

## Operational contract

Run only one destructive maintenance operation per vault at a time, across
all machines. Pause scheduled and interactive Sync, including no-op runs that
can repair Content, until maintenance finishes. Manual writer removal must
also be serialized with Sync and other maintenance.

Exclusivity is cooperative: the local profile lock, remote token-owned barrier,
writer registration, and initial writer check coordinate participating clients.
The local lock covers one profile on one machine; the remote protocol has no
distributed CAS or fencing token. Non-cooperative mutation after observation
can invalidate the deletion plan and cause data loss.

The backend must expose completed control and namespace changes to protocol
`LIST` and `PRESENCE` checks. The visibility probe tests its own temporary object;
it cannot certify provider-wide consistency or detect every stale listing. See
[Transport](transport.md) for backend requirements.

An `analysis_only` result means no candidate removal occurred, although barrier
and probe publication/cleanup may have occurred. It is not a selectable mode.
Transport and protocol errors fail the operation.

### Maintenance procedure

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

## Manual barrier removal

`kasumi gc remove-barrier <profile> --confirm-abandoned` is a controlled, diagnostic
manual recovery operation for an abandoned remote maintenance barrier left behind
when a Garbage Collection process was terminated abruptly (e.g., killed process,
power loss, or ungraceful shutdown).

When an abandoned barrier remains on remote storage, subsequent GC runs fail
immediately with:

```text
another maintenance barrier is already present
```

### Protocol and Operational Principles

1. **Inspection**: Use `kasumi remote writers <profile>` to inspect whether a
   barrier is present. When present, Kasumi displays its full remote identifier
   (derived deterministically from the vault's key layout):
   ```text
   Maintenance barrier:
     Present: Yes
     Identifier: <barrier-identifier>

   Writers: 0
   Maintenance blocked: Yes
   ```
2. **Mandatory Confirmation (`--confirm-abandoned`)**: Because Kasumi operates
   over passive storage backends that lack distributed process liveness detection, it
   cannot determine whether an active GC process is still executing on another
   device or machine. Never assume a barrier is abandoned merely because of its
   age or timestamp. The operator must verify externally that no maintenance or sync
   operation is active before passing `--confirm-abandoned`.
3. **Control Token Verification**: The barrier object contains a control payload
   token (`kasumi-gc-v1:barrier:<32-hex-token>`). Kasumi downloads and performs
   structural validation of this token (checking prefix and canonical 32-character
   hexadecimal format) before attempting removal, rejecting corrupted or foreign
   objects. This token is an internal control token; it is not a cryptographic
   signature or MAC.
4. **Physical Identity Verification vs. Absence of Distributed CAS**: Prior to
   deletion, Kasumi verifies the object's physical identity (via remote SHA-256
   hash or verified GET readback fallback) against the downloaded copy to ensure
   it has not been altered. However, physical identity verification is **not** an
   atomic conditional delete (compare-and-swap / CAS). Because passive object
   storage lacks distributed CAS, a concurrent process could replace or recreate
   the barrier in the residual window between revalidation and DELETE. Kasumi
   does not pretend to eliminate this residual race; this fundamental limitation
   is why operator confirmation is mandatory. If the barrier is replaced prior to
   revalidation, removal is aborted and the replacement is preserved.
5. **Post-removal Confirmation and Diagnostic Mutation States**: After issuing a
   DELETE call, Kasumi immediately re-checks absence via transport PRESENCE.
   Failures are classified into three explicit mutation states:
   - `NotAttempted`: Failure occurred before any DELETE was sent (e.g., control
     token validation failure or physical identity mismatch).
   - `Confirmed`: DELETE was acknowledged and post-removal PRESENCE confirmed absence.
   - `Uncertain`: DELETE was issued, but its final consequence could not be proven
     (e.g., ambiguous transport error such as timeout or network drop, or post-removal
     PRESENCE check failed or reported the barrier still present).
   Kasumi never converts an ambiguous error into success and never retries DELETE
   automatically after an uncertain result. When an operation returns `Uncertain`,
   the operator must re-inspect the remote state using `kasumi remote writers <profile>`.
   Any subsequent recovery attempt observes fresh remote state rather than reusing
   stale decisions.
6. **Deadlock Elimination with Writers**: If an interrupted process left both a
   barrier and writer markers, `remove-barrier` does not deadlock. It removes the
   barrier and reports any remaining active writers, allowing the operator to
   subsequently remove those writers using `kasumi gc remove-writer <profile> <writer-id>`.
7. **Isolation**: Barrier recovery runs under the local exclusive profile lock,
   operates even if the local SQLite state database is absent or unaccepted
   (requiring only valid profile configuration and credentials), and never executes
   Sync, GC, or local file modifications.

## Inspecting before maintenance

Prefer `kasumi remote health <profile>`, `kasumi remote writers <profile>`,
`kasumi remote orphans <profile>`, and `kasumi fsck <profile>` to understand the
state before maintenance. Do not remove remote protocol objects through the
storage backend.
