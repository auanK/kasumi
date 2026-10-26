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
   variants, content references, and structural reachability classification
   (without orphan payload downloads). Malformed history, unknown objects,
   missing required content, invalid control state, or transport errors stop
   collection before candidate deletion.
5. GC builds the complete deletion plan and validates the plan as a set before
   the first `REMOVE`. If online mutation cannot be established, the collector
   returns `analysis_only` and performs no candidate deletion.
6. Immediately before Apply, GC revalidates barrier ownership using remote
   SHA-256 or the existing control-payload GET fallback. Replacement, absence,
   or verification failure stops all candidate deletion and preserves the plan's
   count for diagnostics. This is one additional ownership check per run.

## Global deletion plan

The plan is an in-memory candidate list and a sorted set of protected object
identifiers. It is discarded at the end of the run. Eligible candidates are:

| Candidate | Eligibility |
|---|---|
| Orphan Content | Physically present Content not referenced by protected reachable history, eligible for deletion without downloading or auditing its payload |
| Redundant CommitVariant | Valid ciphertext of a reachable Commit that is not a required variant |

The observation authenticates history and classifies deletion eligibility based strictly on reachability:

```text
Physically observed Content
+
Structurally valid identifier
+
Not referenced by protected authenticated history
+
Globally validated deletion plan
=
Eligible for deletion
```

Under Kasumi v0.9.0, GC does not authenticate orphan candidate bytes, download ciphertexts, or decrypt payloads before deletion. Unreferenced content is discarded based solely on reachability. Corrupted orphan ciphertext does not alter its reachability: a corrupted unreferenced content object is still an orphan and remains eligible for deletion without downloading its payload. Conversely, all Content referenced by protected history remains strictly protected; if a referenced Content object is damaged, its integrity is audited and reported by [Fsck](fsck.md), not downloaded or repaired by GC.

The controlled remote vault namespace contract assumes that physical storage objects within the vault scope adhere to protocol identity structure. Unknown or ambiguous storage objects (such as alien files or malformed identifiers) are never inferred safe to delete and trigger fail-closed aborts before any deletion. The maintenance barrier coordinates cooperative clients but provides no distributed compare-and-swap (CAS).

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
verify_barrier_ownership()
for candidate in deletion_plan:
    check_cancellation()
    result = transport.remove(candidate)

    if result is successful:
        increment acknowledged_removals
        continue

    preserve failure diagnostic
    stop applying further candidates
```

After the fixed pre-Apply ownership check, Apply consumes the frozen plan without
per-candidate observation, writer or barrier checks, batching, or readback. It
performs no candidate `GET`, `LIST`, or `PRESENCE` calls. Periodic checkpoints,
whether by object count or elapsed time, are deliberately absent: they would add
latency without providing fencing and could suggest false concurrency safety.

A `Removed` or `AlreadyAbsent` result increments `removed_objects` /
`confirmed_removed`: these count **REMOVE operations acknowledged by the API**,
not independently verified physical absence.

On a failed `REMOVE`, the collector preserves the transport error category,
message, native code, and candidate identifier; keeps the count of previously
acknowledged removals; stops further deletion without retry or compensation;
attempts barrier cleanup through the normal path; and returns the partial
diagnostic. Exceptions during DELETE also leave the candidate `Uncertain` and
preserve earlier acknowledgements. A later GC run starts from a new observation
and does not reuse the old plan.

| Mutation state | Meaning |
|---|---|
| `NotAttempted` | No candidate DELETE was started for this failure, including cancellation before the next candidate |
| `Confirmed` | A candidate REMOVE returned `Removed` or `AlreadyAbsent`; this is transport acknowledgement, not an independent absence audit |
| `Uncertain` | DELETE was attempted, but its remote effect cannot be proven; error categories alone do not establish absence of effects |

`NotApplied` would mean a DELETE was attempted with a documented guarantee of no
mutation. The current transport does not provide that evidence for removal
errors, so no such state is emitted or added to the enum. A failed DELETE is
never reported as `NotAttempted`. Cancellation observed before a subsequent
DELETE stops Apply with `NotAttempted` and keeps the exact previous
acknowledgement count; it does not retry or restore earlier objects.

Barrier cleanup remains special. It verifies ownership, attempts release at most
once, refuses to intentionally remove a detected foreign or replaced barrier,
preserves primary and cleanup errors separately, and does not declare a healthy
finish when release is ambiguous. Absence is checked after acknowledged barrier
release. Cleanup exceptions leave release unconfirmed, and the destructor never
opens a second release path. Ownership checks cannot eliminate the TOCTOU window
between verification and DELETE without conditional deletion/CAS.

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
depend exclusively on distinct authenticated history objects (markers, commits, epochs);
`gc.analysis_get_calls` reflects necessary history downloads, while `GET` calls for
orphan Content payloads remain strictly zero (`GET(orphan content) == 0`).
Barrier/probe operations are separate from candidate traffic.

Additional measurements separate listing (`gc.analysis_list_us`), Content
classification (`gc.content_classification_us`), plan construction
(`gc.plan_build_us`), global validation (`gc.plan_validation_us`) and the single
pre-Apply revalidation (`gc.pre_apply_ownership_us`). The latter is also part of
the aggregate `gc.barrier_ownership_check_us`; phase and nested timers overlap
and must not be summed as independent elapsed time.

`gc.physical_object_count` is the authenticated observation's physical listing,
including the active barrier. `gc.physical_content_count` counts classified
Content, and `gc.protected_content_count` counts distinct reachable Content IDs.
`gc.protected_object_count` is the explicit plan-protected set of required
variants, Content and Epochs; HEAD and control objects are additionally excluded
by construction. `gc.content_get_calls` measures actual reads in Content
classification, including zero; Apply's read counters exclude pre-Apply control
verification. No extra remote queries are issued to collect these metrics.

After barrier acquisition, zero-valued candidate attempt/acknowledgement/error
counters are emitted explicitly. `gc.candidate_remove_errors` counts rejected
or throwing candidate attempts; `gc.barrier_cleanup_errors` separately counts
failed cleanup. `gc.errors` counts a failed GC outcome (zero or one), preserving
the distinction between its primary and secondary errors. Earlier admission
failures can leave these metrics unavailable. A missing metric in a benchmark
report is `null`, not zero. Counts never reinterpret a failed DELETE as success.

Use the [GC benchmark harness](../build-and-test.md#gc-performance) for isolated
fixtures and separate fixture/GC/FSCK/cleanup timings. Apply throughput includes
sequential DELETE latency, loop overhead and the fixed pre-Apply check. Small
encrypted payloads do not model large payload transfer workloads. Cloud latency,
throttling and provider retries must be measured rather than extrapolated from
local storage; Kasumi's lack of retries does not prove the provider made none.

### Phase 4 measurements (2026-10-26)

Release/GCC on Windows, small encrypted orphan payloads, one protected Commit,
one HEAD and one Content. Local baseline production is `644a3a1`; the GREEN
changes add measurements without changing the deletion algorithm. Each local
size has two successful samples. Wall-clock differences between these small
sample sets are not evidence of a speedup or regression; the host was not
isolated from other work. Values below are seconds.

| Orphans | Preparing median | Analysis median | Apply median | Finalizing median | GREEN GC median (min–max) |
|---:|---:|---:|---:|---:|---:|
| 0 | 0.0106 | 0.0128 | 0.0020 | 0.0040 | 0.0294 (0.0289–0.0298) |
| 100 | 0.0107 | 0.1244 | 0.0262 | 0.0042 | 0.1655 (0.1654–0.1657) |
| 1,000 | 0.0102 | 1.1612 | 0.2856 | 0.0045 | 1.4615 (1.4357–1.4874) |
| 5,000 | 0.0099 | 5.3287 | 1.3893 | 0.0041 | 6.7320 (6.6780–6.7860) |
| 20,000 | 0.0135 | 30.7682 | 7.2241 | 0.0051 | 38.0108 (36.3076–39.7140) |

| Orphans | Phase 3 GC median (min–max) | GREEN fixture median | FSCK median | Fixture cleanup median |
|---:|---:|---:|---:|---:|
| 0 | 0.0302 (0.0270–0.0334) | 0.0314 | 0.0358 | 0.0074 |
| 100 | 0.1609 (0.1608–0.1610) | 0.4052 | 0.0317 | 0.0070 |
| 1,000 | 1.6735 (1.3972–1.9498) | 3.8144 | 0.0321 | 0.0076 |
| 5,000 | 8.3687 (7.8062–8.9312) | 18.8605 | 0.0300 | 0.0067 |
| 20,000 | 34.7056 (32.3009–37.1103) | 86.0035 | 0.0406 | 0.0098 |

The local bottleneck is LIST: at 20,000 orphans its median is 30.7283 s,
compared with 7.2241 s for Apply. Content classification and plan work are small;
plan construction plus validation is approximately 0.013 s at that size.
History authentication uses exactly two GETs at every size. These fixtures do
not measure growth in protected history. Process peak working set grows from
about 7.5 MiB at zero orphans to 29.7 MiB at 20,000, including fixture memory;
this is not a measurement of GC-exclusive heap use.

All successful local sizes observed one full LIST plus five prefix LISTs, eight
GETs (two history, six fixed control reads), two PRESENCE calls, four ownership
verifications, N candidate REMOVE attempts/acknowledgements, and N+2 total
REMOVE calls (the probe and barrier are additional). Content classification
and candidate readback GETs remain zero, as do candidate/cleanup GC errors.
The fixture has N+3 physical objects before GC; analysis observes N+4 including
the active barrier. It classifies N+1 Content objects with one protected Content,
zero CommitVariant candidates and one history reconstruction. The explicit
plan-protected count is two; the protected HEAD is excluded separately.

One initial local 20,000-object fixture preparation failed during encryption
before GC started. Its workspace was preserved; the exact cause was not
determined. Two new fixtures subsequently produced valid baseline samples.
The failed preparation is not included in successful GC timing statistics.

The currently authorized rclone parent is `kasumi:g-cert` (pass it without a
trailing slash). Its backend reports `IsLocal=false` and SHA-256 support. The
100- and 1,000-object rows marked "prior" were measured on a different disposable
parent, `kasumi:kasumi-benchmarks-gc-v090`; they remain historical backend
measurements, not a substitute for a fresh isolated run. The current g-cert
100-object run is recorded separately below. Rclone system tests and the
three-object harness test used disposable **local** alias backends, separately
from these real remote measurements.

| Remote run | Fixture | Preparing | Analysis | Apply | Finalizing | GC total | Fixture cleanup |
|---|---:|---:|---:|---:|---:|---:|---:|
| Phase 3 / 100 (prior) | 236.9841 | 10.0583 | 4.0927 | 86.2004 | 1.7823 | 102.1336 | 11.6399 |
| GREEN / 100 (prior) | 228.6140 | 10.0097 | 4.2557 | 83.5578 | 1.6366 | 99.4598 | 11.5843 |
| GREEN / 100 (g-cert) | 223.6727 | 9.9004 | 4.4511 | 80.2448 | 1.6205 | 96.2168 | 11.1609 |
| GREEN / 1,000 first attempt (prior) | 1972.9008 (failed preparation) | unavailable | unavailable | unavailable | unavailable | unavailable | not attempted |
| GREEN / 1,000 repeat (prior) | 2010.9799 | 9.6970 | 6.3929 | 814.1836 | 1.7166 | 831.9903 | 12.2598 |

The real remote 100-object baseline spent 85.8868 s inside DELETE calls out of
102.1336 s of GC: unlike the local backend, sequential DELETE latency dominates
this sample. The GREEN 100-object GC took 99.4598 s; each version has one remote
sample, so this difference is not an optimization result. Both runs acknowledged
100 candidate DELETEs, passed FSCK, and completed owned cleanup. The GREEN
1,000-object repeat spent 813.8993 s inside DELETE calls out of 831.9903 s of GC
and acknowledged all 1,000 candidates; its 33.5-minute fixture preparation is
recorded separately and is not GC time. The current g-cert 100-object run spent
79.9603 s inside DELETE calls out of 96.2168 s of GC; it acknowledged all 100
candidates, passed FSCK and removed four owned cleanup objects. Its unique child
was `kasumi:g-cert/kasumi-gc-live-96ded05f9705442eeb6a749e1622d60b`; only that
child belonged to the run.

Each 100-object remote run observed two history GETs, six LISTs, two PRESENCE
calls, four ownership verifications and 102 REMOVE calls. The RC layer recorded
120 HTTP requests: 102 deletefile, four copyfile, six hashsumfile, six list and
two stat. Its 119 completed / one failed HTTP responses are distinct from the
successful GC outcome: handled negative control replies can count as RC HTTP
failures. The 1,000-object repeat observed the same fixed history/control
counters and 1,002 REMOVE calls; its RC layer recorded 1,020 attempts, 1,019
completed and one failed response. Do not interpret these counters alone as
provider throttling or GC failure. Internal provider retries are unavailable,
not assumed absent.

The first 1,000-object remote fixture stopped on its 877th orphan PUT with
`protocol_failure`, native **RC HTTP 500**. This is the RC response status, not
a confirmed provider HTTP status; the underlying provider/rclone cause was not
established. GC never started, so its timings and counters are unavailable.
A subsequent read-only listing found 880 objects in that disposable vault;
this does not acknowledge the rejected PUT or establish a safe cleanup decision.
The failed child, external owner marker, private test key and inventory evidence
were preserved without automatic retry or cleanup. The user separately requested
a new preparation in a fresh child, leaving the failed child intact.

Remote 5,000 and 20,000 scenarios were not executed in this campaign: the
1,000-object fixture took 33.5 minutes and its GC 831.99 s, so larger volumes
were not scheduled without an additional cost/limit decision; 20,000 also
requires the harness's explicit `--confirm-large-remote` flag. No Batch DELETE,
parallel deletion, periodic ownership checkpoints, candidate
readback or history reobservation was added. Plan allocation/sorting changes
are not justified by these timings. Future local LIST work should investigate
path/metadata costs while preserving symlink/security checks; any remote
DELETE optimization needs a separate failure-contract review.

Raw local artifacts are in `build-rel/gc-performance-baseline/`,
`build-rel/gc-performance-green-local/` and `build-rel/gc-performance-phase4-local/`;
remote reports are in the corresponding `build-rel/gc-performance-remote-*`
directories. These campaign artifacts are local, not checked in; use the harness
to reproduce them.

## Operational contract

**GC is not safe to run concurrently with Sync on the same vault.** Run only one
destructive maintenance operation per vault at a time, across all machines.
Stop scheduled and interactive Sync, including no-op runs that can repair
Content, before starting GC. Resume Sync only after a healthy completion or
after resolving all maintenance uncertainty. Manual writer removal must also be
serialized with Sync and other maintenance.

Exclusivity is cooperative: the local profile lock, remote token-owned barrier,
writer registration, and initial writer check coordinate participating clients.
The local lock covers one profile on one machine; the remote protocol has no
distributed CAS or fencing token. Non-cooperative mutation after observation
can invalidate the deletion plan and cause data loss.

Pre-Apply and cleanup ownership checks do not guarantee distributed exclusivity.
If ownership is lost after pre-Apply verification, Apply may continue deleting
the frozen plan until another observed failure or cleanup detects the loss.
This is an accepted limitation of cooperative exclusion, not an invitation to
run Sync during GC. Running `gc remove-barrier --confirm-abandoned` while a GC
is active can break exclusivity and allow data loss.

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
   Mutation outcomes use three explicit states:
   - `NotAttempted`: Failure occurred before any DELETE was sent (e.g., control
     token validation failure or physical identity mismatch).
   - `Confirmed`: DELETE was acknowledged and post-removal PRESENCE confirmed absence.
   - `Uncertain`: DELETE was attempted, but its final consequence could not be
     proven (any removal error without a no-effect guarantee, or post-removal
     PRESENCE check failed or reported the barrier still present).
   An `AlreadyAbsent` DELETE result is still an attempted, acknowledged operation
   and must pass the same post-removal absence check. This differs from initial
   PRESENCE reporting absence, which returns `AlreadyAbsent` without any DELETE.
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
