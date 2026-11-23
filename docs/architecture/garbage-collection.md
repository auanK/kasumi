# Garbage Collection

GC acquires cooperative exclusivity per vault, observes authenticated history
once, validates a global deletion plan, removes candidates in bounded batches of eight, and
releases the maintenance barrier.

## Admission and analysis contract

The collector preserves this order:

1. `application::execute` resolves the profile/key, validates retention and `--min-age` (`0..8760` hours), takes the **local** profile lock, and opens the transport. Pending [Sync transaction recovery](transactions-and-recovery.md) runs before live GC (dry-run inspects the journal read-only).
2. **Pre-barrier read-only busy check (`CheckingControls`)**: Before acquiring or mutating any remote barrier, GC performs a read-only check of writer markers, multi-barrier entries (`<barriers-ns>/<token>`), and the legacy single barrier (`<barrier-id>`) using a single `control_read_batch` when supported, or sequential fallback. If active/abandoned writers or an existing barrier are present, GC bails out read-only with zero barrier writes (`remote_busy = true` when no uncertain mutation occurred).
3. **Unique multi-barrier with settle delay (`EstablishingBarrier`)**: GC publishes a unique token-owned barrier under `<barriers-ns>/<32-hex-token>` (carrying diagnostic `started_at`, `pid`, and `machine` metadata — never auto-expired by time), waits a cooperative settle window (`2000 ms` in CLI runs; `0 ms` default in library/unit calls), and verifies exclusivity (no legacy `<barrier-id>`, only our barrier token present under `<barriers-ns>/`, zero active writers, and our payload SHA-256/bytes intact). If contention appears during the settle window, GC deletes **only its own** `<barriers-ns>/<token>` and aborts read-only without disturbing peer barriers or writers. Cooperative Sync writers register a visible writer marker and check both legacy `<barrier-id>` and `<barriers-ns>/`, denying admission while any barrier is present.
4. GC performs **one complete authenticated observation** using `transport::list_metadata` (`ListingRemote`, falling back to `list` when `Unsupported`), HEAD/Commit/Epoch reachability with batched Epoch/Marker prefetch (`AuthenticatingHistory`), content reachability (`AnalyzingReachability`), and `KACT` v1 activity loading (`LoadingActivities`) with zero orphan payload downloads. Malformed history, unknown objects, missing required content, invalid control state, or transport errors stop collection before candidate deletion.
5. GC builds and validates the global deletion plan and filters candidates against the remote-clock fail-closed grace period (`min_orphan_age`, defaulting to `runtime_data.min_history_age_hours` = 6h, alongside `min_history_depth` = 5 commits). During live mutating GC with positive grace, `effective_now` is clamped to `min(local_now, remote_now)` where `remote_now` is the backend-assigned `ModTime` of the freshly published barrier (failing closed and deferring all candidates if the barrier timestamp is unavailable or non-positive), so a fast local clock cannot prune recent objects early. When `candidates.empty()`, GC skips the online consistency probe and pre-Apply re-check and releases its barrier immediately (`Finalizing`).
6. When `!candidates.empty()`, GC publishes and verifies a temporary provider-visibility probe (`ProbingConsistency`), requires listings to confirm creation and removal, and returns `analysis_only` if online visibility cannot be established. Probe errors fail closed.
7. Immediately before Apply, GC revalidates full barrier exclusivity (`verify_barrier_exclusivity`: owns `<barriers-ns>/<token>`, no competing barriers, no legacy barrier, and no writers). Replacement, absence, contention, or verification failure stops all candidate deletion (`NotAttempted`).

## Global deletion plan

The plan is an in-memory candidate list (with byte sizes resolved from metadata listing) and a sorted set of protected object identifiers. It is discarded at the end of the run. Eligible candidates are:

| Candidate | Eligibility |
|---|---|
| Orphan Content | Physically present Content/Pack not referenced by protected reachable history, passing the grace-period check, eligible for deletion without downloading or auditing its payload |
| Redundant CommitVariant | Valid ciphertext of a reachable Commit that is not a required variant, passing the remote `ModTime` grace check |
| Expired Unreachable CommitVariant | Valid ciphertext of a valid unreachable Commit (e.g., superseded strictly behind `latest_epoch.anchors` or aged orphan commit) not in `PROTECTED_SET`, passing **both** `Commit.created_at` and remote `ModTime` grace checks |
| Expired `KACT` v1 Activity | Valid remote activity records outside retention (`min_history_depth` and effective age window), not the newest `Succeeded` record for their `(machine_id, operation)` pair, and passing the remote `ModTime` grace check |

GC loads and authenticates all objects under `<activity-ns>/<version-ns>/` before deletion; any unreadable, corrupt, or structurally invalid activity identifier/payload causes GC to fail closed before deleting any candidate. After completion, GC (as well as `gc remove-writer` and `gc remove-barrier`) publishes a best-effort `KACT` v1 activity record, and on successful GC refreshes the local `remote_activity_cache` in `db.sqlite` with retained records.

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

GC does not authenticate orphan candidate bytes, download ciphertexts, or decrypt payloads before deletion. Unreferenced content is discarded based solely on reachability. Corrupted orphan ciphertext does not alter its reachability: a corrupted unreferenced content object is still an orphan and remains eligible for deletion without downloading its payload. Conversely, all Content referenced by protected history remains strictly protected; if a referenced Content object is damaged, its integrity is audited and reported by [Fsck](fsck.md), not downloaded or repaired by GC.

The controlled remote vault namespace contract assumes that physical storage objects within the vault scope adhere to protocol identity structure. Unknown or ambiguous storage objects (such as alien files or malformed identifiers) are never inferred safe to delete and trigger fail-closed aborts before any deletion. The maintenance barrier coordinates cooperative clients but provides no distributed compare-and-swap (CAS).

The protected set includes:

- every variant selected by a valid HEAD marker (all HEAD-selected ciphertext
  variants are preserved);
- at least one valid variant for every reachable, unmarked Commit, including
  unmarked parents and Epoch-anchored Commits;
- every reachable physical Content and Pack object resolved through reachable Commits and their `StorageManifest` entries:
  - loose Content IDs referenced by any reachable Commit Snapshot;
  - `KPAK\x01` Pack IDs in `StorageManifest.packed_blobs` for which **at least one** packed member `logical_hash` remains referenced by a reachable Commit (a Pack ID becomes an eligible orphan only when zero members of that pack are referenced by any reachable Commit);
  - individual FastCDC chunk Content IDs in `StorageManifest.chunked_files` referenced by any reachable chunked file (unreferenced old chunks from modified large files become eligible orphans while shared unchanged chunks remain protected);
- valid Epoch objects and retained orphan Epoch objects;
- protected `KACT` v1 operational activity records (newest `Succeeded` per `(machine_id, operation)` plus records retained under `min_history_depth` / `min_history_age_hours`);
- all protocol/control objects by construction.

The content reachability limit applies to one million distinct physical IDs. GC stores the type and expected size for each reachable ID, checks each occurrence for conflicting metadata, and discards per-commit reference details as it walks the authenticated history.

Before the first DELETE the collector enforces:

```text
DELETE_SET ∩ PROTECTED_SET = ∅
```

During candidate selection, the collector constructs a deterministically ordered,
deduplicated deletion list (passing fail-safe age checks and excluding every
identifier in `PROTECTED_SET`), failing closed if any candidate is empty, is a
control object, or intersects `PROTECTED_SET`. When `min_orphan_age > 0s`
(default 6h), live GC computes `effective_now = min(local_now, remote_now)` from
the freshly written barrier's backend `ModTime` (failing closed when missing or
non-positive), and any candidate with a missing, non-positive (`<= 0`), future
(`> effective_now`), or `< min_orphan_age` remote `ModTime` (or missing
`list_metadata` support) — and any unreachable commit whose `Commit.created_at`
fails the same dual-clock check — is kept untouched and counted in
`deferred_recent_objects`.
Unknown, invalid, or ambiguously classified objects are not inferred safe to
delete. Epoch objects are never candidates.

## Destructive phase

Apply consumes the frozen, deterministically ordered plan in batches of at most
8 candidates. The transport may execute these DELETEs concurrently. Cancellation
and periodic barrier-exclusivity revalidation are checked before continuing later
batches (`apply_revalidation_batch_interval = 16` batches / `128` candidates, or
`apply_revalidation_time_interval = 30s`); an in-flight batch drains before the
next decision. If a new writer, competing barrier, legacy barrier, or lost
barrier ownership is detected between batches, Apply aborts further batches with
`ConcurrentChange` (`NotAttempted` for the unstarted batch while preserving
earlier `confirmed_removed` counts) and releases only its own barrier. When
batching is unsupported, GC falls back to individual removals only if no item
was submitted.

A complete batch report must identify every submitted candidate exactly once.
Acknowledgements from all items in the batch are retained, including successful
peers of a failed item. A failed batch, malformed report, exception or cancellation
stops admission of later batches, without retry or compensation. A whole-batch
failure can leave the failed identifier unavailable and effects uncertain.

Except for bounded periodic exclusivity checkpoints between batches (which
verify `<writers-ns>/`, `<barriers-ns>/`, legacy `<barrier-id>`, and own barrier
integrity), Apply performs no candidate `GET` or `PRESENCE` and no history
reobservation, limiting remote DELETE overhead while tightening late-join
contention detection.

A `Removed` or `AlreadyAbsent` result increments `removed_objects` /
`confirmed_removed`: these count **REMOVE operations acknowledged by the API**,
not independently verified physical absence.

On a failed `REMOVE`, the collector preserves the transport error category,
message, native code, and candidate identifier when available; keeps the count of all
acknowledged removals, including successful peers in the completed batch; stops further deletion without retry or compensation;
attempts barrier cleanup through the normal path; and returns the partial
diagnostic. Exceptions during DELETE also leave the candidate `Uncertain` and
preserve earlier acknowledgements. A later GC run starts from a new observation
and does not reuse the old plan.

| Mutation state | Meaning |
|---|---|
| `NotAttempted` | No candidate DELETE was started for this failure, including cancellation before the next batch |
| `Confirmed` | A candidate REMOVE returned `Removed` or `AlreadyAbsent`; this is transport acknowledgement, not an independent absence audit |
| `Uncertain` | DELETE was attempted, but its remote effect cannot be proven; error categories alone do not establish absence of effects |

`NotApplied` would mean a DELETE was attempted with a documented guarantee of no
mutation. The current transport does not provide that evidence for removal
errors, so no such state is emitted or added to the enum. A failed DELETE is
never reported as `NotAttempted`. Cancellation observed before a subsequent
batch stops Apply with `NotAttempted` and keeps the exact previous
acknowledgement count; it does not retry or restore earlier objects.

Barrier cleanup remains special. It verifies ownership, attempts release at most
once, refuses to intentionally remove a detected foreign or replaced barrier,
preserves primary and cleanup errors separately, and does not declare a healthy
finish when release is ambiguous. Absence is checked after acknowledged barrier
release. Cleanup exceptions leave release unconfirmed, and the destructor never
opens a second release path. Ownership checks cannot eliminate the TOCTOU window
between verification and DELETE without conditional deletion/CAS.

## Operational contract

### Scheduled Automation and Grace Period

Cooperative exclusivity uses the local profile lock, unique token-owned remote
barriers (`<barriers-ns>/<token>`) with a `2s` post-write settle check and
periodic Apply revalidation, writer registration, pre-/post-barrier checks, and
backward read-compatibility with legacy `v0.23.x` single barriers (`<barrier-id>`).
Because object storage lacks distributed CAS or fencing tokens, three safeguards
make scheduled unattended `kasumi gc <profile>` safe alongside asynchronous
Sync schedules:

1. **Pre-barrier read-only busy backoff & unique-barrier settle verification**:
   Active Sync writers or any existing barrier (legacy or multi-barrier) fail
   fast read-only (`remote_busy`) without creating markers. Because every new
   barrier uses its own `<barriers-ns>/<token>`, racing GCs cannot silently
   overwrite each other and abort cleanly during the `2s` settle check while
   deleting only their own marker.
2. **Remote-clock fail-closed grace period (`min_orphan_age` / `--min-age`, default 6h)**:
   Live mutating GC clamps `effective_now = min(local_now, remote_now)` using
   the backend timestamp on its newly published barrier (keeping defaults of `6`
   hours and `5` commits unchanged). Even if a writer uploaded an in-flight
   payload or Commit variant without coordination or a client has an ahead local
   clock, any remote object newer than `min_orphan_age` (or with missing,
   non-positive, or clock-skewed timestamps) is deferred intact in
   `deferred_recent_objects`. For manual offline cleanups where all clients
   are stopped, pass `--min-age 0` to collect fresh candidates immediately.
3. **Diagnostic-only marker metadata without auto-expiration**:
   Writer and barrier markers record `started_at`, `pid`, and `machine` for
   operator triage in `kasumi remote writers <profile>`, but Kasumi never
   auto-expires writers or barriers based on elapsed time.

Exclusivity remains cooperative rather than distributed locking: do not bypass
coordination with `--min-age 0` while Sync is uploading recent unlinked objects,
and do not run `gc remove-barrier [<barrier-id>] --confirm-abandoned` while
another GC process is actively deleting objects.

The backend must expose completed control and namespace changes to protocol
`LIST` and `PRESENCE` checks. The visibility probe tests its own temporary object;
it cannot certify provider-wide consistency or detect every stale listing. See
[Transport](transport.md) for backend requirements.

An `analysis_only` result means no candidate removal occurred, although barrier
and probe publication/cleanup may have occurred. It is not a selectable mode.
Transport and protocol errors fail the operation.

By contrast, `kasumi gc <profile> --dry-run` is an explicit read-only preview:
it inspects the local transaction journal read-only (refusing active or invalid
journals without running recovery), verifies that no maintenance barrier or
active writer markers exist, runs the authenticated history/content/activity
observation and global candidate validation, reports candidate totals broken
down into content objects, redundant commit variants, and expired `KACT` v1
activities, establishes no remote barrier, deletes zero objects, and publishes
no `KACT` activity record.

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

`kasumi gc remove-barrier <profile> [<barrier-id>] --confirm-abandoned` is a controlled,
diagnostic manual recovery operation for abandoned remote maintenance barriers
left behind when a Garbage Collection process was terminated abruptly (e.g., killed
process, power loss, or ungraceful shutdown).

When one or more maintenance barriers remain on remote storage, subsequent GC runs
fail during pre-barrier or exclusivity checks (for example, returning `remote_busy`
or reporting that a competing maintenance barrier is already present).

### Protocol and Operational Principles

1. **Inspection**: Use `kasumi remote writers <profile>` (or with `--json`) to
   inspect active barriers and writer markers, including optional diagnostic
   metadata (`started_at`, `pid`, `machine`) when present:
   ```text
   Maintenance barriers: 1
     - Identifier: <barriers-ns>/<32-hex-token> (v0.24+) or <barrier-id> (legacy)
       Machine: <machine>
       PID: <pid>
       Started at: <utc-timestamp>

   Writers: 0
   Maintenance blocked: Yes
   ```
2. **Target Selection**:
   - When exactly one barrier is present (either a multi-barrier object under
     `<barriers-ns>/<32-hex-token>` or a legacy `<barrier-id>`), `<barrier-id>` may
     be omitted.
   - When multiple barriers are present, `<barrier-id>` (full remote identifier or
     its 32-hex token) is required so only the explicitly selected barrier is removed;
     remaining barriers stay intact and are reported in the output warning.
3. **Mandatory Confirmation (`--confirm-abandoned`)**: Because Kasumi operates
   over passive storage backends that lack distributed process liveness detection, it
   cannot determine whether an active GC process is still executing on another
   device or machine. Diagnostic metadata (`started_at`, `pid`, `machine`) never
   triggers automatic expiration; never assume a barrier is abandoned merely because
   of its age or timestamp. The operator must verify externally that no maintenance
   or sync operation is active before passing `--confirm-abandoned`.
4. **Control Token Verification**: Each barrier object contains a control payload
   whose first line is a token (`kasumi-gc-v1:barrier:<32-hex-token>`) optionally
   followed by diagnostic metadata lines (`started_at`, `pid`, `machine`). Kasumi
   downloads and performs structural validation of the header token (checking prefix
   and canonical 32-character hexadecimal format) before attempting removal,
   rejecting corrupted or foreign objects. This token is an internal control token;
   it is not a cryptographic signature or MAC.
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

## Removal progress

GC emits high-level stage events (`Preparing`, `Analyzing`, `Applying`,
`Finalizing`) paired with granular `GarbageCollectSubStage` progress:
`CheckingControls`, `EstablishingBarrier`, `ListingRemote`,
`AuthenticatingHistory` (`commits_processed / commits_total`),
`AnalyzingReachability`, `LoadingActivities`, `ProbingConsistency`,
`RemovingObjects` (confirmed removals, `removed_bytes`, and `candidate_bytes`),
and `ReleasingBarrier`. Interactive CLI output renders live sub-stage status,
rates, byte totals, ETA, and elapsed time; plain logs emit spaced 10%
milestones. Progress observers do not participate in candidate selection or deletion.
