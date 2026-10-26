# Troubleshooting

This guide provides symptom-oriented troubleshooting steps for operational issues in Kasumi.

Remediations prioritize fail-safe actions: inspect observed state, understand the underlying condition, retry normal operations, and verify backend configuration. **Never manually modify or delete internal objects on remote storage.**

---

## Profile is Already in Use / Profile Lock Collision

### Symptom
An application operation can exit with this English error:
```text
[ERROR] profile is already in use by another execution
```
Other lock failures report `could not lock profile:` followed by the operating system's error detail.

### Likely Meaning
Another Kasumi process is currently running on the same machine using the specified profile. Kasumi acquires an exclusive OS file lock (`profile-<name>.lock` in Kasumi's data directory) to prevent concurrent execution on the same local profile state.

### Safe Next Steps
1. Wait for the active operation (such as a large synchronization, Fsck, or GC) to complete.
2. Check your operating system process list for active Kasumi processes:
   * **Linux**: `pgrep -a kasumi`
   * **Windows**: `Get-Process kasumi`
3. If an automated script or scheduler is running, verify that job schedules do not overlap.
4. If a previous Kasumi process was forcibly terminated (e.g., system power loss or killed process), the operating system releases the file lock automatically when the process handle closes. Check that no orphaned processes remain before rerunning the command.
5. Do not run `status`, `sync --dry-run`, `sync`, `fsck`, or `gc` simultaneously against the same profile on the same machine. `remote ...` inspection does not take this lock and may observe concurrent changes.

### Related Documentation
* [Concurrency & Multiple Profiles](configuration-and-usage.md#concurrency--multiple-profiles)
* [Automation](best-practices.md#automation)

---

## Interrupted Synchronization and Transaction Recovery

### Symptom
At the start of `sync`, `fsck`, `resolve-missing`, or `gc`, Kasumi may report a recovery conflict or indeterminate recovery diagnostic. The detail depends on the journal and observed remote state.

### Likely Meaning
A prior synchronization was interrupted before completion. Kasumi detected the
authenticated `transaction.bin.enc/` journal directory. Its snapshot, delta log,
confirmation, and retirement proof are distinct from the staging and backups in
`.transactions/<id>/`; preserve the complete evidence if recovery fails.

### Safe Next Steps
1. **Automatic Evaluation**: Kasumi evaluates the journal before Sync, Fsck, `resolve-missing`, and GC. Read-only planners/inspection and manual writer maintenance do not run recovery. Prefer `kasumi sync <profile>` to recover; `resolve-missing` additionally makes an explicit logical-deletion decision.
2. Depending on the checkpointed transaction phase:
   * **Pre-publication interruptions**: Kasumi may roll back local mutations from staged backups or resume only when pinned inputs still match.
   * **Post-publication interruptions**: Kasumi verifies the published Commit and HEAD marker before advancing local state; contradictory state stops recovery.
3. **If Recovery Reports Indeterminate**: Remote transport uncertainty can prevent Kasumi from confirming publication. Check network connectivity and storage backend availability, then rerun `kasumi sync <profile>`.
4. **Never Manually Delete `transaction.bin.enc`**: The journal contains references to staged backups needed to restore local files. Deleting the journal manually can leave local files in a corrupted state.

### Related Documentation
* [Transactions and Recovery Architecture](architecture/transactions-and-recovery.md)
* [Interruption and Recovery](configuration-and-usage.md#interruption-and-recovery)

---

## Local File Changed During Synchronization

### Symptom
Sync stops with a concurrent-modification or destination-conflict error before completing a local Download, delete, rename, or conflict-resolution step.

### Likely Meaning
Kasumi observed a local path change before the operation's effect and refused the stale operation. It keeps completed peer file effects, clears their transaction progress durably, and asks the next Sync to reobserve and replan. Validation cannot be atomic with the following filesystem syscall, so an unrelated writer racing that final interval can still have its edit overwritten, removed, or moved.

### Safe Next Steps
1. Check the reported path and decide whether another editor or process is still changing it.
2. Run `kasumi sync <profile>` again after that writer is done; the new run reobserves the local tree and plans from the current contents.
3. If Kasumi leaves `transaction.bin.enc` after a recovery conflict, keep it and `.transactions/<id>` with its backups intact. Do not remove them manually; resolve the reported recovery condition first.

Kasumi synchronizes files but does not retain every past version or replace an independent backup. Keep a separate backup of important data.

### Related Documentation
* [Synchronization Architecture](architecture/synchronization.md#execute-and-validate)
* [Transactions and Recovery Architecture](architecture/transactions-and-recovery.md#local-mutation-contract-and-external-writers)

---

## Windows Path Exceeds the Supported Limit

### Symptom
Sync reports that Windows rejected a path and recommends enabling long-path
support or shortening the profile path.

### Likely Meaning
The host may still enforce legacy Win32 path limits. Kasumi embeds a
`longPathAware` manifest, but long Win32 paths also require the Windows
`LongPathsEnabled` policy. The manifest alone does not remove every filesystem
or API limit. An upload can fail on an internal staging path even when its source
path is short enough: `.transactions/<id>/upload-batches/<batch>/<content-id>`
adds directories and identifiers beneath the private profile.

### Safe Next Steps
1. Read the rejected path's reported length and operation. Short paths work
   without changing global Windows policy; using shorter parent paths for the
   synchronized folder and private profile may avoid the limit. Preserve the
   complete profile and recovery state before changing paths.
2. If long paths are needed, ask your administrator about enabling
   `LongPathsEnabled`, then restart Kasumi. Host policy, filesystem component
   limits, and the APIs used by external tools still apply.
3. Run Sync again. If Kasumi retained a transaction journal after reporting a
   recovery conflict, preserve it and its backups until recovery succeeds.

### Related Documentation
* [Configuration and Usage](configuration-and-usage.md)
* [Microsoft's Win32 path-length contract](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)

---

## Exit Code 2 / Pending Materializations

### Symptom
Running `kasumi sync <profile>` completes, but the process exits with status code `2`. English output can include:
```text
[WARNING] Synchronization completed partially.
1 file is waiting for unavailable remote content.
Pending:
  docs/report.pdf
```

### Likely Meaning
The synchronization was a non-fatal **partial synchronization**. Remote commit metadata and history were successfully accepted and recorded, but one or more required payloads were missing from remote storage and no compatible local source was available to repair them. Sync preserves the logical files, expected Content IDs, accepted state, and pending evidence; it does not infer a deletion.

### Safe Next Steps
1. **Treat Exit Code 2 as Non-Fatal**: In automated scripts or pipelines, exit code `2` indicates that metadata was updated, but content remains unresolved until a verified payload becomes available.
2. **Identify Pending Files**: Run `kasumi status <profile>` or `kasumi status <profile> --full` to inspect the list of pending paths.
3. **Trigger Payload Upload from Source Client**: If another machine created or modified the pending files, run `kasumi sync <profile>` there. The repair check runs even when that machine's local tree is otherwise unchanged and no upload was otherwise planned.
4. **Subsequent Synchronization**: Once the missing content objects are present on remote storage, the next `kasumi sync <profile>` will download and materialize the pending files automatically. If a client holds intact bytes for the expected Content ID, its normal Sync can repair the physical object without publishing a new logical version.

### Related Documentation
* [Reconciliation and SyncPlan](architecture/reconciliation.md)
* [Synchronization Architecture](architecture/synchronization.md)

---

## Missing Remote Payload or Corrupt Content

### Symptom
Running `kasumi fsck <profile>` reports an audit failure, commonly introduced as
`Audit finished with failures:`. The diagnostic includes affected paths; its
detail depends on the failure.

### Likely Meaning
A content payload referenced by the history DAG is absent from remote storage or failed cryptographic authentication (AEAD decryption failure or BLAKE3 plaintext hash mismatch).

### Safe Next Steps
1. Run `kasumi fsck <profile>` to audit the full vault and determine all affected paths.
2. Run `kasumi remote contents --audit <profile>` to inspect physical content states across the entire vault.
3. **Repair from Intact Client**: If an intact version of the affected file exists locally on any client machine:
   * Verify the file content on that machine.
   * Run `kasumi sync <profile>` from that machine. Even if no local file changed, the required-content probe detects the absent remote object, reuses the existing local source only after hash/size authentication, and restores the physical object without changing logical history.
4. If the payload is permanently lost from remote storage and no client has a copy, restore the file from an external backup into the synchronized folder on one client and run `kasumi sync <profile>`.
5. If Sync reports a transport failure or a LIST/PRESENCE disagreement instead of repairing, treat the content as unverified rather than logically deleted. Rerun after the backend is consistent and inspect with `kasumi remote contents --audit <profile>`. Do not delete protocol objects manually or run `resolve-missing` merely to silence the error.

### Related Documentation
* [Fsck Architecture](architecture/fsck.md)
* [Effective Tree and Content Inspection](architecture/remote-content-inspection.md)

---

## Conflicts and Preserved Conflict Files

### Symptom
Files with conflict suffixes appear in the synchronized directory:
```text
notes.txt.kasumiconflict_a1b2c3d4e5f6
project.docx.kasumiconflict_local
project.docx.kasumiconflict_remote
```

### Likely Meaning
Concurrent modifications were made to the same file across multiple machines or branches:
* **Remote Branch Conflicts** (`.kasumiconflict_<12-char-commit-id>`): Two remote branches modified the same path. Kasumi preserved one variant at the canonical path and preserved the competing variant under the commit-tagged path.
* **Local vs. Remote Conflicts**: The file was modified both locally and remotely relative to the last synchronized state. Kasumi uses filesystem modification time (`mtime`) as a deterministic tie-breaker:
  * If local `mtime` is strictly newer, the local file stays at the canonical path, and the remote version is saved as `<path>.kasumiconflict_remote`.
  * If remote `mtime` is newer or equal, the remote file keeps the canonical path, and the local file is renamed to `<path>.kasumiconflict_local` and uploaded.

### Safe Next Steps
1. Open and compare the canonical file and the conflict file.
2. Manually merge the desired changes into the canonical file.
3. Delete the conflict file (`.kasumiconflict_*`) once merged.
4. Run `kasumi sync <profile>` to synchronize the resolved canonical file and record the deletion of the conflict file.

### Related Documentation
* [History DAG, Concurrency, and Retention](architecture/history-and-concurrency.md#conflict-handling)
* [Reconciliation](architecture/reconciliation.md)

---

## Multiple Logical Heads

### Symptom
`kasumi remote heads <profile>` outputs more than one commit ID, or `kasumi remote tree <profile>` starts its English error with:
```text
[ERROR] Remote history has multiple logical heads.
```

### Likely Meaning
Multiple machines synchronized and published changes concurrently without synchronizing with each other first. In Kasumi's multi-master architecture, concurrent publications form independent branches in the shared history DAG. This is normal and expected.

### Safe Next Steps
1. To inspect individual branches before syncing, specify the head ID:
   ```bash
   kasumi remote tree <profile> --head <id>
   ```
2. Run synchronization:
   ```bash
   kasumi sync <profile>
   ```
   For a resolvable multi-head history, Kasumi can:
   * Identify the unique best common ancestor (merge base);
   * Reconcile divergent branches, merging independent paths automatically;
   * Deterministically resolve any file conflicts;
   * Publish a multi-parent merge commit (`CM`) for the observed heads. Without another concurrent publication, `CM` becomes the sole logical head.

   If multiple incomparable best common ancestors exist, synchronization stops with `AmbiguousMergeBase`.

### Related Documentation
* [Physical HEAD Markers vs. Logical Heads](architecture/history-and-concurrency.md#physical-head-markers-vs-logical-heads)
* [Multi-Parent Merge Commits](architecture/history-and-concurrency.md#multi-parent-merge-commits)

---

## History Regression or Inconsistent Remote History

### Symptom
Synchronization fails with a history continuity diagnostic. For example, the error detail can say `local base commit is not reachable from storage`; other history or Epoch failures have different details.

### Likely Meaning
The observed remote history is inconsistent with the client's locally accepted state. This typically happens if:
* Remote storage was restored from an out-of-date backup;
* Files in the remote storage directory were deleted or overwritten out-of-band;
* Storage backend replication or caching returned stale data.

### Safe Next Steps
1. Run diagnostic commands to inspect remote history and Epoch state:
   ```bash
   kasumi remote health <profile>
   kasumi remote epochs <profile>
   kasumi remote heads <profile>
   ```
2. Verify backend storage consistency. If using cloud storage, ensure caching layers or eventual consistency delays have settled.
3. If remote storage was rolled back from an external backup, consult the project documentation for recovery procedures. Do not attempt to force synchronization or delete local SQLite state without understanding the cause.

### Related Documentation
* [Epochs & Retention Horizons](architecture/history-and-concurrency.md#epochs--retention-horizons)
* [Remote History Inspection](architecture/remote-history-inspection.md)

---

## Slow Synchronization or Preview

### Symptom

A synchronization or preview spends a long time observing files, including when
few files have changed.

### Diagnose

Every observation walks the local directory tree and reads metadata. A warm
cache can avoid reading unchanged file content, but cannot skip enumeration or
remote history observation. `status` and `sync --dry-run` also reuse matching
strong fingerprints, but never save cache deltas. New or changed files,
insufficient native identity, and cache misses require hashing. An authenticated
ignore projection differing from local rules uses full hashing.

Enable `KASUMI_PERF_TRACE=1` for a normal sync you intend to apply. These examples
write diagnostics to `kasumi-perf.log`; normal output remains on the terminal.
Use your own profile name instead of `work`.

PowerShell (restore the previous setting afterwards):

```powershell
$previousTrace = $env:KASUMI_PERF_TRACE
try {
    $env:KASUMI_PERF_TRACE = '1'
    kasumi sync work 2> kasumi-perf.log
} finally {
    $env:KASUMI_PERF_TRACE = $previousTrace
}
```

CMD (unset the diagnostic variable afterwards):

```bat
set "KASUMI_PERF_TRACE=1"
kasumi sync work 2> kasumi-perf.log
set "KASUMI_PERF_TRACE="
```

POSIX shells (the setting applies only to this command):

```sh
KASUMI_PERF_TRACE=1 kasumi sync work 2> kasumi-perf.log
```

Trace records begin with `KASUMI_PERF` and contain `name`, `calls`, and `total_us`.
`calls` is the metric's counter (including byte counts for byte metrics);
`total_us` is accumulated wall-clock microseconds, not CPU time. Instrumented
stages can overlap, so do not sum them as total run duration.

- Compare `local hash cache hits`, `local hash cache misses`, and
  `local hash cache unsupported` across completed syncs. Fingerprint changes,
  unsupported native identity, or a cold cache require content hashing.
- Compare `local filesystem scan wall`, `local content hashing wall`, and
  `local hash bytes` to distinguish enumeration/metadata cost from scanner
  content reads. Directed destructive checks and other verification can still
  read content separately.
- Check `initial observation`, remote history/transport metrics, and
  `transaction execution` for provider latency, history loading, or transfer cost.
- `KASUMI_PERF_TRACE_LIVE=1` adds live fsck audit-completion and checkpoint-write
  counters when tracing is enabled; it is not a live counter for every operation.

For a read-only diagnostic, trace `kasumi status work`, accounting for cache
misses and any required full hashing. Trace output is diagnostic instrumentation, not a stable machine
protocol. Check the command's [exit code](configuration-and-usage.md#exit-codes)
as well as the timing report. See [Local Observation](architecture/local-observation.md).

---

## Remote Storage Unavailable / Rclone Issues

### Symptom
Commands fail with transport or remote-observation diagnostics. For example, a missing rclone installation can be reported as `rclone not found in an absolute and allowed PATH directory`; the displayed error also depends on the command and transport.

### Likely Meaning
Kasumi cannot establish a connection to the configured shared storage backend. This can occur if:
* Network connectivity is down;
* The `rclone` executable is missing from your system `PATH`;
* Cloud provider authentication tokens in rclone have expired;
* The remote path syntax in `config.toml` is invalid.

### Safe Next Steps
1. **Verify Rclone Installation**: Ensure `rclone` is installed and reachable in your terminal:
   ```bash
   rclone version
   ```
2. **Verify Backend Connectivity Directly**: Test the configured remote using rclone:
   ```bash
   rclone lsd drive:
   ```
   If this prompts for re-authentication, follow rclone's instructions to refresh credentials.
3. **Verify Profile Configuration**: Check `config.toml` in Kasumi's data directory. For rclone remotes:
   * The destination must follow the format `remote:relative/path` (e.g., `drive:kasumi/vault`).
   * Do not include leading slashes after `:` (e.g., `drive:/kasumi` is invalid).
   * For local filesystem paths, paths must be absolute.

### Related Documentation
* [Profile Setup](configuration-and-usage.md#profile-setup)
* [Transport Architecture](architecture/transport.md)

---

## Permission Failures (Local Filesystem or Remote)

### Symptom
Kasumi reports an operating system or transport error while reading or writing local files or remote storage. The wording depends on the failed operation.

### Likely Meaning
The operating system user account running Kasumi lacks sufficient filesystem permissions:
* Local profile directory permissions (in `%APPDATA%/kasumi` on Windows or `$XDG_CONFIG_HOME/kasumi` on Linux);
* Local synchronized directory permissions;
* Write access to the remote storage directory.

### Safe Next Steps
1. **Local Synchronized Path**: Ensure your operating system user account owns and has read/write permissions for all files and directories inside the synchronized path:
   * **Linux**: `ls -ld <path>` and adjust ownership with `chown -R $USER <path>`.
   * **Windows**: Check file properties and security tab DACLs.
2. **Kasumi Profile Storage**: Verify that your user account has read/write permissions on Kasumi's data folder:
   * **Windows**: `%APPDATA%/kasumi`
   * **Linux**: `~/.config/kasumi`
3. **Remote Storage Permissions**: If using a local network share (SMB/NFS) or cloud bucket, verify that the configured user/API key has read, write, and delete permissions on the vault directory.

### Related Documentation
* [Security Specification](security.md#threat-c-compromised-local-os-account--malware)

---

## GC Partial Failures and Uncertain Deletions

### Symptom

`kasumi gc <profile>` returns `GarbageCollectionFailure`, or reports that a candidate or barrier operation may be ambiguous.

### Likely Meaning

GC stops on an analysis failure, transport error, ownership loss, or ambiguous DELETE. The error carries the candidate total, transport-acknowledged removals, failed identifier when one exists, stage, transport category/message/native code when available, mutation state (`NotAttempted`, `Confirmed`, or `Uncertain`), and barrier-cleanup status. An ambiguous mutation is not retried automatically, and an observed absence after a failed DELETE is not counted as an acknowledged removal. Successful REMOVE calls are not read back with PRESENCE.

### Safe Next Steps

1. **Preserve Protocol Objects**: Do not delete legacy quarantine objects or other protocol objects directly through the provider.
2. **Inspect Writer Markers and Barrier**:
   ```bash
   kasumi remote writers <profile>
   ```
   If you know another client is synchronizing, wait for it to finish.
   - If a maintenance barrier is present from an interrupted GC run (`Barrier: present`), inspect its identifier. Ensure that no GC process is active on any device (never assume a barrier is abandoned merely because of its age or timestamp), then recover it:
     ```bash
     kasumi gc remove-barrier <profile> --confirm-abandoned
     ```
     If removal exits with an `Uncertain` mutation state (e.g. after a network timeout or connection reset during DELETE or post-removal verification), do not perform manual provider mutations. Re-run `kasumi remote writers <profile>` to inspect actual remote state. If the barrier is already absent, a subsequent `remove-barrier` will report `Already absent` with zero deletes. If it remains present and maintenance is verified inactive, retry the command.
   - If writer markers remain, verify that no Sync or maintenance operation is running, copy that writer's exact identifier, and run:
     ```bash
     kasumi gc remove-writer <profile> <writer-id>
     ```
   Kasumi cannot establish process liveness; removal is the operator's responsibility. The command removes only the selected control object and does not run GC or Sync.
3. **Inspect Remote Health**:
   ```bash
   kasumi remote health <profile>
   ```
4. **Use Fsck for Integrity**: `kasumi fsck <profile>` audits referenced content and verifies payload integrity; GC relies strictly on reachability and does not certify or download orphan payloads.
5. **Investigate Before Retrying**: Treat `Uncertain` mutation state and barrier-cleanup errors as reasons to inspect the remote namespace and retry only after the state is understood. Do not substitute ad-hoc provider deletion for GC. See [Garbage Collection Architecture](architecture/garbage-collection.md).

### Related Documentation
* [Garbage Collection Architecture](architecture/garbage-collection.md)
* [Physical and Maintenance Inspection](architecture/remote-maintenance-inspection.md)

---

## Sync Cannot Establish Content Availability

### Symptom

`kasumi sync <profile>` fails while calculating with a transport/presence error or a message that LIST and PRESENCE disagree about a Content object.

### Likely Meaning

Sync requires a definitive physical-availability answer before repairing or planning around required Content. A transport failure, cancelled presence request, malformed batch response, or LIST/PRESENCE disagreement is an indeterminate observation, not a missing object. Sync fails closed and does not upload, delete, or convert the affected paths to pending based on that result.

### Safe Next Steps

1. **Retry after checking connectivity and backend health**. Do not interpret the error as evidence that the Content is gone.
2. **Inspect the vault** with `kasumi remote contents --audit <profile>` and `kasumi fsck <profile>` once the transport is stable.
3. **Check provider consistency** if LIST and PRESENCE continue to disagree. Confirm completed writes and listings are visible as required by [Transport](architecture/transport.md) and [Garbage Collection](architecture/garbage-collection.md#operational-contract).
4. **Repair from a verified local source** by running Sync on a client whose file still matches the expected logical hash and size. Never remove the logical row, HEAD, journal, or remote Content object merely to make the diagnostic disappear.

---

## Explicitly Resolving Missing Remote Content

If pending materializations remain because the necessary encrypted payload no longer exists, first investigate with `kasumi status <profile>`, `kasumi fsck <profile>`, and other enrolled clients. Recover the original bytes or remote object from an intact source whenever possible.

`kasumi resolve-missing <profile>` is a **last-resort logical deletion workflow**, not a repair command. It validates which pending paths are eligible, may publish a new remote history state removing those entries, and can make the loss visible to all clients. Do not run it merely to silence exit code `2`. Preserve an independent copy and confirm that the missing content cannot be restored before choosing to remove its logical references.

---

## Unknown or Malformed Remote Objects

### Symptom
Running `kasumi remote objects <profile>` or `kasumi remote health <profile>` reports unknown objects or an unknown-object count.

### Likely Meaning
Objects exist in the remote storage directory that do not conform to Kasumi's key-derived namespace layout. This typically happens if non-Kasumi files were manually saved in the vault directory, or if an external tool created auxiliary files.

### Safe Next Steps
1. **Protected Behavior**: Kasumi treats unknown objects as protected. Neither `sync` nor `gc` will delete or overwrite unknown objects.
2. **Inspect Remote Objects**:
   ```bash
   kasumi remote objects <profile>
   ```
   Examine the listed paths.
3. **Do Not Store Non-Kasumi Files in the Vault**: Ensure the remote directory specified in `config.toml` is dedicated exclusively to the Kasumi vault. Do not store external files, manual backups, or third-party files in the same directory.
4. If you intentionally placed external files in the vault root, move them to a separate storage location.

### Related Documentation
* [Remote Layout and Publication](architecture/remote-layout.md)
* [Physical and Maintenance Inspection](architecture/remote-maintenance-inspection.md)

---

## Differences Between Diagnostic Commands

The table below clarifies the purpose and operational behavior of Kasumi's diagnostic and inspection commands:

| Command | Purpose | Content payload audit | Transaction recovery | Same-machine profile lock | Concurrent remote writers |
|---|---|---|---|---|---|
| `kasumi status <profile>` | Preview pending changes | No | No | Exclusive | Point-in-time observation |
| `kasumi sync <profile> --dry-run` | Preview pending changes | No | No | Exclusive | Point-in-time observation |
| `kasumi fsck <profile>` | Audit referenced payloads | Yes | Yes | Exclusive | Audit may overlap writers |
| `kasumi gc <profile>` | Storage reclamation | Reachability-only (zero orphan payload GETs) | Yes | Exclusive | Barrier plus writer/ownership checks; not distributed exclusion |
| `kasumi gc remove-writer <profile> <writer-id>` | Remove one explicitly selected writer marker | No | No | Exclusive | Operator verifies liveness; other markers still block GC |
| `kasumi gc remove-barrier <profile> --confirm-abandoned` | Remove an abandoned maintenance barrier | No | No | Exclusive | Operator verifies liveness; breaks deadlock with coexisting writers |
| `kasumi remote health <profile>` | Operational diagnostic | No | No | None | Point-in-time observation |
| `kasumi remote contents --audit <profile>` | Audit all physical payloads | Yes (all present) | No | None | Point-in-time observation |
| `kasumi remote summary <profile>` | Overview of vault state | No | No | None | Point-in-time observation |

The exclusive lock prevents another normal application command using the same profile on this machine from running concurrently. Remote inspection does not take that lock; it can observe changing remote state. Fsck and GC run pending Sync transaction recovery first, which may change local files or complete remote publication. Manual writer removal takes the local lock but does not run recovery or acquire a remote barrier; the operator must verify that the associated process is inactive. Fsck's audit itself does not intentionally modify remote objects. GC modifies remote objects only after its barrier, probe, single authenticated observation, and global plan validation pass.

Fsck counts distinct payloads referenced by the effective current tree; physical
content inspection can include retained historical versions. Neither count is
the total number of protocol objects. `remote summary` missing/orphan counters
can also reflect the initial observation before the private history cache adds
older Commits; use `remote contents`, `remote health`, and `remote orphans` for
their respective inventories. A cached head can display zero parents/time in
`remote heads` without being genesis; `remote commit <profile> <id>` inspects
complete retained metadata. See [History Inspection](architecture/remote-history-inspection.md).
