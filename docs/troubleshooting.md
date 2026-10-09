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
At the start of `sync`, `fsck`, or `gc`, Kasumi may report a recovery conflict or indeterminate recovery diagnostic. The detail depends on the journal and observed remote state.

### Likely Meaning
A prior synchronization was interrupted before completion (due to network disconnection, power outage, process termination, or SIGINT). Kasumi detected the encrypted local transaction journal (`transaction.bin.enc` and `.transactions/<id>`).

### Safe Next Steps
1. **Automatic Evaluation**: Kasumi evaluates the journal automatically whenever `kasumi sync`, `kasumi fsck`, or `kasumi gc` runs. (Read-only operations like `status` and `remote ...` do not run recovery.)
2. Depending on the checkpointed transaction phase:
   * **Pre-publication interruptions**: Kasumi may roll back local mutations from staged backups or resume only when pinned inputs still match.
   * **Post-publication interruptions**: Kasumi verifies the published Commit and HEAD marker before advancing local state; contradictory state stops recovery.
3. **If Recovery Reports Indeterminate**: Remote transport uncertainty can prevent Kasumi from confirming publication. Check network connectivity and storage backend availability, then rerun `kasumi sync <profile>`.
4. **Never Manually Delete `transaction.bin.enc`**: The journal contains references to staged backups needed to restore local files. Deleting the journal manually can leave local files in a corrupted state.

### Related Documentation
* [Transactions and Recovery Architecture](architecture/transactions-and-recovery.md)
* [Interruption and Recovery](configuration-and-usage.md#interruption-and-recovery)

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
The synchronization was a non-fatal **partial synchronization**. Remote commit metadata and history were successfully accepted and recorded, but one or more file payloads could not be downloaded or were missing from remote storage.

### Safe Next Steps
1. **Treat Exit Code 2 as Non-Fatal**: In automated scripts or pipelines, exit code `2` indicates that metadata was updated, but content downloads are deferred until payloads become available.
2. **Identify Pending Files**: Run `kasumi status <profile>` or `kasumi status <profile> --full` to inspect the list of pending paths.
3. **Trigger Payload Upload from Source Client**: If another machine originally created or modified the pending files, ensure that machine runs `kasumi sync <profile>` to upload the required payloads.
4. **Subsequent Synchronization**: Once the missing content objects are present on remote storage, the next `kasumi sync <profile>` will download and materialize the files automatically.

### Related Documentation
* [Reconciliation and SyncPlan](architecture/reconciliation.md)
* [Synchronization Architecture](architecture/synchronization.md)

---

## Missing Remote Payload or Corrupt Content

### Symptom
Running `kasumi fsck <profile>` reports an audit failure for missing or corrupted referenced content. The diagnostic includes affected paths; its detail depends on the failure.

### Likely Meaning
A content payload referenced by the history DAG is absent from remote storage or failed cryptographic authentication (AEAD decryption failure or BLAKE3 plaintext hash mismatch).

### Safe Next Steps
1. Run `kasumi fsck <profile>` to audit the full vault and determine all affected paths.
2. Run `kasumi remote contents --audit <profile>` to inspect physical content states across the entire vault.
3. **Repair from Intact Client**: If an intact version of the affected file exists locally on any client machine:
   * Verify the file content on that machine.
   * Run `kasumi sync <profile>` from that machine. Kasumi will detect the missing remote payload, upload the local file bytes, and repair remote storage without changing logical history.
4. If the payload is permanently lost from remote storage and no client has a copy, restore the file from an external backup into the synchronized folder on one client and run `kasumi sync <profile>`.

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

## Fsck Failure

### Symptom
Running `kasumi fsck <profile>` fails with an audit diagnostic for affected paths. The English presenter introduces the detail with `Audit finished with failures:`.

### Likely Meaning
Fsck downloaded and audited content objects referenced by the effective remote tree, but found missing payloads, corrupted bytes, or AEAD decryption errors.

### Safe Next Steps
1. **Review Fsck Output**: Examine the specific paths and Content IDs reported as failing.
2. **Check Other Clients**: If another client has the intact files, running `kasumi sync` from that client can upload the missing payloads and restore remote integrity.
3. **Run Remote Content Audit**: Run `kasumi remote contents --audit <profile>` to audit physically present content objects, including orphans.
4. **Restore Missing Files**: If objects are permanently corrupted or missing from remote storage and no client has a local copy, restore the affected files from an external backup into the local synchronized folder on one machine, then run `kasumi sync <profile>`.

### Related Documentation
* [Fsck: Integrity Audit](architecture/fsck.md)
* [Effective Tree and Content Inspection](architecture/remote-content-inspection.md)

---

## GC Refusing Destructive Operation / Analysis-Only Result

### Symptom
Running `kasumi gc <profile>` can return an `analysis_only` result with an English warning that no candidate objects were moved. If writer markers block GC, its failure detail reports active or abandoned writers.

### Likely Meaning
Kasumi's garbage collector enforces strict safety conditions before performing destructive quarantine or purge operations:
* **Writer Marker Detected**: Any observed writer marker blocks maintenance, including one left behind by a client that is no longer running. A marker does not prove its originating process is alive.
* **Visibility Probe Failure**: The storage provider did not show consistent visibility during probe checks (e.g., temporary object listing inconsistency).
* **Observation Discrepancy**: Successive listings of the physical namespace did not agree.
* **Epoch Continuity**: History or Epoch anchors could not be validated.

### Safe Next Steps
1. **Understand Safety Behavior**: `analysis_only` means GC did not restore quarantine, remove candidates, or purge objects. The maintenance barrier and visibility probe may already have been created and cleaned up remotely.
2. **Inspect Writer Markers**:
   ```bash
   kasumi remote writers <profile>
   ```
   If you know another client is synchronizing, wait for it to finish. Before removal, verify that no Sync or maintenance operation is running; the barrier check is not distributed exclusion. Then copy only that writer's exact identifier and run `kasumi gc remove-writer <profile> <writer-id>`. Kasumi cannot establish process liveness; removal is the operator's responsibility. The command removes only the selected marker and does not run GC.
3. **Inspect Remote Health**:
   ```bash
   kasumi remote health <profile>
   ```
4. **Retry in a Quiet Maintenance Window**: Rerun `kasumi gc <profile>` during a low-activity window when no clients are synchronizing.
5. **Keep Normal GC Checks**: Retry normal `kasumi gc <profile>` after the marker is removed. Any other writer marker continues to block destructive GC.

### Related Documentation
* [Garbage Collection Architecture](architecture/garbage-collection.md)
* [Physical and Maintenance Inspection](architecture/remote-maintenance-inspection.md)

---

## Manual Quarantine Purge or Repair

### Symptom

A quarantine entry remains after normal `kasumi gc <profile>`, or a failed operation has left metadata without a corresponding quarantine payload.

### Safe Next Steps

1. Inspect the state with `kasumi remote quarantine <profile>` and `kasumi remote health <profile>`; use `kasumi fsck <profile>` if referenced content may be missing or corrupt.
2. Prefer rerunning normal `kasumi gc <profile>` after investigating writer markers, retention and backend visibility. A normal analysis-only result is not permission for manual deletion.
3. `kasumi gc repair-quarantine <profile> --confirm-permanent-loss` is for eligible **metadata-only** quarantine remnants. It does not restore any file, content object or missing ciphertext. Ambiguous and invalid quarantine state is rejected.
4. `kasumi gc purge-quarantine <profile> --confirm-permanent-loss` permanently removes authenticated quarantine entries **without the normal retention/reachability safety decision**. This can destroy the only copy of content still referenced by history. Use it only after explicitly deciding to accept that permanent loss and preserving any recoverable independent copies.
5. Never modify quarantine objects, markers or Epoch data directly through the cloud provider.

The confirmation flag only records deliberate operator intent. It does not guarantee that the deleted data is unnecessary.

### Related Documentation

* [Garbage Collection Architecture](architecture/garbage-collection.md)
* [Remote Quarantine Inspection](architecture/remote-maintenance-inspection.md)

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
| `kasumi gc <profile>` | Storage reclamation | No Fsck-style audit | Yes | Exclusive | Barrier blocks collection if any writer marker exists |
| `kasumi gc remove-writer <profile> <writer-id>` | Remove one explicitly selected writer marker | No | No | Exclusive | Operator verifies liveness; other markers still block GC |
| `kasumi remote health <profile>` | Operational diagnostic | No | No | None | Point-in-time observation |
| `kasumi remote contents --audit <profile>` | Audit all physical payloads | Yes (all present) | No | None | Point-in-time observation |
| `kasumi remote summary <profile>` | Overview of vault state | No | No | None | Point-in-time observation |

The exclusive lock prevents another normal application command using the same profile on this machine from running concurrently. Remote inspection does not take that lock; it can observe changing remote state. Fsck and GC run pending Sync transaction recovery first, which may change local files or complete remote publication. Manual writer removal takes the local lock but does not run recovery or acquire a remote barrier; the operator must verify that the associated process is inactive. Fsck's audit itself does not intentionally modify remote objects. GC may transfer encrypted candidate bytes through a local workspace for quarantine verification without performing Fsck's plaintext audit.

* Use **`status`** to see what will change locally and remotely.
* Use **`remote health`** for an operational diagnostic without Fsck's payload audit.
* Use **`fsck`** to verify payload authenticity and detect missing files.
* Use **`gc`** to reclaim remote disk space.
