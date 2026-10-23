# Best Practices

This guide provides operational guidance and recommended habits for managing Kasumi synchronization, maintenance routines, and multi-machine setups.

## Regular Synchronization

Kasumi is a multi-master synchronization system without a central coordination server. Multiple machines synchronize independently and do not need to be online simultaneously.

* **Synchronize Frequently**: Routine, frequent synchronization keeps local and remote histories closely aligned. Small, frequent syncs minimize merge complexity and reduce the likelihood of overlapping modifications.
* **Machines Offline for Extended Periods**: A machine can remain offline indefinitely while continuing to modify files locally. When reconnecting:
  * Run `kasumi status <profile>` or `kasumi sync <profile> --dry-run` to inspect incoming changes before modifying files.
  * Run `kasumi sync <profile>` to pull remote changes, reconcile branches, and publish your local updates.
  * If the offline machine's accepted base commit has aged past the remote vault's active Epoch retention horizon, Kasumi automatically rebases observation on current authenticated history.
* **Inspect Before Large Operations**: Before performing major directory reorganizations, mass file deletions, or large imports, run `kasumi status <profile>` to ensure your local view is current with remote storage.
* **Concurrent Operation**: Kasumi does not require clients to acquire an exclusive global synchronization lock during ordinary file synchronization. Multiple clients can publish independent commits concurrently, which are reconciled during subsequent synchronizations.

## Previewing Changes

Kasumi provides non-mutating preview commands to inspect synchronization plans before applying filesystem or remote changes:

| Command | Mutates Local Files | Mutates Remote Vault | Recovers Transactions | Advances Accepted State |
|---|---|---|---|---|
| `kasumi status <profile>` | No | No | No | No |
| `kasumi sync <profile> --dry-run` | No | No | No | No |
| `kasumi sync <profile>` | Yes | Yes | Yes | Yes |

* **`kasumi status <profile>`**: Compares the local filesystem snapshot, the accepted local base state, and the authenticated remote tree, then displays the resulting synchronization plan. Use this for quick, routine inspection.
* **`kasumi sync <profile> --dry-run`**: Dispatches through the same planner as `status`, verifying prerequisites without applying changes. Use this before running automated workflows or after significant local edits.
* **Complete Plan**: Pass `--full` to display all items; the [command reference](configuration-and-usage.md#core-commands) describes truncation:
  ```bash
  kasumi status my-profile --full
  kasumi sync my-profile --dry-run --full
  ```
* **Staleness Notice**: Output from `status` or `sync --dry-run` reflects the observed state at that specific moment. If local files or remote storage change before a subsequent `kasumi sync`, the actual execution will re-observe and re-plan against current state.

For internal planning details, see [Preview and Status](architecture/planning-and-status.md).

Both previews enumerate the managed tree and read metadata, reusing persisted
BLAKE3 hashes only when the complete native fingerprint matches. Cache misses,
changed files, or insufficient identity require content hashing. An effective
ignore projection that differs from local rules uses full hashing. Preview and
Status never save cache deltas; Sync saves them on successful finalization and
independently verifies destructive local targets by content. These checks do not
provide an atomic filesystem snapshot. Diagnose slow runs with
[performance tracing](troubleshooting.md#slow-synchronization-or-preview).

## Backups

Synchronization propagates changes and deletions. Immutable history is subject
to retention and garbage collection; it does not replace an independent backup.
Keep versioned copies outside the synchronized folder and encrypted vault.

Back up synchronized files and the complete Kasumi data directory, including
`config.toml`, profile `key.bin`, accepted SQLite state, and any recovery workspace.
Take the private-state backup with Kasumi stopped so database files and WAL
sidecars are copied consistently. Preserve both Password and Password Salt
securely, and test restoration to a separate location. Do not delete accepted
state or transaction evidence merely to make a failing synchronization proceed.

## Garbage Collection

`kasumi gc <profile>` reclaims storage by directly deleting eligible orphan
Content and redundant CommitVariants while preserving required history and
Epochs. Deletions are permanent; keep independent backups.

* **Reserve a Maintenance Window**: Stop Sync on every client and run only one
  destructive maintenance or writer-removal operation at a time. Size the window
  using observed GC duration; running GC after every Sync is unnecessary.
* **Inspect Results**: Check acknowledged removals and investigate partial or
  uncertain results before retrying. A later run builds a new plan.
* **Respect Protocol Objects**: Use Kasumi's maintenance commands rather than
  treating a provider listing as a deletion list.

See [Garbage Collection Architecture](architecture/garbage-collection.md#operational-contract)
for the protocol, backend assumptions, and maintenance procedure. Use the
integrity tools below to audit payloads.

## Integrity Checks

Kasumi provides distinct tools for auditing vault integrity and remote storage health:

* **`kasumi fsck <profile>`**: Audits the observed vault structure and downloads every content payload referenced by the effective remote tree. For each referenced payload, Fsck decrypts AEAD ciphertext, verifies plaintext BLAKE3 logical hash and size against committed metadata, and verifies keyed Content ID binding. Fsck tracks progress in a private local checkpoint (`fsck_checkpoint.bin.enc`) and recovers interrupted sync transactions before auditing.
* **`kasumi remote health <profile>`**: A non-destructive operational diagnostic covering physical listing, authenticated history and Epoch reachability, content availability, writer controls, and orphan/unknown counts. It does not perform Fsck's payload audit.
* **`kasumi remote contents --audit <profile>`**: Audits and validates all **physically present** content objects in remote storage (including orphans), but without Fsck's private checkpoint or preceding transaction recovery.

| Tool | Audits Referenced Payloads | Audits Orphan Payloads | Uses Checkpoint | Runs Transaction Recovery | Modifies Remote Vault |
|---|---|---|---|---|---|
| `kasumi fsck` | Yes (full download & verify) | No | Yes | Yes | No during audit; preceding recovery may publish |
| `kasumi remote health` | No payload audit | No | No | No | No |
| `kasumi remote contents --audit` | Yes (full download & verify) | Yes | No | No | No |
| `kasumi gc` | No Fsck-style payload audit | Candidate authentication only | No | Yes | Yes: authorized direct deletions and control cleanup; preceding recovery may publish |

Fsck and GC run pending Sync transaction recovery first. Recovery may change local files or complete remote publication; Fsck's audit itself does not intentionally modify the remote vault.

Schedule `kasumi fsck` periodically (e.g., monthly) to verify that remote storage has not suffered bit rot or silent corruption.

For details, see [Fsck Architecture](architecture/fsck.md) and [Remote Maintenance Inspection](architecture/remote-maintenance-inspection.md).

## Multi-Machine Usage

Kasumi is designed for multi-machine workflows where each device publishes changes independently.

* **Independent Publication**: Machines do not communicate directly with each other; all synchronization occurs through the shared storage vault.
* **Automatic Branch Merging**: When multiple machines publish changes concurrently, Kasumi records these as concurrent branches in the history DAG. When a machine synchronizes, Kasumi identifies the best common ancestor (merge base), combines non-overlapping edits automatically, and publishes a multi-parent merge commit (`CM`).
* **Conflict Handling**:
  * **Independent Paths**: If Machine A edits `docs/notes.txt` and Machine B edits `src/main.cpp`, both changes merge cleanly without conflicts.
  * **Concurrent Edits on the Same File**:
    * If local modification time (`mtime`) is strictly newer than remote `mtime`, the local file keeps the canonical path, and the remote variant is materialized as `<path>.kasumiconflict_remote`.
    * Otherwise (including equal timestamps), the remote file keeps the canonical path, and the local file is renamed to `<path>.kasumiconflict_local` and uploaded.
  * **Remote Branch Conflicts**: When resolving multiple competing remote heads, Kasumi keeps one variant at the canonical path and preserves additional variants under `<path>.kasumiconflict_<12-char-commit-id>`.
  * **Edit vs. Deletion**: If one machine modifies a file while another deletes it, the modified content is preserved.
* **Operational Habit**: After resolving conflicts, review the files, incorporate changes into the canonical file, delete the conflict artifacts, and run `kasumi sync <profile>` to publish the resolution.

For merge rules and conflict naming, see [History and Concurrency](architecture/history-and-concurrency.md#conflict-handling).

## Credentials and Local Machine Security

Keep Password and Password Salt in a secure record; the wizard needs the exact
same pair to enroll another machine. The local `key.bin` uses reversible masking,
not password encryption at rest. Anyone who can read it can recover the vault key.
Use BitLocker on Windows or LUKS on Linux for sensitive devices, and protect the
local account: same-user processes can access its private state. See
[Security](security.md) for key derivation, filesystem permissions, and threat models.

## Upgrading Kasumi

Kasumi 0.x has no general compatibility guarantee between releases or automatic
migration of SQLite, journals, configuration, keys, or remote formats. No in-place
upgrade from **0.7.0 to 0.8.0** has been certified. Use the same release on all
clients; downgrade is not a supported recovery procedure.

Before replacing binaries:

1. Read the release notes and verify compatibility before reusing existing state.
2. Complete pending Sync/recovery with the compatible executable, then stop Sync
   and maintenance on every client using the vault.
3. Independently back up synchronized files, complete profiles/local state, and
   credentials securely; preserve access to remote data and retain the old binary.
4. Preserve journals and diagnostics for partial or uncertain operations. Never
   delete SQLite, accepted state, or recovery evidence to force initialization.

[`kasumi update`](configuration-and-usage.md#updating-kasumi) replaces only the
executable; it does not migrate data or validate cross-version compatibility.

## Automation

When running Kasumi in automated scripts, cron jobs, or task schedulers:

* **Process Exit Codes**: Handle every [documented exit code](configuration-and-usage.md#exit-codes). Code `2` means partial synchronization with pending materializations, not full success; retry once the missing content is restored. Never automatically accept those files as deletions.
* **Single-Process Profile Lock**: `status`, `sync --dry-run`, `sync`, `fsck`, and `gc` use an OS file lock (`profile-<name>.lock`). If an automated script attempts one of these operations while another holds that profile lock, it exits with code `1`. Remote inspection uses a separate path without this lock. Ensure scheduled jobs do not overlap.
* **External Scheduling**: Kasumi does not contain an internal background daemon. Use system scheduling tools:
  * **Linux**: `cron` or `systemd` timers.
  * **Windows**: Task Scheduler.
* **Concurrency Configuration**: Adjust transfer concurrency using the environment variable `KASUMI_CONTENT_CONCURRENCY` (default: 8, maximum: 16).

## Suggested Maintenance Routines

These routines serve as practical starting points. Adjust intervals according to repository size, churn rate, and storage constraints:

### Personal / Low Churn
* **Synchronization**: Run `kasumi sync` on demand or at the start/end of work sessions.
* **Integrity Audit**: Run `kasumi remote health` occasionally; run `kasumi fsck` every 1 to 3 months.
* **Garbage Collection**: Run `kasumi gc` roughly monthly or when storage reclamation is desired.

### Regular Multi-Machine Use
* **Synchronization**: Run `kasumi sync` regularly (e.g., every 1 to 4 hours via automated scheduler).
* **Pre-Sync Checks**: Use `kasumi status` or `kasumi sync --dry-run` before applying unusually large changes.
* **Integrity Audit**: Schedule `kasumi fsck` monthly.
* **Garbage Collection**: Schedule `kasumi gc` weekly during off-hours maintenance windows. Frequency and timing are recommendations; maintenance exclusivity is required.

### High Churn / Large Vault
* **Synchronization**: Run `kasumi sync` frequently (e.g., hourly or continuous automated triggers).
* **Storage Monitoring**: Monitor storage usage with your backend/provider; use `kasumi remote summary` and `kasumi remote objects` to inspect history and object counts.
* **Garbage Collection**: Reserve a dedicated weekly off-hours maintenance window for `kasumi gc`. If churn is high, increase frequency based on observed storage growth and measured GC duration. Keep all Sync and maintenance processes stopped across clients while it runs.
* **Integrity Audit**: Schedule `kasumi fsck` separately during dedicated off-hours maintenance windows.

## Things Not To Do

Avoid these operational anti-patterns:

* **Do NOT manually delete raw remote objects**: Never delete files directly in the remote storage directory using cloud consoles, SFTP clients, or `rclone delete`. Kasumi manages object reachability, Epoch anchors, and retention internally; deleting files manually can cause missing-content errors and break history continuity.
* **Do NOT replace binaries during an unfinished transaction**: Complete recovery before replacing the application binary. Never delete the journal to bypass recovery.
* **Do NOT rely on `key.bin` for offline protection without Full-Disk Encryption**: `key.bin` uses a reversible XOR mask and OS file permissions; always enable BitLocker or LUKS on devices containing sensitive profile keys.
* **Do NOT run concurrent normal application operations on the same profile**: `status`, `sync --dry-run`, `sync`, `fsck`, and `gc` use the local exclusive `profile-<name>.lock`. `remote ...` inspection does not acquire it and reports a point-in-time view.

