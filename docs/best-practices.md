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
* **Plan Truncation & `--full`**: When a synchronization plan contains more than 10 items, Kasumi truncates output to show the first 5 and last 5 items (separated by an ellipsis line) to avoid terminal overflow. Pass `--full` to display all items:
  ```bash
  kasumi status my-profile --full
  kasumi sync my-profile --dry-run --full
  ```
* **Staleness Notice**: Output from `status` or `sync --dry-run` reflects the observed state at that specific moment. If local files or remote storage change before a subsequent `kasumi sync`, the actual execution will re-observe and re-plan against current state.

For internal planning details, see [Preview and Status](architecture/planning-and-status.md).

## Garbage Collection

Garbage collection (`kasumi gc <profile>`) reclaims remote storage occupied by unreachable objects, such as obsolete commit variants, history outside retained Epoch anchors, and unreferenced content payloads.

* **GC is NOT Fsck**: Garbage collection manages reachability, retention, and quarantine; it does **not** perform Fsck-style cryptographic payload auditing. Depending on transport capabilities, quarantine staging may transfer encrypted candidate bytes through a local workspace to verify physical-byte preservation. Running GC does not prove payload integrity.
* **GC is Operationally Expensive**: GC coordinates through a distributed remote maintenance barrier and validates provider visibility with temporary probe objects. Online collection takes **two complete, stable observations** of the physical namespace and history reachability. In large vaults or high-churn repositories, GC can take a significant amount of time and consumes substantial network I/O.
* **Plan Dedicated Maintenance Windows**: GC should be scheduled during off-peak periods or low-activity windows. Do **not** run GC after every synchronization.
* **Frequency Guidelines (Heuristics)**:
  * **Low Churn (Personal Use)**: Monthly maintenance is generally sufficient.
  * **Moderate Churn (Small Teams / Multi-Machine)**: Weekly GC is a reasonable starting policy.
  * **High Churn (Automated Pipelines / Large Vaults)**: Weekly or scheduled off-hours GC, adjusted based on measured storage growth and observed execution duration.
  * *Note*: These frequencies are heuristic recommendations, not protocol requirements. Tune frequency according to observed storage usage and provider performance.
* **Safety & Quarantine Retention**:
  * Newly identified unreachable candidates are staged into quarantine in bounded batches (up to 8 objects per batch), with physical SHA-256 verification before source removal.
  * Previously quarantined objects are **not** purged immediately on the next GC run. Purging requires at least **10 days of quarantine age** recorded in authenticated metadata, verified absence of the original, remaining unreachability, verified physical SHA-256, and active barrier ownership.
  * If provider visibility cannot support safe online collection, GC may return `analysis_only`: no quarantine restore, candidate removal, or purge occurs. The maintenance barrier and visibility probe may already have been created and cleaned up remotely. Other safety failures can stop GC with an error.
* **Do Not Manually Delete Remote Objects**: Never treat raw remote object listings (e.g., from cloud consoles or `rclone`) as deletion lists. Manual deletion can destroy active Epoch anchors or referenced content.

For the protocol specification, see [Garbage Collection Architecture](architecture/garbage-collection.md).

## Integrity Checks

Kasumi provides distinct tools for auditing vault integrity and remote storage health:

* **`kasumi fsck <profile>`**: Audits the observed vault structure and downloads every content payload referenced by the effective remote tree. For each referenced payload, Fsck decrypts AEAD ciphertext, verifies plaintext BLAKE3 logical hash and size against committed metadata, and verifies keyed Content ID binding. Fsck tracks progress in a private local checkpoint (`fsck_checkpoint.bin.enc`) and recovers interrupted sync transactions before auditing.
* **`kasumi remote health <profile>`**: A non-destructive operational diagnostic covering physical listing, authenticated history and Epoch reachability, content availability, quarantine, writer controls, and orphan/unknown counts. It does not perform Fsck's payload audit.
* **`kasumi remote contents --audit <profile>`**: Audits and validates all **physically present** content objects in remote storage (including orphans), but without Fsck's private checkpoint or preceding transaction recovery.

| Tool | Audits Referenced Payloads | Audits Orphan Payloads | Uses Checkpoint | Runs Transaction Recovery | Modifies Remote Vault |
|---|---|---|---|---|---|
| `kasumi fsck` | Yes (full download & verify) | No | Yes | Yes | No during audit; preceding recovery may publish |
| `kasumi remote health` | No payload audit | No | No | No | No |
| `kasumi remote contents --audit` | Yes (full download & verify) | Yes | No | No | No |
| `kasumi gc` | No Fsck-style payload audit | No | No | Yes | Yes during collection; preceding recovery may publish |

Fsck and GC run pending Sync transaction recovery first. Recovery may change local files or complete remote publication; Fsck's audit itself does not intentionally modify the remote vault. GC may transfer encrypted candidate bytes while staging quarantine, without auditing their plaintext.

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

Kasumi enforces client-side encryption and authentication, but operational security depends on proper credential handling and host-level protection:

* **Password & Password Salt Reproducibility**:
  * The **Password** (minimum 12 characters) and **Password Salt** (minimum 16 characters) are used by Argon2id to derive the 32-byte master key.
  * The salt is **user-provided and reproducible**, not an automatically generated random salt stored remotely.
  * Any machine connecting to the same vault must be configured with the **exact same** Password and Password Salt.
* **Local Key Storage Boundary (`key.bin`)**:
  * Once a profile is created, the derived master key is stored in `profiles/<profile>/key.bin` using a **reversible XOR mask** and restricted OS filesystem permissions (explicit DACLs on Windows, `0600`/`0700` on POSIX).
  * `key.bin` is **not** password-encrypted at rest against an attacker with physical access to the disk. An adversary with offline read access can extract the file and unmask the key without guessing the password.
* **Host Protection Recommendations**:
  * Use OS-level **Full-Disk Encryption (FDE)** to protect local profile keys and data against physical theft or offline disk inspection:
    * **Windows**: BitLocker
    * **Linux**: LUKS (`dm-crypt`)
  * Keep the local operating system updated. Operating system permissions prevent unprivileged accounts on the same machine from accessing `key.bin`, but processes executing under your local user account inherit full access.

For cryptographic algorithms and threat models, see [Security Specification](security.md).

## Upgrading Kasumi

Kasumi follows a strict pre-1.0 release policy:

* **Review Release Compatibility**: Read release notes and compatibility information before replacing binaries.
* **Pre-1.0 Compatibility Boundary**: Before version 1.0, internal persisted formats (such as local SQLite database schemas, transaction journals, or internal protocol layouts) are **not** guaranteed to remain compatible across releases.
* **Complete In-Flight Operations**: Complete active synchronizations and transaction recovery before replacing binaries. Never delete transaction journals to bypass recovery.
* **No Automatic Migration Machinery**: Kasumi does not provide automatic migration scripts or legacy compatibility readers for incompatible persisted formats.

## Automation

When running Kasumi in automated scripts, cron jobs, or task schedulers:

* **Process Exit Codes**:
  * **`0`**: Success. The operation finished cleanly.
  * **`2`**: Partial synchronization with pending materializations. Synchronization accepted remote metadata into history, but one or more file payloads could not be downloaded or are temporarily unavailable on remote storage. Automated workflows should treat exit code 2 as a non-fatal condition; pending materializations will be downloaded on a subsequent sync once payloads become available.
  * **`1`**: Hard failure (e.g., network failure, storage inaccessible, permission denied, cryptographic failure, or profile lock error).
  * **`130`**: Process terminated by user cancellation (SIGINT / SIGTERM).
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
* **Garbage Collection**: Schedule `kasumi gc` weekly during off-hours maintenance windows.

### High Churn / Large Vault
* **Synchronization**: Run `kasumi sync` frequently (e.g., hourly or continuous automated triggers).
* **Storage Monitoring**: Monitor storage usage with your backend/provider; use `kasumi remote summary` and `kasumi remote objects` to inspect history and object counts.
* **Garbage Collection**: Reserve a dedicated weekly off-hours maintenance window for `kasumi gc`. If churn is high, increase frequency based on observed storage growth and measured GC duration.
* **Integrity Audit**: Schedule `kasumi fsck` separately during dedicated off-hours maintenance windows.

## Things Not To Do

Avoid these operational anti-patterns:

* **Do NOT manually delete raw remote objects**: Never delete files directly in the remote storage directory using cloud consoles, SFTP clients, or `rclone delete`. Kasumi manages object reachability, Epoch anchors, and retention internally; deleting files manually can cause missing-content errors and break history continuity.
* **Do NOT modify quarantine objects through the provider**: Normal `kasumi gc` applies its 10-day retention and verification checks; deleting quarantine files directly can corrupt maintenance state. `kasumi gc purge-quarantine <profile> --confirm-permanent-loss` is an explicit last-resort command that bypasses normal retention/reachability checks and may permanently delete referenced data.
* **Do NOT assume GC replaces Fsck**: GC verifies physical-byte preservation with SHA-256, but does **not** perform Fsck-style cryptographic plaintext integrity auditing.
* **Do NOT replace binaries during an unfinished transaction**: Complete recovery before replacing the application binary. Never delete the journal to bypass recovery.
* **Do NOT rely on `key.bin` for offline protection without Full-Disk Encryption**: `key.bin` uses a reversible XOR mask and OS file permissions; always enable BitLocker or LUKS on devices containing sensitive profile keys.
* **Do NOT run concurrent normal application operations on the same profile**: `status`, `sync --dry-run`, `sync`, `fsck`, and `gc` use the local exclusive `profile-<name>.lock`. `remote ...` inspection does not acquire it and reports a point-in-time view.

