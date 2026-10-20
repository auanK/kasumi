# Local Persistent State

Each machine keeps private, **unsynchronized** profile state under Kasumi's application data root. It is local trust and recovery context, not the remote vault's source of truth. [Application and Runtime](application-and-runtime.md) explains path resolution and locking; [Security](../security.md) owns permissions, key derivation, and at-rest limitations. File names below are local, not remote object identifiers.

## Artifacts and owners

| Artifact | Role, reads/writes, and failure boundary |
|---|---|
| `config.toml` | Profile configuration (paths and retention), owned by `config`; read during profile resolution, atomically rewritten for create/edit/rename/delete. It is **not** a synchronized Snapshot or accepted history. Missing configuration allows an empty `config` list/create flow but prevents ordinary profile resolution; malformed configuration is an error. It relies on private filesystem permissions, not encryption. |
| `profiles/<profile>/key.bin` | Vault credential material, written at profile creation and read by routine operations unless a supplied key is used. The persisted key is **reversibly XOR-masked**, not cryptographically encrypted; permissions limit other-user access. A missing file requires the original explicit master key, and a supplied key must match any persisted key. It cannot be reconstructed safely from remote ciphertext or SQLite. |
| `profiles/<profile>/db.sqlite` | SQLite owner of accepted `StoredState` plus the file-hash cache. Profile creation initializes the current schema before saving profile configuration. Operations validate an existing database read-only before resolving credentials or opening transport; a missing, corrupt, or unsupported database is rejected without recreation. WAL sidecars can exist. Database contents are not encrypted/authenticated as a whole; private permissions (and optional disk encryption) are the at-rest boundary. Invalid schema or accepted-state corruption is not silently rebuilt as an empty base for Sync/Preview/Status. |
| `profiles/<profile>/transaction.bin.enc/` | [Authenticated journal directory](transaction-journal.md): immutable encrypted `snapshot.enc`, encrypted deltas in `transaction.log.enc`, authenticated `confirmed.enc` selecting the durable prefix, and `retired.enc` authorizing cleanup of that generation. It governs the unfinished Sync's pinned plan, phase, and progress. Sync, Fsck, `resolve-missing`, and a reconnected GC read it during recovery. Invalid authority or missing confirmed bytes stop recovery and preserve evidence. Session caches are accelerators, not authority; clear requires verified rollback or terminal cleanup. |
| `profiles/<profile>/.transactions/<id>/` | Transaction staging and pre-mutation backups, addressed by journal ID and operation backup slots. These workspace files are not uniformly encrypted; private filesystem access controls matter. Recovery validates paths and required backup hashes. A missing/invalid required backup blocks rollback rather than risking overwrite. Completed work removes the workspace before deleting the journal. |
| `profiles/<profile>/inspection-history-v1.cache` | Optional authenticated, **unencrypted** decoded Commit-history acceleration for complete-history `remote ...` queries. It is neither accepted `StoredState` nor transaction authority. Inspection may read it when a local database exists and save it for a suitable single-head complete history; bad/stale cache or failed merge falls back to cold authenticated remote observation. It can be discarded and rebuilt. |
| `profiles/<profile>/fsck_checkpoint.bin.enc` | Optional encrypted/authenticated Fsck progress metadata, written best-effort during/after payload audits and matched to vault identity. Missing, stale, mismatched, or corrupt data is ignored for audit decisions. Even a matching entry/provider physical SHA-256 **never skips** current payload download and authentication; it can be rebuilt by Fsck. |
| `profile-<name>.lock` at the application data root | OS-backed exclusive **local** profile-operation lock acquired by Sync, Preview, Status, Fsck, and GC; it serializes those processes on one machine, not different machines or `remote ...` inspection. It is a control file, not a credential/history record and not a remote writer marker. |

## SQLite's two distinct responsibilities

**Accepted reconciliation base — `StoredState`.** The complete accepted [Snapshot](data-model.md), height, logical Commit ID, physical Ciphertext ID, accepted Epoch ID/sequence, and pending materializations describe what this client last accepted. The Commit ID identifies the logical history state; the Ciphertext ID identifies its accepted encrypted variant/HEAD reference. The Epoch reference is a local continuity checkpoint, not proof of a newer state the client has never observed. Pending materializations keep accepted logical files that could not yet be installed locally, so they can later be downloaded or repaired rather than silently deleted. Sync writes a new `StoredState` **after** verified remote Commit/HEAD and any required Epoch, then prunes eligible markers and finishes transaction cleanup. A local-only Sync validates the pinned head before its SQLite commit. This state is authoritative as this client's reconciliation base, **not** as remote truth: remote history is authenticated and compared on each observation.

**File-hash cache — performance hint.** Cache rows record logical path, BLAKE3 hash, size, nanosecond modification time, and native identity components. Windows and Linux scan metadata on every observation and reuse a hash only when the uniform contract permits it. Missing identity forces content hashing. Loading errors or unusable rows disable reuse; they cannot authorize destructive operations, which receive directed content validation. Preview/Status reuse valid strong fingerprints read-only without saving cache deltas, hashing files only on cache misses or modifications. See [Local Observation](local-observation.md).

### Schema and durability

The current database requires `PRAGMA user_version=1` and the validated `nodes`,
`metadata`, `pending_materializations`, and `file_cache` schemas, including their
column and primary-key contracts. The version number alone does not establish
compatibility. Only profile creation initializes a missing database; normal
application operations reject missing or incompatible databases before opening
transport. No old-schema conversion or automatic accepted-base reset occurs.

Initialization selects WAL mode; writable state-storage connections set
`synchronous=NORMAL`, while read-only connections do not execute write PRAGMAs.
SQLite transactions protect database consistency, but NORMAL in WAL mode does
not guarantee that the latest committed transaction survives power loss. This
is separate from the journal's authenticated confirmation protocol, not an
atomic transaction spanning SQLite, user files, and remote storage. See
[SQLite's synchronous contract](https://www.sqlite.org/pragma.html#pragma_synchronous)
and [journal durability limits](transaction-journal.md).

### Cache encoding

File-cache rows use `fingerprint_kind=3`: `fp0` through `fp2` encode the native identity and `fp3` the signed nanosecond mtime as a 64-bit hex word. Unknown kinds are not trusted for hash reuse; affected files are rehashed.

Auxiliary observation-checkpoint and directory-lineage tables, if present, are ignored and preserved. New databases do not create them. Neither canonical-state validation nor cache persistence depends on those tables.

## Missing, stale, or contradictory state

| Condition | Safe interpretation |
|---|---|
| Valid current `db.sqlite` has no accepted rows | There is no local reconciliation base. Kasumi still authenticates whatever current remote history is present; absence of accepted rows does **not** assert an empty remote vault. A pending journal, if present, must be recovered first. |
| `db.sqlite` is missing, corrupt, or has an unsupported schema | Reject the profile before credential resolution or transport access. Do not recreate or reinterpret it; existing files and recovery evidence remain untouched. |
| Accepted base Commit is missing from remote history | Missing remote history with a persisted base is an error. If the base is unreachable and there is **no authenticated newer Epoch** advancing retention, report history regression. A valid Epoch advance can deliberately release the old base and force reconciliation without that base; malformed/rollback Epoch continuity still fails. |
| Hash-cache rows cannot be used | Rehash from disk; cache failure is not a synchronization result. |
| Inspection cache is stale/corrupt | Reject it and observe authenticated remote history cold; do not change accepted `StoredState`. |
| Fsck checkpoint is stale/corrupt | Ignore it for verification and audit referenced payloads again; even a valid checkpoint does not skip them. |

No cache or checkpoint can override the authenticated remote history, the accepted local base, or an active journal. Kasumi does not automatically migrate incompatible persisted formats; unsupported configuration, database, or journal data is rejected and retained for recovery or independent inspection. [Transactions and Recovery](transactions-and-recovery.md) defines when pre-operation versus committed `StoredState` is accepted after interruption; [Remote Inspection](remote-inspection.md) and [Fsck](fsck.md) define the two optional private accelerators.
