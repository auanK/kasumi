# Application and Runtime

The CLI handles profile management, application operations, and remote
inspection. Application operations include Sync, Preview, Status, Fsck, Garbage
Collection, Repack, Resolve Missing, and manual writer/barrier removal. Preview
and Status share a planner; remote inspection has a separate flow. The CLI
selects language from a global `--lang <code>` prefix, recognizes `--full`
on `sync`, `status`, `repack`, `show`, and `remote summary`,
installs interruption handlers, obtains environment credentials, and presents
results and errors. Syntax and environment variables are in
[Configuration and Usage](../configuration-and-usage.md).

## Profiles and Resolution

The execution environment supplies an application data root. By default this is `%APPDATA%/kasumi` on Windows or `$XDG_CONFIG_HOME/kasumi` (falling back to `$HOME/.config/kasumi`) on Linux; if unavailable, Kasumi uses `.kasumi_data` under the current directory. `config.toml` contains named profiles with an absolute local directory, a local path or rclone remote destination, positive retention depth and age, and `key_storage` (`vault`, `file`, or `memory`). Profile names are restricted to letters, digits, `_`, and `-`; resolved state paths must remain beneath `profiles/`.

`kasumi config`, `kasumi profile ...`, `kasumi conflicts <profile>`, `kasumi completion <shell>`, and `kasumi key <profile>` manage local configuration, read-only local conflict inspection, shell completions, OS credential vault entries, and isolated private profile directories, without changing synchronized or remote data. Their validation, list/create/clone/edit/key/storage/rename/delete ordering, rollback behavior, and key lifecycle are in [Profile Management](profile-management.md); key protection limits are in [Security](../security.md).

Before an application operation, runtime resolution validates the profile and paths. Sync and ResolveMissing use writable resolution, which can create a missing local directory and private profile directory; other operations use read-only path resolution. The application validates retention settings, takes an exclusive `profile-<name>.lock`, and validates the existing SQLite schema read-only before resolving credentials or opening transport. A missing, corrupt, or unsupported database is rejected without recreation. It then resolves the master key according to `key_storage` (`vault` OS credential vault, `file` `key.bin`, or `memory` runtime prompt / `KASUMI_PASSWORD` + `KASUMI_PASSWORD2`) or `KASUMI_MASTER_KEY`, and opens a local or rclone [transport](transport.md). When a profile has a persisted key (`vault` or `file`), any supplied `KASUMI_MASTER_KEY` must agree with it. The lock serializes operations on one local profile, not clients on separate machines. On exit, transport state closes, the lock releases, and key/credential buffers are wiped at defined cleanup points.

## Local Persistent State

The private profile directory contains distinct credential, accepted-state, cache, and recovery artifacts. [Local Persistent State](local-state.md) owns their exact roles, failure/fallback rules, and write ordering; [Security](../security.md) owns filesystem and cryptographic protection limits. In particular, SQLite `StoredState` is the accepted **local reconciliation base**, not remote truth, while the [transaction journal](transactions-and-recovery.md) governs an unfinished Sync.

`sync` alone owns normal file-hash cache updates and accepted-state commits. `application::execute` records local execution metadata (`local_executions` in schema v2, marking stale `InProgress` rows from crashed runs as `Interrupted`), updates `accepted_commit_meta` on sync/repack/resolve-missing acceptance, and publishes best-effort encrypted `KACT` v1 records for maintenance operations (`fsck`, `gc`, `remove-writer`, `remove-barrier`), emitting a stderr warning and keeping `remote_publish_state = Pending` if remote activity upload fails without rolling back a completed operation. [Preview and Status](planning-and-status.md) report a plan without execution or recovery. [Fsck](fsck.md) and [Garbage Collection](garbage-collection.md) first run transaction recovery, which may have local or remote effects; GC then deletes only stable authenticated candidates. [Micro-Pack Repack](repack.md) (`repack`) requires a clean synchronized workspace: `--dry-run` inspects the journal read-only without mutating local or remote state, whereas a real run runs preceding recovery (refusing resumable uploads) and, when publishing consolidated packs, updates SQLite `StoredState` (`StorageManifest` + commit ID) and cache deltas without modifying synchronized files. [Remote Inspection](remote-inspection.md) reads authenticated remote state without modifying accepted history, `remote_activity_cache`, or the local workspace, and `remote get` writes the chosen destination.

`resolve-missing` also runs recovery, then uses the synchronization coordinator
to publish validated logical deletions and accept their state. It is an explicit
data-loss decision, not a repair. Manual writer and barrier removal use their own
maintenance paths; see the
[command reference](../configuration-and-usage.md#partial-synchronization-and-explicit-data-loss-operations).
