# Application and Runtime

The CLI parses an invocation into a profile-management action, one of five `application::Operation` values, or an `InspectionOperation`. `application::execute` dispatches Sync, Preview, Status, Fsck, and GarbageCollect; Preview and Status use the same planner and return a `PlanReport`. Remote inspection has a separate read-oriented dispatch. The CLI selects language, strips the display-only `--full` switch, installs interruption handlers, obtains environment credentials, and presents typed results and errors. Syntax and environment variables are in [Configuration and Usage](../configuration-and-usage.md).

## Profiles and Resolution

The execution environment supplies an application data root. By default this is `%APPDATA%/kasumi` on Windows or `$XDG_CONFIG_HOME/kasumi` (falling back to `$HOME/.config/kasumi`) on Linux; if unavailable, Kasumi uses `.kasumi_data` under the current directory. `config.toml` contains named profiles with an absolute local directory, a local path or rclone remote destination, and positive retention depth and age. Profile names are restricted to letters, digits, `_`, and `-`; resolved state paths must remain beneath `profiles/`.

`kasumi config` manages the local configuration and isolated private profile directories, without changing synchronized or remote data. Its list/create/edit/rename/delete ordering, rollback behavior, and key lifecycle are in [Profile Management](profile-management.md); key protection limits are in [Security](../security.md).

Before an application operation, runtime resolution validates the profile and paths. Sync can create a missing local directory and private profile directory; other operations use read-only path resolution. The application validates retention settings, takes an exclusive `profile-<name>.lock`, resolves `KASUMI_MASTER_KEY` or the persisted `key.bin`, and opens a local or rclone [transport](transport.md). A supplied master key must agree with the persisted profile key. The lock serializes operations on one local profile, not clients on separate machines. On exit, transport state closes, the lock releases, and key/credential buffers are wiped at defined cleanup points.

## Local Persistent State

The private profile directory contains distinct credential, accepted-state, cache, checkpoint, and recovery artifacts. [Local Persistent State](local-state.md) owns their exact roles, failure/fallback rules, and write ordering; [Security](../security.md) owns filesystem and cryptographic protection limits. In particular, SQLite `StoredState` is the accepted **local reconciliation base**, not remote truth, while the [transaction journal](transactions-and-recovery.md) governs an unfinished Sync.

`sync` alone owns normal cache/checkpoint updates and accepted-state commits. [Preview and Status](planning-and-status.md) report a plan without execution or recovery. [Fsck](fsck.md) and [Garbage Collection](garbage-collection.md) first run transaction recovery, which may have local or remote effects. [Remote Inspection](remote-inspection.md) may update its private history cache, and `remote get` writes the chosen destination.
