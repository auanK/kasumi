# Profile Management

`kasumi config` is the interactive CLI for listing, creating, editing, renaming, and deleting profiles. It changes local configuration and private profile storage, **not** the synchronized directory or remote vault. The wizard's prompts and accepted locations are in [Configuration and Usage](../configuration-and-usage.md); [Application and Runtime](application-and-runtime.md) owns runtime resolution and private-state layout.

## Ownership and credentials

`config.toml` at the application data root owns named profiles: absolute synchronized `local_dir`, local or rclone `remote_dir`, and positive history-retention depth/age. Each profile has a separate `profiles/<name>/` private directory, `key.bin`, SQLite state, and local operation lock. A profile name must be safe for a child of `profiles/`. Configuration is saved by atomic private-file replacement; loading it may enforce owner-focused permissions. These config actions do not take the application's per-profile operation lock, so concurrent config edits are not a serialized read-modify-write transaction. Separate profiles do not implicitly share an accepted base or key; to use one vault on another machine, configure the same remote destination and master key. Creating a profile does not publish remote history.

The creation API accepts either a 32-byte master key encoded as hex or a Password/Password Salt pair; the interactive wizard prompts for the pair and derives the key with Argon2id. It writes `key.bin` using reversible masking plus filesystem access controls, **not** encryption at rest. Routine operations read `key.bin` or a matching `KASUMI_MASTER_KEY`; passwords are not rederived or checked after creation. See [Security](../security.md).

## Operation flows

| Action | Validation, state transition, and failure boundary |
|---|---|
| List | Load and parse `config.toml`, return its profiles; a missing file means an empty list, while malformed configuration is an error. No key, transport, local tree, or remote object is opened. |
| Create | Validate name, retention, absolute local path, and remote location; derive/decode the key; load configuration and reject a duplicate name or pre-existing private directory/key; create the private directory, write `key.bin`, then persist the new configuration. A failed key/configuration write attempts to remove newly created private state; credentials and temporary key bytes are wiped. No synchronized directory is initialized and no remote object is published. |
| Edit | Validate the new absolute local path and remote location; find the named entry, change only `local_dir` and `remote_dir`, then save configuration. Name, retention fields, and key stay as they were. It does not move either the existing synchronized directory or private state, rekey the vault, or validate that the new remote contains matching history. Missing/malformed configuration, absent profile, or failed save stops the edit. |
| Rename | Validate the new name, reject a duplicate name or occupied target private path, resolve both private paths, move the existing private directory if present, then save the renamed configuration. If saving fails, it attempts to move the private directory back and reports a rollback failure if that also fails. The key and SQLite state move with the directory; synchronized and remote paths do not move. |
| Delete | Remove the entry from configuration and save it first, then remove its private profile directory (including key, state, journal, and caches). If private removal fails, it attempts to restore the original configuration and reports a rollback failure if necessary. It does **not** delete the synchronized local directory or remote objects. |

Profile-management actions do not enter the Sync transaction recovery, [Fsck](fsck.md), or [Garbage Collection](garbage-collection.md) flows. Editing a destination or deleting a key can make later access to a vault impossible unless the original key and destination are retained elsewhere; it is not a remote migration or remote delete operation.
