# Incremental transaction journal

The corrected 0.7.0 journal is incompatible with every preceding development
journal format. There is one supported format, with no legacy reader, migration,
fallback or downgrade. An incompatible journal stops recovery and retains its
artifacts.

The profile's private `transaction.bin.enc` directory contains:

| Artifact | Authority |
| --- | --- |
| `snapshot.enc` | Immutable KTX3 AEAD snapshot, containing the current transaction codec v9 record |
| `transaction.log.enc` | KTD3 AEAD deltas, numbered from zero and chained from the snapshot ciphertext hash |
| `confirmed.enc` | KTC3 authenticated confirmation: snapshot hash, committed log length, delta count and terminal chain hash |
| `retired.enc` | KTQ3 authenticated authorization to clear the same confirmed generation |
| `*.new` | Unconfirmed temporary output; never replay authority |

A checkpoint writes, flushes, closes and syncs its delta. It then writes, flushes,
closes and syncs a new confirmation, atomically replaces `confirmed.enc`, and syncs
the directory. Initial creation also syncs the profile directory. Success is
reported only after those operations succeed. An interrupted confirmation replace
may leave either the preceding or the new authenticated confirmation; an operation
whose caller saw an error may therefore have committed.

Recovery authenticates the confirmation and snapshot, then replays exactly the
confirmed byte prefix. Sequence, hash chain, AEAD, bounded fields and each delta's
semantics are checked. Missing confirmed bytes, including a complete removed
suffix, are errors. Bytes after the confirmed prefix never affect recovery. Load
retains that unconfirmed tail; a verified retry must truncate and sync it before
appending. This distinction does not determine whether those extra bytes came
from an interrupted writer or deliberate tampering.

There is no session cache. Every save reconstructs authenticated persisted state;
failed sync never means that bytes are absent. An equal-state retry re-establishes
durability without adding another sequence number. Concurrent calls serialize;
stale checkpoints that regress phase or progress are rejected. The Coordinator's
profile lock provides process ownership. `SaveMode::Rollback` explicitly permits
a full reset to Started/Pending, or local-only recovery's return of restored local
operations to Prepared/FilesStaged. Ordinary saves cannot request those reversions.
All changed publication, Epoch,
pending-path and progress fields are encoded explicitly.

An active snapshot is never replaced. A different operation ID or immutable
plan, generation, publication requirement or observed identity is rejected.
Changing generations requires successful recovery and clear first. Snapshot and
confirmation hashes prevent mixed generations; deltas bind the snapshot chain
and operation ID. Restoring an older valid confirmation together with its matching
log prefix, or erasing the complete authority bundle, cannot be detected without
an independent external authority.

Clear requires the key, validates the confirmed record and permits only
CleanupCompleted or a complete Started/Pending reset. It durably writes
`retired.enc` before atomically renaming the directory to
`transaction.bin.enc.cleared`, syncing its parent and deleting other artifacts.
The proof survives partial deletion; remaining snapshots, logs and confirmations
must match its generation. A directory name alone never authorizes deletion.
After syncing removal of the other files, clear removes the proof last, syncs
that removal and removes the empty directory. Errors remain errors; authenticated
retirement can be completed on restart. Only an empty retired directory can be
removed without a remaining proof. The Coordinator calls clear after rollback
or terminal cleanup, never to abandon unapplied effects.

Snapshot payloads are limited to 64 MiB; log files to 128 MiB; replay to one million
deltas. Codec fields and counts have independent bounds, and counts must fit the
remaining input before allocation. Plaintext buffers and derived keys have scope
guards. Symlinks and unexpected files/directories are rejected, and profile
storage is restricted to its owner. As elsewhere in the platform filesystem API,
path inspection and stream opening are separate operations: protection assumes
a trusted profile owner and its process lock, not a hostile process running as
the same OS account.

Logical writes are O(N + changed data), with 124 confirmation bytes per checkpoint
in addition to the 88-byte delta header, plus one 124-byte retirement proof per
transaction. Durable synchronization count is O(N).
One replay costs O(snapshot size + confirmed log size + decoded state). An owned
Session caches a confirmed Record and Tip. Every save still performs the complete
codec validation and immutable identity comparison: a mutable caller's Record
cannot be trusted from an old pointer or fingerprint. Computing the delta scans
progress once; advance monotonicity checks only its changed entries. These O(N)
scans retain potential O(N²) accumulated CPU for N checkpoints.

A normal confirmed session verifies every path, key identity, authenticated KTC3
and artifact fingerprints/sizes before appending. Fingerprints use file ID and
change time on Windows, device/inode/ctime on Linux. Unsupported identities use
full authenticated replay. Discrepancies invalidate the cache and require replay;
missing/truncated confirmed bytes fail closed. Checks occur before private-storage
validation changes ACL/ctime itself. This detects known discrepancies under the
profile lock and trusted owner model, not every hostile same-account alteration
that preserves metadata or restores a complete older authority bundle.

The delta owns its changed fields before confirmation. Persistence takes the
previous Record by const reference and returns only confirmed Tip and changes.
After confirmation, the same prepared changes used by replay are moved/swapped
into the cached Record without allocating or copying the plan. Any post-confirmation
failure invalidates the cache; durable authority remains and equal-state retry
reauthenticates and syncs without duplicating sequence. Fresh initialization copies
the Record once; load may copy once to give the caller a separate Record. Session
internals are private and retirement cannot be reversed on that instance. The
requested Record must be owned independently; aliasing the cached Record is
rejected before invalidation can release its storage.

Linux uses file and parent-directory fsync. Windows uses FlushFileBuffers and
MoveFileEx with WRITE_THROUGH; its platform parent-directory sync is a no-op.
These are the supported platform primitives, not proof of equivalent power-loss
behavior on all filesystems or hardware. Fault builds test real process exits,
partial writes and reported I/O failures; `_Exit` does not simulate power loss.

Download candidate ownership: the exact sibling
`.filename.kasumi-new-<workspace basename>-<operation index>` belongs to the
transaction once BackupCreated is confirmed. Coordinator workspaces use the
authenticated operation ID as their basename. Apply rejects existing candidates.
Rollback removes only this exact regular file, even if interrupted decrypt left
partial bytes; unexpected types/symlinks fail and similar names are untouched.
Pending/Prepared states do not authorize deletion. Parent removal is synced.
No recursive user-directory removal, wildcard matching or legacy random-name
compatibility is allowed. This retains the trusted-owner/process-lock boundary.
