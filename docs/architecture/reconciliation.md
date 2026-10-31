# Reconciliation and SyncPlan

Reconciliation receives three distinct validated views: the current local `Snapshot`, the locally accepted `StoredState` tree (the **reconciliation base**), and the effective remote tree obtained by resolving authenticated history. The remote DAG may have multiple logical heads; [history resolution](history-and-concurrency.md) combines those branches before local/base/remote comparison. The base makes deletion and independent edits distinguishable. A missing local base is normal for a new profile, while loss of remote history after a base was accepted is an error. If a newer authenticated Epoch legitimately moves the retention horizon beyond the old base, observation may discard that obsolete base and rebase on current history.

The reconciler validates all input Snapshots and pending-materialization rows before computing changes. It builds a logical local view that includes accepted remote files still pending on disk, then compares local/base/remote by path. Independent edits combine; a modified file wins over deletion; incompatible file edits preserve both versions. For simultaneous local/remote file changes, the local `mtime` must be strictly newer to keep the canonical path, placing the remote variant at a conflict path. Otherwise, including equal timestamps, the remote variant keeps the canonical path and the local one is renamed and uploaded. Conflict destinations are reserved against exact and portable Unicode case-key collisions. Remote-branch conflict paths are described in [History and Concurrency](history-and-concurrency.md). Unsupported structures or unsafe paths stop planning.

The output is a `SyncPlan` plus a **candidate shared tree** and flags for local mutation, physical storage repair, publication, and local state commit. A plan contains safe relative paths, expected file hashes/sizes, a target generation, and ordered phases:

1. `RenameLocal`
2. `Upload`
3. `CreateLocalDirectory`
4. `CreateRemoteDirectory`
5. `MoveLocal`
6. `Download`
7. `DeleteLocal`
8. `DeleteLocalDirectory`
9. `DeleteRemote`
10. `DeleteRemoteDirectory`

Directory creation is parent-first and removal child-first. When a remote file or directory is renamed or moved, reconciliation deterministically pairs eligible `DeleteLocal` sources (whose `(hash, size)` matches a `Download` destination and whose source path is not retained in the candidate shared tree) 1-to-1 into `MoveLocal` (`path = source`, `alt_path = destination`, `hash`, `size`) after `CreateLocalDirectory` and before `Download` / `DeleteLocalDirectory`. When a local file or directory is renamed or moved, uploads whose `(hash, size)` is already accounted for in the accepted `StoredState` tree reuse the accepted remote content without re-uploading. The remote-directory and remote-delete actions change the logical publication tree; storage contains content-addressed payloads and history objects, not a mirrored plaintext directory. Plan validation checks phase boundaries, action grouping, and path safety before execution.

Normal planning does not perform a full physical content audit. Stabilization probes content needed for the plan, records known missing payloads, and recalculates. A compatible local file can repair missing remote content without changing the logical tree; otherwise an accepted logical file may remain as a **pending materialization** until content becomes available. The candidate shared tree describes the intended logical result; [synchronization execution](synchronization.md) validates an actual publication tree after file operations. Publication is required for initial history, multiple logical heads, or a changed shared tree. A local-only download, local move, or accepted-state advance can complete without a new Commit.
