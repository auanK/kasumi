# History DAG, Concurrency, and Retention

Remote history records publications as immutable commits. Each commit records canonical parent commit IDs, allowing clients to reconstruct ancestry and identify concurrent branches. Commits loaded from remote storage are cryptographically authenticated before resolution.

## Commit Anatomy

A `Commit` contains:

* `tree`: Canonical Merkle Snapshot of the entire synchronized directory.
* `parents`: Sorted, unique canonical commit IDs.
* `height`: Maximum height of parents + 1.
* `created_at`: Unix creation timestamp included in the authenticated commit payload.

The genesis commit, `C0`, has zero parents and height 0. Subsequent commits reference their ancestor publication(s).

## Physical HEAD Markers vs. Logical Heads

* A **Physical HEAD** is a remote protocol marker under `history/heads/` binding a commit ID to a specific ciphertext ID. It signals that this encrypted commit variant has been published.
* A **Logical Head** is a marked commit in the DAG that is not an ancestor of any other marked commit.

Ancestral physical markers may temporarily linger during pruning windows. For example, markers for `C0`, `CA`, and `CB` might coexist physically even though `C0` is already an ancestor of the other two. In this scenario, `C0` is an ancestral physical marker, while the active logical heads are `{CA, CB}`.

## Linear vs. Concurrent History

Successive serial publications form a simple chain:

```text
C0 ──> C1 ──> C2
```

When Machine A and Machine B synchronize concurrently from `C0`:
* Machine A publishes `CA`;
* Machine B publishes `CB` before observing `CA`:

```text
       CA
      /
C0 ──┤
      \
       CB
```

Each publication is immutable and establishes its own HEAD marker. Neither publisher overwrites the other. Both publications remain represented by their HEAD markers and can appear as separate logical heads until a later publication makes them ancestors.

Commit publication does not require an exclusive global synchronization lock that serializes all clients. Multiple writers can publish distinct immutable commits and HEAD markers. Normal publication also does not depend on a remote Compare-And-Swap primitive. Writer markers and the GC barrier are separate maintenance coordination mechanisms and do not serialize ordinary synchronization writers.

## Merge Base & Three-Way Reconciler

When a client observes multiple concurrent heads (`CA` and `CB`), it traverses ancestry to find their common ancestors:

1. Ancestry traversal identifies all common ancestor commits of the active logical heads;
2. Kasumi determines the maximum commit height among those common ancestors;
3. Kasumi selects the unique common ancestor with the greatest commit height as the **merge base**;
4. If more than one common ancestor exists at that maximum height, resolution stops with an ambiguous merge-base error (`AmbiguousMergeBase`) rather than selecting one arbitrarily.

```text
C0 → CA: Mutations on branch A
C0 → CB: Mutations on branch B
```

When the observed heads have a unique merge base and the resulting snapshot is structurally valid, a client can reconcile the observed branches and publish the resulting state. Changes on independent paths (such as Machine A modifying `docs/` while Machine B modifies `src/`) are combined in the merged snapshot without generating conflict artifacts.

## Multi-Parent Merge Commits

When publishing the resolution, the client generates a merge commit `CM`:

```text
       CA
      /  \
C0 ──┤    ├──> CM
      \  /
       CB
```

`CM.parents = {CA, CB}` in canonical order. Relative to the heads observed when `CM` was prepared, publishing `CM` makes `CA` and `CB` ancestors of the merge commit. If no additional concurrent publication introduces another branch, `CM` becomes the sole logical head.

## Conflict Handling

A multi-head condition is not itself a file conflict. Conflict preservation is required when active branches contribute incompatible states for the same canonical path or path structure.

### Remote Branch Conflicts

When resolving competing remote heads, the remote reconciler deduplicates identical variants, orders distinct variants deterministically, keeps one applicable variant at the canonical path, and preserves additional non-absent variants under deterministic conflict paths:

```text
<path>.kasumiconflict_<first 12 chars of source head commit ID>
```

If that candidate conflict path is already in use by another row, Kasumi appends `.1`, `.2`, and so forth until an unused path is found.

### Local/Remote Conflicts

When a file has been modified both locally and remotely relative to the reconciliation base, observed filesystem modification timestamps (`mtime`) provide a deterministic resolution rule:
* The local file keeps the canonical path only when its observed `mtime` is strictly greater than the remote `mtime`; the remote variant is materialized as `<path>.kasumiconflict_remote`.
* Otherwise (including equal timestamps), the remote file keeps the canonical path, and the local file is renamed to `<path>.kasumiconflict_local` and uploaded.

When one branch deletes a file while another modifies it, the non-absent modified content is retained.

## Epochs & Retention Horizons

As history accumulates, an authenticated **Epoch** establishes a pruning horizon for the active DAG:

| Field | Description |
|---|---|
| `vault_id` | Stable unique identifier of the shared vault |
| `sequence` | Monotonic position in the Epoch chain |
| `issued_at` | Authenticated issuance timestamp |
| `policy` | Minimum retention depth and retention age parameters |
| `anchors` | Set of retained boundary commits |
| `previous_epoch_id` | Identifier linking the Epoch to its predecessor |

### Default Retention Policy
```text
min_history_depth = 5 commits
min_history_age_hours = 6 hours
```

A commit reaches the pruning boundary only when both depth and age criteria are satisfied. Boundary anchor commits are preserved, while historical objects prior to the anchors become eligible for garbage-collection processing according to the reachability, retention, barrier, and quarantine rules described in [Remote Storage, Integrity & Maintenance](remote-storage-and-maintenance.md).
