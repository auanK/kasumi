# Data Model and Merkle Trees

Kasumi maps physical filesystem structures into a deterministic, canonical data representation used for snapshot comparison, local accepted-state persistence, and Merkle verification.

```text
Local Filesystem
       ↓
Flat Canonical Snapshot
       ├── Merkle Hash Hierarchy ──> Root Merkle Hash
       └── Full Snapshot Record ───> Encrypted Commit
```

## The Snapshot

A `Snapshot` represents an entire synchronized directory hierarchy as a flat sequence of sorted `NodeRow` values.

Consider this filesystem directory:

```text
Documents/
├── a.txt
└── Projects/
    └── b.txt
```

Its canonical representation follows this structure:

```text
Snapshot.rows
├── ""
├── "Documents"
├── "Documents/a.txt"
├── "Documents/Projects"
└── "Documents/Projects/b.txt"
```

`Snapshot.rows` is stored in memory as a flat, contiguous, path-based, and canonically ordered array (`std::vector<NodeRow>`). Hierarchical relationships are derived purely from relative paths; operations traverse the tree without allocating pointer-linked node graphs in memory.

## NodeRow

Each `NodeRow` describes an individual file or directory:

| Field | Description |
|---|---|
| `path` | Normalized relative path within the synchronization root |
| `hash` | Content hash for files; Merkle composite hash for directories |
| `size` | File size in bytes; cumulative descendant file-content size for directories |
| `mtime` | Last observed filesystem modification time; serialized using a nanosecond-based timestamp representation |
| `is_directory` | Distinguishes directories from regular files |

* The synchronization root uses the empty path `""` and is always the first row.
* Snapshot paths are relative to the synchronization root and use `/` as the canonical hierarchy separator.
* Canonical ordering ensures directories precede their children, and siblings are sorted lexicographically.
* Empty directories have their own dedicated `NodeRow`.

Before reconciliation or publication, snapshot validation verifies:
1. Canonical root row presence, empty path `""`, and directory flag;
2. Strict canonical lexicographical ordering and exact path uniqueness;
3. Explicit parent directory row existence for every file and subdirectory;
4. Portable logical path component validation (see [Synchronized Path Rules](../configuration-and-usage.md#synchronized-path-rules));
5. Portable Unicode case-key uniqueness preventing case-equivalent path collisions within the snapshot.

## Merkle Tree Construction

Overlaid on the logical directory tree is a cryptographic **Merkle tree**. Every leaf file possesses a content hash, and each directory node hashes the sorted composition of its immediate children:

```text
                 Root Hash
                    │
             Hash Documents
              /            \
        Hash a.txt      Hash Projects
                            │
                        Hash b.txt
```

The Merkle tree is the logical verification structure over hashes. It does not alter the fact that the underlying `Snapshot` is stored contiguously in memory as an array of `NodeRow` structs.

## File Hashes

The logical hash of a file is computed using plain BLAKE3:

```text
BLAKE3(plaintext bytes)
```

File size and `mtime` are tracked alongside the hash in `NodeRow`. Encryption nonces and remote blinded identifiers are decoupled layers, detailed in [Security Specification](../security.md) and [Remote Storage & Maintenance](remote-storage-and-maintenance.md).

## Directory Hashes

A directory's composite Merkle hash is computed from the canonical sequence of its immediate children. For each child, its base name and lower-case hexadecimal hash are fed into BLAKE3:

```text
H(dir) = BLAKE3(
    name(child_1) || hex(hash(child_1)) ||
    name(child_2) || hex(hash(child_2)) ||
    ...
)
```

Because a subdirectory's hash already incorporates all its descendant files, changes propagate hierarchically up to the root.

## Root Merkle Hash

A change to a file content hash or to the hashed child composition propagates through ancestor directory hashes up to the root:

```text
hash(Documents/Projects/b.txt)
             ↓
hash(Documents/Projects)
             ↓
      hash(Documents)
             ↓
         Root Hash
```

The Root Hash resides in the first row of the `Snapshot`. It is derived from the canonical hierarchy of child names and content/composite hashes. Comparing two already-computed root hashes requires comparing fixed-size BLAKE3 digests in $O(1)$ time. Changes to file content hashes or to the hashed child composition propagate through ancestor directory hashes to the root.

### Merkle Trees vs. Commit DAGs

A Merkle tree represents the composition of a single point-in-time filesystem snapshot. The commit DAG records how snapshots evolve over time and under concurrency:

```text
Snapshot (Merkle Tree)
          ↓
     Commit Node
          ↓
 History Commit DAG
```

A Commit contains a canonical Snapshot together with its parent commit IDs, height, and authenticated timestamp metadata. Parent commit IDs connect the commit into the history DAG. Multi-parent merge resolution is detailed in [History DAG, Concurrency & Retention](history-and-concurrency.md).

## Local State Artifacts

Each local profile maintains isolated state files:

| Artifact | Location | Purpose |
|---|---|---|
| `config.toml` | Data Root | Profiles, paths, endpoints, and retention limits |
| `profiles/<profile>/key.bin` | Profile Dir | Masked master encryption key |
| `profiles/<profile>/db.sqlite` | Profile Dir | Accepted snapshot state, caches, and checkpoints |
| `profiles/<profile>/inspection-history-v1.cache` | Profile Dir | Non-authoritative cache used by CLI inspection operations |
| `profiles/<profile>/transaction.bin.enc` | Profile Dir | Authenticated and encrypted mutation journal |
| `profiles/<profile>/.transactions/<id>` | Profile Dir | Temporary staging and rollback workspaces |
| `profile-<profile>.lock` | Data Root | Inter-process mutual exclusion lock |

In `db.sqlite`, `StoredState` persists the locally accepted snapshot (`tree`), tree `height`, `commit_id`, `ciphertext_id`, and accepted Epoch certificate reference (`epoch_id` and `epoch_sequence`). This state serves as the locally accepted reconciliation base for the next synchronization cycle.

## Change Detection & Checkpoints

* **File Cache**: Persists the content hash, size, and platform-specific file identity fingerprint. When the stored size and strong fingerprint match the current file, Kasumi can reuse the cached content hash without reading the file contents again.
* **NTFS Change Journal**: On Windows/NTFS, an `ObservationCheckpoint` records the USN Change Journal position and binds it to the previously observed snapshot. When the checkpoint is valid and journal evidence reports no relevant changes, Kasumi can reuse the previous snapshot without invoking the filesystem scanner. Patchable journal deltas can be applied selectively; otherwise Kasumi falls back to the normal scanner.
