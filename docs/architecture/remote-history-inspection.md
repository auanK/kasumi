# History and Epoch Inspection

These commands start with the [common inspection path](remote-inspection.md). They authenticate the history objects needed for their view but do **not** download/decrypt file-content payloads or publish history. The private history cache may be read or saved by complete-history queries; see [Remote Inspection](remote-inspection.md). The [History and Concurrency](history-and-concurrency.md) page owns logical heads, DAG resolution, and Epoch anchors.

## Logical history and trees

| Command | View built and result | Boundary |
|---|---|---|
| `remote heads` | Authenticated current **logical heads**, with heights, parent/root/size metadata plus counts of physical and ancestral markers. It follows observed head history, not one selected file tree. | No file-content download; physical marker counts are distinct from logical-head count. Invalid history fails observation. |
| `remote tree [--head <id>]` | One current logical head's committed **Snapshot**, not the resolved effective tree. With one head, it can select implicitly; with multiple heads, `--head` is required and must name a current logical head. | Authentication covers the selected Commit/Snapshot, not file payload bytes. Absent, non-head, or ambiguous selection is an error rather than an arbitrary choice. |
| `remote commits` | Complete authenticated reachable Commit DAG, including parent/height/head/marker relationships. | May use/save private complete-history cache; no file-content download. |
| `remote commit <id>` | Selects a reachable Commit from complete history, validates its Snapshot, then inspects the physical ciphertext variants for that Commit ID and reports each Ciphertext ID and validity. | An unreachable ID fails; invalid variants are reported as such. Commit ciphertext authentication is not a file-content audit. |
| `remote summary` | Complete authenticated history plus physical content-availability inventory and active-writer listing; reports reachable Commit/head counts, conflicts, missing/orphan content counts, and writer count. | Counts are structural/availability observations, not payload AEAD validation or [Fsck](fsck.md). A concurrent writer can change counts immediately afterward. |

Complete-history queries traverse retained reachable history rather than choosing one head. Physical HEAD markers can outnumber logical heads because an ancestral marker need not be removed immediately. Commit ID identifies logical content; Ciphertext ID distinguishes its encrypted physical variants. See [Remote Layout and Publication](remote-layout.md) for object naming and marker publication.

## Epoch chain

| Command | View built and result | Boundary |
|---|---|---|
| `remote epochs` | Loads and authenticates the Epoch chain directly, then lists its sequence/ID, policy, anchors, and links. | It is an Epoch-chain view, not a full content-payload or physical-object scan. Invalid chain fails closed. |
| `remote epoch <id-or-sequence>` | Loads the same chain and selects one verified record by Epoch ID or canonical decimal sequence; reports policy, anchors, predecessor, and successor. | Invalid selector or absent Epoch is an error. No file-content download or remote write. |

Epoch anchors bound retained history and GC reachability; this inspection does not itself revise retention. All commands are observation-only remotely, with the local cache/permission effects described in [Remote Inspection](remote-inspection.md).
