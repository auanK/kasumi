# Micro-Pack Repack

`kasumi repack <profile> [--dry-run] [--reclaim-dirty] [--full]` performs local-first consolidation of loose small files and fragmented `KPAK\x01` Micro-Packs into fresh Micro-Packs without downloading remote content payloads or deleting remote objects.

## Core invariants

* **Zero remote payload downloads**: All repacked member bytes are read from live local files in `local_dir` and verified against their expected BLAKE3 hash and size while staging fresh encrypted `KPAK\x01` packs.
* **Zero remote deletions**: Old loose objects and replaced Micro-Packs are never deleted by `repack`. Because older history Commits remain valid under Epoch retention, replaced packs remain protected by history reachability until retention advances and [`kasumi gc`](garbage-collection.md) removes them.
* **Identical logical tree**: A published repack creates a new `KCOM` v3 Commit carrying the exact same logical `Snapshot` tree and an updated `StorageManifest`. Other enrolled clients fast-forward cleanly on their next Sync without re-downloading unchanged files, while fresh `sync --initial` clients enroll directly into the consolidated packs.

## Deterministic planning policy

Repack builds a deterministic plan from the live `Snapshot` tree and effective `StorageManifest` using these fixed policy thresholds:

| Parameter | Value / rule |
|---|---|
| Small-file threshold (`max_blob_size`) | `<= 256 KiB` (`MAX_MICRO_PACK_BLOB_SIZE`), excluding `.kasumiignore` and FastCDC-chunked files; zero-byte files are preserved |
| Target pack size (`target_pack_size`) | `4 MiB` (`TARGET_MICRO_PACK_SIZE`) per consolidated pack |
| Underfilled threshold (`underfilled_pack_threshold`) | `2 MiB` (`TARGET_MICRO_PACK_SIZE / 2`) live bytes |
| Member count bounds | Minimum `2`, maximum `65536` (`MAXIMUM_PACK_MEMBERS`) per pack; a trailing single-member bin merges into the preceding bin within `16 MiB` (`MAXIMUM_PACK_PLAINTEXT_SIZE`) |

To detect fragmentation without network I/O, the planner groups `StorageManifest.packed_blobs` by `pack_hash`, skips any pack containing an oversized member as retained, and recomputes the canonical `pack_hash` over each pack's remaining live members. A mismatch against the recorded remote `pack_hash` proves that dead (deleted or modified) blobs occupy space in the immutable remote pack:

* **Consolidated by default**: Eligible loose small blobs (when consolidating with other loose blobs or eligible packs), clean underfilled packs (`< 2 MiB` when strictly reducing object count), and dirty underfilled packs (`< 2 MiB`). Clean source bins whose recomputed `pack_hash` already exists intact are kept without re-uploading.
* **Retained untouched**: Healthy packs (`>= 2 MiB` live bytes with no dead blobs) and FastCDC `chunked_files`.
* **Large dirty packs (`>= 2 MiB` live bytes with dead blobs)**: Detected and reported during observation, but skipped by default to avoid upload amplification. Pass `--reclaim-dirty` to include them.
* **Non-reducing layouts**: If no dirty pack is selected and consolidation does not strictly reduce the source object count, the plan is treated as a no-op.

## Lifecycle and publication order

1. **Runtime resolution and lock**: `application::execute` performs read-only profile resolution (never creating a missing `local_dir`), validates retention bounds, acquires the local exclusive `profile-<name>.lock`, validates existing SQLite state, resolves the master key, and opens the transport.
2. **Transaction journal gate**:
   * `--dry-run` inspects the local [transaction journal](transactions-and-recovery.md) read-only and fails if any pending journal exists without mutating local or remote state.
   * Normal `repack` executes Sync transaction recovery and rejects `ResumableTransaction` (requiring `sync` to finish the interrupted upload before repack).
3. **Synchronized workspace verification**: Observes local files and authenticated remote history, then verifies through reconciliation that remote history is non-empty, local base state exists, there is a single non-conflicting remote logical HEAD, there are no pending materializations, and there are zero pending local, remote, or repair changes. File-hash cache deltas are persisted only on non-`--dry-run` runs.
4. **Pure planning**: Computes the consolidation plan. `--dry-run` or non-actionable plans exit here without registering a remote writer or performing remote writes.
5. **Cooperative writer and parallel staging**: Registers a remote writer marker (failing closed if a GC maintenance barrier is active), resolves distinct content hashes to readable local source paths, and creates and encrypts new `KPAK\x01` packs in a private temporary workspace across a bounded worker pool (`content_concurrency()`). Concurrent local edits, size mismatches, or pack hash mismatches fail before remote writes.
6. **Upload and verification**: Re-checks writer admission, uploads the staged packs in parallel, verifies remote objects (`verify_upload_batch`), then re-checks writer admission and remote HEAD markers (`list_remote_head_commit_ids`) to reject concurrent remote publications before committing.
7. **Publication and cleanup**: Publishes and verifies the new `KCOM` v3 Commit and HEAD marker preserving the live `Snapshot` with `target_manifest`, saves accepted `StoredState` locally, best-effort prunes observed parent/ancestral HEAD markers, and releases the writer marker.

## Operational contract and two-step reclamation

Exclusivity is **cooperative**, using the same writer registration and GC barrier protocol described in [Garbage Collection](garbage-collection.md#operational-contract) with no distributed compare-and-swap (CAS) or fencing token. Stop Sync on all clients and serialize maintenance across the vault before running `kasumi repack`.

Because `repack` never deletes remote objects directly, physical space reclamation happens in two steps:

1. Run `kasumi repack <profile>` (adding `--reclaim-dirty` when reclaiming dead space inside large fragmented packs) to move the live logical head onto consolidated Micro-Packs.
2. Run [`kasumi gc <profile>`](garbage-collection.md) once history retention depth and age (`min_history_depth` and `min_history_age_hours`) / Epoch progression no longer anchor the older commits still referencing the superseded packs.
