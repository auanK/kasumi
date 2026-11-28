# Remote Layout and Publication

The production remote layout is derived from the 32-byte vault master key using
the remote-identifier subkey and namespace-specific domain tags. Truncated
lowercase hexadecimal components identify history, commits, heads, epochs, GC,
barrier, writers, and probes. History-family components are eight hexadecimal
characters; the version component is four hexadecimal characters. The remote
root also contains 64-hex-character keyed Content IDs (for loose files and individual FastCDC chunks) and keyed Pack IDs (for `KPAK\x01` Micro-Packs). The following is
structural notation, not literal path names:

```text
<remote root>/
  <content-id>
  <pack-id>
  <history-ns>/<commits-ns>/<commit-id>_<ciphertext-id>
  <history-ns>/<heads-ns>/<commit-id>-<ciphertext-id>
  <history-ns>/<epochs-ns>/<version-ns>/<20-digit-sequence>-<epoch-id>
  <history-ns>/<gc-ns>/<version-ns>/<barriers-ns>/<token>
  <history-ns>/<gc-ns>/<version-ns>/<barrier-id>   (legacy v0.23.x barrier)
  <history-ns>/<gc-ns>/<version-ns>/<writers-ns>/<token>
  <history-ns>/<gc-ns>/<version-ns>/<probes-ns>/<token>
  <activity-ns>/<version-ns>/<20-digit-finished-at>-<event-id>
```

Commit variants, physical markers, Epoch objects, writer/probe objects, activity
records, Pack IDs, and ordinary Content IDs are extensionless. Commits are published at the flat path `<history-ns>/<commits-ns>/<commit-id>_<ciphertext-id>` so that all commit variants in the namespace can be discovered with a single directory listing, while immutable operational activity records (`KACT` v1, encrypted with Protocol v3 under `FilePurpose::Activity`) live in their own derived namespace `<activity-ns>/<version-ns>/` so they remain bounded (`maximum_activity_object_count = 1024`) independently of the 8,192-identifier history inventory cap, which counts both commit variants and physical HEAD markers. Normal `sync` adds zero extra remote objects or requests for traceability: commit authorship rides inside `KCOM` v4, and download-only or no-op syncs are recorded locally in `db.sqlite`. The active layout is key-derived.
Former fixed `history/...` paths are not parsed, migrated, or deleted.
Unrecognized objects, including legacy quarantine state, are left untouched.
For compatibility and backup requirements, see
[Upgrading Kasumi](../best-practices.md#upgrading-kasumi).

## Physical Storage Layout: Loose Objects, Micro-Packs (`KPAK\x01`), and FastCDC Chunks

Logical file rows in a `Snapshot` are always identified by their whole-file plaintext BLAKE3 `logical_hash` and `size`. How a logical file is stored physically at the remote root is determined by the commit's canonical `StorageManifest`:

1. **Micro-Packed Small Files (`<= 256 KiB`, `KPAK\x01`)**:
   * Sync considers files up to 256 KiB, excluding `.kasumiignore`. It sorts candidates by hash and targets 4 MiB of member data per pack. Packing starts at two candidates when the transport exposes batch physical hashing, or sixteen otherwise. A bin containing just one candidate stays loose.
   * Each pack has a deterministic **Pack Hash** (`BLAKE3` over the bytes of `KASUMI_PACK_V1` including the trailing NUL, a little-endian 32-bit member count, and sorted `(32-byte hash, little-endian 32-bit size)` pairs) and is stored at the remote root under its 64-hex-character **Pack ID** (`crypto::pack_identifier`, keyed BLAKE2b under `IdentifierPurpose::Pack`), compressed and encrypted with Protocol v3 under `KeyPurpose::Pack` (`FilePurpose::Pack`).
   * `StorageManifest.packed_blobs` binds the blob hash and size to the logical pack hash. Readers derive the keyed Pack ID and find the member in the authenticated pack table. Offsets are relative to the start of the payload area. The pack codec supports 65,536 members and the writer bounds aggregate member data at 16 MiB. [Manifest types](../../include/core/history.hpp) · [Pack codec](../../src/crypto/pack.cpp)
2. **FastCDC Chunked Large Files (`> 8 MiB`)**:
   * Uploaded files larger than `8 MiB` (`FASTCDC_FILE_THRESHOLD`) are split into content-defined chunks using a normalized 64-bit Gear rolling hash with size-tiered bounds: `256 KiB`–`4 MiB` (`1 MiB` average) up to `64 MiB`, `1 MiB`–`16 MiB` (`4 MiB` average) up to `512 MiB`, and `4 MiB`–`32 MiB` (`16 MiB` average) above `512 MiB`.
   * Each unique chunk is hashed with BLAKE3 (`chunk_hash`) and stored at the remote root under its 64-hex-character **Content ID** (`crypto::remote_identifier(chunk_hash)`, `IdentifierPurpose::Content`), streamed in `1 MiB` frames with Protocol v3 under `KeyPurpose::Content` (`FilePurpose::Content`).
   * The commit's `StorageManifest.chunked_files` records `(logical_hash, file_size, chunks[])` where each `ChunkSlice` specifies `(chunk_hash, size)` (`size <= 32 MiB`, summing to `file_size`). Legacy `<= 4 MiB` manifests remain valid without vault migration, though older clients cannot parse slices larger than `4 MiB`.
3. **Loose Content Objects**:
   * Files absent from `StorageManifest` (such as medium files between `256 KiB` and `8 MiB`, `.kasumiignore`, or files published by older commits) are stored directly at `<remote root>/<content-id>` where `<content-id>` is derived from the whole-file `logical_hash`.

## Identities and Visibility

A **Commit ID** is a keyed identifier of canonical Commit bytes (`KCOM` v4): the complete Snapshot, sorted parents, height, timestamp, commit authorship (`origin`, `machine_id`, `machine_name`), and canonical `StorageManifest` (`KCOM` v3 commits are rejected without legacy fallback). A **Ciphertext ID** is BLAKE3 of one encrypted Commit payload. Random encryption nonces permit several physical ciphertext variants for one logical Commit ID. `HeadReference` binds both IDs. A physical HEAD marker names that reference and records publication; a **logical head** is a marked Commit that is not an ancestor of another marked Commit. Old ancestral markers can coexist until pruning. Content IDs and Pack IDs derive from plaintext logical BLAKE3 hashes and Pack Hashes under the vault key, enabling deduplication inside a vault without exposing raw hashes as object names. See [History and Concurrency](history-and-concurrency.md) and [Security](../security.md).

Remote storage still sees object count, byte sizes, access timing, deduplication, opaque IDs, Commit/Ciphertext relationships, and the clear decimal Epoch sequence in its object name. Derived namespace components hide literal protocol labels from a storage listing but are short and do not hide the structural pattern. Commit payloads contain encrypted paths, metadata, parents, and trees. Provider metadata and transport behavior remain outside Kasumi's encrypted payload boundary.

## Publication Order

The client confirms required encrypted content first. It prepares a canonical Commit for the validated publication tree and observed logical heads (or a parentless genesis Commit), uploads or reuses an authenticated variant, and checks its remote physical representation before publishing a HEAD marker. A backend SHA-256 **physical hash** can be used for this transport check; when unsupported, Kasumi downloads and validates the object. The provider-supplied hash is not an independent cryptographic attestation against a malicious provider; later history loading authenticates the protected Commit. Only after the Commit check does it publish and verify the marker. Bootstrap publishes an authenticated genesis Epoch under single-initializer admission. Ordinary 0.32 Sync retains `DeferMultiWriter` on established vaults and validates any confirmed successor against its local checkpoint, while maintenance [`kasumi gc`](garbage-collection.md) advances pruning Epochs under cooperative maintenance exclusion and durable `.pending-gc-epoch` recovery. SQLite `StoredState` advances after the remote publication checks, then observed ancestral markers are pruned and the transaction journal is cleared. A concurrent client can publish another immutable branch while this happens; later reconciliation resolves both heads. Ambiguous visibility or failed verification stops or enters [recovery](transactions-and-recovery.md), rather than treating a PUT response alone as acceptance.

Content, Commit, and marker publication can use verified reuse and scoped inventory fast paths; these avoid redundant transfers without changing the identity or validation requirements. Once authenticated Epoch anchors advance, older superseded Commit variants behind the Epoch frontier become eligible for garbage collection after passing dual-clock (`Commit.created_at` and remote `ModTime`) grace checks, while Epoch objects and active controls remain protected. The [Transport](transport.md) page owns backend capabilities and fallbacks.
