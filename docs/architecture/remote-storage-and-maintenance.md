# Remote Storage, Integrity, and Maintenance

Remote storage acts as a passive object store. Clients assign meaning to objects, verify authenticity, resolve history DAGs, and coordinate synchronization. Kasumi does not require a dedicated Kasumi coordination server.

```text
Remote: Stores Kasumi data and protocol objects
Clients: Validate and interpret protocol semantics
```

## Transport Abstraction

Kasumi accesses storage through the **Transport** interface:

```text
PUT       Upload object payload
GET       Fetch object payload
PRESENCE  Query object existence
LIST      Observe identifiers under a prefix
REMOVE    Idempotently delete object
```

Backends can implement optional capabilities: bulk PUT, bulk presence queries, bulk physical hash verification, and batched control reads. Where an optional capability is unavailable or reports `Unsupported`, Kasumi provides sequential fallbacks (for example, verifying transfers by readback or issuing sequential control reads).

Currently supported backends:
1. **Local Filesystem**: Local absolute directory paths, mounted SMB shares, or network NAS volumes.
2. **rclone Engine**: Remotes configured through rclone (such as S3, B2, Google Drive, OneDrive, SFTP, WebDAV, and other rclone-supported storage providers).

## Remote Namespace Structure

Content objects reside at the storage root. History, lifecycle, and maintenance controls reside under `history/`:

```text
remote/
├── <content-id>
└── history/
    ├── commits/<commit-id>/<ciphertext-id>.kcom
    ├── heads/<commit-id>-<ciphertext-id>.head
    ├── epochs/v1/<decimal-20-sequence>-<epoch-id>.epoch
    └── gc/v1/
        ├── barrier
        ├── writers/<token-32-hex>.writer
        ├── probes/<token-32-hex>.probe
        └── quarantine/
            ├── content/<content-id>[.meta]
            └── commits/<commit-id>/<ciphertext-id>.kcom[.meta]
```

## Content Deduplication & Storage

A content object holds the encrypted and authenticated payload of a file. Its content ID is derived via keyed BLAKE2b over the plaintext's logical BLAKE3 hash. Identical logical content within the same vault maps to the same content identifier, allowing the same remote content object to be referenced by multiple files or commits. Under different master keys, the keyed derivation produces different content identifiers for the same logical input.

Content objects are immutable and addressed by identity. Deleting or editing a file in the synchronized tree merely updates commit references; physical object cleanup is delegated to garbage collection once references fall out of the active retention horizon.

## Commits & Physical Variants

The protocol separates logical identity from physical representation:
* **Commit ID**: Keyed identifier derived from canonical logical commit bytes (Snapshot, parents, height, creation timestamp). Two representations that decrypt to the identical canonical commit share the same commit ID.
* **Ciphertext ID**: Plain BLAKE3 digest of the encrypted commit byte stream. Because AEAD encryption utilizes random nonces, the same logical commit can produce distinct physical ciphertexts.

```text
Logical Commit C
├── Ciphertext A
├── Ciphertext B
└── Ciphertext C
```

Physical storage paths track both identities:
`history/commits/<commit-id>/<ciphertext-id>.kcom`

The HEAD marker references the specific commit ID and ciphertext ID pair required to locate and authenticate the published variant. HEAD markers are structurally validated protocol objects; the referenced commit payload is then fetched and cryptographically authenticated.

## Remote Integrity Verification (`fsck`)

`kasumi fsck <profile>` validates the observed remote history and audits content objects referenced by the effective remote state:
1. Recovers any interrupted local transaction;
2. Fetches and validates the remote history DAG and Epoch chain;
3. Validates the physical namespace and flags unknown or malformed identifiers;
4. Compiles the complete content inventory required by the effective remote tree;
5. Downloads every referenced content object;
6. Verifies AEAD authentication, content identifier, size, and logical BLAKE3 hash;
7. Reports missing or corrupted payloads.

## Garbage Collection (`gc`)

Garbage collection identifies objects outside the reachable/retained history set and processes eligible objects through quarantine before permanent removal:

```text
History DAG
    ↓
Reachable Inventory (HEADs + Epoch Anchors)
    ↓
Orphan Identification
    ↓
Quarantine Staging (10-Day Quarantine Retention)
    ↓
Permanent Purge
```

### Writers & Distributed Barrier Protocol

Before running destructive deletions on passive storage without central servers, Kasumi coordinates through a barrier protocol:

```text
Active Sync  ──> Creates ephemeral .writer marker
GC Process   ──> Creates 'barrier' marker ──> Confirms zero active writers
```

1. **Barrier**: The GC barrier blocks admission of new writer registrations; active synchronization work requiring writer registration cannot be admitted while the barrier is present. Read-only inspection commands are not blocked.
2. **Writer Verification**: GC observes the writer set twice while holding and verifying its barrier registration before continuing. Any active or abandoned writer marker stops destructive collection.
3. **Backend Consistency Probes**: Tests read-after-write and delete visibility using probe files (`history/gc/v1/probes/<token>.probe`). The probe is published, verified across repeated directory listings, removed, and verified absent across repeated directory listings. If the probe does not demonstrate the visibility behavior required for online collection, GC performs analysis only (`analysis_only = true`) without moving objects to quarantine.

### Quarantine Staging

Candidate objects are not deleted outright:
1. The candidate object is copied to the `quarantine/` namespace;
2. The physical SHA-256 identity of the quarantined copy is verified;
3. Encrypted and authenticated quarantine metadata records the quarantine timestamp and the physical SHA-256 of the quarantined object (the original object identifier is derived directly from the quarantine path);
4. The original object is removed only after re-verifying barrier ownership;
5. The quarantined copy is retained for a 10-day quarantine period (`864,000` seconds).

At the beginning of online collection, reachable quarantined objects are restored before new candidates are processed. Quarantined objects are permanently purged only when their quarantine retention period has elapsed, the object remains outside the active reachable history set, and barrier ownership checks succeed.
