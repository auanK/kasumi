# Security Specification

## Threat & Trust Model

Kasumi uses symmetric authenticated cryptography to protect synchronized files and history. Clients participating in the same vault share the same 32-byte master key. Any client possessing this key holds full authority to read, decrypt, publish, and reconcile data within that vault.

The threat model distinguishes three threat scenarios:

### Threat A: Untrusted Remote Storage & Network Eavesdropping
* **Threat Profile**: The remote storage provider (cloud bucket, SFTP host, NAS share), an untrusted third party, or a network eavesdropper inspects or tampers with stored objects.
* **Mitigations & Observable Data**:
  * File content payloads (loose objects, FastCDC chunks, and `KPAK\x01` Micro-Packs), commit payloads, Epoch records, and `KACT` v1 maintenance activity records are compressed in memory (where applicable) and encrypted and authenticated client-side using **XChaCha20-Poly1305** before remote storage.
  * The local transaction journal is also encrypted and authenticated, but resides exclusively on local client storage and is not uploaded to remote storage.
  * Domain-separated keyed BLAKE2b derivations generate Content, Pack, Commit, Epoch, and namespace identifiers. Canonical file paths, directory structure, file modification timestamps, and `StorageManifest` pack/chunk mappings are contained within encrypted Commit payloads when represented in remote history and are not used directly as remote object identifiers. The local transaction journal may also contain synchronization paths and logical hashes inside its encrypted record.
  * Protected payloads that fail AEAD authentication, purpose-binding checks, or identifier/structural validation are rejected.
  * History continuity checks compare the observed remote history with locally persisted state when such state exists.
  * **Observable Metadata**: Remote storage providers cannot read authenticated plaintext file contents or the encrypted Commit tree without the key. They can observe the key-derived namespace structure, opaque identifiers, `<commit-id>_<ciphertext-id>` object names, clear Epoch sequence numbers, physical HEAD-marker presence, writer/barrier/probe objects, compressed/packed/chunked object count and size distributions, deduplication within a vault, and access/operation timing. Because Protocol v3 compresses chunks with Zstandard before encryption when compression saves more than 32 bytes, encrypted object sizes reflect compressed chunk lengths rather than raw plaintext lengths. See [Remote Layout](architecture/remote-layout.md).

### Threat B: Stolen or Offline Physical Disk
* **Threat Profile**: A physical device is lost or stolen, and an adversary gains offline read access to the local storage drive.
* **Mitigations & Limitations**:
  * Local master-key persistence depends on the profile's configured `key_storage` mode (`vault`, `file`, or `memory`):
    * In `file` mode, the local master key is persisted in `profiles/<profile>/key.bin` using a **reversible XOR mask**, not cryptographic encryption. An attacker with offline read access to the filesystem can extract `key.bin` and invert the mask with the compiled constant, obtaining the master key without needing to guess or break the Argon2id password.
    * In `vault` mode (the default for new profiles), the master key is stored in the operating system credential vault (Windows Credential Manager on Windows; Freedesktop Secret Service / GNOME Keyring or KDE KWallet on Linux) rather than `key.bin`, and its offline protection depends on the OS keyring/DPAPI encryption and login password.
    * In `memory` mode, the master key is never persisted to disk or to an OS vault and is derived in RAM on every command.
  * Even when `vault` or `memory` mode is used for the master key, synchronized working-tree files and `db.sqlite` metadata reside on the local disk in plaintext.
  * **Recommendation**: For protection of local profile data and working files against offline disk access, use OS-level Full-Disk Encryption (FDE):
    * **Windows**: BitLocker
    * **Linux**: LUKS (`dm-crypt`)
  * Kasumi does not configure or manage OS full-disk encryption.

### Threat C: Compromised Local OS Account / Malware
* **Threat Profile**: Malware or an unauthorized process executes within the security context of the authenticated local user account.
* **Mitigations & Limitations**:
  * Operating system filesystem permissions (explicit DACLs on Windows, mode `0600`/`0700` on POSIX) restrict access to the owner user account (and `SYSTEM` on Windows), preventing access from other unprivileged user accounts on the same system.
  * Filesystem permissions and unlocked OS user vaults are access control mechanisms, **not** isolation against the same OS user account. If the local user account itself is compromised, processes running as that user inherit access to unlocked OS credential vault entries, `key.bin`, and local profile state.
  * The authenticated local OS user account, the operating system, the Kasumi binary, and cryptographic libraries constitute the Trusted Computing Base (TCB). Kasumi does not defend against execution within an untrusted or compromised local host.

## Key Derivation & Local Persistence

> [!WARNING]
> In `file` mode, the persisted file `key.bin` uses a reversible XOR mask and OS filesystem permissions; it is **not** password-encrypted at rest.
> An attacker who can read `key.bin` can recover the master key directly without breaking Argon2id.
> Use `key_storage = "vault"` (the default for new profiles) to store the key in the OS credential vault, or `key_storage = "memory"` to require Password and Password Salt on every command without persisting the key.

The profile creation wizard (`kasumi config`), local key entry/replacement (`kasumi key <profile>`), and `memory`-mode runtime operations derive a 32-byte symmetric master key:

```text
Password + Password Salt
        ↓
     Argon2id
        ↓
     Master Key
```

`kasumi key <profile>` only updates the locally stored key (and asks for confirmation before overwriting a different existing key); it does **not** re-encrypt remote vault data. Rotating a compromised key requires creating a new vault (see [Compromise Recovery](#compromise-recovery)).

* **Password**: Minimum 12 characters.
* **Password Salt**: Minimum 16 characters. A reproducible, user-provided passphrase that serves as the cryptographic salt for Argon2id key derivation (not an automatically generated or stored random salt). Machines that derive the same vault master key from Password and Password Salt must use the same two inputs. A machine may instead be provisioned with the same 32-byte master key directly (`KASUMI_MASTER_KEY`).
* **Argon2id Parameters**: 64 MiB memory (65,536 1-KiB blocks), 3 passes, 1 lane. The Argon2 work area is wiped before release; ephemeral password, salt, and master-key temporary buffers in memory are wiped at defined cleanup points using `crypto_wipe`.
* **Derivation Scope**: In `vault` and `file` modes, Argon2id derives the 32-byte master key when creating a profile or running `kasumi key <profile>`, and routine operations (`kasumi sync`, `kasumi status`, etc.) load the persisted 32-byte key from the OS vault or `key.bin`. In `memory` mode, no key is persisted and every operation that requires the profile key derives it in memory from interactive prompts or `KASUMI_PASSWORD` + `KASUMI_PASSWORD2` (or loads `KASUMI_MASTER_KEY`).

### Local Key Storage Modes (`vault`, `file`, `memory`)

Each profile in `config.toml` requires `key_storage = "vault" | "file" | "memory"` (newly created profiles default to `"vault"` in the wizard):

* **`vault` (Default for new profiles)**: Persists the 32-byte master key in the OS credential vault under target `kasumi/<profile>`:
  * **Windows**: Windows Credential Manager (`CredWriteW` / `CredReadW` / `CredDeleteW` with `CRED_TYPE_GENERIC` and `CRED_PERSIST_LOCAL_MACHINE`).
  * **Linux**: Dynamically loads system shared libraries on demand via `dlopen` (verifying root ownership and non-writable permissions before loading) to communicate with the active desktop vault over D-Bus without hard binary dependencies on headless servers—using `libsecret-1.so.0` (Freedesktop Secret Service / GNOME Keyring) or `libdbus-1.so.3` (KDE KWallet `org.kde.kwalletd6` / `org.kde.kwalletd5`).
* **`file`**: Persists the 32-byte master key in `profiles/<profile>/key.bin`, obscured using a fixed, reversible byte-wise XOR mask with the `KASUMI_EDGE_SYNC_V1_MASK` constant. Applying the same operation reverses the representation; this is **not cryptographic encryption**.
* **`memory`**: Never writes the master key to `key.bin` or the OS vault. Every command requiring the key prompts on `/dev/tty` or `CONIN$` (or reads `KASUMI_PASSWORD` and `KASUMI_PASSWORD2`, or `KASUMI_MASTER_KEY`). Switching a profile's `key_storage` mode automatically deletes the key from the previously configured storage backend.
* **Access Control at Rest**: Operating system file permissions restrict read and write access to local profile directories and files:
  * **Windows**: Explicit, protected DACLs (`D:P(A;FA;;;SY)(A;FA;;;<user-sid>)`) disable inheritance and restrict access to the owner user and `SYSTEM`. Symlinks and reparse points are rejected.
  * **POSIX**: Mode `0600` for files and `0700` for private directories (`O_NOFOLLOW` and `lstat` checks reject symlinks).
* **Sensitive File Writes**: Private-file writes such as `key.bin`, temporary reassembled plaintext files, and the transaction journal use private handles, filesystem flushing (`FlushFileBuffers` / `fsync`), and atomic replacement/rename (`MoveFileExW` on Windows, POSIX rename). SQLite `StoredState` instead uses database transactions; see [Local Persistent State](architecture/local-state.md).

### Domain-Separated Subkeys

Keyed BLAKE2b derives distinct 32-byte subkeys across isolated domains:

* `Content`: loose file content and FastCDC chunk payload encryption
* `History`: commit DAG encryption
* `Epoch`: Epoch lifecycle envelope encryption
* `Journal`: local transaction journal encryption
* `RemoteIdentifier`: keyed identifier derivation (`Content`, `Commit`, `Epoch`, `Namespace`, `Pack`)
* `Pack`: `KPAK\x01` Micro-Pack container payload encryption
* `Activity`: immutable `KACT` v1 operational maintenance record encryption

Content, Pack, Commit, Epoch, and namespace identifiers also use disjoint cryptographic domain tags. Derived namespace components are truncated to eight hex characters (the version component to four), so namespace derivation is not a confidentiality guarantee for protocol structure. Ephemeral subkey buffers in memory are wiped at defined cleanup points using `crypto_wipe`; Kasumi does not claim to prevent all copies or swap exposure of secrets.

## Encryption Standards

File contents, FastCDC chunks, `KPAK\x01` Micro-Packs, and commit payloads use **Protocol v3 (`KASUMI\x03\x00`, `FILE_HEADER_SIZE = 57`)** with **XChaCha20-Poly1305** authenticated encryption (AEAD) via Monocypher and per-chunk **Zstandard (`zstd` level 1)** compression:

* **Authenticated Header (`57 bytes`)**: Contains the 8-byte magic `KASUMI\x03\x00`, a random 24-byte file nonce, the 8-byte little-endian uncompressed total plaintext size, a 1-byte `FilePurpose` tag (`Content = 0`, `History = 1`, `Pack = 2`, `Activity = 3`), and a 16-byte Poly1305 header authentication tag. Binding `FilePurpose` into the header's associated data prevents cross-domain substitution between loose/chunk Content blobs, Commit objects, `KPAK\x01` Micro-Packs, and `KACT` v1 activity records even if an attacker renames objects in remote storage.
* **In-Memory Chunk Compression & AEAD (`CHUNK_SIZE = 1 MiB`)**: Plaintext streams are processed in chunks of up to `1 MiB` (`1,048,576` bytes). Before encryption, each chunk is compressed in RAM with Zstandard (`zstd` level 1). If compression reduces the chunk size by more than 32 bytes, the compressed payload is used (`flags = 1`); otherwise the raw uncompressed bytes are used (`flags = 0`). Each encrypted chunk prepends a 5-byte cleartext prefix (`CHUNK_PREFIX_SIZE = 5`: 1-byte `flags` + 4-byte little-endian `wire_len`), followed by `wire_len` encrypted bytes and a 16-byte Poly1305 authentication tag whose associated data binds the 57-byte file header, the 64-bit chunk index, the 1-byte compression flag, and the 32-bit wire length. Decompressed chunk lengths are verified against the expected plaintext slice size (bounded by `1 MiB` per chunk and the declared file total size) before release.
* **Micro-Pack Container Format (`KPAK\x01`)**: The plaintext inside a `FilePurpose::Pack` stream starts with `KPAK\x01` (5 bytes), a 4-byte entry count (`<= 4096`), a directory table of `(32-byte logical_hash, 4-byte offset, 4-byte size)` entries sorted canonically by `logical_hash`, and contiguous concatenated file payloads. During extraction, every requested member's bounds are checked against the pack buffer and its extracted bytes are re-hashed with BLAKE3 and verified against `logical_hash`.

Epoch records use an authenticated XChaCha20-Poly1305 envelope under the Epoch subkey, with the AEAD nonce derived from the Epoch identifier.

The local transaction journal uses the same AEAD scheme with the Journal subkey, a random nonce, and verified format headers. The transaction journal is local and is not stored on remote storage.

An authentication failure, `FilePurpose` mismatch, decompression failure, or post-decryption BLAKE3 hash mismatch causes the protected object or journal record to be rejected, and it is not accepted as synchronization state.

## Cryptographic Identifiers

| Identifier | Derivation | Purpose |
|---|---|---|
| Logical Hash | Plaintext BLAKE3 | `NodeRow` identity, FastCDC chunk logical identity, change detection, deduplication |
| Content ID | Keyed BLAKE2b of logical hash (`IdentifierPurpose::Content`) | Opaque remote storage object name for loose files and individual FastCDC chunks |
| Pack Hash | Plaintext BLAKE3 over `"KASUMI_PACK_V1"`, member count, and sorted `(logical_hash, size)` descriptors | Deterministic content-addressed identity of a `KPAK\x01` Micro-Pack |
| Pack ID | Keyed BLAKE2b of Pack Hash (`IdentifierPurpose::Pack`) | Opaque remote storage object name for a `KPAK\x01` Micro-Pack |
| Commit ID | Keyed BLAKE2b of canonical commit (`IdentifierPurpose::Commit`) | Parent references, `<commit-id>_<ciphertext-id>` object path, and HEAD-marker binding |
| Epoch ID | Keyed BLAKE2b of canonical Epoch (`IdentifierPurpose::Epoch`) | Lifecycle chain sequencing and Epoch object path |
| Ciphertext ID | BLAKE3 of encrypted Commit payload | Physical Commit variant tracking |
| Physical Hash | SHA-256 of stored bytes | Remote transport and transfer integrity verification |
| Namespace component | Truncated keyed BLAKE2b derivation (`IdentifierPurpose::Namespace`) | Remote protocol path components |

Under different master keys, the keyed Content, Pack, Commit, and Epoch identifier derivations produce different identifiers for the same logical input. Plaintext BLAKE3 logical hashes and Pack Hashes are not used directly as remote object identifiers. They may appear in encrypted commit or transaction journal records and in protected local database state.

## History DAG Integrity

A canonical commit (`KCOM` v4) contains the Snapshot tree, parent commit IDs, tree height, creation timestamp, commit authorship (`origin` operation, declared `machine_id`, and `machine_name` recorded at creation), and canonical `StorageManifest`. The commit ID authenticates this entire canonical serialized representation (including authorship and `StorageManifest`) under the vault key, and the commit payload is encrypted and authenticated under the History domain (`FilePurpose::History`). `KCOM` v3 commits are rejected without legacy fallback.

Declared `machine_id` and `machine_name` provenance (also carried in encrypted `KACT` v1 `FilePurpose::Activity` records) represents an installation-declared identifier from a client holding the vault master key, **not** individual user authentication or hardware attestation; copying the private app-data directory (`machine.id`) copies that identity. Historical records retain the machine name captured when created and never log passwords, salts, keys, or secrets.

Before accepting any commit into the local history DAG, Kasumi verifies:
* AEAD authentication tag validity and `FilePurpose::History` binding;
* Keyed commit ID integrity;
* Snapshot canonical structure, ordering, hierarchy, and path constraints;
* `StorageManifest` canonical ordering, uniqueness, size bounds (`packed_blobs` entries `<= 16 MiB`; `chunked_files` slices `<= 32 MiB` each and summing exactly to `file_size`), disjointness between packed and chunked logical hashes, and consistency with the commit's live Snapshot file rows;
* Parent existence, height consistency (`height = max(parent height) + 1`), and absence of cycles;
* Timestamp non-regression along parent edges.

```text
Encrypted Commit → AEAD Auth → Topological Validation → HEAD Marker Validation → Physical Verification → Local State
```

The commit object is published and verified using the transport's physical-hash capability or readback fallback before its HEAD marker is published. HEAD markers are structurally validated and bind a commit ID to a ciphertext ID. The referenced commit variant is cryptographically authenticated before the marked commit participates in validated history.

Epochs define authenticated retention horizons and boundary anchors. The cooperative writer and multi-barrier protocol checks for active synchronization writers and competing barriers (with a post-publish settle delay and periodic `Apply` revalidation) during garbage collection; it remains cooperative on passive storage and does not provide atomic distributed CAS or fencing.

## Local Filesystem Isolation

* **Windows**: Private application directories and state databases are created with explicit DACLs granting access exclusively to the current user and `SYSTEM`.
* **POSIX**: Private directories use mode `0700` and sensitive files use mode `0600`.

Internal routines reject symlinks and Windows reparse points inside private state directories. Writing configuration, master key, and journal files employs temporary files, filesystem flush (`fsync` / `FlushFileBuffers`), and atomic rename replacement.

`db.sqlite` persists accepted history trees, Commit and Epoch references, pending materializations, and the file-hash cache (logical paths, hashes, sizes, timestamps, and native identities). It is not encrypted or authenticated as a whole. These local files rely on filesystem permissions and disk encryption for at-rest privacy. The `transaction.bin.enc/` directory contains encrypted journal snapshot/deltas and authenticated confirmation/retirement records used by [interruption recovery](architecture/transactions-and-recovery.md). Staging and plaintext backups under `.transactions/<id>/` are not uniformly encrypted. [Local Persistent State](architecture/local-state.md) distinguishes these authorities from caches and checkpoints.

Hash-cache fingerprint equality is a metadata optimization, not a proof of
unchanged bytes. Sync independently hashes destructive targets, but its final
validation and filesystem syscall are separate: an external same-user writer
can still race that interval, including during rollback. Kasumi supplies no
atomic filesystem snapshot or universal external-write protection. Local journal
durability depends on OS/filesystem/hardware persistence behavior and cannot
detect restoration of a complete older valid authority bundle. Preserve
independent backups; retention and GC can permanently remove the last vault copy.

## Remote Metadata Privacy

Remote storage providers observe key-derived protocol namespace components and their hierarchy, keyed or otherwise opaque object identifiers, Commit ID/Ciphertext ID relationships, clear Epoch sequence numbers, HEAD-marker and maintenance control-object presence, object counts and sizes, deduplication/reuse patterns within a vault, and operation timing. Canonical file paths, directory hierarchy, file modification timestamps, Commit parent IDs, and Snapshot rows are inside protected Commit payloads and are not directly remote object names. Provider-specific metadata may reveal further operational information outside Kasumi's payload encryption boundary.

Directory listings are treated as untrusted observations. Where publication or maintenance requires byte confirmation, Kasumi compares a remote physical SHA-256 when supported or uses a verified readback fallback; downloaded protected payloads still require cryptographic authentication. A provider-reported hash alone is not a substitute for fsck's payload audit. See [Transport](architecture/transport.md).

## Rollback Protection & History Continuity

Each client validates history continuity against its own local accepted state:
* The base commit in `db.sqlite` must remain reachable in the remote DAG unless an authenticated, newer Epoch explicitly moves the retention horizon forward. Missing base commit without an Epoch advance reports `StorageHistoryRegression`.
* An exact locally trusted Epoch reference serves as an ancestry checkpoint: sequence regression, same-sequence ID replacement, and presented ancestry that fails to reach the trusted checkpoint are rejected.
* **Newly Enrolled Clients**: A newly enrolled client without an existing local Epoch checkpoint authenticates the chain presented by remote storage back to genesis, but cannot independently infer whether the remote storage has withheld a newer valid state it has never observed.

## Compromise Recovery

Because the master key grants full authority over a vault, if a machine's key is compromised:

1. Terminate all active sync clients;
2. Revoke remote storage credentials exposed to the compromised machine;
3. Select an authenticated, trusted local copy or backup snapshot;
4. Create a new profile with a new master key and a distinct remote storage namespace;
5. Publish the verified snapshot to the new vault;
6. Re-enroll only intended client machines.
