# Security Specification

## Threat & Trust Model

Kasumi uses symmetric authenticated cryptography to protect synchronized files and history. Clients participating in the same vault share the same 32-byte master key. Any client possessing this key holds full authority to read, decrypt, publish, and reconcile data within that vault.

The threat model distinguishes three threat scenarios:

### Threat A: Untrusted Remote Storage & Network Eavesdropping
* **Threat Profile**: The remote storage provider (cloud bucket, SFTP host, NAS share), an untrusted third party, or a network eavesdropper inspects or tampers with stored objects.
* **Mitigations & Observable Data**:
  * File content payloads, commit payloads, Epoch records, and quarantine metadata are encrypted and authenticated client-side using **XChaCha20-Poly1305** before remote storage.
  * The local transaction journal is also encrypted and authenticated, but resides exclusively on local client storage and is not uploaded to remote storage.
  * Domain-separated keyed BLAKE2b derivations generate Content, Commit, Epoch, and namespace identifiers. Canonical file paths, directory structure, and file modification timestamps are contained within encrypted Commit payloads when represented in remote history and are not used directly as remote object identifiers. The local transaction journal may also contain synchronization paths and logical hashes inside its encrypted record.
  * Protected payloads that fail AEAD authentication or identifier/structural validation are rejected.
  * History continuity checks compare the observed remote history with locally persisted state when such state exists.
  * **Observable Metadata**: Remote storage providers cannot read authenticated plaintext file contents or the encrypted Commit tree without the key. They can observe the key-derived namespace structure, opaque identifiers, Commit ID/Ciphertext ID pairs in object names, clear Epoch sequence numbers, physical HEAD-marker presence, writer/barrier/probe and quarantine objects, object count and size distributions, deduplication within a vault, and access/operation timing. See [Remote Layout](architecture/remote-layout.md).

### Threat B: Stolen or Offline Physical Disk
* **Threat Profile**: A physical device is lost or stolen, and an adversary gains offline read access to the local storage drive.
* **Mitigations & Limitations**:
  * The local master key is persisted in `profiles/<profile>/key.bin` using a **reversible XOR mask**, not cryptographic encryption.
  * An attacker with offline read access to the filesystem can extract `key.bin` and invert the mask with the compiled constant, obtaining the master key without needing to guess or break the Argon2id password.
  * **Recommendation**: For protection of local profile data against offline disk access, use OS-level Full-Disk Encryption (FDE):
    * **Windows**: BitLocker
    * **Linux**: LUKS (`dm-crypt`)
  * Kasumi does not configure or manage OS full-disk encryption.

### Threat C: Compromised Local OS Account / Malware
* **Threat Profile**: Malware or an unauthorized process executes within the security context of the authenticated local user account.
* **Mitigations & Limitations**:
  * Operating system filesystem permissions (explicit DACLs on Windows, mode `0600`/`0700` on POSIX) restrict access to the owner user account (and `SYSTEM` on Windows), preventing access from other unprivileged user accounts on the same system.
  * Filesystem permissions are an access control mechanism, **not** cryptographic encryption at rest. If the local user account itself is compromised, processes running as that user inherit full access to `key.bin` and local profile state.
  * The authenticated local OS user account, the operating system, the Kasumi binary, and cryptographic libraries constitute the Trusted Computing Base (TCB). Kasumi does not defend against execution within an untrusted or compromised local host.

## Key Derivation & Local Persistence

> [!WARNING]
> The Password and Password Salt are used exclusively during profile creation or import to derive the master key.
> The persisted file `key.bin` uses a reversible XOR mask and OS filesystem permissions; it is **not** password-encrypted at rest.
> An attacker who can read `key.bin` can recover the master key directly without breaking Argon2id.

The profile creation wizard derives a 32-byte symmetric master key:

```text
Password + Password Salt
        ↓
     Argon2id
        ↓
     Master Key
```

* **Password**: Minimum 12 characters.
* **Password Salt**: Minimum 16 characters. A reproducible, user-provided passphrase that serves as the cryptographic salt for Argon2id key derivation (not an automatically generated or stored random salt). Machines that derive the same vault master key from Password and Password Salt must use the same two inputs. A machine may instead be provisioned with the same 32-byte master key directly.
* **Argon2id Parameters**: 64 MiB memory (65,536 1-KiB blocks), 3 passes, 1 lane. The Argon2 work area is wiped before release; ephemeral password, salt, and master-key temporary buffers in memory are wiped at defined cleanup points using `crypto_wipe`.
* **Derivation Scope**: Argon2id is used to derive the 32-byte master key from Password and Password Salt inputs during profile creation or import through that path. Once `key.bin` is generated, routine operations (`kasumi sync`, `kasumi status`, etc.) load the master key directly from `key.bin` and do not require or verify the password.

### Local Key Storage & Masking

The profile-management API can create a profile from a directly supplied master key; the CLI `kasumi config` wizard derives it from Password and Password Salt. On creation, the 32-byte key is written to:

```text
profiles/<profile>/key.bin
```

* **Storage Representation**: The key bytes are obscured using a fixed, reversible byte-wise XOR mask with the `KASUMI_EDGE_SYNC_V1_MASK` constant. Applying the same operation reverses the representation. This is **not cryptographic encryption**.
* **Access Control at Rest**: Operating system file permissions restrict read and write access:
  * **Windows**: Explicit, protected DACLs (`D:P(A;FA;;;SY)(A;FA;;;<user-sid>)`) disable inheritance and restrict access to the owner user and `SYSTEM`. Symlinks and reparse points are rejected.
  * **POSIX**: Mode `0600` for files and `0700` for private directories (`O_NOFOLLOW` and `lstat` checks reject symlinks).
* **Sensitive File Writes**: Private-file writes such as `key.bin` and the transaction journal use temporary same-directory files, filesystem flushing (`FlushFileBuffers` / `fsync`), and atomic replacement/rename (`MoveFileExW` on Windows, POSIX rename). SQLite `StoredState` instead uses database transactions; see [Local Persistent State](architecture/local-state.md).

### Domain-Separated Subkeys

Keyed BLAKE2b derives distinct 32-byte subkeys across isolated domains:

* `Content`: file content payload encryption
* `History`: commit DAG and quarantine metadata encryption
* `Epoch`: Epoch lifecycle envelope encryption
* `Journal`: local transaction journal encryption
* `RemoteIdentifier`: keyed identifier derivation
* `FsckCheckpoint`: local authenticated fsck checkpoint

Content, Commit, Epoch, and namespace identifiers also use disjoint cryptographic domain tags. Derived namespace components are truncated to eight hex characters (the version component to four), so namespace derivation is not a confidentiality guarantee for protocol structure. Ephemeral subkey buffers in memory are wiped at defined cleanup points using `crypto_wipe`; Kasumi does not claim to prevent all copies or swap exposure of secrets.

## Encryption Standards

File contents and commit payloads use **XChaCha20-Poly1305** authenticated encryption (AEAD) via Monocypher. Each file receives an independent, random 24-byte nonce and is encrypted in chunks of up to 4 MiB (`CHUNK_SIZE`). The file header authenticates protocol magic, format version, nonce, and total size. Each chunk authenticates the header, its chunk index, and chunk length with a 16-byte Poly1305 tag.

Epoch records use an authenticated XChaCha20-Poly1305 envelope under the Epoch subkey, with the AEAD nonce derived from the Epoch identifier.

The local transaction journal uses the same AEAD scheme with the Journal subkey, a random nonce, and verified format headers. The transaction journal is local and is not stored on remote storage.

An authentication failure causes the protected object or journal record to be rejected, and it is not accepted as synchronization state.

## Cryptographic Identifiers

| Identifier | Derivation | Purpose |
|---|---|---|
| Logical Hash | Plaintext BLAKE3 | `NodeRow` identity, change detection, deduplication |
| Content ID | Keyed BLAKE2b of logical hash | Opaque remote storage object name |
| Commit ID | Keyed BLAKE2b of canonical commit | Parent references, commit object path, and HEAD-marker binding |
| Epoch ID | Keyed BLAKE2b of canonical Epoch | Lifecycle chain sequencing and Epoch object path |
| Ciphertext ID | BLAKE3 of encrypted Commit payload | Physical Commit variant tracking |
| Physical Hash | SHA-256 of stored bytes | Remote transport and transfer integrity verification |
| Namespace component | Truncated keyed BLAKE2b derivation | Remote protocol path components |

Under different master keys, the keyed Content, Commit, and Epoch identifier derivations produce different identifiers for the same logical input. Plaintext BLAKE3 logical hashes are not used directly as remote content object identifiers. They may appear in encrypted commit or transaction journal records and in protected local database state.

## History DAG Integrity

A canonical commit contains the Snapshot tree, parent commit IDs, tree height, and creation timestamp. The commit ID authenticates this canonical serialized representation under the vault key, and the commit payload is encrypted and authenticated under the History domain.

Before accepting any commit into the local history DAG, Kasumi verifies:
* AEAD authentication tag validity;
* Keyed commit ID integrity;
* Snapshot canonical structure, ordering, hierarchy, and path constraints;
* Parent existence, height consistency (`height = max(parent height) + 1`), and absence of cycles;
* Timestamp non-regression along parent edges.

```text
Encrypted Commit → AEAD Auth → Topological Validation → HEAD Marker Validation → Physical Verification → Local State
```

The commit object is published and verified using the transport's physical-hash capability or readback fallback before its HEAD marker is published. HEAD markers are structurally validated and bind a commit ID to a ciphertext ID. The referenced commit variant is cryptographically authenticated before the marked commit participates in validated history.

Epochs define authenticated retention horizons and boundary anchors. The writer/barrier protocol separately coordinates garbage collection with active synchronization work.

## Local Filesystem Isolation

* **Windows**: Private application directories and state databases are created with explicit DACLs granting access exclusively to the current user and `SYSTEM`.
* **POSIX**: Private directories use mode `0700` and sensitive files use mode `0600`.

Internal routines reject symlinks and Windows reparse points inside private state directories. Writing configuration, master key, and journal files employs temporary files, filesystem flush (`fsync` / `FlushFileBuffers`), and atomic rename replacement.

`db.sqlite` persists accepted history trees, Commit references, height metadata, and Epoch references. The local `inspection-history-v1.cache` can also contain decoded Commit trees and is authenticated but not encrypted. These local files rely on filesystem permissions and disk encryption for at-rest privacy. `transaction.bin.enc` records encrypted, authenticated mutation phases used by [interruption recovery](architecture/transactions-and-recovery.md). [Local Persistent State](architecture/local-state.md) distinguishes these authorities from caches and checkpoints.

## Remote Metadata Privacy

Remote storage providers observe key-derived protocol namespace components and their hierarchy, keyed or otherwise opaque object identifiers, Commit ID/Ciphertext ID relationships, clear Epoch sequence numbers, HEAD-marker and maintenance control-object presence, object counts and sizes, deduplication/reuse patterns within a vault, quarantine state, and operation timing. Canonical file paths, directory hierarchy, file modification timestamps, Commit parent IDs, and Snapshot rows are inside protected Commit payloads and are not directly remote object names. Provider-specific metadata may reveal further operational information outside Kasumi's payload encryption boundary.

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
