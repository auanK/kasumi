# Architecture Overview

## High-Level Design

Kasumi synchronizes local directories using shared remote storage. Each client observes its local directory and remote protocol state, determining which mutations to publish or materialize. Remote storage serves as a passive repository for Kasumi data and protocol objects; synchronization and reconciliation logic execute on clients. Kasumi does not require a dedicated Kasumi coordination server.

```text
Machine A ── publish ──> Shared Storage ── consume ──> Machine B
```

File payloads, commit payloads, and Epoch records are encrypted and authenticated before being stored remotely. Clients synchronize asynchronously: Machine A can publish changes while Machine B is offline, and Machine B observes and incorporates those changes during a subsequent synchronization.

All reconciliation, cryptographic validation, three-way reconciliation, and recovery operations execute locally on client machines. Clients can publish concurrently without an exclusive global synchronization lock between machines. Concurrent publications form immutable branches in the history DAG; subsequent synchronization reconciles the observed branches and can publish a merge commit with multiple parents.

## Profiles vs. Vaults

* A **Profile** is the local configuration and state associated with a synchronized directory on one machine, including its local directory path, remote storage endpoint, retention policy, local database, and local key material. Operations on the same profile are serialized locally by a profile lock.
* A **Vault** is the shared logical identity of the remote history. Its identifier, `vault_id`, is established in the genesis Epoch and validated by clients using the shared master key.

Different machines configure independent profile names and local directory paths while interacting with the same shared vault. Clients participate in that vault when they connect to the same remote storage namespace, use the matching master key, and observe the same authenticated genesis Epoch defining the shared `vault_id`.

## A Simple Sync Walkthrough

In a basic scenario with a single initial commit, Machine A creates a file:

```text
Documents/
└── work.txt
```

Upon executing `kasumi sync`, Machine A:
1. Scans the local directory and computes the Merkle tree snapshot;
2. Encrypts and uploads the content payload;
3. Encrypts and publishes the commit, `C0`, followed by a HEAD marker pointing to `C0`.

```text
Machine A                         Shared Remote
Documents/work.txt  ──────> Encrypted Content Object
                            Encrypted Commit C0
                            HEAD marker -> C0
```

When Machine B subsequently synchronizes against the same vault:
1. Downloads and validates the HEAD marker, then fetches, authenticates, and decrypts commit `C0`;
2. Fetches the required encrypted content objects;
3. Decrypts and materializes `Documents/work.txt` into its local folder;
4. Persists `C0` into its local SQLite database as the accepted state for future reconciliations.

## Architecture Deep Dives

* [Data Model & Merkle Trees](architecture/data-model.md)
* [Synchronization & Reconciliation](architecture/synchronization.md)
* [History DAG, Concurrency & Retention](architecture/history-and-concurrency.md)
* [Remote Storage, Integrity & Maintenance](architecture/remote-storage-and-maintenance.md)
* [Security Specification](security.md)
