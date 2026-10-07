# Remote Layout and Publication

The production remote layout is derived from the 32-byte vault master key. `namespace_identifier` uses the remote-identifier subkey and a namespace domain tag; `derive_remote_layout` takes truncated lowercase hex components for history, commits, heads, epochs, GC, barrier, writers, probes, quarantine, and content. The history-family components are eight hex characters; the version component is four. The remote root also contains 64-hex-character keyed Content IDs. The following is structural notation, not literal path names:

```text
<remote root>/
  <content-id>
  <history-ns>/<commits-ns>/<commit-id>/<ciphertext-id>
  <history-ns>/<heads-ns>/<commit-id>-<ciphertext-id>
  <history-ns>/<epochs-ns>/<version-ns>/<20-digit-sequence>-<epoch-id>
  <history-ns>/<gc-ns>/<version-ns>/<barrier-id>
  <history-ns>/<gc-ns>/<version-ns>/<writers-ns>/<token>
  <history-ns>/<gc-ns>/<version-ns>/<probes-ns>/<token>
  <history-ns>/<gc-ns>/<version-ns>/<quarantine-ns>/<content-ns>/<content-id>[.meta]
  <history-ns>/<gc-ns>/<version-ns>/<quarantine-ns>/<commits-ns>/<commit-id>/<ciphertext-id>[.meta]
```

Commit variants, physical markers, Epoch objects, writer/probe objects, and ordinary content IDs are extensionless. `.meta` is used for quarantine metadata. `default_remote_layout()` and some legacy path recognition remain in code, but key-derived `RemoteLayout` is passed through production sync, inspection, and maintenance flows. Literal protocol labels and the old filename extensions do not describe current publications.

## Identities and Visibility

A **Commit ID** is a keyed identifier of canonical Commit bytes: the complete Snapshot, sorted parents, height, and timestamp. A **Ciphertext ID** is BLAKE3 of one encrypted Commit payload. Random encryption nonces permit several physical ciphertext variants for one logical Commit ID. `HeadReference` binds both IDs. A physical HEAD marker names that reference and records publication; a **logical head** is a marked Commit that is not an ancestor of another marked Commit. Old ancestral markers can coexist until pruning. Content IDs derive from plaintext logical BLAKE3 hashes under the vault key, enabling deduplication inside a vault without exposing the raw logical hash as the object name. See [History and Concurrency](history-and-concurrency.md) and [Security](../security.md).

Remote storage still sees object count, byte sizes, access timing, deduplication, opaque IDs, Commit/Ciphertext relationships, and the clear decimal Epoch sequence in its object name. Derived namespace components hide literal protocol labels from a storage listing but are short and do not hide the structural pattern. Commit payloads contain encrypted paths, metadata, parents, and trees. Provider metadata and transport behavior remain outside Kasumi's encrypted payload boundary.

## Publication Order

The client confirms required encrypted content first. It prepares a canonical Commit for the validated publication tree and observed logical heads (or a parentless genesis Commit), uploads or reuses an authenticated variant, and checks its remote physical representation before publishing a HEAD marker. A backend SHA-256 **physical hash** can be used for this transport check; when unsupported, Kasumi downloads and validates the object. The provider-supplied hash is not an independent cryptographic attestation against a malicious provider; later history loading authenticates the protected Commit. Only after the Commit check does it publish and verify the marker. Genesis then publishes an authenticated Epoch; later pruning Epochs are published when retention advances safely. SQLite `StoredState` advances after the remote publication checks, then observed ancestral markers are pruned and the transaction journal is cleared. A concurrent client can publish another immutable branch while this happens; later reconciliation resolves both heads. Ambiguous visibility or failed verification stops or enters [recovery](transactions-and-recovery.md), rather than treating a PUT response alone as acceptance.

Content, Commit, and marker publication can use verified reuse and scoped inventory fast paths; these avoid redundant transfers without changing the identity or validation requirements. The [Transport](transport.md) page owns backend capabilities and fallbacks.
