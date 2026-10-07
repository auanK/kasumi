# Fsck: Integrity Audit

`kasumi fsck <profile>` audits the observed vault's authenticated structure and every content object referenced by its effective remote tree. It is not a repair, GC, or a guarantee about future provider state. [Remote Layout and Publication](remote-layout.md) defines the objects; [Security](../security.md) defines their cryptographic boundaries.

## Lifecycle

1. The CLI dispatches `Operation::Fsck` through `application::execute`. Read-only runtime/profile resolution validates retention, the local exclusive profile lock is acquired, the saved or matching supplied key is loaded, and the local/rclone [transport](transport.md) is opened.
2. **Before the audit**, [Sync transaction recovery](transactions-and-recovery.md) runs if a journal exists. It may roll back or roll forward local mutations and remote publication; failure stops Fsck. The Fsck audit itself does not intentionally publish or remove remote objects.
3. Fsck obtains an authenticated remote storage observation, including history and the physical namespace. Missing history, malformed/unknown identifiers, invalid history, or inconsistent references fail closed. It also performs a normal local-tree scan for inventory analysis; the local tree is a comparison input, not a substitute for authenticated remote bytes. Inventory identifies distinct content objects referenced by the effective remote state and the paths affected by each. It does not select orphan-only content for its payload audit.
4. A private workspace holds downloads and plaintext only during the audit. Fsck loads the encrypted/authenticated `fsck_checkpoint.bin.enc` when it matches the current vault identity and records matching prior entries as resume candidates. A bad/mismatched checkpoint is not trusted. Provider `physical_hash` may compare SHA-256 for a candidate, but **even a match does not skip download, AEAD authentication, or plaintext verification**: provider metadata cannot prove bytes against an untrusted provider.
5. A bounded worker window (content concurrency defaults to 8, capped at 16) downloads **every referenced keyed Content ID**. Each worker decrypts/authenticates ciphertext and verifies plaintext BLAKE3 logical hash and size against committed metadata. The object is fetched by the keyed Content ID derived from that expected hash, binding verified plaintext to the requested ID. Missing/corrupt objects are collected with their referenced paths; transport/workspace errors are hard failures. Verified entries include a locally computed physical ciphertext SHA-256 for checkpoint recording.
6. Verified progress can be written to the private checkpoint in groups of 64 and again after a fully healthy audit; checkpoint saves are best effort and do not advance `StoredState`. A hard failure or cancellation stops new worker admissions, drains in-flight work, removes the workspace, and returns an error. Missing/corrupt referenced objects produce an unrecoverable-path result after classification. Healthy completion returns the number of checked objects (and byte progress when available). Transport, key, and lock are cleaned up on exit.

The checkpoint retains audit progress metadata and candidate comparisons on later runs; it is **not authority to mark remote payloads healthy** and current Fsck never skips a referenced payload because it was previously verified. Audit workers may overlap downloads, so results describe the observed run, not an atomic global snapshot against concurrent remote writers. The local profile lock only serializes processes using that same profile on one machine.

## Boundaries

| View | What it proves or changes |
|---|---|
| Fsck | Authenticated history/namespace plus full AEAD, logical-hash, size, and keyed-ID binding for **referenced** content; private checkpoint and possible preceding recovery effects. No repair/quarantine/purge in the audit. |
| [`remote contents --audit`](remote-content-inspection.md) | Inspection inventory plus byte validation of **all physically present** content, including orphans; reports per-object states, without Fsck's checkpoint or prior transaction recovery. |
| [`remote health`](remote-maintenance-inspection.md) | Diagnostic composition of history, availability, reachability, controls, and unknowns; no content-payload AEAD audit by default. |
| [Garbage Collection](garbage-collection.md) | Reachability-based quarantine, restore, and eventual purge under a barrier; does not perform Fsck's full referenced-payload audit. |
