# Fsck: Integrity Audit

`kasumi fsck <profile>` audits the observed vault's authenticated structure and every content object referenced by its effective remote tree. [Remote Layout and Publication](remote-layout.md) defines the objects; [Security](../security.md) defines their cryptographic boundaries.

## Lifecycle

1. Runtime/profile resolution validates retention, acquires the local exclusive
   profile lock, loads the saved or matching supplied key, and opens the local
   or rclone [transport](transport.md).
2. **Before the audit**, [Sync transaction recovery](transactions-and-recovery.md) runs if a journal exists. It may roll back or roll forward local mutations and remote publication; failure stops Fsck. The Fsck audit does not modify synchronized files, Content/Pack objects, or commits; upon finishing (clean, issues found, failed, or cancelled), it records local execution metadata in `db.sqlite` and publishes a best-effort encrypted `KACT` v1 operational activity record (`FilePurpose::Activity`) to `<activity-ns>/<version-ns>/` (emitting a warning and leaving local `remote_publish_state` as `Pending` if activity publication fails).
3. Fsck obtains an authenticated remote storage observation, including history and the physical namespace. Missing history, malformed/unknown identifiers, invalid history, or inconsistent references fail closed. It also performs a normal local-tree scan for inventory analysis; the local tree is a comparison input, not a substitute for authenticated remote bytes. Inventory identifies distinct content objects referenced by the effective remote state and the paths affected by each. It does not select orphan-only content for its payload audit.
4. A private workspace holds downloads and plaintext only during the audit.
5. Using the effective `StorageManifest` alongside the effective remote tree, Fsck deduplicates physical objects (`KPAK\x01` Pack IDs, FastCDC chunk Content IDs, and loose Content IDs) and runs a bounded worker window (content concurrency defaults to 8, capped at 16) to download **every referenced physical object once**:
   * **Loose Content objects**: Each worker decrypts/authenticates the ciphertext (`FilePurpose::Content`) and verifies plaintext BLAKE3 logical hash and size against committed metadata.
   * **`KPAK\x01` Micro-Packs**. Each referenced Pack ID is downloaded and authenticated once (`FilePurpose::Pack`). The audit verifies the Pack ID binding and the size and BLAKE3 of every member against the pack descriptors.
   * **FastCDC chunked files**. Fsck authenticates each required chunk once. It streams the verified chunks in manifest order and verifies the assembled BLAKE3 and size against the committed file. Plaintext chunks live in the private workspace until all audit workers that reference them have finished using them.
   Missing/corrupt objects are collected with their referenced paths; transport/workspace errors are hard failures.
6. A hard failure or cancellation stops new worker admissions, drains in-flight work, removes the workspace, and returns an error. Missing/corrupt referenced objects produce an unrecoverable-path result after classification. Healthy completion returns the number of checked objects (and byte progress when available). Transport, key, and lock are cleaned up on exit.

## Boundaries

Workers may overlap downloads, so the audit describes an observed run rather
than an atomic snapshot against concurrent writers. The profile lock serializes
only that profile on one machine. Temporary-file cleanup can replace an earlier
GET/corruption diagnostic with a workspace error; some observation errors retain
detail only as text. Incomplete audits remain failures.

| View | What it proves or changes |
|---|---|
| Fsck | Authenticated history/namespace plus full AEAD, logical-hash, size, and keyed-ID binding for **referenced** content; possible preceding recovery effects plus best-effort `KACT` v1 activity publication. No file/commit repair or deletion. |
| [`remote contents <profile> --audit`](remote-content-inspection.md) | Inspection inventory plus byte validation of **all physically present** content, including orphans; reports per-object states, without prior transaction recovery. |
| [`remote health`](remote-maintenance-inspection.md) | Diagnostic composition of history, availability, reachability, controls, and unknowns; no content-payload AEAD audit by default. |
| [Garbage Collection](garbage-collection.md) | `--dry-run` preview or direct removal of eligible orphan Content, redundant CommitVariants, expired unreachable Commits behind Epochs, and pruned `KACT` activities under cooperative multi-barrier maintenance controls. |

## Live audit progress

The audit driver samples download bytes while its workers are running. It reports physical objects downloaded, logical objects verified, and FastCDC files reconstructed. Transfer counters are atomic and progress observers run outside the audit workers.
