# Provider Certification

Provider evidence is specific to a source/build, configuration, workload, and
observed storage state. Synchronization results, optional physical-hash support,
payload integrity, and destructive-maintenance consistency are separate claims.

## Google Drive Operational Validation — 0.7.0

The 2026-10-15–16 campaign used real Google Drive through rclone, Windows 11,
and Ubuntu under WSL2 with its local tree on ext4. Two independently configured
profiles exchanged changes in both directions within an isolated test vault.
This establishes results for that setup; it does not recertify the other ten
backends below with the same build or promise provider availability.

### Source and build identity

The campaign began at
[`913317f`](https://github.com/auanK/kasumi/commit/913317f8baf9523c8c5cc5a64e7b497231877636).
Simultaneous sibling-head publication exposed an ancestry-validation defect.
After the fix, locally rebuilt Release binaries resolved the existing heads and
passed a repeat of the simultaneous-publication scenario. That correction and
its regression test are committed in
[`e1a0ce3`](https://github.com/auanK/kasumi/commit/e1a0ce3c74762b0bc00931377aae4dc35ff117f0).
The initial SHA does **not** contain the fix; the campaign combines pre-fix
scenarios and post-fix reruns, rather than a complete rerun at the final SHA.

Hosted CI is a separate gate. As checked on 2026-10-16, the corrected commit's
[Ubuntu run](https://github.com/auanK/kasumi/actions/runs/38844759389) and
[Windows run](https://github.com/auanK/kasumi/actions/runs/38844759361) both
completed successfully. Their five toolchain jobs passed Debug and Release
builds/tests: Ubuntu GCC 14 and Clang 19; Windows MSVC 2022, GCC/UCRT64, and Clang64.
The earlier stabilization commit also passed its
[Ubuntu](https://github.com/auanK/kasumi/actions/runs/38831613296) and
[Windows](https://github.com/auanK/kasumi/actions/runs/38831613310) CI; those earlier
results alone do not establish the later fix's status. This record does not
declare an RC, tag, or release published.

### Observed coverage and limits

| Area | Evidence established by the campaign | Limit |
|---|---|---|
| Initialization and bidirectional Sync | Upload, download, update, rename, delete, Unicode paths, and subsequent no-op runs | Two clients on the recorded Windows/WSL2 setup |
| Large content | Initial transfer of 1, 10, and 100 MiB files, plus a real 100 MiB update; cross-client BLAKE3 and SHA-256 matched | The interrupted large-file scenario used **10 MiB**, not 100 MiB; timings are run-specific |
| Concurrency | File conflicts, independent edits, simultaneous sibling HEADs, post-fix resolution and repeat convergence | Multiple HEADs are normal; no global writer lock or universal conflict-free guarantee |
| Interruptions | Abrupt Windows process termination, Linux SIGKILL, transport termination, unreachable proxy endpoint, and later successful Sync | Process/transport failure tests do not simulate physical power loss; one download-failure attempt stopped during observation |
| Integrity | Both clients' Fsck audits passed; physical content audit authenticated all 36 then-present payloads, including retained historical versions | Fsck checked 27 current-tree payloads at that point, and 120 after later workload changes; these are not total protocol-object counts |
| Writer maintenance and GC (historical) | GC refused observed abandoned writers; six markers were removed after operational checks, then GC completed with **0 candidates, 0 quarantined, 0 restored, 0 purged**; subsequent Fsck passed | This campaign predates phase GC-R1. The GC/quarantine lifecycle scenario was removed with the quarantine subsystem; no eligible-object purge, quarantine restoration, or corruption repair was demonstrated, and quarantine stayed empty. |
| Volume | 100 small files in ten directories, update of 25 files, final cross-client manifest equality and no-op convergence | A workload sample, not a scalability bound |

The evidence is the campaign's `large-file-results.md`, `concurrency-results.md`,
`recovery-results.md`, `network-failure-results.md`, `integrity-results.md`,
`retention-results.md`, `performance-results.md`, and their original stage/final
logs and hash manifests. The final Fsck total changed after seven large test
files were logically deleted and the 100-file workload was added; historical
payloads remained in storage. Public performance guarantees cannot be inferred
from these runs. Detailed raw evidence remains in the external certification
archive, outside the source repository.

## Historical Multi-Provider Validation — 0.6.0

The recorded provider-neutral certification runs cover the following storage
backends. Every listed provider passed all 16 scenarios of that historical
campaign and completed ownership-safe cleanup; see the
[changelog's validation record](../CHANGELOG.md#060). These are historical
results, not certification of every later binary or provider configuration.
Phase GC-R1 removed the `gc-lifecycle` scenario, so the current runner registers
15 scenarios and does not certify GC behavior.

| Provider | Remote physical SHA-256 |
|---|---|
| Local Filesystem | Unsupported |
| Google Drive | Supported |
| OneDrive | Unsupported |
| SFTP | Not recorded |
| FTP | Unsupported |
| Explicit FTPS | Unsupported |
| WebDAV | Unsupported |
| Dropbox | Unsupported |
| Backblaze B2 | Unsupported |
| Azure Blob Storage | Unsupported |
| S3-compatible (MinIO) | Unsupported |

`physical_hash` is an optional transport optimization. In these historical runs,
providers without remote SHA-256 were validated through Kasumi's verified
fallback path; unsupported hash capability is not a payload-integrity failure.

## Maintenance and Integrity Boundaries

This table records only physical-hash capability. It does not certify provider-wide `LIST`/`PRESENCE` consistency for online destructive maintenance. The maintenance probe checks its own temporary object and cannot establish visibility of every existing control object; confirm those provider guarantees separately as described in [Transport](architecture/transport.md).

Google Drive's operational results do not remove that boundary. Stop Sync on
every client and serialize destructive maintenance and writer removal. A
zero-candidate historical GC run did not exercise the current direct-deletion
collector and does not certify it. Fsck's
AEAD/BLAKE3/size checks, the physical content audit, and optional provider SHA-256
measure different things; a provider-reported hash is not proof against a
malicious provider. Keep [independent backups](best-practices.md#backups).

See [Transport](architecture/transport.md) for the capability boundary and [Garbage Collection](architecture/garbage-collection.md) for runtime visibility checks.
